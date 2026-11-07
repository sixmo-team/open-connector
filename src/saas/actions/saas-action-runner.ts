import type { CatalogStore, RuntimeActionDefinition } from "../../catalog-store.ts";
import type { ConnectionService } from "../../connection-service.ts";
import type { RuntimeExecutionOptions } from "../../core/runtime-execution.ts";
import type { ExecutionContext, ExecutionResult, RuntimeLogger, TransitFileWriter } from "../../core/types.ts";
import type { ExecutionTarget } from "../../execution-target.ts";
import type { MarketplaceService } from "../../marketplace/marketplace-service.ts";
import type { IProviderLoader } from "../../providers/provider-loader.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { SaasExecutionService } from "../saas-execution-service.ts";
import type { PostgresActionPolicyStore } from "../storage/postgres-action-policy-store.ts";
import type { SaasRuntimeConnectionStore } from "../storage/postgres-runtime-database.ts";

import { Buffer } from "node:buffer";
import { createHash, randomUUID } from "node:crypto";
import { ExecutionError } from "../../core/execution-error.ts";
import { executeAction } from "../../core/execution.ts";
import { withRuntimeExecution } from "../../core/runtime-execution.ts";
import { resolveExecutionTarget } from "../../execution-target.ts";
import { maximumActionOutputBytes } from "../contracts.ts";
import { createIdempotencyExpiry, hashIdempotencyKey, readIdempotencyKey } from "./action-idempotency.ts";
import { canonicalActionRequestHash } from "./canonical-request.ts";
import { safeRunLogError } from "./run-log-summary.ts";

export interface ExecutionIntent {
  executionId: string;
  connectionId: string;
  service: string;
  actionId: string;
  requestHash: string;
  inputBytes: number;
  startedAt: string;
}

export interface ExecutionCompletion {
  executionId: string;
  durationMs: number;
  outputBytes: number;
  resultFingerprint?: string;
  providerRequestCount?: number;
  completedAt: string;
}

export interface ExecutionFailure extends ExecutionCompletion {
  status: "failed" | "unknown";
  safeErrorCode: string;
}

/** Durable, payload-free audit boundary used before and after provider execution. */
export interface ExecutionJournal {
  start(intent: ExecutionIntent): Promise<void>;
  complete(completion: ExecutionCompletion): Promise<void>;
  fail(failure: ExecutionFailure): Promise<void>;
}

export interface SaasActionRequest {
  actionId: string;
  connectorConnectionId: string;
  input: unknown;
  idempotencyKey: string;
  signal?: AbortSignal;
}

export interface SaasActionSuccess {
  ok: true;
  executionId: string;
  status: "succeeded";
  output: unknown;
}

export interface SaasActionFailure {
  ok: false;
  executionId?: string;
  status: "failed" | "unknown";
  error: {
    code: string;
    message: string;
    retryable?: boolean;
  };
}

export type SaasActionRunResult = SaasActionSuccess | SaasActionFailure;

export interface SaasIdempotencyClaimInput {
  keyHash: string;
  requestHash: string;
  claimId: string;
  now: string;
  expiresAt: string;
}

export type SaasIdempotencyClaimResult =
  | { kind: "acquired" }
  | { kind: "in_progress" }
  | { kind: "completed"; response: SaasActionRunResult }
  | { kind: "conflict" };

export interface SaasIdempotencyCompletionInput extends SaasIdempotencyClaimInput {
  response: SaasActionRunResult;
  resultFingerprint?: string;
  safeErrorCode?: string;
}

export interface SaasActionIdempotencyStore {
  claimAction(input: SaasIdempotencyClaimInput): Promise<SaasIdempotencyClaimResult>;
  completeAction(input: SaasIdempotencyCompletionInput): Promise<boolean>;
}

export interface SaasActionRunnerOptions extends RuntimeExecutionOptions {
  scope: Readonly<SaasRequestScope>;
  catalog: CatalogStore;
  providerLoader: IProviderLoader;
  connectionStore: Pick<SaasRuntimeConnectionStore, "getSafeConnection">;
  connections: Pick<ConnectionService, "getConnectionSummary" | "resolveConnection">;
  actionPolicy: Pick<PostgresActionPolicyStore, "getEffectiveForActor">;
  saasExecution?: Pick<SaasExecutionService, "executeAction">;
  marketplace?: MarketplaceService;
  idempotency: SaasActionIdempotencyStore;
  journal: ExecutionJournal;
  transitFiles?: TransitFileWriter;
  providerRequestCount?: () => number | undefined;
  logger?: RuntimeLogger;
}

/** Execute one backend-authorized action only after durable deduplication and audit intent. */
export class SaasActionRunner {
  private readonly options: SaasActionRunnerOptions;

  constructor(options: SaasActionRunnerOptions) {
    this.options = options;
  }

  async run(request: SaasActionRequest): Promise<SaasActionRunResult> {
    const binding = await this.authorize(request);
    if (!binding.ok) return binding.result;

    const key = readIdempotencyKey(request.idempotencyKey);
    if (!key.ok || !key.key)
      return failed("invalid_idempotency_key", key.ok ? "Idempotency-Key is required." : key.message);

    const now = new Date();
    const claimId = randomUUID();
    const keyHash = hashIdempotencyKey(JSON.stringify([this.options.scope.actorUserId, key.key]));
    const claimInput: SaasIdempotencyClaimInput = {
      keyHash,
      requestHash: binding.requestHash,
      claimId,
      now: now.toISOString(),
      expiresAt: createIdempotencyExpiry(now),
    };
    let claim: SaasIdempotencyClaimResult;
    try {
      claim = await this.options.idempotency.claimAction(claimInput);
    } catch {
      return reconciliation("idempotency_unavailable");
    }
    if (claim.kind === "completed") {
      const current = await this.authorize(request);
      if (!current.ok) return current.result;
      if (claim.response.ok && jsonBytes(claim.response.output) > binding.maxOutputBytes) {
        return failed(
          "action_output_too_large",
          "Action output exceeds its reviewed size limit.",
          claim.response.executionId,
        );
      }
      return claim.response;
    }
    if (claim.kind === "conflict")
      return failed("idempotency_conflict", "Idempotency-Key was already used for a different request.");
    if (claim.kind === "in_progress") return reconciliation("execution_reconciliation_required");

    const executionId = randomUUID();
    const startedAtMs = Date.now();
    const startedAt = new Date(startedAtMs).toISOString();
    const inputBytes = jsonBytes(request.input);
    try {
      await this.options.journal.start({
        executionId,
        connectionId: binding.connectionId,
        service: binding.action.service,
        actionId: binding.action.id,
        requestHash: binding.requestHash,
        inputBytes,
        startedAt,
      });
    } catch {
      return reconciliation("audit_unavailable", executionId);
    }

    let execution: ExecutionResult;
    try {
      execution = await withRuntimeExecution(
        this.options,
        {
          operation: "action",
          service: binding.action.service,
          actionId: binding.action.id,
          executionId,
          connectionId: binding.connectionId,
          connectionName: binding.connectionName,
        },
        async () => {
          const connection = await resolveExecutionTarget({
            connections: this.options.connections,
            service: binding.action.service,
            connectionName: binding.connectionName,
            connectionId: binding.connectionId,
            operation: "action",
            actionId: binding.action.id,
            marketplace: this.options.marketplace,
            signal: request.signal,
          });
          if (connection.summary?.id !== binding.connectionId) {
            throw new ExecutionError("connection_changed", "Connection changed before execution.", "conflict");
          }
          const executor =
            connection.kind === "local" && binding.action.execution.locallyExecutable
              ? await this.options.providerLoader.loadActionExecutor(
                  binding.action.service,
                  binding.action.id,
                  this.options.catalog.providers.find((provider) => provider.service === binding.action.service)
                    ?.displayName,
                )
              : undefined;
          const current = await this.authorize(request);
          if (!current.ok) return current.result;
          if (connection.kind === "saas") {
            if (!this.options.saasExecution) {
              throw new ExecutionError("oauth_source_unavailable", "SaaS execution is not configured.", "unavailable");
            }
            const remote = await this.options.saasExecution.executeAction(
              connection.reference,
              binding.action.service,
              binding.action.id,
              request.input,
              request.signal,
            );
            return { ok: true, output: remote.output };
          }
          if (connection.kind === "marketplace") {
            return this.options.marketplace!.execute(binding.action.id, request.input, request.signal);
          }
          return executeAction(
            binding.action,
            executor,
            request.input,
            this.executionContext(connection, request.signal),
          );
        },
      );
    } catch {
      await this.markUnknown(executionId, startedAtMs);
      return reconciliation("execution_reconciliation_required", executionId);
    }

    const completedAtMs = Date.now();
    const completedAt = new Date(completedAtMs).toISOString();
    const durationMs = completedAtMs - startedAtMs;
    let result: SaasActionRunResult;
    let completion: ExecutionCompletion;
    let resultFingerprint: string;
    try {
      const outputBytes = execution.ok ? jsonBytes(execution.output ?? null) : 0;
      result =
        execution.ok && outputBytes > binding.maxOutputBytes
          ? failed("action_output_too_large", "Action output exceeds its reviewed size limit.", executionId)
          : toSafeResult(executionId, execution);
      resultFingerprint = createHash("sha256").update(JSON.stringify(result)).digest("base64url");
      completion = {
        executionId,
        durationMs,
        outputBytes: result.ok ? outputBytes : 0,
        resultFingerprint,
        completedAt,
      };
      const providerRequestCount = this.options.providerRequestCount?.();
      if (
        typeof providerRequestCount === "number" &&
        Number.isSafeInteger(providerRequestCount) &&
        providerRequestCount >= 0
      ) {
        completion.providerRequestCount = providerRequestCount;
      }
    } catch {
      await this.markUnknown(executionId, startedAtMs);
      return reconciliation("execution_reconciliation_required", executionId);
    }

    try {
      if (result.ok) await this.options.journal.complete(completion);
      else await this.options.journal.fail({ ...completion, status: "failed", safeErrorCode: result.error.code });
    } catch {
      await this.markUnknown(executionId, startedAtMs);
      return reconciliation("execution_reconciliation_required", executionId);
    }

    let completed = false;
    try {
      completed = await this.options.idempotency.completeAction({
        ...claimInput,
        response: result,
        resultFingerprint,
        safeErrorCode: result.ok ? undefined : result.error.code,
        expiresAt: createIdempotencyExpiry(new Date()),
      });
    } catch {
      // The durable run is complete, but the claim intentionally remains non-replayable.
    }
    if (!completed) return reconciliation("execution_reconciliation_required", executionId);

    this.options.logger?.info(
      {
        actionId: binding.action.id,
        service: binding.action.service,
        executionId,
        ok: result.ok,
        errorCode: result.ok ? undefined : result.error.code,
        inputBytes,
        outputBytes: completion.outputBytes,
        providerRequestCount: completion.providerRequestCount,
        durationMs,
      },
      "saas action completed",
    );
    return result;
  }

  private async authorize(request: SaasActionRequest): Promise<
    | {
        ok: true;
        action: RuntimeActionDefinition;
        connectionId: string;
        connectionName: string;
        requestHash: string;
        maxOutputBytes: number;
      }
    | { ok: false; result: SaasActionFailure }
  > {
    const summary = this.options.catalog.actionsById.get(request.actionId);
    const maxOutputBytes = this.options.scope.maxOutputBytes;
    if (
      this.options.scope.purpose !== "action:execute:v2" ||
      !this.options.scope.permissions.includes("action:execute:v2") ||
      !summary ||
      summary.id !== this.options.scope.actionId ||
      request.connectorConnectionId !== this.options.scope.connectorConnectionId ||
      typeof maxOutputBytes !== "number" ||
      !Number.isSafeInteger(maxOutputBytes) ||
      maxOutputBytes <= 0 ||
      maxOutputBytes > maximumActionOutputBytes
    ) {
      return { ok: false, result: failed("forbidden", "Action authorization does not match this request.") };
    }

    let requestHash: string;
    try {
      requestHash = canonicalActionRequestHash(summary.id, request.connectorConnectionId, request.input);
    } catch {
      return { ok: false, result: failed("invalid_input", "Action input must be canonical JSON.") };
    }
    if (requestHash !== this.options.scope.requestHash) {
      return { ok: false, result: failed("request_hash_mismatch", "Action request does not match its authorization.") };
    }

    let action: RuntimeActionDefinition | undefined;
    try {
      action = await this.options.catalog.getAction(summary.id);
    } catch {
      return { ok: false, result: failed("action_schema_unavailable", "Action definition could not be loaded.") };
    }
    if (!action) return { ok: false, result: failed("forbidden", "Action definition is unavailable.") };

    try {
      const connection = await this.options.connectionStore.getSafeConnection(request.connectorConnectionId);
      if (
        !connection ||
        connection.service !== action.service ||
        connection.localConnectionId !== this.options.scope.localConnectionId ||
        connection.subjectUserId !== this.options.scope.subjectUserId ||
        connection.status !== "active" ||
        (this.options.scope.actorUserId !== this.options.scope.subjectUserId && connection.visibility !== "workspace")
      ) {
        return {
          ok: false,
          result: failed("connection_provider_mismatch", "Connection is not authorized for this provider."),
        };
      }
      try {
        const decisions = await this.options.actionPolicy.getEffectiveForActor(this.options.scope, [summary.id]);
        const decision = decisions[0];
        if (decisions.length !== 1 || decision?.actionId !== summary.id || typeof decision.enabled !== "boolean") {
          return { ok: false, result: failed("action_policy_unavailable", "Action permission could not be verified.") };
        }
        if (!decision.enabled) {
          return { ok: false, result: failed("action_not_granted", "This action is not permitted.") };
        }
      } catch {
        return { ok: false, result: failed("action_policy_unavailable", "Action permission could not be verified.") };
      }
      return {
        ok: true,
        action,
        connectionId: connection.id,
        connectionName: connection.connectionName,
        requestHash,
        maxOutputBytes,
      };
    } catch {
      return { ok: false, result: failed("connection_unavailable", "Connection authorization could not be verified.") };
    }
  }

  private executionContext(
    connection: Extract<ExecutionTarget, { kind: "local" }>,
    signal: AbortSignal | undefined,
  ): ExecutionContext {
    return {
      getCredential: connection.getCredential,
      credentialCacheOwner: connection.credentialCacheOwner,
      ...(this.options.transitFiles ? { transitFiles: this.options.transitFiles } : {}),
      ...(signal ? { signal } : {}),
    };
  }
  private async markUnknown(executionId: string, startedAtMs: number): Promise<void> {
    const completedAtMs = Date.now();
    try {
      await this.options.journal.fail({
        executionId,
        status: "unknown",
        safeErrorCode: "execution_reconciliation_required",
        durationMs: completedAtMs - startedAtMs,
        outputBytes: 0,
        completedAt: new Date(completedAtMs).toISOString(),
      });
    } catch {
      // Retaining the original running intent is the fail-closed fallback.
    }
  }
}

/** Validate a completed SaaS result loaded from the scoped idempotency store. */
export function parseSaasActionRunResult(value: unknown): SaasActionRunResult {
  if (!value || typeof value !== "object") throw new Error("Invalid persisted SaaS action result");
  const result = value as Record<string, unknown>;
  if (
    result.ok === true &&
    typeof result.executionId === "string" &&
    result.status === "succeeded" &&
    "output" in result
  ) {
    return result as unknown as SaasActionSuccess;
  }
  if (
    result.ok === false &&
    (result.executionId === undefined || typeof result.executionId === "string") &&
    (result.status === "failed" || result.status === "unknown")
  ) {
    const error = result.error;
    if (
      error &&
      typeof error === "object" &&
      typeof (error as Record<string, unknown>).code === "string" &&
      typeof (error as Record<string, unknown>).message === "string"
    ) {
      return result as unknown as SaasActionFailure;
    }
  }
  throw new Error("Invalid persisted SaaS action result");
}

function toSafeResult(executionId: string, result: ExecutionResult): SaasActionRunResult {
  if (result.ok) return { ok: true, executionId, status: "succeeded", output: result.output ?? null };
  const safe = safeRunLogError(result.error);
  return {
    ok: false,
    executionId,
    status: "failed",
    error: {
      code: safeErrorCode(safe.errorCode),
      message: safe.errorMessage ?? "Action execution failed.",
    },
  };
}

function failed(code: string, message: string, executionId?: string): SaasActionFailure {
  return { ok: false, ...(executionId ? { executionId } : {}), status: "failed", error: { code, message } };
}

function reconciliation(code: string, executionId?: string): SaasActionFailure {
  return {
    ok: false,
    ...(executionId ? { executionId } : {}),
    status: "unknown",
    error: { code, message: "Execution requires durable reconciliation before it can be retried.", retryable: true },
  };
}

function safeErrorCode(code: string | undefined): string {
  return code && /^[a-z][a-z0-9_]{0,63}$/.test(code) ? code : "provider_error";
}

function jsonBytes(value: unknown): number {
  const serialized = JSON.stringify(value);
  return serialized === undefined ? 0 : Buffer.byteLength(serialized);
}
