import type { CatalogStore, RuntimeActionDefinition } from "../../catalog-store.ts";
import type { ExecutionConnection, IConnectionStore } from "../../connection-service.ts";
import type { ExecutionContext, ExecutionResult, RuntimeLogger, TransitFileWriter } from "../../core/types.ts";
import type { IProviderLoader } from "../../providers/provider-loader.ts";
import type { SaasRequestScope } from "../contracts.ts";

import { Buffer } from "node:buffer";
import { createHash, randomUUID } from "node:crypto";
import { executeAction } from "../../core/execution.ts";
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

export interface SaasExecutionConnections {
  resolveForExecution(service: string, connectionName?: string): Promise<ExecutionConnection>;
}

export interface SaasActionRunnerOptions {
  scope: Readonly<SaasRequestScope>;
  catalog: CatalogStore;
  providerLoader: IProviderLoader;
  connectionStore: IConnectionStore;
  connections: SaasExecutionConnections;
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
    const keyHash = hashIdempotencyKey(key.key);
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
    let connection: ExecutionConnection;
    try {
      connection = await this.options.connections.resolveForExecution(binding.action.service, binding.connectionName);
      const executor = binding.action.execution.locallyExecutable
        ? await this.options.providerLoader.loadActionExecutor(
            binding.action.service,
            binding.action.id,
            this.options.catalog.providers.find((provider) => provider.service === binding.action.service)?.displayName,
          )
        : undefined;
      execution = await executeAction(
        binding.action,
        executor,
        request.input,
        this.executionContext(connection, request.signal),
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
    const action = this.options.catalog.actionsById.get(request.actionId);
    const maxOutputBytes = this.options.scope.maxOutputBytes;
    if (
      this.options.scope.purpose !== "action:execute" ||
      !this.options.scope.permissions.includes("action:execute") ||
      !action ||
      action.id !== this.options.scope.actionId ||
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
      requestHash = canonicalActionRequestHash(action.id, request.connectorConnectionId, request.input);
    } catch {
      return { ok: false, result: failed("invalid_input", "Action input must be canonical JSON.") };
    }
    if (requestHash !== this.options.scope.requestHash) {
      return { ok: false, result: failed("request_hash_mismatch", "Action request does not match its authorization.") };
    }

    try {
      // ponytail: reuse the scoped upstream contract; add a metadata-only getById if connection counts make this measurable.
      const connection = (await this.options.connectionStore.list()).find(
        (candidate) => candidate.id === request.connectorConnectionId,
      );
      if (!connection || connection.service !== action.service) {
        return {
          ok: false,
          result: failed("connection_provider_mismatch", "Connection is not authorized for this provider."),
        };
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

  private executionContext(connection: ExecutionConnection, signal: AbortSignal | undefined): ExecutionContext {
    return {
      getCredential: connection.getCredential,
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
