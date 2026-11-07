import type { CatalogStore } from "../../catalog-store.ts";
import type { TriggerRunner } from "../../triggers/trigger-runner.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { PostgresActionPolicyStore } from "../storage/postgres-action-policy-store.ts";
import type { PostgresConnectionStore } from "../storage/postgres-connection-store.ts";
import type { PostgresTriggerStore } from "./postgres-trigger-store.ts";

import { assertProcessingActive, captureRequestProcessing, getRequestSignal } from "../../core/cancellation.ts";
import { ExecutionError } from "../../core/execution-error.ts";
import { readTriggerRequest } from "../../triggers/request.ts";
import { subscriptionId } from "../../triggers/subscriptions.ts";
import { canonicalActionRequestHash } from "../actions/canonical-request.ts";
import { maximumActionOutputBytes } from "../contracts.ts";
import { scopedTriggerOwner } from "./postgres-trigger-store.ts";
import { triggerCapability } from "./trigger-capability.ts";

export interface SaasTriggerRunnerOptions {
  scope: Readonly<SaasRequestScope>;
  catalog: CatalogStore;
  actionPolicy: Pick<PostgresActionPolicyStore, "getEffectiveForActor" | "withEffectiveForActor">;
  connectionStore: Pick<PostgresConnectionStore, "getSafeConnection">;
  store: Pick<PostgresTriggerStore, "withConnectionForExecution">;
  runner: Pick<TriggerRunner, "run">;
}
export interface SaasTriggerRequest {
  service: string;
  triggerId: string;
  connectorConnectionId: string;
  input: unknown;
  signal?: AbortSignal;
}

/** Final owner permission and current connection authority precede every native read/replay/provider call. */
export class SaasTriggerRunner {
  private readonly scope: Readonly<SaasRequestScope>;
  private readonly options: SaasTriggerRunnerOptions;
  constructor(options: SaasTriggerRunnerOptions) {
    this.options = options;
    const captured = { ...captureRequestProcessing(options.scope), permissions: [...options.scope.permissions] };
    Object.freeze(captured.permissions);
    this.scope = Object.freeze(captured);
  }
  async run(request: SaasTriggerRequest): Promise<unknown> {
    assertProcessingActive(this.scope);
    let capability: string;
    try {
      capability = triggerCapability(this.options.catalog, request.service, request.triggerId);
    } catch {
      throw new ExecutionError("trigger_not_found", "Declared Trigger not found.", "not_found");
    }
    const maximum = this.scope.maxOutputBytes;
    if (
      this.scope.purpose !== "action:execute:v2" ||
      this.scope.permissions.length !== 1 ||
      this.scope.permissions[0] !== this.scope.purpose ||
      this.scope.actionId !== capability ||
      this.scope.connectorConnectionId !== request.connectorConnectionId ||
      !this.scope.localConnectionId ||
      typeof maximum !== "number" ||
      !Number.isSafeInteger(maximum) ||
      maximum <= 0 ||
      maximum > maximumActionOutputBytes
    )
      throw new ExecutionError("forbidden", "Trigger authorization does not match this request.", "forbidden");
    let hash: string;
    try {
      hash = canonicalActionRequestHash(capability, request.connectorConnectionId, request.input);
    } catch {
      throw new ExecutionError("invalid_input", "Trigger input must be canonical JSON.");
    }
    if (hash !== this.scope.requestHash)
      throw new ExecutionError(
        "request_hash_mismatch",
        "Trigger request does not match its authorization.",
        "forbidden",
      );
    try {
      const decisions = await this.options.actionPolicy.getEffectiveForActor(this.scope, [capability]);
      if (decisions.length !== 1 || decisions[0]?.actionId !== capability || typeof decisions[0]?.enabled !== "boolean")
        throw new Error("Incomplete permission decision");
      if (!decisions[0].enabled)
        throw new ExecutionError("action_not_granted", "This Trigger is not permitted.", "forbidden");
    } catch (error) {
      if (error instanceof ExecutionError) throw error;
      throw new ExecutionError("action_policy_unavailable", "Trigger permission could not be verified.", "unavailable");
    }
    const connection = await this.options.connectionStore.getSafeConnection(request.connectorConnectionId);
    if (
      !connection ||
      connection.id !== request.connectorConnectionId ||
      connection.service !== request.service ||
      connection.localConnectionId !== this.scope.localConnectionId ||
      connection.subjectUserId !== this.scope.subjectUserId ||
      connection.status !== "active" ||
      (this.scope.actorUserId !== this.scope.subjectUserId && connection.visibility !== "workspace")
    )
      throw new ExecutionError("connection_not_found", "Trigger connection is not currently authorized.", "not_found");
    const input = readTriggerRequest(request.input);
    // Secret-bearing stateless SourceConfiguration is an internal native protocol. The private
    // wire uses its real persistent SourceReference equivalent, never a client-owned envelope.
    if (input.operation === "source")
      throw new ExecutionError("invalid_input", "Use sourceReference for private persistent Source operations.");
    const inherited = getRequestSignal(this.scope);
    const signal =
      inherited && request.signal
        ? AbortSignal.any([inherited, request.signal])
        : (inherited ?? request.signal ?? AbortSignal.timeout(120000));
    signal.throwIfAborted();
    return this.options.store.withConnectionForExecution(
      request.service,
      request.connectorConnectionId,
      this.options.actionPolicy,
      async () => {
        const raw = await this.options.runner.run({
          service: request.service,
          triggerId: request.triggerId,
          connectionId: request.connectorConnectionId,
          ownerId: scopedTriggerOwner(this.scope),
          request: input,
          signal,
        });
        let output = raw;
        if (
          (input.operation === "resource" || input.operation === "reconcile" || input.operation === "receive") &&
          raw &&
          typeof raw === "object" &&
          !Array.isArray(raw)
        ) {
          const {
            checkpoint: _privateCheckpoint,
            subscription: _privateSubscription,
            ...receipt
          } = raw as Record<string, unknown>;
          if (receipt.result && typeof receipt.result === "object" && !Array.isArray(receipt.result)) {
            const { checkpoint: _privateResultCheckpoint, ...result } = receipt.result as Record<string, unknown>;
            receipt.result = result;
          }
          if (
            input.operation !== "receive" &&
            !(input.operation === "reconcile" && input.subscriptionId) &&
            !connection.profile?.accountId
          )
            throw new ExecutionError(
              "trigger_connection_error",
              "The subscription requires a verified provider account.",
              "conflict",
            );
          const id =
            input.operation === "receive"
              ? input.subscriptionId
              : input.operation === "reconcile" && input.subscriptionId
                ? input.subscriptionId
                : await subscriptionId(
                    {
                      ownerId: scopedTriggerOwner(this.scope),
                      service: request.service,
                      triggerId: request.triggerId,
                      connectionId: connection.id,
                      providerAccountId: connection.profile!.accountId,
                      connectionRevision: "",
                    },
                    input.requestKey,
                  );
          output = { ...receipt, subscription: { id } };
        }
        assertProcessingActive(this.scope);
        signal.throwIfAborted();
        if (Buffer.byteLength(JSON.stringify(output) ?? "null") > maximum)
          throw new ExecutionError("action_output_too_large", "Trigger output exceeds its signed limit.", "too_large");
        return output;
      },
    );
  }
}
