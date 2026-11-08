import type {
  ProviderCredentialRevocationOutcome,
  SaasProviderCredentialRevoker,
} from "../connections/provider-credential-revoker.ts";
import type {
  ActionPolicyAuditRecord,
  ActionPolicyRecord,
  SafeConnectionSummary,
  SaasRequestScope,
} from "../contracts.ts";
import type { SeaweedFsTransitFileService } from "../files/seaweedfs-transit-files.ts";
import type { PostgresActionPolicyStore } from "../storage/postgres-action-policy-store.ts";
import type { PostgresConnectionRequestStore } from "../storage/postgres-connection-request-store.ts";
import type {
  LifecycleConnectionCursor,
  LifecycleConnectionRetirement,
  LifecyclePurgeConnection,
  PostgresConnectionStore,
} from "../storage/postgres-connection-store.ts";
import type { PostgresOAuthStateStore } from "../storage/postgres-oauth-state-store.ts";
import type { PostgresRunStore } from "../storage/postgres-run-store.ts";
import type { PostgresSaasProjectStore } from "../storage/postgres-saas-project-store.ts";
import type { PostgresTransitFileStore, TransitFileRecord } from "../storage/postgres-transit-file-store.ts";
import type { RunLog } from "../storage/run-store.ts";
import type {
  PostgresTriggerStore,
  TriggerLifecycleCleanup,
  TriggerSourceApplicationMetadata,
  TriggerSubscriptionMetadata,
} from "../triggers/postgres-trigger-store.ts";
import type { Pool, PoolClient } from "pg";

import { Buffer } from "node:buffer";
import { toSafeConnectionSummary } from "../connections/safe-connection-summary.ts";
import { lifecyclePurgeInputSchema } from "../contracts.ts";
import { LifecyclePurgeClaimConflictError } from "../storage/postgres-connection-store.ts";
import { decodeRunLogCursor } from "../storage/run-store.ts";
import { withScopedClient } from "../storage/scoped-query.ts";

const lifecycleEnumerationLimit = 100;

export interface SafeLifecycleRun {
  id: string;
  service: string;
  actionId: string;
  caller: RunLog["caller"];
  startedAt: string;
  completedAt: string;
  durationMs: number;
  ok: boolean;
  connectionId?: string;
  connectionProfile?: RunLog["connectionProfile"];
  runtimeTokenId?: string;
  policy?: RunLog["policy"];
  errorCode?: string;
}

export interface LifecycleStatusSummary {
  total: number;
  statuses: Array<{ status: string; count: number }>;
}

export interface LifecycleRecordCounts {
  connections: number;
  runs: number;
  oauthStates: LifecycleStatusSummary;
  idempotencyRecords: LifecycleStatusSummary;
  transitFiles: LifecycleStatusSummary;
  actionGrants: number;
  actionPolicyAudit: number;
  connectionRequests: LifecycleStatusSummary;
  requestSecrets: number;
  saasCleanup: LifecycleStatusSummary;
  connectionRetirements: number;
  triggerSubscriptions: LifecycleStatusSummary;
  triggerSourceApplications: number;
  triggerSecrets: number;
  triggerExecutionLeases: number;
}

export interface LifecycleExportPage {
  tenantId: string;
  workspaceId: string;
  subjectUserId: string;
  connections: SafeConnectionSummary[];
  runs: SafeLifecycleRun[];
  actionGrants: ActionPolicyRecord[];
  actionPolicyAudit: ActionPolicyAuditRecord[];
  connectionRequests: Array<{ id: string; status: string }>;
  saasCleanup: Array<{ id: string; status: string }>;
  connectionRetirements: LifecycleConnectionRetirement[];
  triggerSubscriptions: TriggerSubscriptionMetadata[];
  triggerSourceApplications: TriggerSourceApplicationMetadata[];
  counts: LifecycleRecordCounts;
  nextCursor: string | null;
}

export interface LifecyclePurgeCounts {
  connections: number;
  runs: number;
  oauthStates: number;
  idempotencyRecords: number;
  transitFiles: number;
  connectionSecrets: number;
  oauthStateSecrets: number;
  transitObjects: number;
  actionGrants: number;
  actionPolicyAudit: number;
  connectionRequests: number;
  saasCleanup: number;
  connectionRetirements: number;
  requestSecrets: number;
  triggerSubscriptions: number;
  triggerSourceApplications: number;
  triggerSecrets: number;
  triggerExecutionLeases: number;
}
export interface LifecycleRemoteRevocationAudit {
  revoked: number;
  unsupported: number;
  unresolved: number;
}

export interface LifecyclePurgeResult {
  tenantId: string;
  workspaceId: string;
  subjectUserId: string;
  correlationId: string;
  status: "purged";
  deleted: LifecyclePurgeCounts;
  remoteRevocations: LifecycleRemoteRevocationAudit;
}

export class LifecycleReconciliationRequiredError extends Error {
  readonly code = "LIFECYCLE_RECONCILIATION_REQUIRED";

  constructor(cause?: unknown) {
    super("Lifecycle cleanup requires reconciliation", { cause });
    this.name = "LifecycleReconciliationRequiredError";
  }
}

export class LifecyclePurgeConflictError extends Error {
  readonly code = "LIFECYCLE_PURGE_CONFLICT";

  constructor() {
    super("The exact scope is already being purged by another correlation");
    this.name = "LifecyclePurgeConflictError";
  }
}

export interface ScopedLifecycleServiceOptions {
  pool: Pool;
  scope: Readonly<SaasRequestScope>;
  actionPolicy: Pick<PostgresActionPolicyStore, "getLifecycleCounts" | "exportForLifecycle">;
  connectionRequests: Pick<
    PostgresConnectionRequestStore,
    "listExactOwnedForLifecycle" | "countExactOwnedForLifecycle" | "purgeExactOwnedForLifecycle"
  >;
  saasProjects: Pick<
    PostgresSaasProjectStore,
    "listExactOwnedCleanupForLifecycle" | "countExactOwnedCleanupForLifecycle" | "drainExactOwnedCleanupForLifecycle"
  >;
  runSaasCleanup: () => Promise<void>;
  triggers: Pick<
    PostgresTriggerStore,
    | "listExactOwnedForLifecycle"
    | "countExactOwnedForLifecycle"
    | "cleanupExactOwnedForLifecycle"
    | "purgeExactOwnedForLifecycle"
  >;
  triggerCleanup?: TriggerLifecycleCleanup;
  connections: Pick<
    PostgresConnectionStore,
    | "listExactOwnedForLifecycle"
    | "prepareExactOwnedForLifecyclePurge"
    | "markExactOwnedLifecycleProviderRevocation"
    | "deleteExactOwnedLifecycleSecret"
    | "listExactOwnedRetirementsForLifecycle"
    | "countExactOwnedRetirementsForLifecycle"
    | "purgeExactOwnedRetirementsForLifecycle"
  >;
  oauthStates: Pick<PostgresOAuthStateStore, "listExactOwnedForLifecycle" | "deleteExactOwnedLifecycleSecret">;
  runLogs: Pick<PostgresRunStore, "list">;
  transitMetadata: Pick<PostgresTransitFileStore, "listExactOwnedForLifecycle">;
  transitFiles?: Pick<SeaweedFsTransitFileService, "delete">;
  credentialRevoker?: SaasProviderCredentialRevoker;
}

const lifecyclePhases = [
  "connections",
  "runs",
  "policies",
  "connectionRequests",
  "saasCleanup",
  "connectionRetirements",
  "triggers",
] as const;
type LifecyclePhase = (typeof lifecyclePhases)[number];
type LifecycleCursor =
  | { phase: "connections"; after?: LifecycleConnectionCursor }
  | { phase: Exclude<LifecyclePhase, "connections">; after?: string };

/** Exact tenant/workspace/subject lifecycle export and purge. */
export class ScopedLifecycleService {
  private readonly options: ScopedLifecycleServiceOptions;

  constructor(options: ScopedLifecycleServiceOptions) {
    this.options = options;
  }

  async exportPage(input: { cursor?: string; limit: number }): Promise<LifecycleExportPage> {
    if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 100) {
      throw new TypeError("Lifecycle export limit must be between 1 and 100");
    }
    const cursor = decodeCursor(input.cursor, this.options.scope);
    const counts = await this.readCounts();
    const result: LifecycleExportPage = {
      tenantId: this.options.scope.tenantId,
      workspaceId: this.options.scope.workspaceId,
      subjectUserId: this.options.scope.subjectUserId,
      connections: [],
      runs: [],
      actionGrants: [],
      actionPolicyAudit: [],
      connectionRequests: [],
      saasCleanup: [],
      connectionRetirements: [],
      triggerSubscriptions: [],
      triggerSourceApplications: [],
      counts,
      nextCursor: null,
    };
    let remaining = input.limit;
    const totals: Record<LifecyclePhase, number> = {
      connections: counts.connections,
      runs: counts.runs,
      policies: counts.actionGrants + counts.actionPolicyAudit,
      connectionRequests: counts.connectionRequests.total,
      saasCleanup: counts.saasCleanup.total,
      connectionRetirements: counts.connectionRetirements,
      triggers: counts.triggerSubscriptions.total + counts.triggerSourceApplications,
    };
    for (let index = cursor ? lifecyclePhases.indexOf(cursor.phase) : 0; index < lifecyclePhases.length; index++) {
      const phase = lifecyclePhases[index]!;
      let next: LifecycleCursor | undefined;
      switch (phase) {
        case "connections": {
          const page = await this.options.connections.listExactOwnedForLifecycle(
            cursor?.phase === phase ? cursor.after : undefined,
            remaining,
          );
          result.connections.push(...page.items.map(toSafeConnectionSummary));
          remaining -= page.items.length;
          if (page.nextCursor) next = { phase, after: page.nextCursor };
          break;
        }
        case "runs": {
          const page = await this.options.runLogs.list({
            limit: remaining,
            cursor: cursor?.phase === phase ? cursor.after : undefined,
          });
          result.runs.push(...page.items.map(toSafeRun));
          remaining -= page.items.length;
          if (page.nextCursor) next = { phase, after: page.nextCursor };
          break;
        }
        case "policies": {
          const page = await this.options.actionPolicy.exportForLifecycle(this.options.scope, {
            limit: remaining,
            cursor: cursor?.phase === phase ? cursor.after : undefined,
          });
          result.actionGrants.push(...page.items);
          result.actionPolicyAudit.push(...page.audit);
          remaining -= page.items.length + page.audit.length;
          if (page.nextCursor) next = { phase, after: page.nextCursor };
          break;
        }
        case "connectionRequests": {
          const page = await this.options.connectionRequests.listExactOwnedForLifecycle(
            cursor?.phase === phase ? cursor.after : undefined,
            remaining,
          );
          result.connectionRequests.push(...page.items);
          remaining -= page.items.length;
          if (page.nextCursor) next = { phase, after: page.nextCursor };
          break;
        }
        case "saasCleanup": {
          const page = await this.options.saasProjects.listExactOwnedCleanupForLifecycle(
            cursor?.phase === phase ? cursor.after : undefined,
            remaining,
          );
          result.saasCleanup.push(...page.items);
          remaining -= page.items.length;
          if (page.nextCursor) next = { phase, after: page.nextCursor };
          break;
        }
        case "connectionRetirements": {
          const page = await this.options.connections.listExactOwnedRetirementsForLifecycle(
            cursor?.phase === phase ? cursor.after : undefined,
            remaining,
          );
          result.connectionRetirements.push(...page.items);
          remaining -= page.items.length;
          if (page.nextCursor) next = { phase, after: page.nextCursor };
          break;
        }
        case "triggers": {
          const page = await this.options.triggers.listExactOwnedForLifecycle(
            cursor?.phase === phase ? cursor.after : undefined,
            remaining,
          );
          result.triggerSubscriptions.push(...page.subscriptions);
          result.triggerSourceApplications.push(...page.sourceApplications);
          remaining -= page.subscriptions.length + page.sourceApplications.length;
          if (page.nextCursor) next = { phase, after: page.nextCursor };
          break;
        }
      }
      if (remaining < 0) throw new Error("Lifecycle store exceeded the combined page bound");
      if (next) {
        result.nextCursor = encodeCursor(next, this.options.scope);
        break;
      }
      if (remaining === 0) {
        for (let later = index + 1; later < lifecyclePhases.length; later++) {
          const nextPhase = lifecyclePhases[later]!;
          if (totals[nextPhase] > 0) {
            result.nextCursor = encodeCursor({ phase: nextPhase }, this.options.scope);
            break;
          }
        }
        break;
      }
    }
    return result;
  }

  async purge(input: { correlationId: string }, signal: AbortSignal): Promise<LifecyclePurgeResult> {
    const { correlationId } = lifecyclePurgeInputSchema.parse(input);
    try {
      await this.requirePolicyPurged();
      const triggerCounts = await this.options.triggers.countExactOwnedForLifecycle();
      if (triggerCounts.requiresCleanup) {
        const cleanup = this.options.triggerCleanup;
        if (!cleanup) throw new Error("Native trigger cleanup is unavailable");
        await this.options.triggers.cleanupExactOwnedForLifecycle((record, save, nativeSignal) =>
          cleanup(record, save, AbortSignal.any([signal, nativeSignal])),
        );
      }
      const triggers = await this.options.triggers.purgeExactOwnedForLifecycle();
      const requests = await this.options.connectionRequests.purgeExactOwnedForLifecycle();
      const connections = await this.options.connections.prepareExactOwnedForLifecyclePurge(correlationId);
      const oauthStates = await this.listAllOAuthStates();
      const transitFiles = await this.listAllTransitFiles();

      for (const connection of connections) await this.revokeConnectionCredential(connection, correlationId, signal);
      const remoteRevocations: LifecycleRemoteRevocationAudit = { revoked: 0, unsupported: 0, unresolved: 0 };
      for (const connection of connections) {
        if (connection.providerRevocationOutcome === "revoked") remoteRevocations.revoked += 1;
        else if (connection.providerRevocationOutcome === "unsupported") remoteRevocations.unsupported += 1;
        else remoteRevocations.unresolved += 1;
      }
      for (const connection of connections) {
        if (!connection.secretDeleted) {
          await this.options.connections.deleteExactOwnedLifecycleSecret(connection.id, correlationId);
        }
      }
      for (const state of oauthStates) await this.options.oauthStates.deleteExactOwnedLifecycleSecret(state.id);
      const transitObjectStore = this.options.transitFiles;
      if (transitFiles.length > 0 && !transitObjectStore) {
        throw new Error("Scoped transit object cleanup is unavailable");
      }
      if (transitObjectStore) {
        for (const file of transitFiles) {
          if (!(await transitObjectStore.delete(file.id, true))) {
            throw new Error("Transit metadata changed during lifecycle cleanup");
          }
        }
      }

      await this.assertInventoryStable(correlationId, connections, oauthStates, transitFiles);
      const deleted = await this.finalizePurge({
        connections: connections.length,
        oauthStates: oauthStates.length,
        transitFiles: transitFiles.length,
      });
      const cleanup = await this.options.saasProjects.drainExactOwnedCleanupForLifecycle(this.options.runSaasCleanup);
      const retirements = await this.options.connections.purgeExactOwnedRetirementsForLifecycle();
      await this.requirePolicyPurged();
      return {
        tenantId: this.options.scope.tenantId,
        workspaceId: this.options.scope.workspaceId,
        subjectUserId: this.options.scope.subjectUserId,
        correlationId,
        status: "purged",
        deleted: {
          ...deleted,
          connectionSecrets: connections.length,
          oauthStateSecrets: oauthStates.length,
          transitObjects: transitFiles.length,
          actionGrants: 0,
          actionPolicyAudit: 0,
          connectionRequests: requests.deletedRequests,
          requestSecrets: requests.deletedRequestSecrets,
          saasCleanup: cleanup.deletedCleanup,
          connectionRetirements: retirements,
          triggerSubscriptions: triggers.deletedSubscriptions,
          triggerSourceApplications: triggers.deletedSourceApplications,
          triggerSecrets: triggers.deletedTriggerSecrets,
          triggerExecutionLeases: triggers.deletedExecutionLeases,
        },
        remoteRevocations,
      };
    } catch (error) {
      if (error instanceof LifecyclePurgeClaimConflictError || error instanceof LifecyclePurgeConflictError) {
        throw new LifecyclePurgeConflictError();
      }
      if (error instanceof LifecycleReconciliationRequiredError) throw error;
      throw new LifecycleReconciliationRequiredError(error);
    }
  }

  private async revokeConnectionCredential(
    connection: LifecyclePurgeConnection,
    correlationId: string,
    signal: AbortSignal,
  ): Promise<void> {
    if (connection.providerRevocationOutcome) return;
    let outcome: ProviderCredentialRevocationOutcome = "failed";
    if (connection.credential && this.options.credentialRevoker) {
      try {
        outcome = await this.options.credentialRevoker.revoke({
          service: connection.service,
          credential: connection.credential,
          signal,
        });
      } catch {
        outcome = "failed";
      }
    }
    await this.options.connections.markExactOwnedLifecycleProviderRevocation(connection.id, correlationId, outcome);
    connection.providerRevocationOutcome = outcome;
  }

  private async listAllOAuthStates(): Promise<Array<{ id: string; status: string }>> {
    const states: Array<{ id: string; status: string }> = [];
    let cursor: string | undefined;
    do {
      const page = await this.options.oauthStates.listExactOwnedForLifecycle(cursor, lifecycleEnumerationLimit);
      states.push(...page.items);
      cursor = page.nextCursor;
    } while (cursor);
    return states;
  }

  private async listAllTransitFiles(): Promise<TransitFileRecord[]> {
    const files: TransitFileRecord[] = [];
    let cursor: string | undefined;
    do {
      const page = await this.options.transitMetadata.listExactOwnedForLifecycle(cursor, lifecycleEnumerationLimit);
      files.push(...page.items);
      cursor = page.nextCursor;
    } while (cursor);
    return files;
  }

  private async assertInventoryStable(
    correlationId: string,
    connections: LifecyclePurgeConnection[],
    oauthStates: Array<{ id: string }>,
    transitFiles: TransitFileRecord[],
  ): Promise<void> {
    const currentConnections = await this.options.connections.prepareExactOwnedForLifecyclePurge(correlationId);
    const currentOAuthStates = await this.listAllOAuthStates();
    const currentTransitFiles = await this.listAllTransitFiles();
    const ids = (values: Array<{ id: string }>): string =>
      values
        .map(({ id }) => id)
        .sort()
        .join("\n");
    if (
      ids(currentConnections) !== ids(connections) ||
      ids(currentOAuthStates) !== ids(oauthStates) ||
      ids(currentTransitFiles) !== ids(transitFiles)
    ) {
      throw new Error("Lifecycle scope changed during external cleanup");
    }
  }

  private async requirePolicyPurged(): Promise<void> {
    const counts = await this.options.actionPolicy.getLifecycleCounts(this.options.scope);
    if (counts.actionGrants !== 0 || counts.actionPolicyAudit !== 0) {
      throw new LifecycleReconciliationRequiredError(new Error("Dedicated action policy purge must complete first"));
    }
  }

  private async readCounts(): Promise<LifecycleRecordCounts> {
    const [core, policy, requests, cleanup, retirements, triggers] = await Promise.all([
      this.readCoreCounts(),
      this.options.actionPolicy.getLifecycleCounts(this.options.scope),
      this.options.connectionRequests.countExactOwnedForLifecycle(),
      this.options.saasProjects.countExactOwnedCleanupForLifecycle(),
      this.options.connections.countExactOwnedRetirementsForLifecycle(),
      this.options.triggers.countExactOwnedForLifecycle(),
    ]);
    return {
      ...core,
      ...policy,
      connectionRequests: { total: requests.total, statuses: requests.statuses },
      requestSecrets: requests.secrets,
      saasCleanup: cleanup,
      connectionRetirements: retirements,
      triggerSubscriptions: triggers.subscriptions,
      triggerSourceApplications: triggers.sourceApplications,
      triggerSecrets: triggers.secrets,
      triggerExecutionLeases: triggers.executionLeases,
    };
  }

  private async readCoreCounts(): Promise<
    Pick<LifecycleRecordCounts, "connections" | "runs" | "oauthStates" | "idempotencyRecords" | "transitFiles">
  > {
    return withScopedClient(this.options.pool, this.options.scope, async (client) => {
      const parameters = [
        this.options.scope.tenantId,
        this.options.scope.workspaceId,
        this.options.scope.subjectUserId,
      ];
      const count = async (table: "connections" | "run_intents"): Promise<number> => {
        const result = await client.query<{ count: string | number }>(
          `SELECT count(*) AS count FROM integration_runtime.${table}
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3`,
          parameters,
        );
        return Number(result.rows[0]?.count ?? 0);
      };
      const statuses = async (
        table: "oauth_states" | "idempotency_records" | "transit_files",
      ): Promise<LifecycleStatusSummary> => {
        const result = await client.query<{ status: string; count: string | number }>(
          `SELECT status, count(*) AS count FROM integration_runtime.${table}
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
           GROUP BY status ORDER BY status`,
          parameters,
        );
        const values = result.rows.map(({ status, count: value }) => ({ status, count: Number(value) }));
        return { total: values.reduce((sum, value) => sum + value.count, 0), statuses: values };
      };
      const connections = await count("connections");
      const runs = await count("run_intents");
      const oauthStates = await statuses("oauth_states");
      const idempotencyRecords = await statuses("idempotency_records");
      const transitFiles = await statuses("transit_files");
      return { connections, runs, oauthStates, idempotencyRecords, transitFiles };
    });
  }

  private async finalizePurge(
    expected: Pick<LifecyclePurgeCounts, "connections" | "oauthStates" | "transitFiles">,
  ): Promise<
    Pick<LifecyclePurgeCounts, "connections" | "runs" | "oauthStates" | "idempotencyRecords" | "transitFiles">
  > {
    return await withScopedClient(this.options.pool, this.options.scope, async (client) => {
      const parameters = [
        this.options.scope.tenantId,
        this.options.scope.workspaceId,
        this.options.scope.subjectUserId,
      ];
      const deleted = {
        oauthStates: await deleteExact(client, "oauth_states", parameters),
        runs: await deleteExact(client, "run_intents", parameters),
        idempotencyRecords: await deleteExact(client, "idempotency_records", parameters),
      };
      await deleteExact(client, "refresh_leases", parameters);
      const connections = await deleteExact(client, "connections", parameters);
      const transitFiles = await deleteExact(client, "transit_files", parameters);
      await deleteExact(client, "connection_revocation_receipts", parameters);

      if (
        connections !== expected.connections ||
        deleted.oauthStates !== expected.oauthStates ||
        transitFiles !== expected.transitFiles
      ) {
        throw new Error("Lifecycle PostgreSQL inventory changed before finalization");
      }
      for (const table of [
        "oauth_states",
        "run_intents",
        "idempotency_records",
        "refresh_leases",
        "connections",
        "transit_files",
        "connection_revocation_receipts",
      ] as const) {
        const remaining = await client.query(
          `SELECT 1 FROM integration_runtime.${table}
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3 LIMIT 1`,
          parameters,
        );
        if (remaining.rowCount !== 0) throw new Error("Lifecycle PostgreSQL scope is not empty");
      }
      return {
        connections,
        runs: deleted.runs,
        oauthStates: deleted.oauthStates,
        idempotencyRecords: deleted.idempotencyRecords,
        transitFiles,
      };
    });
  }
}

async function deleteExact(
  client: PoolClient,
  table:
    | "oauth_states"
    | "run_intents"
    | "idempotency_records"
    | "refresh_leases"
    | "connections"
    | "transit_files"
    | "connection_revocation_receipts",
  parameters: string[],
): Promise<number> {
  const result = await client.query(
    `DELETE FROM integration_runtime.${table}
     WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3`,
    parameters,
  );
  return result.rowCount ?? 0;
}

function toSafeRun(run: RunLog): SafeLifecycleRun {
  return {
    id: run.id,
    service: run.service,
    actionId: run.actionId,
    caller: run.caller,
    startedAt: run.startedAt,
    completedAt: run.completedAt,
    durationMs: run.durationMs,
    ok: run.ok,
    ...(run.connectionId === undefined ? {} : { connectionId: run.connectionId }),
    ...(run.connectionProfile === undefined ? {} : { connectionProfile: run.connectionProfile }),
    ...(run.runtimeTokenId === undefined ? {} : { runtimeTokenId: run.runtimeTokenId }),
    ...(run.policy === undefined ? {} : { policy: run.policy }),
    ...(run.errorCode === undefined ? {} : { errorCode: run.errorCode }),
  };
}

function encodeCursor(cursor: LifecycleCursor, scope: Readonly<SaasRequestScope>): string {
  const encoded = Buffer.from(
    JSON.stringify({ v: 2, target: [scope.tenantId, scope.workspaceId, scope.subjectUserId], ...cursor }),
  ).toString("base64url");
  if (encoded.length > 4096) throw new Error("Lifecycle cursor exceeds its wire bound");
  return encoded;
}

function decodeCursor(cursor: string | undefined, scope: Readonly<SaasRequestScope>): LifecycleCursor | undefined {
  if (cursor === undefined) return undefined;
  if (cursor.length < 1 || cursor.length > 4096) throw new TypeError("Invalid lifecycle cursor");
  let value: Record<string, unknown>;
  try {
    const decoded = Buffer.from(cursor, "base64url");
    if (decoded.toString("base64url") !== cursor) throw new Error("non-canonical cursor");
    value = JSON.parse(decoded.toString("utf8"));
    if (
      !value ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      value.v !== 2 ||
      Object.keys(value).some((key) => !["v", "target", "phase", "after"].includes(key)) ||
      !Array.isArray(value.target) ||
      value.target.length !== 3 ||
      value.target.some((part, index) => part !== [scope.tenantId, scope.workspaceId, scope.subjectUserId][index]) ||
      typeof value.phase !== "string" ||
      !lifecyclePhases.includes(value.phase as LifecyclePhase)
    )
      throw new Error("invalid cursor");
    if (value.phase === "connections") {
      if (value.after === undefined) return { phase: "connections" };
      const after = value.after as Record<string, unknown>;
      if (
        !after ||
        typeof after !== "object" ||
        Array.isArray(after) ||
        Object.keys(after).length !== 2 ||
        typeof after.createdAt !== "string" ||
        !Number.isFinite(Date.parse(after.createdAt)) ||
        typeof after.id !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(after.id)
      )
        throw new Error("invalid connection cursor");
      return { phase: "connections", after: { createdAt: after.createdAt, id: after.id } };
    }
    if (value.after !== undefined && (typeof value.after !== "string" || !value.after))
      throw new Error("invalid opaque cursor");
    if (value.phase === "runs" && value.after !== undefined) decodeRunLogCursor(value.after as string);
    return {
      phase: value.phase as Exclude<LifecyclePhase, "connections">,
      ...(value.after === undefined ? {} : { after: value.after as string }),
    };
  } catch {
    throw new TypeError("Invalid lifecycle cursor");
  }
}
