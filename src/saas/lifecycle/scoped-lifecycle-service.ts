import type {
  ProviderCredentialRevocationOutcome,
  SaasProviderCredentialRevoker,
} from "../connections/provider-credential-revoker.ts";
import type { SafeConnectionSummary, SaasRequestScope } from "../contracts.ts";
import type { SeaweedFsTransitFileService } from "../files/seaweedfs-transit-files.ts";
import type {
  LifecycleConnectionCursor,
  LifecyclePurgeConnection,
  PostgresConnectionStore,
} from "../storage/postgres-connection-store.ts";
import type { PostgresOAuthStateStore } from "../storage/postgres-oauth-state-store.ts";
import type { PostgresRunStore } from "../storage/postgres-run-store.ts";
import type { PostgresTransitFileStore, TransitFileRecord } from "../storage/postgres-transit-file-store.ts";
import type { RunLog } from "../storage/run-store.ts";
import type { Pool, PoolClient } from "pg";

import { Buffer } from "node:buffer";
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
}

export interface LifecycleExportPage {
  tenantId: string;
  workspaceId: string;
  subjectUserId: string;
  connections: SafeConnectionSummary[];
  runs: SafeLifecycleRun[];
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
  connections: Pick<
    PostgresConnectionStore,
    | "listExactOwnedForLifecycle"
    | "prepareExactOwnedForLifecyclePurge"
    | "markExactOwnedLifecycleProviderRevocation"
    | "deleteExactOwnedLifecycleSecret"
  >;
  oauthStates: Pick<PostgresOAuthStateStore, "listExactOwnedForLifecycle" | "deleteExactOwnedLifecycleSecret">;
  runLogs: Pick<PostgresRunStore, "list">;
  transitMetadata: Pick<PostgresTransitFileStore, "listExactOwnedForLifecycle">;
  transitFiles?: Pick<SeaweedFsTransitFileService, "delete">;
  credentialRevoker?: SaasProviderCredentialRevoker;
}

type LifecycleCursor =
  | { v: 1; phase: "connections"; after: LifecycleConnectionCursor }
  | { v: 1; phase: "runs"; after?: string };

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
    const cursor = decodeCursor(input.cursor);
    const counts = await this.readCounts();
    let connections: SafeConnectionSummary[] = [];
    let runs: SafeLifecycleRun[] = [];
    let nextCursor: string | null = null;

    if (!cursor || cursor.phase === "connections") {
      const page = await this.options.connections.listExactOwnedForLifecycle(cursor?.after, input.limit);
      connections = page.items.map((connection) => ({ ...connection }));
      if (page.nextCursor) {
        nextCursor = encodeCursor({ v: 1, phase: "connections", after: page.nextCursor });
      } else {
        const remaining = input.limit - connections.length;
        if (remaining > 0) {
          const runPage = await this.options.runLogs.list({ limit: remaining });
          runs = runPage.items.map(toSafeRun);
          if (runPage.nextCursor) nextCursor = encodeCursor({ v: 1, phase: "runs", after: runPage.nextCursor });
        } else if (counts.runs > 0) {
          nextCursor = encodeCursor({ v: 1, phase: "runs" });
        }
      }
    } else {
      const runPage = await this.options.runLogs.list({ limit: input.limit, cursor: cursor.after });
      runs = runPage.items.map(toSafeRun);
      if (runPage.nextCursor) nextCursor = encodeCursor({ v: 1, phase: "runs", after: runPage.nextCursor });
    }

    return {
      tenantId: this.options.scope.tenantId,
      workspaceId: this.options.scope.workspaceId,
      subjectUserId: this.options.scope.subjectUserId,
      connections,
      runs,
      counts,
      nextCursor,
    };
  }

  async purge(input: { correlationId: string }, signal: AbortSignal): Promise<LifecyclePurgeResult> {
    const { correlationId } = lifecyclePurgeInputSchema.parse(input);
    try {
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

  private async readCounts(): Promise<LifecycleRecordCounts> {
    return await withScopedClient(this.options.pool, this.options.scope, async (client) => {
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
      const [connections, runs, oauthStates, idempotencyRecords, transitFiles] = await Promise.all([
        count("connections"),
        count("run_intents"),
        statuses("oauth_states"),
        statuses("idempotency_records"),
        statuses("transit_files"),
      ]);
      return { connections, runs, oauthStates, idempotencyRecords, transitFiles };
    });
  }

  private async finalizePurge(
    expected: Pick<LifecyclePurgeCounts, "connections" | "oauthStates" | "transitFiles">,
  ): Promise<Omit<LifecyclePurgeCounts, "connectionSecrets" | "oauthStateSecrets" | "transitObjects">> {
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

function encodeCursor(cursor: LifecycleCursor): string {
  const encoded = Buffer.from(JSON.stringify(cursor)).toString("base64url");
  if (encoded.length > 512) throw new Error("Lifecycle cursor exceeds its wire bound");
  return encoded;
}

function decodeCursor(cursor: string | undefined): LifecycleCursor | undefined {
  if (cursor === undefined) return undefined;
  if (cursor.length < 1 || cursor.length > 512) throw new TypeError("Invalid lifecycle cursor");
  let decoded: Buffer;
  let value: unknown;
  try {
    decoded = Buffer.from(cursor, "base64url");
    if (decoded.toString("base64url") !== cursor) throw new Error("non-canonical base64url");
    value = JSON.parse(decoded.toString("utf8"));
  } catch {
    throw new TypeError("Invalid lifecycle cursor");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("Invalid lifecycle cursor");
  if (!("v" in value) || value.v !== 1 || !("phase" in value)) throw new TypeError("Invalid lifecycle cursor");
  if (value.phase === "connections") {
    if (
      Object.keys(value).length !== 3 ||
      !("after" in value) ||
      !value.after ||
      typeof value.after !== "object" ||
      Array.isArray(value.after) ||
      Object.keys(value.after).length !== 2 ||
      !("createdAt" in value.after) ||
      typeof value.after.createdAt !== "string" ||
      !Number.isFinite(Date.parse(value.after.createdAt)) ||
      !("id" in value.after) ||
      typeof value.after.id !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value.after.id)
    ) {
      throw new TypeError("Invalid lifecycle cursor");
    }
    return { v: 1, phase: "connections", after: { createdAt: value.after.createdAt, id: value.after.id } };
  }
  if (
    value.phase !== "runs" ||
    Object.keys(value).some((key) => key !== "v" && key !== "phase" && key !== "after") ||
    Object.keys(value).length < 2 ||
    Object.keys(value).length > 3
  ) {
    throw new TypeError("Invalid lifecycle cursor");
  }
  if (!("after" in value)) return { v: 1, phase: "runs" };
  if (typeof value.after !== "string" || !value.after) throw new TypeError("Invalid lifecycle cursor");
  try {
    decodeRunLogCursor(value.after);
  } catch {
    throw new TypeError("Invalid lifecycle cursor");
  }
  return { v: 1, phase: "runs", after: value.after };
}
