import type { ResolvedCredential } from "../../core/types.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { LifecyclePurgeConnection, SafeStoredConnection } from "../storage/postgres-connection-store.ts";
import type { TransitFileRecord } from "../storage/postgres-transit-file-store.ts";
import type { RunLog } from "../storage/run-store.ts";
import type { ScopedLifecycleServiceOptions } from "./scoped-lifecycle-service.ts";
import type { Pool } from "pg";

import { describe, expect, it } from "vitest";
import { LifecyclePurgeClaimConflictError } from "../storage/postgres-connection-store.ts";
import {
  LifecyclePurgeConflictError,
  LifecycleReconciliationRequiredError,
  ScopedLifecycleService,
} from "./scoped-lifecycle-service.ts";

const scope: Readonly<SaasRequestScope> = Object.freeze({
  tenantId: "tenant-exact",
  workspaceId: "workspace-exact",
  actorUserId: "actor-exact",
  subjectUserId: "subject-exact",
  workspaceRole: "member",
  purpose: "lifecycle:delete",
  permissions: ["lifecycle:delete"],
});
const correlationId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

function credential(accountId: string): ResolvedCredential {
  return {
    authType: "oauth2",
    accessToken: `access-${accountId}`,
    refreshToken: `refresh-${accountId}`,
    tokenType: "Bearer",
    profile: { accountId, displayName: accountId, grantedScopes: ["mail.read"] },
    metadata: {},
  };
}

class FakeLifecyclePool {
  readonly deletes: string[] = [];
  readonly queryParameters: unknown[][] = [];
  rows: Record<string, number> = {
    connections: 0,
    run_intents: 0,
    oauth_states: 0,
    idempotency_records: 0,
    refresh_leases: 0,
    transit_files: 0,
    connection_revocation_receipts: 0,
  };
  statuses: Record<string, Array<{ status: string; count: number }>> = {
    oauth_states: [],
    idempotency_records: [],
    transit_files: [],
  };
  failDeleteTable?: string;
  private snapshot?: Record<string, number>;
  private fenced = false;

  readonly pool = {
    connect: async () => ({
      query: async (sql: string, parameters: unknown[] = []) => this.query(sql, parameters),
      release: () => undefined,
    }),
  } as unknown as Pool;

  private query(sql: string, parameters: unknown[]): { rows: unknown[]; rowCount: number } {
    this.queryParameters.push(parameters);
    if (sql === "BEGIN") {
      if (this.snapshot) throw new Error("Unexpected nested lifecycle transaction");
      this.snapshot = { ...this.rows };
      this.fenced = false;
      return { rows: [], rowCount: 0 };
    }
    if (sql === "ROLLBACK" || sql === "COMMIT") {
      if (!this.snapshot) throw new Error("No lifecycle transaction to finish");
      if (sql === "ROLLBACK") this.rows = { ...this.snapshot };
      this.snapshot = undefined;
      this.fenced = false;
      return { rows: [], rowCount: 0 };
    }
    if (!this.snapshot) throw new Error("Lifecycle query requires a transaction");
    if (sql.includes("set_config(")) return { rows: [], rowCount: 0 };
    if (/^SELECT pg_advisory_xact_lock(?:_shared)?\(/.test(sql)) {
      this.fenced = true;
      return { rows: [], rowCount: 0 };
    }
    if (!this.fenced) throw new Error("Lifecycle data query requires a maintenance fence");
    const table = /integration_runtime\.([a-z_]+)/.exec(sql)?.[1];
    if (!table) throw new Error(`Unexpected SQL: ${sql}`);
    if (sql.includes("SELECT count(*) AS count")) {
      return { rows: [{ count: this.rows[table] ?? 0 }], rowCount: 1 };
    }
    if (sql.includes("GROUP BY status")) {
      const rows = this.statuses[table] ?? [];
      return { rows, rowCount: rows.length };
    }
    if (sql.startsWith("DELETE")) {
      this.deletes.push(table);
      if (this.failDeleteTable === table) {
        this.failDeleteTable = undefined;
        throw new Error("injected PostgreSQL finalization failure");
      }
      const count = this.rows[table] ?? 0;
      this.rows[table] = 0;
      return { rows: [], rowCount: count };
    }
    if (sql.includes("SELECT 1")) return { rows: this.rows[table] ? [{}] : [], rowCount: this.rows[table] ? 1 : 0 };
    throw new Error(`Unexpected SQL: ${sql}`);
  }
}

interface Harness {
  service: ScopedLifecycleService;
  pool: FakeLifecyclePool;
  events: string[];
  connections: LifecyclePurgeConnection[];
  oauthStates: Array<{ id: string; status: string }>;
  transitFiles: TransitFileRecord[];
  fail: {
    phase?: "provider" | "secret" | "oauth" | "transit" | "unsupported";
    providerServiceOnce?: string;
    claimConflict?: boolean;
  };
}

function createHarness(
  input: {
    connectionCount?: number;
    oauthCount?: number;
    transitCount?: number;
    runs?: RunLog[];
    safeConnections?: SafeStoredConnection[];
    actionGrants?: number;
  } = {},
): Harness {
  const pool = new FakeLifecyclePool();
  const events: string[] = [];
  const fail: Harness["fail"] = {};
  const connections: LifecyclePurgeConnection[] = Array.from({ length: input.connectionCount ?? 0 }, (_, index) => ({
    id: `00000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
    service: `service-${index}`,
    credential: credential(`account-${index}`),
    providerRevocationOutcome: undefined,
    secretDeleted: false,
  }));
  const oauthStates = Array.from({ length: input.oauthCount ?? 0 }, (_, index) => ({
    id: `10000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
    status: index % 2 ? "completed" : "pending",
  }));
  const transitFiles = Array.from({ length: input.transitCount ?? 0 }, (_, index) => ({
    id: `20000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
    objectKey: `exact/object-${index}`,
    byteSize: index,
    status: "available" as const,
    expiresAt: "2030-01-01T00:00:00.000Z",
  }));
  pool.rows.connections = connections.length;
  pool.rows.oauth_states = oauthStates.length;
  pool.rows.transit_files = transitFiles.length;
  const safeConnections = input.safeConnections ?? [];
  const runs = input.runs ?? [];

  const connectionStore: ScopedLifecycleServiceOptions["connections"] = {
    async listExactOwnedRetirementsForLifecycle() {
      return { items: [] };
    },
    async countExactOwnedRetirementsForLifecycle() {
      return 0;
    },
    async purgeExactOwnedRetirementsForLifecycle() {
      return 0;
    },
    async listExactOwnedForLifecycle(cursor, limit) {
      const offset = cursor ? safeConnections.findIndex(({ id }) => id === cursor.id) + 1 : 0;
      const items = safeConnections.slice(offset, offset + limit);
      const last = items[items.length - 1];
      return {
        items,
        ...(offset + limit < safeConnections.length && last
          ? { nextCursor: { createdAt: last.createdAt, id: last.id } }
          : {}),
      };
    },
    async prepareExactOwnedForLifecyclePurge(requestCorrelationId) {
      events.push(`block:${requestCorrelationId}`);
      if (fail.claimConflict) throw new LifecyclePurgeClaimConflictError();
      return connections.map((connection) => {
        if (!connection.secretDeleted) return { ...connection };
        const { credential: _credential, ...result } = connection;
        return result;
      });
    },
    async markExactOwnedLifecycleProviderRevocation(id, _correlationId, outcome) {
      events.push(`provider-mark:${id}:${outcome}`);
      const connection = connections.find((candidate) => candidate.id === id)!;
      connection.providerRevocationOutcome = outcome;
    },
    async deleteExactOwnedLifecycleSecret(id) {
      events.push(`secret:${id}`);
      if (fail.phase === "secret") throw new Error("injected OpenBao connection failure");
      const connection = connections.find((candidate) => candidate.id === id)!;
      connection.secretDeleted = true;
    },
  };
  const oauthStore: ScopedLifecycleServiceOptions["oauthStates"] = {
    async listExactOwnedForLifecycle(cursor, limit) {
      expect(limit).toBe(100);
      const offset = cursor ? oauthStates.findIndex(({ id }) => id === cursor) + 1 : 0;
      const items = oauthStates.slice(offset, offset + limit);
      const last = items[items.length - 1];
      return { items, ...(offset + limit < oauthStates.length && last ? { nextCursor: last.id } : {}) };
    },
    async deleteExactOwnedLifecycleSecret(id) {
      events.push(`oauth:${id}`);
      if (fail.phase === "oauth") throw new Error("injected OpenBao OAuth failure");
    },
  };
  const transitStore: ScopedLifecycleServiceOptions["transitMetadata"] = {
    async listExactOwnedForLifecycle(cursor, limit) {
      expect(limit).toBe(100);
      const offset = cursor ? transitFiles.findIndex(({ id }) => id === cursor) + 1 : 0;
      const items = transitFiles.slice(offset, offset + limit);
      const last = items[items.length - 1];
      return { items, ...(offset + limit < transitFiles.length && last ? { nextCursor: last.id } : {}) };
    },
  };
  let runOffset = 0;
  const service = new ScopedLifecycleService({
    pool: pool.pool,
    scope,
    actionPolicy: {
      async getLifecycleCounts() {
        return { actionGrants: input.actionGrants ?? 0, actionPolicyAudit: 0 };
      },
      async exportForLifecycle() {
        if (input.actionGrants) throw new Error("Nonempty policy export is outside this fixture");
        return { items: [], audit: [], nextCursor: null };
      },
    },
    connectionRequests: {
      async listExactOwnedForLifecycle() {
        return { items: [] };
      },
      async countExactOwnedForLifecycle() {
        return { total: 0, statuses: [] };
      },
      async purgeExactOwnedForLifecycle() {
        return { deletedRequests: 0, deletedRequestSecrets: 0 };
      },
    },
    saasProjects: {
      async listExactOwnedCleanupForLifecycle() {
        return { items: [] };
      },
      async countExactOwnedCleanupForLifecycle() {
        return { total: 0, statuses: [] };
      },
      async drainExactOwnedCleanupForLifecycle() {
        return { deletedCleanup: 0 };
      },
    },
    async runSaasCleanup() {
      throw new Error("No native SaaS cleanup records in this fixture");
    },
    triggers: {
      async listExactOwnedForLifecycle() {
        return { subscriptions: [], sourceApplications: [] };
      },
      async countExactOwnedForLifecycle() {
        return {
          subscriptions: { total: 0, statuses: [] },
          sourceApplications: 0,
          secrets: 0,
          pendingSecrets: 0,
          executionLeases: 0,
          pendingExecutions: 0,
          requiresCleanup: false,
        };
      },
      async cleanupExactOwnedForLifecycle() {
        throw new Error("No native triggers in this fixture");
      },
      async purgeExactOwnedForLifecycle() {
        return {
          deletedSubscriptions: 0,
          deletedSourceApplications: 0,
          deletedTriggerSecrets: 0,
          deletedExecutionLeases: 0,
        };
      },
    },
    connections: connectionStore,
    oauthStates: oauthStore,
    transitMetadata: transitStore,
    runLogs: {
      async list(input = {}) {
        const offset = input.cursor ? Number(input.cursor) : runOffset;
        const limit = input.limit ?? runs.length;
        const items = runs.slice(offset, offset + limit);
        runOffset = offset + items.length;
        return {
          items,
          ...(offset + limit < runs.length ? { nextCursor: String(offset + limit) } : {}),
        };
      },
    },
    transitFiles: {
      async delete(id, preserveMetadata) {
        events.push(`transit:${id}:${String(preserveMetadata)}`);
        if (fail.phase === "transit") throw new Error("injected SeaweedFS failure");
        return true;
      },
    },
    credentialRevoker: {
      async revoke(input) {
        events.push(`provider:${input.service}`);
        if (fail.phase === "provider") throw new Error("injected provider failure");
        if (fail.providerServiceOnce === input.service) {
          fail.providerServiceOnce = undefined;
          throw new Error("injected later provider failure");
        }
        return fail.phase === "unsupported" ? "unsupported" : "revoked";
      },
    },
  });
  return { service, pool, events, connections, oauthStates, transitFiles, fail };
}

describe("ScopedLifecycleService export", () => {
  it("uses one bounded combined cursor and emits only approved run fields", async () => {
    const safeConnections: SafeStoredConnection[] = [0, 1].map((index) => ({
      id: `00000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
      localConnectionId: `30000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
      service: `service-${index}`,
      connectionName: `connection-${index}`,
      subjectUserId: scope.subjectUserId,
      visibility: "user",
      status: index ? "failed" : "active",
      createdAt: `2026-01-0${index + 1}T00:00:00.000Z`,
      updatedAt: `2026-01-0${index + 1}T00:00:00.000Z`,
    }));
    const runs: RunLog[] = [
      {
        id: "run-1",
        service: "gmail",
        actionId: "gmail.send",
        caller: "http",
        startedAt: "2026-01-03T00:00:00.000Z",
        completedAt: "2026-01-03T00:00:01.000Z",
        durationMs: 1_000,
        ok: false,
        inputSummary: { secret: "input" },
        outputSummary: { secret: "output" },
        errorCode: "safe_failure",
        errorMessage: "provider payload",
      },
    ];
    const harness = createHarness({ safeConnections, runs });
    harness.pool.rows = { ...harness.pool.rows, connections: 2, run_intents: 1 };
    harness.pool.statuses.oauth_states = [{ status: "pending", count: 2 }];
    harness.pool.statuses.idempotency_records = [{ status: "completed", count: 1 }];
    harness.pool.statuses.transit_files = [{ status: "available", count: 3 }];

    const first = await harness.service.exportPage({ limit: 2 });
    expect(first.connections).toHaveLength(2);
    expect(first.runs).toEqual([]);
    expect(first.nextCursor).toBeTypeOf("string");
    expect(first.nextCursor!.length).toBeLessThanOrEqual(512);
    expect(first.counts).toEqual({
      connections: 2,
      runs: 1,
      oauthStates: { total: 2, statuses: [{ status: "pending", count: 2 }] },
      idempotencyRecords: { total: 1, statuses: [{ status: "completed", count: 1 }] },
      transitFiles: { total: 3, statuses: [{ status: "available", count: 3 }] },
      actionGrants: 0,
      actionPolicyAudit: 0,
      connectionRequests: { total: 0, statuses: [] },
      saasCleanup: { total: 0, statuses: [] },
      connectionRetirements: 0,
      triggerSubscriptions: { total: 0, statuses: [] },
      triggerSourceApplications: 0,
      triggerSecrets: 0,
      triggerExecutionLeases: 0,
    });

    const second = await harness.service.exportPage({ cursor: first.nextCursor!, limit: 2 });
    expect(second.connections).toEqual([]);
    expect(second.runs).toEqual([
      {
        id: "run-1",
        service: "gmail",
        actionId: "gmail.send",
        caller: "http",
        startedAt: "2026-01-03T00:00:00.000Z",
        completedAt: "2026-01-03T00:00:01.000Z",
        durationMs: 1_000,
        ok: false,
        errorCode: "safe_failure",
      },
    ]);
    expect(JSON.stringify(second)).not.toContain("provider payload");
    expect(JSON.stringify(second)).not.toContain("secret");
    expect(second.connections.length + second.runs.length).toBeLessThanOrEqual(2);
    expect(harness.pool.queryParameters.filter((parameters) => parameters.length === 3)).toEqual(
      expect.arrayContaining([[scope.tenantId, scope.workspaceId, scope.subjectUserId]]),
    );
  });

  it("rejects malformed and oversized opaque cursors", async () => {
    const { service } = createHarness();
    await expect(service.exportPage({ cursor: "not-json", limit: 50 })).rejects.toThrow(TypeError);
    await expect(service.exportPage({ cursor: "x".repeat(513), limit: 50 })).rejects.toThrow(TypeError);
    await expect(service.exportPage({ limit: 101 })).rejects.toThrow(TypeError);
  });
});

describe("ScopedLifecycleService purge", () => {
  it("refuses local erasure until dedicated action policy purge completes", async () => {
    const harness = createHarness({ connectionCount: 1, actionGrants: 1 });
    await expect(harness.service.purge({ correlationId }, AbortSignal.timeout(1_000))).rejects.toBeInstanceOf(
      LifecycleReconciliationRequiredError,
    );
    expect(harness.events).toEqual([]);
    expect(harness.pool.deletes).toEqual([]);
    expect(harness.pool.rows.connections).toBe(1);
  });

  it("is a zero-row idempotent success with exact FK-safe finalization", async () => {
    const harness = createHarness();
    const result = await harness.service.purge({ correlationId }, AbortSignal.timeout(1_000));
    expect(result).toEqual({
      tenantId: scope.tenantId,
      workspaceId: scope.workspaceId,
      subjectUserId: scope.subjectUserId,
      correlationId,
      status: "purged",
      deleted: {
        connections: 0,
        runs: 0,
        oauthStates: 0,
        idempotencyRecords: 0,
        transitFiles: 0,
        connectionSecrets: 0,
        oauthStateSecrets: 0,
        transitObjects: 0,
        actionGrants: 0,
        actionPolicyAudit: 0,
        connectionRequests: 0,
        requestSecrets: 0,
        saasCleanup: 0,
        connectionRetirements: 0,
        triggerSubscriptions: 0,
        triggerSourceApplications: 0,
        triggerSecrets: 0,
        triggerExecutionLeases: 0,
      },
      remoteRevocations: { revoked: 0, unsupported: 0, unresolved: 0 },
    });
    expect(harness.pool.deletes).toEqual([
      "oauth_states",
      "run_intents",
      "idempotency_records",
      "refresh_leases",
      "connections",
      "transit_files",
      "connection_revocation_receipts",
    ]);
    await expect(harness.service.purge({ correlationId }, AbortSignal.timeout(1_000))).resolves.toEqual(result);
  });

  it("paginates many exact external records and deletes objects before the final transaction", async () => {
    const harness = createHarness({ connectionCount: 2, oauthCount: 201, transitCount: 201 });
    harness.pool.rows = {
      connections: 2,
      run_intents: 7,
      oauth_states: 201,
      idempotency_records: 5,
      refresh_leases: 2,
      transit_files: 201,
      connection_revocation_receipts: 1,
    };
    const result = await harness.service.purge({ correlationId }, AbortSignal.timeout(1_000));
    expect(result.deleted).toEqual({
      connections: 2,
      runs: 7,
      oauthStates: 201,
      idempotencyRecords: 5,
      transitFiles: 201,
      connectionSecrets: 2,
      oauthStateSecrets: 201,
      transitObjects: 201,
      actionGrants: 0,
      actionPolicyAudit: 0,
      connectionRequests: 0,
      requestSecrets: 0,
      saasCleanup: 0,
      connectionRetirements: 0,
      triggerSubscriptions: 0,
      triggerSourceApplications: 0,
      triggerSecrets: 0,
      triggerExecutionLeases: 0,
    });
    expect(result.remoteRevocations).toEqual({ revoked: 2, unsupported: 0, unresolved: 0 });
    expect(harness.events.filter((event) => event.startsWith("oauth:"))).toHaveLength(201);
    expect(harness.events.filter((event) => event.startsWith("transit:"))).toHaveLength(201);
    expect(harness.events.every((event) => !event.startsWith("transit:") || event.endsWith(":true"))).toBe(true);
    expect(harness.pool.deletes).toHaveLength(7);
  });

  for (const phase of ["secret", "oauth", "transit"] as const) {
    it(`retains all PostgreSQL rows when ${phase} cleanup fails`, async () => {
      const harness = createHarness({ connectionCount: 1, oauthCount: 1, transitCount: 1 });
      harness.pool.rows.connections = 1;
      harness.pool.rows.oauth_states = 1;
      harness.pool.rows.transit_files = 1;
      harness.fail.phase = phase;
      await expect(harness.service.purge({ correlationId }, AbortSignal.timeout(1_000))).rejects.toBeInstanceOf(
        LifecycleReconciliationRequiredError,
      );
      expect(harness.pool.deletes).toEqual([]);
      expect(harness.pool.rows.connections).toBe(1);
      expect(harness.pool.rows.oauth_states).toBe(1);
      expect(harness.pool.rows.transit_files).toBe(1);
    });
  }

  it.each([
    ["unsupported", "unsupported", { revoked: 0, unsupported: 1, unresolved: 0 }],
    ["provider", "failed", { revoked: 0, unsupported: 0, unresolved: 1 }],
  ] as const)("erases locally and records a safe remote audit for %s revocation", async (phase, outcome, audit) => {
    const harness = createHarness({ connectionCount: 1 });
    harness.fail.phase = phase;
    const first = await harness.service.purge({ correlationId }, AbortSignal.timeout(1_000));
    expect(first.remoteRevocations).toEqual(audit);
    expect(harness.connections[0]).toMatchObject({ providerRevocationOutcome: outcome, secretDeleted: true });
    expect(harness.events.filter((event) => event === "provider:service-0")).toHaveLength(1);
    harness.connections.splice(0);
    await expect(harness.service.purge({ correlationId }, AbortSignal.timeout(1_000))).resolves.toMatchObject({
      remoteRevocations: { revoked: 0, unsupported: 0, unresolved: 0 },
    });
    expect(harness.events.filter((event) => event === "provider:service-0")).toHaveLength(1);
  });

  it("persists each provider outcome before local erasure when a later remote revoke fails", async () => {
    const harness = createHarness({ connectionCount: 2 });
    harness.fail.providerServiceOnce = "service-1";
    const result = await harness.service.purge({ correlationId }, AbortSignal.timeout(1_000));
    expect(result.remoteRevocations).toEqual({ revoked: 1, unsupported: 0, unresolved: 1 });
    expect(harness.connections).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ providerRevocationOutcome: "revoked", secretDeleted: true }),
        expect.objectContaining({ providerRevocationOutcome: "failed", secretDeleted: true }),
      ]),
    );
  });

  it("rolls back final PostgreSQL deletion and safely retries after external deletion", async () => {
    const harness = createHarness({ connectionCount: 1, oauthCount: 1, transitCount: 1 });
    harness.pool.rows.connections = 1;
    harness.pool.rows.oauth_states = 1;
    harness.pool.rows.transit_files = 1;
    harness.pool.failDeleteTable = "connections";
    await expect(harness.service.purge({ correlationId }, AbortSignal.timeout(1_000))).rejects.toBeInstanceOf(
      LifecycleReconciliationRequiredError,
    );
    expect(harness.pool.rows).toMatchObject({ connections: 1, oauth_states: 1, transit_files: 1 });
    await expect(harness.service.purge({ correlationId }, AbortSignal.timeout(1_000))).resolves.toMatchObject({
      status: "purged",
    });
    expect(harness.events.filter((event) => event.startsWith("provider:"))).toHaveLength(1);
    expect(harness.pool.rows).toMatchObject({ connections: 0, oauth_states: 0, transit_files: 0 });
  });

  it("surfaces a different-correlation claim as conflict without final deletion", async () => {
    const harness = createHarness();
    harness.fail.claimConflict = true;
    await expect(harness.service.purge({ correlationId }, AbortSignal.timeout(1_000))).rejects.toBeInstanceOf(
      LifecyclePurgeConflictError,
    );
    expect(harness.pool.deletes).toEqual([]);
  });
});
