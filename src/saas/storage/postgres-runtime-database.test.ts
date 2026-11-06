import type { ResolvedCredential } from "../../core/types.ts";
import type { OAuthAuthorizationState } from "../../oauth/oauth-flow-service.ts";
import type { IProviderLoader } from "../../providers/provider-loader.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { PostgresTestDatabase } from "../testing/postgres-test-database.ts";
import type { ConnectionSecret, ConnectionSecretStore } from "./postgres-connection-store.ts";
import type { OAuthStateSecretStore } from "./postgres-oauth-state-store.ts";
import type { RunLog } from "./run-store.ts";

import { Buffer } from "node:buffer";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, expectTypeOf, it } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import { SaasAuthorizationError } from "../auth/saas-jwt-verifier.ts";
import { SaasConnectServer } from "../server/saas-connect-server.ts";
import { createPostgresTestDatabase, postgresTestUrl } from "../testing/postgres-test-database.ts";
import { ConnectionMetadataReconciliationError } from "./postgres-connection-store.ts";
import { migratePostgres } from "./postgres-migrator.ts";
import { OAuthStateConsumeReconciliationError, PostgresOAuthStateStore } from "./postgres-oauth-state-store.ts";
import { probeSaasRuntimeDatabase, SaasRuntimeDatabaseFactory } from "./postgres-runtime-database.ts";
import { withScopedClient } from "./scoped-query.ts";

const testPostgresUrl = postgresTestUrl();
const nonce = randomBytes(6).toString("hex");
let runtimeRole: string;
const ownerMembershipRole = `integration_owner_test_${process.pid}_${randomBytes(4).toString("hex")}`;
const ownerMembershipTable = `owner_membership_${process.pid}_${randomBytes(4).toString("hex")}`;
let adminPool: Pool;
let runtimePool: Pool;
let testDatabase: PostgresTestDatabase;
let factory: SaasRuntimeDatabaseFactory;
let connectionSecrets: MemoryConnectionSecrets;
let oauthStateSecrets: MemoryOAuthStateSecrets;
const tenantAUserA = scope(`tenant-a-${nonce}`, `workspace-a-${nonce}`, "user-a");
const tenantAUserB = scope(`tenant-a-${nonce}`, `workspace-a-${nonce}`, "user-b");
const tenantBUserA = scope(`tenant-b-${nonce}`, `workspace-a-${nonce}`, "user-a");
const workspaceBUserA = scope(`tenant-a-${nonce}`, `workspace-b-${nonce}`, "user-a");
const localConnectionIds = {
  isolationA: "00000000-0000-4000-8000-000000000101",
  isolationB: "00000000-0000-4000-8000-000000000102",
  isolationC: "00000000-0000-4000-8000-000000000103",
  privateConnection: "00000000-0000-4000-8000-000000000104",
  frozen: "00000000-0000-4000-8000-000000000105",
  journal: "00000000-0000-4000-8000-000000000106",
  revision: "00000000-0000-4000-8000-000000000107",
  deletion: "00000000-0000-4000-8000-000000000108",
} as const;

describe.skipIf(!testPostgresUrl)("SaaS scoped PostgreSQL runtime database", () => {
  beforeAll(async () => {
    if (!testPostgresUrl) throw new Error("TEST_POSTGRES_URL is required");
    connectionSecrets = new MemoryConnectionSecrets();
    oauthStateSecrets = new MemoryOAuthStateSecrets();
    testDatabase = await createPostgresTestDatabase(testPostgresUrl);
    runtimeRole = testDatabase.runtimeRole;
    adminPool = new Pool({ connectionString: testDatabase.adminConnectionString });
    await migratePostgres({
      migratorConnectionString: testDatabase.migratorConnectionString,
      runtimeConnectionString: testDatabase.runtimeConnectionString,
    });
    runtimePool = new Pool({ connectionString: testDatabase.runtimeConnectionString, max: 2 });
    await expect(probeSaasRuntimeDatabase(runtimePool)).resolves.toBeUndefined();
    await expect(probeSaasRuntimeDatabase(adminPool)).rejects.toThrow("runtime");
    factory = new SaasRuntimeDatabaseFactory({
      pool: runtimePool,
      connectionSecrets,
      oauthStateSecrets,
    });
  }, 30_000);

  afterAll(async () => {
    try {
      if (adminPool) {
        await adminPool.query("DELETE FROM integration_runtime.oauth_states WHERE tenant_id LIKE $1", [`%${nonce}`]);
        await adminPool.query(
          "DELETE FROM integration_runtime.connection_revocation_receipts WHERE tenant_id LIKE $1",
          [`%${nonce}`],
        );
        await adminPool.query("DELETE FROM integration_runtime.run_intents WHERE tenant_id LIKE $1", [`%${nonce}`]);
        await adminPool.query("DELETE FROM integration_runtime.idempotency_records WHERE tenant_id LIKE $1", [
          `%${nonce}`,
        ]);
        await adminPool.query("DELETE FROM integration_runtime.connections WHERE tenant_id LIKE $1", [`%${nonce}`]);
      }
    } finally {
      await runtimePool?.end();
      await adminPool?.end();
      await testDatabase?.dispose();
    }
  });
  it("rejects membership in an actual SaaS table owner role", async () => {
    await adminPool.query(`CREATE ROLE "${ownerMembershipRole}" NOLOGIN`);
    await adminPool.query(`GRANT "${ownerMembershipRole}" TO "${runtimeRole}"`);
    await adminPool.query(`CREATE TABLE integration_runtime."${ownerMembershipTable}" (id integer)`);
    await adminPool.query(
      `ALTER TABLE integration_runtime."${ownerMembershipTable}" OWNER TO "${ownerMembershipRole}"`,
    );
    try {
      await expect(probeSaasRuntimeDatabase(runtimePool)).rejects.toThrow("assume");
    } finally {
      await adminPool.query(`DROP TABLE integration_runtime."${ownerMembershipTable}"`);
      await adminPool.query(`REVOKE "${ownerMembershipRole}" FROM "${runtimeRole}"`);
      await adminPool.query(`DROP ROLE "${ownerMembershipRole}"`);
    }
  });

  it("requires revocation receipts with enabled forced RLS and non-runtime ownership", async () => {
    const originalName = "connection_revocation_receipts";
    const missingName = `connection_revocation_receipts_missing_${process.pid}`;
    await adminPool.query(`ALTER TABLE integration_runtime.${originalName} RENAME TO "${missingName}"`);
    try {
      await expect(probeSaasRuntimeDatabase(runtimePool)).rejects.toThrow(`integration_runtime.${originalName}`);
    } finally {
      await adminPool.query(`ALTER TABLE integration_runtime."${missingName}" RENAME TO ${originalName}`);
    }

    await adminPool.query(`ALTER TABLE integration_runtime.${originalName} NO FORCE ROW LEVEL SECURITY`);
    try {
      await expect(probeSaasRuntimeDatabase(runtimePool)).rejects.toThrow(`integration_runtime.${originalName}`);
    } finally {
      await adminPool.query(`ALTER TABLE integration_runtime.${originalName} FORCE ROW LEVEL SECURITY`);
    }

    await adminPool.query(`ALTER TABLE integration_runtime.${originalName} DISABLE ROW LEVEL SECURITY`);
    try {
      await expect(probeSaasRuntimeDatabase(runtimePool)).rejects.toThrow(`integration_runtime.${originalName}`);
    } finally {
      await adminPool.query(`ALTER TABLE integration_runtime.${originalName} ENABLE ROW LEVEL SECURITY`);
    }

    const owner = await adminPool.query<{ owner_name: string }>(
      `SELECT pg_get_userbyid(class.relowner) AS owner_name
       FROM pg_class AS class
       JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
       WHERE namespace.nspname = 'integration_runtime' AND class.relname = $1`,
      [originalName],
    );
    const ownerName = owner.rows[0]?.owner_name;
    if (!ownerName) throw new Error("Could not resolve revocation receipt owner");
    await adminPool.query(`ALTER TABLE integration_runtime.${originalName} OWNER TO "${runtimeRole}"`);
    try {
      await expect(probeSaasRuntimeDatabase(runtimePool)).rejects.toThrow(`integration_runtime.${originalName}`);
    } finally {
      await adminPool.query(
        `ALTER TABLE integration_runtime.${originalName} OWNER TO "${ownerName.replaceAll('"', '""')}"`,
      );
      await adminPool.query(
        `GRANT SELECT, INSERT, UPDATE, DELETE
         ON integration_runtime.${originalName} TO "${runtimeRole}"`,
      );
    }
  });

  it.each([
    "0005_connection_revocation_receipts.sql",
    "0007_connection_revocation_receipts_delete_policy.sql",
    "0008_revocation_outcomes.sql",
  ])("requires the applied lifecycle migration checksum for %s", async (migrationName) => {
    const applied = await adminPool.query<{ checksum: string }>(
      "DELETE FROM integration_runtime_migrations.schema_migrations WHERE name = $1 RETURNING checksum",
      [migrationName],
    );
    const checksum = applied.rows[0]?.checksum;
    if (!checksum) throw new Error("Lifecycle migration was not applied");
    try {
      await expect(probeSaasRuntimeDatabase(runtimePool)).rejects.toThrow(migrationName);
    } finally {
      await adminPool.query(
        `INSERT INTO integration_runtime_migrations.schema_migrations (name, checksum)
         VALUES ($1, $2)`,
        [migrationName, checksum],
      );
    }
  });

  it("deletes revocation receipts only in the forced-RLS exact lifecycle scope", async () => {
    const target = scope(`tenant-receipt-${nonce}`, `workspace-receipt-${nonce}`, "subject-target");
    const adjacent = scope(`tenant-receipt-${nonce}`, `workspace-receipt-${nonce}`, "subject-adjacent");
    const localConnectionId = randomUUID();
    const connectorConnectionId = randomUUID();
    for (const requestScope of [target, adjacent]) {
      await withScopedClient(runtimePool, requestScope, async (client) => {
        await client.query(
          `INSERT INTO integration_runtime.connection_revocation_receipts
             (tenant_id, workspace_id, subject_user_id, local_connection_id, connector_connection_id, outcome)
           VALUES ($1, $2, $3, $4, $5, 'revoked')`,
          [
            requestScope.tenantId,
            requestScope.workspaceId,
            requestScope.subjectUserId,
            localConnectionId,
            connectorConnectionId,
          ],
        );
      });
    }
    const adjacentBefore = await adminPool.query(
      `SELECT * FROM integration_runtime.connection_revocation_receipts
       WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3`,
      [adjacent.tenantId, adjacent.workspaceId, adjacent.subjectUserId],
    );
    await withScopedClient(runtimePool, target, async (client) => {
      const deleted = await client.query(
        `DELETE FROM integration_runtime.connection_revocation_receipts
         WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3`,
        [target.tenantId, target.workspaceId, target.subjectUserId],
      );
      expect(deleted.rowCount).toBe(1);
    });
    const targetAfter = await adminPool.query(
      `SELECT 1 FROM integration_runtime.connection_revocation_receipts
       WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3`,
      [target.tenantId, target.workspaceId, target.subjectUserId],
    );
    const adjacentAfter = await adminPool.query(
      `SELECT * FROM integration_runtime.connection_revocation_receipts
       WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3`,
      [adjacent.tenantId, adjacent.workspaceId, adjacent.subjectUserId],
    );
    expect(targetAfter.rowCount).toBe(0);
    expect(adjacentAfter.rows).toEqual(adjacentBefore.rows);
  });

  it("rejects a nullable contracted local connection identity", async () => {
    await adminPool.query("ALTER TABLE integration_runtime.connections ALTER COLUMN local_connection_id DROP NOT NULL");
    try {
      await expect(probeSaasRuntimeDatabase(runtimePool)).rejects.toThrow(
        "integration_runtime.connections.local_connection_id",
      );
    } finally {
      await adminPool.query(
        "ALTER TABLE integration_runtime.connections ALTER COLUMN local_connection_id SET NOT NULL",
      );
    }
  });

  it("isolates identical calls and aliases across tenant and workspace scopes", async () => {
    const alias = `opaque-${randomUUID()}`;
    const stores = [
      factory.forScope({ ...tenantAUserA, localConnectionId: localConnectionIds.isolationA }).connectionStore,
      factory.forScope({ ...tenantBUserA, localConnectionId: localConnectionIds.isolationB }).connectionStore,
      factory.forScope({ ...workspaceBUserA, localConnectionId: localConnectionIds.isolationC }).connectionStore,
    ];
    const credentials = [credential("account-a"), credential("account-b"), credential("account-c")];
    const connections = await Promise.all(stores.map((store, index) => store.set("gmail", alias, credentials[index])));
    expect(new Set(connections.map((item) => item.id)).size).toBe(3);
    for (let index = 0; index < stores.length; index += 1) {
      expect((await stores[index].get("gmail", alias))?.credential).toEqual(credentials[index]);
      expect(await stores[index].list()).toEqual([connections[index]]);
    }
    await withScopedClient(runtimePool, tenantAUserA, async (client) => {
      const metadata = await client.query<{ auth_metadata: Record<string, unknown> }>(
        `SELECT auth_metadata FROM integration_runtime.connections
         WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3 AND id = $4`,
        [tenantAUserA.tenantId, tenantAUserA.workspaceId, tenantAUserA.subjectUserId, connections[0].id],
      );
      expect(metadata.rows[0]?.auth_metadata).toEqual({});
    });
  });

  it("updates visibility only for the active scoped owner with an owner or admin role", async () => {
    const alias = `private-${randomUUID()}`;
    const ownerScope = {
      ...tenantAUserA,
      workspaceRole: "owner" as const,
      localConnectionId: localConnectionIds.privateConnection,
    };
    const ownerStore = factory.forScope(ownerScope).connectionStore;
    const memberStore = factory.forScope(tenantAUserB).connectionStore;
    const memberExecutionStore = factory.forScope({
      ...ownerScope,
      actorUserId: tenantAUserB.actorUserId,
      workspaceRole: "member",
      purpose: "action:execute",
      permissions: ["action:execute"],
    }).connectionStore;
    const connection = await ownerStore.set("gmail", alias, credential("private"));

    expect(await memberStore.get("gmail", alias)).toBeUndefined();
    const shared = await ownerStore.updateVisibilityById(connection.id, "workspace");
    expect(shared).toMatchObject({
      id: connection.id,
      localConnectionId: localConnectionIds.privateConnection,
      visibility: "workspace",
      status: "active",
    });
    expect((await memberExecutionStore.get("gmail", alias))?.id).toBe(connection.id);
    expect((await memberExecutionStore.list()).map((item) => item.id)).toContain(connection.id);

    const repeated = await ownerStore.updateVisibilityById(connection.id, "workspace");
    expect(repeated?.updatedAt).toBe(shared?.updatedAt);
    await expect(
      factory
        .forScope({ ...ownerScope, workspaceRole: "member" })
        .connectionStore.updateVisibilityById(connection.id, "user"),
    ).rejects.toThrow("owner or admin");
    expect(
      await factory
        .forScope({
          ...tenantAUserB,
          workspaceRole: "admin",
          localConnectionId: localConnectionIds.privateConnection,
        })
        .connectionStore.updateVisibilityById(connection.id, "user"),
    ).toBeUndefined();
    for (const foreignScope of [tenantBUserA, workspaceBUserA]) {
      expect(
        await factory
          .forScope({
            ...foreignScope,
            workspaceRole: "admin",
            localConnectionId: localConnectionIds.privateConnection,
          })
          .connectionStore.updateVisibilityById(connection.id, "user"),
      ).toBeUndefined();
    }
    expect(
      await factory
        .forScope({ ...ownerScope, localConnectionId: randomUUID() })
        .connectionStore.updateVisibilityById(connection.id, "user"),
    ).toBeUndefined();
    expect(await ownerStore.updateVisibilityById(randomUUID(), "user")).toBeUndefined();

    const privateAgain = await factory
      .forScope({ ...ownerScope, workspaceRole: "admin" })
      .connectionStore.updateVisibilityById(connection.id, "user");
    expect(privateAgain?.visibility).toBe("user");
    expect(await memberStore.get("gmail", alias)).toBeUndefined();
    expect((await memberStore.list()).map((item) => item.id)).not.toContain(connection.id);
    await memberStore.delete("gmail", alias);
    expect((await ownerStore.get("gmail", alias))?.id).toBe(connection.id);
    await expect(ownerStore.blockForRevocation(connection.id)).resolves.toMatchObject({
      id: connection.id,
    });
    expect(await ownerStore.updateVisibilityById(connection.id, "workspace")).toBeUndefined();
  });

  it("captures a deeply frozen scope copy and never returns a global list", async () => {
    const mutable = scope(`tenant-frozen-${nonce}`, `workspace-frozen-${nonce}`, "user-frozen");
    mutable.localConnectionId = localConnectionIds.frozen;
    const database = factory.forScope(mutable);
    mutable.tenantId = `tenant-mutated-${nonce}`;
    mutable.workspaceId = `workspace-mutated-${nonce}`;
    mutable.permissions.push("admin:read");
    const connection = await database.connectionStore.set("gmail", `frozen-${randomUUID()}`, credential("frozen"));
    expect(connectionSecrets.observedScopes.every(Object.isFrozen)).toBe(true);
    expect(connectionSecrets.observedScopes.every((item) => Object.isFrozen(item.permissions))).toBe(true);
    expect((await database.connectionStore.list()).map((item) => item.id)).toContain(connection.id);
    expect((await factory.forScope(mutable).connectionStore.list()).map((item) => item.id)).not.toContain(
      connection.id,
    );
    expect((await factory.forScope(tenantBUserA).connectionStore.list()).map((item) => item.id)).not.toContain(
      connection.id,
    );
  });

  it("rejects default aliases and exposes no alternate identity parameters", async () => {
    const store = factory.forScope(tenantAUserA).connectionStore;
    await expect(store.set("gmail", "default", credential("forbidden"))).rejects.toThrow("non-default");
    await expect(store.get("gmail", "default")).rejects.toThrow("non-default");
    expectTypeOf(store.get).parameters.toEqualTypeOf<[service: string, connectionName: string]>();
    expectTypeOf(store.list).parameters.toEqualTypeOf<[]>();
  });

  it("replays the exact SaaS result and conflicts on a different authorized request hash", async () => {
    const actionScope = {
      ...tenantAUserA,
      purpose: "action:execute" as const,
      permissions: ["action:execute"],
      actionId: "gmail.messages_list",
      requestHash: `saas-request-${nonce}`,
    };
    const store = factory.forScope(actionScope).saasIdempotencyStore;
    const claim = {
      keyHash: `saas-key-${nonce}`,
      requestHash: actionScope.requestHash,
      claimId: randomUUID(),
      now: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };
    const response = {
      ok: true as const,
      executionId: randomUUID(),
      status: "succeeded" as const,

      output: { id: "message-1" },
    };
    expect(await store.claimAction(claim)).toEqual({ kind: "acquired" });
    expect(await store.completeAction({ ...claim, response })).toBe(true);
    expect(await store.claimAction({ ...claim, claimId: randomUUID() })).toEqual({ kind: "completed", response });

    const driftStore = factory.forScope({
      ...actionScope,
      requestHash: `saas-request-drift-${nonce}`,
    }).saasIdempotencyStore;
    expect(
      await driftStore.claimAction({
        ...claim,
        requestHash: `saas-request-drift-${nonce}`,
        claimId: randomUUID(),
      }),
    ).toEqual({ kind: "conflict" });
    const unknownClaim = {
      ...claim,
      keyHash: `saas-unknown-key-${nonce}`,
      claimId: randomUUID(),
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
    };
    expect(await store.claimAction(unknownClaim)).toEqual({ kind: "acquired" });
    expect(
      await store.claimAction({
        ...unknownClaim,
        claimId: randomUUID(),
        now: new Date(Date.now() + 60_000).toISOString(),
      }),
    ).toEqual({ kind: "in_progress" });
  });

  it("persists payload-free intent before safe completion metrics", async () => {
    const journalScope = { ...tenantAUserA, localConnectionId: localConnectionIds.journal };
    const connection = await factory
      .forScope(journalScope)
      .connectionStore.set("gmail", `journal-${randomUUID()}`, credential("journal"));
    const requestHash = `journal-request-${nonce}`;
    const actionScope = {
      ...tenantAUserA,
      localConnectionId: journalScope.localConnectionId,
      purpose: "action:execute" as const,
      permissions: ["action:execute"],
      connectorConnectionId: connection.id,
      actionId: "gmail.messages_list",
      requestHash,
    };
    const executionId = randomUUID();
    const startedAt = new Date().toISOString();
    const journal = factory.forScope(actionScope).executionJournal;
    await journal.start({
      executionId,
      connectionId: connection.id,
      service: "gmail",
      actionId: actionScope.actionId,
      requestHash,
      inputBytes: Buffer.byteLength(JSON.stringify({ secret: "input-secret" })),
      startedAt,
    });
    await journal.complete({
      executionId,
      durationMs: 7,
      outputBytes: Buffer.byteLength(JSON.stringify({ secret: "output-secret" })),
      providerRequestCount: 3,
      resultFingerprint: "result-hash",
      completedAt: new Date().toISOString(),
    });

    await withScopedClient(runtimePool, actionScope, async (client) => {
      const row = (
        await client.query<{
          status: string;
          input_bytes: string;
          output_bytes: string;
          duration_ms: string;
          provider_request_count: string;
          persisted: string;
        }>(
          `SELECT status, input_bytes, output_bytes, duration_ms, provider_request_count,
                  row_to_json(run_intent)::text AS persisted
           FROM integration_runtime.run_intents AS run_intent
           WHERE id = $1`,
          [executionId],
        )
      ).rows[0];
      expect(row).toMatchObject({
        status: "succeeded",
        input_bytes: String(Buffer.byteLength(JSON.stringify({ secret: "input-secret" }))),
        output_bytes: String(Buffer.byteLength(JSON.stringify({ secret: "output-secret" }))),
        duration_ms: "7",
        provider_request_count: "3",
      });
      expect(row.persisted).not.toContain("input-secret");
      expect(row.persisted).not.toContain("output-secret");
    });
  });

  it("consumes OAuth state once without exposing it to another user", async () => {
    const ownerScope = { ...tenantAUserA, oauthSessionId: randomUUID() };
    const state: OAuthAuthorizationState = {
      service: "gmail",
      connectionName: `oauth-${randomUUID()}`,
      state: randomBytes(32).toString("hex"),
      createdAt: new Date().toISOString(),
      pkceCodeVerifier: "verifier",
    };
    await factory.forScope(ownerScope).oauthStateStore.set(state);
    await withScopedClient(runtimePool, ownerScope, async (client) => {
      const persisted = await client.query<{ value: string }>(
        `SELECT row_to_json(oauth_state)::text AS value
         FROM integration_runtime.oauth_states AS oauth_state
         WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3 AND connection_name = $4`,
        [ownerScope.tenantId, ownerScope.workspaceId, ownerScope.subjectUserId, state.connectionName],
      );
      expect(persisted.rows[0]?.value).not.toContain(state.state);
      expect(persisted.rows[0]?.value).not.toContain(state.pkceCodeVerifier);
    });
    expect(await factory.forScope(tenantAUserB).oauthStateStore.take(state.state)).toBeUndefined();
    expect(await factory.forScope(ownerScope).oauthStateStore.take(state.state)).toEqual(state);
    expect(await factory.forScope(ownerScope).oauthStateStore.take(state.state)).toBeUndefined();
  });
  it("marks OAuth state failed when secret consumption is ambiguous", async () => {
    const ownerScope = { ...tenantAUserA, oauthSessionId: randomUUID() };
    const state: OAuthAuthorizationState = {
      service: "gmail",
      state: randomBytes(32).toString("hex"),
      createdAt: new Date().toISOString(),
      pkceCodeVerifier: "verifier",
    };
    await factory.forScope(ownerScope).oauthStateStore.set(state);
    oauthStateSecrets.failTake = true;
    await expect(factory.forScope(ownerScope).oauthStateStore.take(state.state)).rejects.toMatchObject({
      code: "OAUTH_STATE_RECONNECT_REQUIRED",
      phase: "secret_take_failed",
      markerWritten: true,
    });
    oauthStateSecrets.failTake = false;

    await withScopedClient(runtimePool, ownerScope, async (client) => {
      const result = await client.query<{ status: string; callback_result_fingerprint: string }>(
        `SELECT status, callback_result_fingerprint
         FROM integration_runtime.oauth_states
         WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3 AND id = $4`,
        [ownerScope.tenantId, ownerScope.workspaceId, ownerScope.subjectUserId, ownerScope.oauthSessionId],
      );
      expect(result.rows[0]).toEqual({
        status: "failed",
        callback_result_fingerprint: "reconcile:secret_take_failed",
      });
    });
  });

  it("lists, filters, paginates, and isolates redacted run logs", async () => {
    const service = `runs-${nonce}`;
    const baseTime = Date.now() + 60_000;
    const run: RunLog = {
      id: randomUUID(),
      service,
      actionId: `${service}.match`,
      caller: "mcp",
      startedAt: new Date(baseTime + 3_000).toISOString(),
      completedAt: new Date(baseTime + 3_001).toISOString(),
      durationMs: 5,
      ok: false,
      errorCode: "provider_error",
      errorMessage: "must not persist",
      inputSummary: { secret: "must not persist" },
      outputSummary: { secret: "must not persist" },
    };
    const second = {
      ...run,
      id: randomUUID(),
      actionId: `${service}.other`,
      caller: "http" as const,
      startedAt: new Date(baseTime + 2_000).toISOString(),
      completedAt: new Date(baseTime + 2_001).toISOString(),
      ok: true,
    };
    const third = {
      ...second,
      id: randomUUID(),
      startedAt: new Date(baseTime + 1_000).toISOString(),
      completedAt: new Date(baseTime + 1_001).toISOString(),
    };
    const ownerRuns = factory.forScope(tenantAUserA).runLogStore;
    await ownerRuns.add(run);
    await ownerRuns.add(second);
    await ownerRuns.add(third);
    for (const adjacentScope of [tenantAUserB, workspaceBUserA, tenantBUserA]) {
      expect(await factory.forScope(adjacentScope).runLogStore.get(run.id)).toBeUndefined();
      expect((await factory.forScope(adjacentScope).runLogStore.list({ service })).items).toEqual([]);
    }
    expect(await ownerRuns.get(run.id)).toEqual({
      ...run,
      errorMessage: undefined,
      inputSummary: undefined,
      outputSummary: undefined,
    });
    expect(await ownerRuns.get(randomUUID())).toBeUndefined();

    const firstPage = await ownerRuns.list({ service, limit: 2 });
    expect(firstPage.items.map((item) => item.id)).toEqual([run.id, second.id]);
    expect(firstPage.nextCursor).toEqual(expect.any(String));
    const secondPage = await ownerRuns.list({ service, limit: 2, cursor: firstPage.nextCursor });
    expect(secondPage.items.map((item) => item.id)).toEqual([third.id]);
    expect(secondPage.nextCursor).toBeUndefined();
    expect(
      await ownerRuns.list({
        service,
        actionId: run.actionId,
        caller: "mcp",
        ok: false,
      }),
    ).toMatchObject({ items: [{ id: run.id }] });
  });
  it("keeps the prior credential revision readable when its metadata update fails", async () => {
    const store = factory.forScope({
      ...tenantAUserA,
      localConnectionId: localConnectionIds.revision,
    }).connectionStore;
    const alias = `revision-${randomUUID()}`;
    const original = await store.set("gmail", alias, credential("revision-old"));
    const invalid = credential("revision-new");
    (invalid.profile.grantedScopes as unknown[]).push(1n);

    await expect(store.updateCredential({ ...original, credential: invalid })).rejects.toBeInstanceOf(
      ConnectionMetadataReconciliationError,
    );
    expect((await store.get("gmail", alias))?.credential).toEqual(original.credential);
  });
  it("resumes local cleanup and records the safe provider outcome in an exact scoped receipt", async () => {
    const scoped = {
      ...tenantAUserA,
      localConnectionId: localConnectionIds.deletion,
    };
    const store = factory.forScope(scoped).connectionStore;
    const alias = `delete-${randomUUID()}`;
    const connection = await store.set("gmail", alias, credential("delete"));
    await expect(store.blockForRevocation(connection.id)).resolves.toMatchObject({ id: connection.id });
    connectionSecrets.failDelete = true;
    await expect(store.deleteById(connection.id, "unsupported")).rejects.toThrow("delete failed");
    connectionSecrets.failDelete = false;

    await withScopedClient(runtimePool, tenantAUserA, async (client) => {
      const row = (
        await client.query<{
          status: string;
          safe_metadata: { reconciliation: string; providerRevocationOutcome: string };
        }>(
          `SELECT status, safe_metadata FROM integration_runtime.connections
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3 AND id = $4`,
          [tenantAUserA.tenantId, tenantAUserA.workspaceId, tenantAUserA.subjectUserId, connection.id],
        )
      ).rows[0];
      expect(row).toEqual({
        status: "revoked",
        safe_metadata: { reconciliation: "secret_delete_failed", providerRevocationOutcome: "unsupported" },
      });
    });
    await expect(store.resumeRevocation(connection.id)).resolves.toBe(true);
    await expect(store.hasRevocationReceipt(connection.id)).resolves.toBe(true);
    await withScopedClient(runtimePool, tenantAUserA, async (client) => {
      const receipt = await client.query<{ outcome: string }>(
        `SELECT outcome FROM integration_runtime.connection_revocation_receipts
         WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
           AND connector_connection_id = $4`,
        [tenantAUserA.tenantId, tenantAUserA.workspaceId, tenantAUserA.subjectUserId, connection.id],
      );
      expect(receipt.rows[0]?.outcome).toBe("unsupported");
    });
    await expect(store.resumeRevocation(connection.id)).resolves.toBe(false);
    await expect(
      factory
        .forScope({ ...tenantAUserB, localConnectionId: localConnectionIds.deletion })
        .connectionStore.hasRevocationReceipt(connection.id),
    ).resolves.toBe(false);
  });
});
describe("SaaS per-request runtime binding", () => {
  it("verifies JWT before creating a fresh scoped bundle for every request", async () => {
    const captured: SaasRequestScope[] = [];
    const providerLoader: IProviderLoader = {
      async loadActionExecutor() {
        return undefined;
      },
      async loadProxyExecutor() {
        return undefined;
      },
      async loadCredentialValidators() {
        return undefined;
      },
    };
    const app = new SaasConnectServer({
      catalog: createCatalogStore([]),
      providerLoader,
      verifyJwt: async (authorization) => {
        if (authorization !== "Bearer valid") throw new SaasAuthorizationError(401);
        return {
          ...scope("server-tenant", "server-workspace", "server-user"),
          purpose: "connection:read",
          permissions: ["connection:read"],
        };
      },
      readiness: async () => ({
        postgres: true,
        openBao: true,
        jwks: true,
        seaweedFs: true,
        providerRegistry: true,
        catalogFingerprint: true,
      }),
      runtimeDatabaseFactory: {
        forScope(requestScope) {
          captured.push(requestScope);
          return undefined as never;
        },
      },
    }).createApp();

    expect((await app.request("/internal/saas/connections")).status).toBe(401);
    expect(captured).toHaveLength(0);
    await app.request("/internal/saas/connections", { headers: { authorization: "Bearer valid" } });
    await app.request("/internal/saas/connections", { headers: { authorization: "Bearer valid" } });
    expect(captured).toHaveLength(2);
    expect(captured[0]).not.toBe(captured[1]);
  });
});
describe("OAuth completion reconciliation", () => {
  it("marks a reserved state terminal when the completion write fails", async () => {
    const queries: string[] = [];
    const client = {
      async query(sql: string): Promise<{ rows: unknown[]; rowCount: number | null }> {
        queries.push(sql);
        if (sql.includes("SET status = 'reserved'")) {
          return {
            rows: [
              {
                id: "oauth-session",
                service: "gmail",
                connection_name: "opaque",
                created_at: "2026-08-04T00:00:00.000Z",
              },
            ],
            rowCount: 1,
          };
        }
        if (sql.includes("SET status = $5")) throw new Error("completion unavailable");
        if (sql.includes("SET status = 'failed'")) return { rows: [], rowCount: 1 };
        return { rows: [], rowCount: null };
      },
      release(): void {},
    };
    const fakePool = { connect: async () => client } as unknown as Pool;
    const requestScope = scope("tenant", "workspace", "user");
    const store = new PostgresOAuthStateStore(fakePool, requestScope, {
      async put() {
        return { secretRef: "unused", secretRevision: 1 };
      },
      async take() {
        return {};
      },
      async delete() {},
    });

    let caught: unknown;
    try {
      await store.take("presented-state");
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(OAuthStateConsumeReconciliationError);
    expect(caught).toMatchObject({
      phase: "completion_write_failed",
      markerWritten: true,
    });
    expect(queries.some((sql) => sql.includes("SET status = 'failed'"))).toBe(true);
    expect(queries.some((sql) => sql.includes("SET status = 'pending'"))).toBe(false);
  });
});

class MemoryConnectionSecrets implements ConnectionSecretStore {
  readonly observedScopes: Array<Readonly<SaasRequestScope>> = [];
  failDelete = false;
  private readonly records = new Map<string, ConnectionSecret>();

  async create(
    requestScope: Readonly<SaasRequestScope>,
    connectionId: string,
    provider: string,
    value: ResolvedCredential,
  ): Promise<{ secretRef: string; secretRevision: number }> {
    this.observedScopes.push(requestScope);
    this.records.set(`${key(requestScope, connectionId)}#1`, toSecret(provider, value, 1));
    return { secretRef: key(requestScope, connectionId), secretRevision: 1 };
  }

  async read(
    requestScope: Readonly<SaasRequestScope>,
    connectionId: string,
    secretRevision: number,
  ): Promise<ConnectionSecret | undefined> {
    this.observedScopes.push(requestScope);
    return this.records.get(`${key(requestScope, connectionId)}#${secretRevision}`);
  }

  async update(
    requestScope: Readonly<SaasRequestScope>,
    connectionId: string,
    provider: string,
    expectedRevision: number,
    value: ResolvedCredential,
  ): Promise<number | false> {
    if (!this.records.has(`${key(requestScope, connectionId)}#${expectedRevision}`)) return false;
    const revision = expectedRevision + 1;
    this.records.set(`${key(requestScope, connectionId)}#${revision}`, toSecret(provider, value, revision));
    return revision;
  }

  async delete(requestScope: Readonly<SaasRequestScope>, connectionId: string): Promise<void> {
    if (this.failDelete) throw new Error("delete failed");
    const prefix = `${key(requestScope, connectionId)}#`;
    for (const recordKey of this.records.keys()) {
      if (recordKey.startsWith(prefix)) this.records.delete(recordKey);
    }
  }
}

class MemoryOAuthStateSecrets implements OAuthStateSecretStore {
  failTake = false;
  private readonly states = new Map<string, { pkceCodeVerifier?: string }>();
  async put(
    requestScope: Readonly<SaasRequestScope>,
    oauthSessionId: string,
    pkceCodeVerifier: string | undefined,
  ): Promise<{ secretRef: string; secretRevision: number }> {
    const secretRef = key(requestScope, oauthSessionId);
    this.states.set(secretRef, pkceCodeVerifier === undefined ? {} : { pkceCodeVerifier });
    return { secretRef, secretRevision: 1 };
  }
  async take(
    requestScope: Readonly<SaasRequestScope>,
    oauthSessionId: string,
  ): Promise<{ pkceCodeVerifier?: string } | undefined> {
    if (this.failTake) throw new Error("ambiguous OpenBao take");
    const secretRef = key(requestScope, oauthSessionId);
    const state = this.states.get(secretRef);
    this.states.delete(secretRef);
    return state;
  }
  async delete(requestScope: Readonly<SaasRequestScope>, oauthSessionId: string): Promise<void> {
    this.states.delete(key(requestScope, oauthSessionId));
  }
}

function scope(tenantId: string, workspaceId: string, subjectUserId: string): SaasRequestScope {
  const digest = createHash("sha256").update(`${tenantId}\0${workspaceId}\0${subjectUserId}`).digest("hex");
  const localConnectionId = `${digest.slice(0, 8)}-${digest.slice(8, 12)}-4${digest.slice(13, 16)}-8${digest.slice(17, 20)}-${digest.slice(20, 32)}`;
  return {
    tenantId,
    workspaceId,
    actorUserId: subjectUserId,
    subjectUserId,
    workspaceRole: "member",
    purpose: "connection:write",
    permissions: ["connection:read", "connection:write"],
    localConnectionId,
  };
}
function credential(accountId: string): Extract<ResolvedCredential, { authType: "api_key" }> {
  return {
    authType: "api_key",
    apiKey: `secret-${accountId}`,
    values: { apiKey: `secret-${accountId}` },
    profile: { accountId, displayName: accountId, grantedScopes: [] },
    metadata: { source: "test" },
  };
}
function key(requestScope: Readonly<SaasRequestScope>, id: string): string {
  return `${requestScope.tenantId}/${requestScope.workspaceId}/${id}`;
}
function toSecret(provider: string, value: ResolvedCredential, revision: number): ConnectionSecret {
  const base = { provider, metadata: "metadata" in value ? value.metadata : {}, revision };
  switch (value.authType) {
    case "no_auth":
      return { ...base, authType: "no_auth", value: {} };
    case "api_key":
      return { ...base, authType: "api_key", value: { apiKey: value.apiKey, values: value.values } };
    case "custom_credential":
      return { ...base, authType: "custom_credential", value: { values: value.values } };
    case "oauth2":
      return {
        ...base,
        authType: "oauth2",
        value: {
          accessToken: value.accessToken,
          tokenType: value.tokenType,
          ...(value.expiresAt === undefined ? {} : { expiresAt: value.expiresAt }),
          ...(value.refreshToken === undefined ? {} : { refreshToken: value.refreshToken }),
          ...(value.providerSecret === undefined ? {} : { providerSecret: value.providerSecret }),
        },
      };
  }
}
