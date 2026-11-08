import type { ResolvedCredential } from "../../core/types.ts";
import type { OAuthAuthorizationState } from "../../oauth/oauth-flow-service.ts";
import type { IProviderLoader } from "../../providers/provider-loader.ts";
import type {
  ActionPolicyAuditRecord,
  ActionPolicyControlPrincipal,
  ActionPolicyRecord,
  ActionPolicyServicePrincipal,
  ActionPolicyTarget,
  ActionPolicyUserTarget,
  SaasRequestScope,
} from "../contracts.ts";
import type { PostgresTestDatabase } from "../testing/postgres-test-database.ts";
import type { ConnectionSecret, ConnectionSecretStore } from "./postgres-connection-store.ts";
import type { OAuthStateSecretStore } from "./postgres-oauth-state-store.ts";
import type { RunLog } from "./run-store.ts";

import { Buffer } from "node:buffer";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, expectTypeOf, it } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import { SaasAuthorizationError } from "../auth/saas-jwt-verifier.ts";
import { SaasConnectServer } from "../server/saas-connect-server.ts";
import { MemorySecretCodec } from "../testing/native-store-fixtures.ts";
import { createPostgresTestDatabase, postgresTestUrl } from "../testing/postgres-test-database.ts";
import { PostgresActionPolicyStore } from "./postgres-action-policy-store.ts";
import { ConnectionMetadataReconciliationError } from "./postgres-connection-store.ts";
import { migratePostgres } from "./postgres-migrator.ts";
import { OAuthStateConsumeReconciliationError, PostgresOAuthStateStore } from "./postgres-oauth-state-store.ts";
import { probeSaasRuntimeDatabase, SaasRuntimeDatabaseFactory } from "./postgres-runtime-database.ts";
import { withActionPolicyClient, withScopedClient } from "./scoped-query.ts";

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
const requestSecretCodec = new MemorySecretCodec();
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
      catalog: createCatalogStore([]),
      connectionSecrets,
      oauthStateSecrets,
      secretCodecForScope: () => requestSecretCodec,
    });
  }, 30_000);

  afterAll(async () => {
    try {
      await Promise.all([runtimePool?.end(), adminPool?.end()]);
    } finally {
      await testDatabase?.dispose();
    }
  });

  it("durably fences callbacks and refresh across revoke, deletion, ownership and visibility changes", async () => {
    const scoped = { ...tenantAUserA, workspaceRole: "owner" as const, localConnectionId: randomUUID() };
    const store = factory.forScope(scoped).connectionStore;
    const alias = `fenced-${randomUUID()}`;
    const oauthCredential = {
      authType: "oauth2" as const,
      accessToken: "original",
      tokenType: "Bearer",
      refreshToken: "rotating-refresh",
      profile: { accountId: "account", displayName: "Account", grantedScopes: [] },
      metadata: {},
    };
    const generation = await store.getRetirementGeneration("gmail", alias);
    const original = await store.setIfCurrentGeneration("gmail", alias, oauthCredential, generation);
    expect(original).toBeDefined();
    await store.blockForRevocation(original!.id);
    expect(
      await store.updateCredential(
        { ...original!, credential: { ...oauthCredential, accessToken: "late-refresh" } },
        true,
      ),
    ).toBe(false);
    expect(
      await store.setIfCurrentGeneration(
        "gmail",
        alias,
        { ...oauthCredential, accessToken: "late-callback" },
        generation,
      ),
    ).toBeUndefined();
    await store.delete("gmail", alias);
    const nextGeneration = await factory.forScope(scoped).connectionStore.getRetirementGeneration("gmail", alias);
    expect(nextGeneration).not.toBe(generation);
    const replacement = await store.setIfCurrentGeneration(
      "gmail",
      alias,
      { ...oauthCredential, accessToken: "replacement" },
      nextGeneration,
    );
    expect(replacement).toBeDefined();
    await expect(store.delete("gmail", alias, original!)).rejects.toMatchObject({ code: "connection_changed" });
    expect((await store.getById(replacement!.id))?.id).toBe(replacement!.id);
    await store.updateVisibilityById(replacement!.id, "workspace");
    const shared = factory.forScope({ ...scoped, actorUserId: tenantAUserB.subjectUserId }).connectionStore;
    expect((await shared.getSafeConnection(replacement!.id))?.subjectUserId).toBe(scoped.subjectUserId);
    await store.updateVisibilityById(replacement!.id, "user");
    expect(await shared.getSafeConnection(replacement!.id)).toBeUndefined();
    expect(await shared.getById(replacement!.id)).toBeUndefined();
    await store.updateVisibilityById(replacement!.id, "workspace");
    const transferGeneration = await store.getRetirementGeneration("gmail", alias);
    await store.transferById(replacement!.id, tenantAUserB.subjectUserId);
    expect(await store.getById(replacement!.id)).toBeUndefined();
    expect(
      await store.setIfCurrentGeneration(
        "gmail",
        alias,
        { ...oauthCredential, accessToken: "old-owner" },
        transferGeneration,
      ),
    ).toBeUndefined();
  });

  it.each(["action_defaults", "action_grants", "action_policy_audit"])(
    "requires forced RLS and presence for policy table %s",
    async (table) => {
      await adminPool.query(`ALTER TABLE integration_runtime.${table} NO FORCE ROW LEVEL SECURITY`);
      try {
        await expect(probeSaasRuntimeDatabase(runtimePool)).rejects.toThrow(table);
      } finally {
        await adminPool.query(`ALTER TABLE integration_runtime.${table} FORCE ROW LEVEL SECURITY`);
      }
      const temporary = `${table}_missing`;
      await adminPool.query(`ALTER TABLE integration_runtime.${table} RENAME TO ${temporary}`);
      try {
        await expect(probeSaasRuntimeDatabase(runtimePool)).rejects.toThrow(table);
      } finally {
        await adminPool.query(`ALTER TABLE integration_runtime.${temporary} RENAME TO ${table}`);
      }
    },
  );

  it("resolves all nine persisted precedence combinations and reads the actor, never the credential owner", async () => {
    const fixture = policyFixture("matrix", 9);
    const combinations = [
      { individual: null, defaults: null, enabled: false, source: "none" },
      { individual: null, defaults: false, enabled: false, source: "platform" },
      { individual: null, defaults: true, enabled: true, source: "platform" },
      { individual: false, defaults: null, enabled: false, source: "individual" },
      { individual: false, defaults: false, enabled: false, source: "individual" },
      { individual: false, defaults: true, enabled: false, source: "individual" },
      { individual: true, defaults: null, enabled: true, source: "individual" },
      { individual: true, defaults: false, enabled: true, source: "individual" },
      { individual: true, defaults: true, enabled: true, source: "individual" },
    ] as const;
    for (const [index, value] of combinations.entries()) {
      const actionIds = [fixture.actionIds[index]!];
      if (value.defaults !== null)
        await fixture.store.applyForControl(policyControl({ kind: "platform" }), {
          actionIds,
          enabled: value.defaults,
          reason: "common review",
        });
      if (value.individual !== null)
        await fixture.store.applyForControl(policyControl(fixture.target), {
          actionIds,
          enabled: value.individual,
          reason: "individual review",
        });
    }
    const decisions = await fixture.store.getEffectiveForActor(fixture.actor, fixture.actionIds);
    expect(decisions).toEqual(
      combinations.map((value, index) => ({
        actionId: fixture.actionIds[index],
        enabled: value.enabled,
        source: value.source,
        individualEnabled: value.individual,
        defaultEnabled: value.defaults,
      })),
    );
    expect(
      await fixture.store.getEffectiveForControl(
        policyControl(fixture.target, "action-policy:read"),
        fixture.actionIds,
      ),
    ).toEqual(decisions);
    const common = await fixture.store.getEffectiveForControl(
      policyControl({ kind: "platform" }, "action-policy:read"),
      fixture.actionIds,
    );
    expect(common[5]).toMatchObject({ enabled: true, source: "platform", individualEnabled: null });
    const reader = policyControl(fixture.target, "action-policy:read");
    expect((await fixture.store.readForControl(reader)).items).toHaveLength(6);
    const pageOne = await fixture.store.readForControl(reader, { limit: 1 });
    const pageTwo = await fixture.store.readForControl(reader, { limit: 1, cursor: pageOne.nextCursor! });
    expect(pageOne.items.map((row) => row.actionId)).toEqual([fixture.actionIds[3]]);
    expect(pageTwo.items.map((row) => row.actionId)).toEqual([fixture.actionIds[4]]);
    const newUser = { ...fixture.target, userId: randomUUID() };
    expect((await fixture.store.readForControl(policyControl(newUser, "action-policy:read"))).items).toEqual([]);
    expect(
      (
        await fixture.store.getEffectiveForControl(policyControl(newUser, "action-policy:read"), [
          fixture.actionIds[2]!,
        ])
      )[0],
    ).toMatchObject({ source: "platform", enabled: true, individualEnabled: null });
    expect((await fixture.store.readForControl(policyControl(newUser, "action-policy:read"))).items).toEqual([]);
    await expect(
      fixture.store.readForControl(policyControl(newUser, "action-policy:read"), { cursor: pageOne.nextCursor! }),
    ).rejects.toThrow("cursor");
    const ownerId = randomUUID();
    await fixture.store.applyForControl(policyControl({ ...fixture.target, userId: ownerId }), {
      actionIds: [fixture.actionIds[5]!],
      enabled: true,
      reason: "owner-only grant",
    });
    const shared = {
      ...fixture.actor,
      subjectUserId: ownerId,
      purpose: "action:execute:v2" as const,
      permissions: ["action:execute:v2"],
    };
    expect(await fixture.store.getEffectiveForActor(shared, [fixture.actionIds[5]!])).toEqual([decisions[5]]);
    const otherTenant = { ...fixture.actor, tenantId: randomUUID() };
    expect((await fixture.store.getEffectiveForActor(otherTenant, [fixture.actionIds[3]!]))[0]).toMatchObject({
      source: "none",
      enabled: false,
      individualEnabled: null,
    });
    const otherWorkspace = { ...fixture.actor, workspaceId: randomUUID() };
    expect((await fixture.store.getEffectiveForActor(otherWorkspace, [fixture.actionIds[3]!]))[0]).toMatchObject({
      source: "none",
    });
  });

  it("keeps ordinary and workspace-owner SQL contexts read-only for policy, and resets verified context on pool reuse", async () => {
    const fixture = policyFixture("rls");
    const actionIds = [fixture.actionIds[0]!];
    await fixture.store.applyForControl(policyControl({ kind: "platform" }), {
      actionIds,
      enabled: true,
      reason: "common",
    });
    await fixture.store.applyForControl(policyControl(fixture.target), {
      actionIds,
      enabled: false,
      reason: "personal",
    });
    for (const workspaceRole of ["member", "owner"] as const) {
      const actor = { ...fixture.actor, workspaceRole };
      await withScopedClient(runtimePool, actor, async (client) => {
        expect(
          (
            await client.query(
              "UPDATE integration_runtime.action_defaults SET enabled = false WHERE action_id = $1",
              actionIds,
            )
          ).rowCount,
        ).toBe(0);
        expect(
          (
            await client.query(
              "UPDATE integration_runtime.action_grants SET enabled = true WHERE action_id = $1",
              actionIds,
            )
          ).rowCount,
        ).toBe(0);
        expect(
          (await client.query("DELETE FROM integration_runtime.action_grants WHERE action_id = $1", actionIds))
            .rowCount,
        ).toBe(0);
        const settings = await client.query(
          `SELECT current_setting('integration.actor_user_id') AS actor, current_setting('integration.purpose') AS purpose, current_setting('integration.principal_kind') AS kind`,
        );
        expect(settings.rows[0]).toEqual({ actor: fixture.target.userId, purpose: "action:search", kind: "user" });
      });
      await expect(
        withScopedClient(runtimePool, actor, (client) =>
          client.query(
            `INSERT INTO integration_runtime.action_defaults (action_id, enabled, created_by_subject, updated_by_subject) VALUES ($1, true, 'forged', 'forged')`,
            [fixture.actionIds[1]],
          ),
        ),
      ).rejects.toThrow(/row-level security/i);
      await expect(
        withScopedClient(runtimePool, actor, (client) =>
          client.query(
            `INSERT INTO integration_runtime.action_grants (id, tenant_id, workspace_id, user_id, action_id, enabled, created_by_subject, updated_by_subject) VALUES ($1, $2, $3, $4, $5, true, 'forged', 'forged')`,
            [
              randomUUID(),
              fixture.target.tenantId,
              fixture.target.workspaceId,
              fixture.target.userId,
              fixture.actionIds[1],
            ],
          ),
        ),
      ).rejects.toThrow(/row-level security/i);
      await expect(
        withScopedClient(runtimePool, actor, (client) =>
          client.query(
            `INSERT INTO integration_runtime.action_policy_audit (id, target_kind, operator_subject, action_ids, enabled, reason, request_id) VALUES ($1, 'platform', 'forged', $2, true, 'forged', 'forged')`,
            [randomUUID(), actionIds],
          ),
        ),
      ).rejects.toThrow(/row-level security/i);
    }
    const other = { ...fixture.target, tenantId: randomUUID() };
    await withActionPolicyClient(runtimePool, policyControl(other, "action-policy:read"), async (client) => {
      expect(
        (
          await client.query("SELECT * FROM integration_runtime.action_grants WHERE tenant_id = $1", [
            fixture.target.tenantId,
          ])
        ).rows,
      ).toEqual([]);
    });
    await withScopedClient(runtimePool, fixture.actor, async (client) => {
      expect(
        (await client.query("SELECT current_setting('integration.policy_target_kind', true) AS target")).rows[0],
      ).toEqual({ target: "" });
    });
    const rows = await fixture.store.readForControl(policyControl(fixture.target, "action-policy:read"));
    expect(rows.items[0]).toMatchObject({
      enabled: false,
      createdBySubject: "verified-operator",
      updatedBySubject: "verified-operator",
    });
  });

  it("validates entire batches and atomically rolls rules back when audit fails", async () => {
    const fixture = policyFixture("atomic");
    const actionIds = fixture.actionIds.slice(0, 2);
    const writer = policyControl(fixture.target);
    const first = await fixture.store.applyForControl(writer, {
      actionIds,
      enabled: true,
      reason: "  approved batch  ",
    });
    expect(first).toMatchObject({ updatedCount: 2, removedCount: 0 });
    await expect(
      fixture.store.applyForControl(writer, {
        actionIds: [...actionIds, "unknown.action"],
        enabled: false,
        reason: "invalid batch",
      }),
    ).rejects.toThrow("Unknown action");
    await adminPool.query(`REVOKE INSERT ON integration_runtime.action_policy_audit FROM "${runtimeRole}"`);
    try {
      await expect(probeSaasRuntimeDatabase(runtimePool)).rejects.toThrow("policy privileges");
      await expect(
        fixture.store.applyForControl(writer, { actionIds, enabled: false, reason: "must roll back" }),
      ).rejects.toThrow(/permission denied/i);
    } finally {
      await adminPool.query(`GRANT INSERT ON integration_runtime.action_policy_audit TO "${runtimeRole}"`);
    }
    expect(
      (await fixture.store.readForControl(policyControl(fixture.target, "action-policy:read"))).items.map(
        (row) => row.enabled,
      ),
    ).toEqual([true, true]);
    const lifecycle = { ...fixture.actor, purpose: "lifecycle:read" as const, permissions: ["lifecycle:read"] };
    const exported = await fixture.store.exportForLifecycle(lifecycle);
    expect(exported.audit).toHaveLength(1);
    expect(exported.audit[0]).toMatchObject({
      id: first.auditId,
      operatorSubject: "verified-operator",
      reason: "approved batch",
      requestId: writer.requestId,
      actionIds,
      enabled: true,
    });
    expect(await fixture.store.getLifecycleCounts(lifecycle)).toEqual({ actionGrants: 2, actionPolicyAudit: 1 });
    const deletion = {
      ...lifecycle,
      purpose: "lifecycle:delete" as const,
      permissions: ["lifecycle:delete"],
      requestHash: "a".repeat(43),
    };
    expect(await fixture.store.getLifecycleCounts(deletion)).toEqual({ actionGrants: 2, actionPolicyAudit: 1 });
    await expect(fixture.store.exportForLifecycle(deletion)).rejects.toThrow("forbidden");
    await withScopedClient(runtimePool, deletion, async (client) => {
      expect(
        (
          await client.query("DELETE FROM integration_runtime.action_grants WHERE tenant_id = $1", [
            fixture.target.tenantId,
          ])
        ).rowCount,
      ).toBe(0);
      expect(
        (
          await client.query("DELETE FROM integration_runtime.action_policy_audit WHERE tenant_id = $1", [
            fixture.target.tenantId,
          ])
        ).rowCount,
      ).toBe(0);
    });
  });

  it("inventories audit-only users, exports bounded exact subject pages, and purges only the signed target", async () => {
    const fixture = policyFixture("lifecycle");
    const actionIds = fixture.actionIds.slice(0, 2);
    const adjacent = { ...fixture.target, userId: randomUUID() };
    const foreign = { ...fixture.target, tenantId: randomUUID() };
    await fixture.store.applyForControl(policyControl({ kind: "platform" }), {
      actionIds,
      enabled: true,
      reason: "survives customer purge",
    });
    await fixture.store.applyForControl(policyControl(fixture.target), { actionIds, enabled: false, reason: "target" });
    await fixture.store.applyForControl(policyControl(adjacent), { actionIds, enabled: true, reason: "adjacent" });
    await fixture.store.applyForControl(policyControl(adjacent), {
      actionIds,
      enabled: null,
      reason: "audit-only subject",
    });
    await fixture.store.applyForControl(policyControl(foreign), { actionIds, enabled: true, reason: "foreign" });
    const inventory = policyService(
      { kind: "workspace", tenantId: fixture.target.tenantId, workspaceId: fixture.target.workspaceId },
      "action-policy:subjects",
    );
    const first = await fixture.store.listSubjects(inventory, { limit: 1 });
    expect(first.items).toHaveLength(1);
    expect(first.nextCursor).not.toBeNull();
    const second = await fixture.store.listSubjects(inventory, { limit: 1, cursor: first.nextCursor! });
    expect([...first.items, ...second.items]).toEqual(expect.arrayContaining([fixture.target, adjacent]));
    expect(second.nextCursor).toBeNull();
    await expect(
      fixture.store.listSubjects(
        { ...inventory, target: { kind: "tenant", tenantId: foreign.tenantId } },
        { cursor: first.nextCursor! },
      ),
    ).rejects.toThrow("cursor");
    const lifecycle = { ...fixture.actor, purpose: "lifecycle:read" as const, permissions: ["lifecycle:read"] };
    const grants: ActionPolicyRecord[] = [];
    const audit: ActionPolicyAuditRecord[] = [];
    let nextCursor: string | null | undefined;
    do {
      const page = await fixture.store.exportForLifecycle(lifecycle, {
        limit: 1,
        ...(nextCursor ? { cursor: nextCursor } : {}),
      });
      expect(page.items.length + page.audit.length).toBe(1);
      grants.push(...page.items);
      audit.push(...page.audit);
      nextCursor = page.nextCursor;
    } while (nextCursor);
    expect(grants).toHaveLength(2);
    expect(audit).toHaveLength(1);
    expect(audit[0]!.target).toEqual(fixture.target);
    const correlationId = randomUUID();
    expect(await fixture.store.purge(policyService(fixture.target, "action-policy:purge"), correlationId)).toEqual({
      correlationId,
      deletedGrants: 2,
      deletedAudit: 1,
    });
    expect(await fixture.store.getLifecycleCounts(lifecycle)).toEqual({ actionGrants: 0, actionPolicyAudit: 0 });
    expect((await fixture.store.listSubjects(inventory)).items).toEqual([adjacent]);
    expect((await fixture.store.readForControl(policyControl(foreign, "action-policy:read"))).items).toHaveLength(2);
    expect(
      (
        await fixture.store.getEffectiveForControl(policyControl({ kind: "platform" }, "action-policy:read"), actionIds)
      ).every((row) => row.enabled && row.source === "platform"),
    ).toBe(true);
    const platformAudit = await adminPool.query(
      "SELECT id FROM integration_runtime.action_policy_audit WHERE target_kind = 'platform' AND action_ids = $1::text[]",
      [actionIds],
    );
    expect(platformAudit.rows).toHaveLength(1);
    expect(
      await fixture.store.purge(
        policyService({ kind: "tenant", tenantId: fixture.target.tenantId }, "action-policy:purge"),
        randomUUID(),
      ),
    ).toMatchObject({ deletedGrants: 0, deletedAudit: 2 });
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
    "0009_action_permissions.sql",
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
      expect((await stores[index].list()).map((connection) => connection.id)).toEqual([connections[index].id]);
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
    const connection = await ownerStore.set("gmail", alias, credential("private"));
    const memberExecutionStore = factory.forScope({
      ...ownerScope,
      actorUserId: tenantAUserB.actorUserId,
      workspaceRole: "member",
      purpose: "action:execute:v2",
      permissions: ["action:execute:v2"],
      connectorConnectionId: connection.id,
      actionId: "gmail.messages_list",
      requestHash: `visibility-request-${nonce}`,
      maxOutputBytes: 1_024,
    }).connectionStore;

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

  it("retains the original scope after caller mutation and never returns a global list", async () => {
    const mutable = scope(`tenant-frozen-${nonce}`, `workspace-frozen-${nonce}`, "user-frozen");
    mutable.localConnectionId = localConnectionIds.frozen;
    const originalScope = { ...mutable, permissions: [...mutable.permissions] };
    const database = factory.forScope(mutable);
    mutable.tenantId = randomUUID();
    mutable.workspaceId = randomUUID();
    mutable.permissions.push("admin:read");
    const connection = await database.connectionStore.set("gmail", `frozen-${randomUUID()}`, credential("frozen"));
    expect(connectionSecrets.observedScopes.at(-1)).toMatchObject(originalScope);
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
    const localConnectionId = randomUUID();
    const connection = await factory
      .forScope({ ...tenantAUserA, localConnectionId })
      .connectionStore.set("gmail", `idempotency-${randomUUID()}`, credential("idempotency"));
    const actionScope = {
      ...tenantAUserA,
      purpose: "action:execute:v2" as const,
      permissions: ["action:execute:v2"],
      localConnectionId,
      connectorConnectionId: connection.id,
      maxOutputBytes: 1_024,
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
      purpose: "action:execute:v2" as const,
      permissions: ["action:execute:v2"],
      connectorConnectionId: connection.id,
      actionId: "gmail.messages_list",
      maxOutputBytes: 1_024,
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
      connectionName: ownerScope.oauthSessionId,
      retirementGeneration: await factory
        .forScope(ownerScope)
        .connectionStore.getRetirementGeneration("gmail", ownerScope.oauthSessionId),
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
      connectionName: ownerScope.oauthSessionId,
      retirementGeneration: await factory
        .forScope(ownerScope)
        .connectionStore.getRetirementGeneration("gmail", ownerScope.oauthSessionId),
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
    invalid.profile.grantedScopes.push("invalid\u0000scope");

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

describe.skipIf(!testPostgresUrl)("PostgreSQL 0015 secret custody upgrade", () => {
  it("upgrades an empty original cleanup queue and removes its original grants", async () => {
    await withBase0015Database(async (database, owner, runtime) => {
      const originalLedger = (await owner.query("SELECT name, checksum FROM integration_runtime_migrations.schema_migrations ORDER BY name")).rows;
      expect((await runtime.query("SELECT integration_runtime.is_trigger_secret_referenced('unused') AS referenced")).rows).toEqual([{ referenced: false }]);
      await expect(migratePostgres({
        migratorConnectionString: database.migratorConnectionString,
        runtimeConnectionString: database.runtimeConnectionString,
      })).resolves.toEqual([
        "0016_workspace_configuration_control.sql",
        "0017_project_secret_custody.sql",
        "0018_managed_project_removal_fence.sql",
        "0019_scoped_secret_custody.sql",
      ]);
      expect((await owner.query("SELECT name, checksum FROM integration_runtime_migrations.schema_migrations WHERE name < '0016' ORDER BY name")).rows).toEqual(originalLedger);
      expect((await owner.query(`SELECT to_regclass('integration_runtime.trigger_secret_cleanup')::text AS queue,
        to_regprocedure('integration_runtime.is_trigger_secret_referenced(text)')::text AS function`)).rows).toEqual([{ queue: null, function: null }]);
      expect((await owner.query("SELECT count(*)::int AS count FROM integration_runtime.secret_custody")).rows).toEqual([{ count: 0 }]);
      await expect(probeSaasRuntimeDatabase(runtime)).resolves.toBeUndefined();
      await expect(migratePostgres({
        migratorConnectionString: database.migratorConnectionString,
        runtimeConnectionString: database.runtimeConnectionString,
      })).resolves.toEqual([]);
    });
  }, 30_000);

  it("reaches the 0019 reconciliation guard without losing a nonempty original queue, grants or forced RLS", async () => {
    await withBase0015Database(async (database, owner, runtime) => {
      const originalLedger = (await owner.query("SELECT name, checksum FROM integration_runtime_migrations.schema_migrations ORDER BY name")).rows;
      const boundarySql = `SELECT relowner, relacl::text, relrowsecurity, relforcerowsecurity
        FROM pg_class WHERE oid='integration_runtime.trigger_secret_cleanup'::regclass`;
      const originalBoundary = (await owner.query(boundarySql)).rows;
      const functionSql = `SELECT proowner, proacl::text, prosecdef, proconfig
        FROM pg_proc WHERE oid='integration_runtime.is_trigger_secret_referenced(text)'::regprocedure`;
      const originalFunction = (await owner.query(functionSql)).rows;
      const row = { tenant_id: tenantAUserA.tenantId, workspace_id: tenantAUserA.workspaceId,
        subject_user_id: tenantAUserA.subjectUserId, secret_ref: "bao:unknown-original-write-outcome" };
      await withScopedClient(runtime, tenantAUserA, (client) => client.query(
        "INSERT INTO integration_runtime.trigger_secret_cleanup (tenant_id,workspace_id,subject_user_id,secret_ref) VALUES ($1,$2,$3,$4)",
        [row.tenant_id, row.workspace_id, row.subject_user_id, row.secret_ref],
      ));
      await expect(migratePostgres({
        migratorConnectionString: database.migratorConnectionString,
        runtimeConnectionString: database.runtimeConnectionString,
      })).rejects.toThrow("Secret custody cutover requires reconciliation");
      expect((await owner.query("SELECT name, checksum FROM integration_runtime_migrations.schema_migrations WHERE name < '0016' ORDER BY name")).rows).toEqual(originalLedger);
      expect((await owner.query("SELECT name FROM integration_runtime_migrations.schema_migrations WHERE name >= '0016' ORDER BY name")).rows).toEqual([
        { name: "0016_workspace_configuration_control.sql" },
        { name: "0017_project_secret_custody.sql" },
        { name: "0018_managed_project_removal_fence.sql" },
      ]);
      expect((await owner.query(boundarySql)).rows).toEqual(originalBoundary);
      expect((await owner.query(functionSql)).rows).toEqual(originalFunction);
      expect((await owner.query("SELECT to_regclass('integration_runtime.secret_custody')::text AS custody")).rows).toEqual([{ custody: null }]);
      expect(await withScopedClient(runtime, tenantAUserA, async (client) =>
        (await client.query("SELECT * FROM integration_runtime.trigger_secret_cleanup")).rows,
      )).toEqual([row]);
      expect(await withScopedClient(runtime, tenantBUserA, async (client) =>
        (await client.query("SELECT * FROM integration_runtime.trigger_secret_cleanup")).rows,
      )).toEqual([]);
      expect((await runtime.query("SELECT integration_runtime.is_trigger_secret_referenced('unused') AS referenced")).rows).toEqual([{ referenced: false }]);
    });
  }, 30_000);
});

async function withBase0015Database(
  run: (database: PostgresTestDatabase, owner: Pool, runtime: Pool) => Promise<void>,
): Promise<void> {
  if (!testPostgresUrl) throw new Error("TEST_POSTGRES_URL is required");
  const database = await createPostgresTestDatabase(testPostgresUrl);
  const owner = new Pool({ connectionString: database.migratorConnectionString, max: 1 });
  const runtime = new Pool({ connectionString: database.runtimeConnectionString, max: 1 });
  try {
    // Migrations 0001–0015 are unchanged from c33aa709. Apply that SQL and its original
    // grants directly: the current migrator must not manufacture its own upgrade fixture.
    const directory = new URL("./migrations/", import.meta.url);
    const names = (await readdir(directory)).filter((name) => /^\d+.*\.sql$/.test(name) && name < "0016").sort();
    await owner.query(`CREATE SCHEMA integration_runtime_migrations;
      REVOKE ALL ON SCHEMA integration_runtime_migrations FROM PUBLIC;
      CREATE TABLE integration_runtime_migrations.schema_migrations (
        name text PRIMARY KEY, checksum text NOT NULL CHECK (length(checksum)=64),
        applied_at timestamptz NOT NULL DEFAULT now());
      REVOKE ALL ON integration_runtime_migrations.schema_migrations FROM PUBLIC`);
    for (const name of names) {
      const sql = await readFile(new URL(name, directory), "utf8");
      await owner.query("BEGIN");
      try {
        await owner.query(sql);
        await owner.query("INSERT INTO integration_runtime_migrations.schema_migrations (name,checksum) VALUES ($1,$2)", [name, createHash("sha256").update(sql).digest("hex")]);
        await owner.query("COMMIT");
      } catch (error) {
        await owner.query("ROLLBACK");
        throw error;
      }
    }
    const role = `"${database.runtimeRole}"`;
    await owner.query(`REVOKE ALL ON SCHEMA integration_runtime FROM PUBLIC;
      REVOKE CREATE ON SCHEMA integration_runtime FROM ${role};
      GRANT USAGE ON SCHEMA integration_runtime, integration_runtime_migrations TO ${role};
      GRANT SELECT (name,checksum) ON integration_runtime_migrations.schema_migrations TO ${role};
      GRANT SELECT,INSERT,UPDATE,DELETE ON
        integration_runtime.connections,integration_runtime.oauth_states,integration_runtime.run_intents,
        integration_runtime.idempotency_records,integration_runtime.refresh_leases,integration_runtime.transit_files,
        integration_runtime.connection_revocation_receipts,integration_runtime.connection_retirements,
        integration_runtime.connection_requests,integration_runtime.managed_projects,integration_runtime.oauth_sources,
        integration_runtime.saas_cleanup,integration_runtime.managed_account_retirements,
        integration_runtime.trigger_subscriptions,integration_runtime.trigger_source_applications,
        integration_runtime.trigger_secret_cleanup,integration_runtime.trigger_execution_leases TO ${role};
      GRANT SELECT,INSERT,UPDATE ON integration_runtime.action_defaults TO ${role};
      GRANT SELECT,INSERT,UPDATE,DELETE ON integration_runtime.action_grants TO ${role};
      GRANT SELECT,INSERT,DELETE ON integration_runtime.action_policy_audit TO ${role};
      GRANT EXECUTE ON FUNCTION integration_runtime.lock_managed_account(uuid,text),
        integration_runtime.retire_managed_account(uuid,text),
        integration_runtime.is_managed_account_referenced(uuid,text),
        integration_runtime.is_managed_account_cleanup_pending(uuid,text),
        integration_runtime.is_managed_account_retired(uuid,text,bigint),
        integration_runtime.can_cleanup_trigger_connection(uuid),
        integration_runtime.trigger_cleanup_connection(uuid),
        integration_runtime.is_trigger_secret_referenced(text) TO ${role};
      REVOKE ALL ON SEQUENCE integration_runtime.managed_account_fence_seq FROM PUBLIC,${role};
      GRANT USAGE ON SEQUENCE integration_runtime.managed_account_fence_seq TO ${role};
      ALTER DEFAULT PRIVILEGES IN SCHEMA integration_runtime
        REVOKE SELECT,INSERT,UPDATE,DELETE ON TABLES FROM ${role}`);
    await run(database, owner, runtime);
  } finally {
    await Promise.all([owner.end(), runtime.end()]);
    await database.dispose();
  }
}

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
        get actionPolicy(): PostgresActionPolicyStore {
          throw new Error("Action policy is not used by connection request binding");
        },
        forScope(requestScope): never {
          captured.push(requestScope);
          throw new Error("No database in request-binding-only test");
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
    const requestScope = { ...scope("tenant", "workspace", "user"), oauthSessionId: randomUUID() };
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
  private readonly states = new Map<
    string,
    { pkceCodeVerifier?: string; authorizationState?: OAuthAuthorizationState }
  >();
  async put(
    requestScope: Readonly<SaasRequestScope>,
    oauthSessionId: string,
    pkceCodeVerifier: string | undefined,
    _expiresAt: string,
    authorizationState?: OAuthAuthorizationState,
  ): Promise<{ secretRef: string; secretRevision: number }> {
    const secretRef = key(requestScope, oauthSessionId);
    this.states.set(secretRef, { pkceCodeVerifier, authorizationState });
    return { secretRef, secretRevision: 1 };
  }
  async take(
    requestScope: Readonly<SaasRequestScope>,
    oauthSessionId: string,
  ): Promise<{ pkceCodeVerifier?: string; authorizationState?: OAuthAuthorizationState } | undefined> {
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

function scope(tenantLabel: string, workspaceLabel: string, subjectLabel: string): SaasRequestScope {
  const tenantId = fixtureId(tenantLabel);
  const workspaceId = fixtureId(workspaceLabel);
  const subjectUserId = fixtureId(subjectLabel);
  const localConnectionId = fixtureId(`${tenantId}\0${workspaceId}\0${subjectUserId}`);
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
function fixtureId(label: string): string {
  const digest = createHash("sha256").update(label).digest("hex");
  return `${digest.slice(0, 8)}-${digest.slice(8, 12)}-4${digest.slice(13, 16)}-8${digest.slice(17, 20)}-${digest.slice(20, 32)}`;
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

interface PolicyFixture {
  store: PostgresActionPolicyStore;
  target: ActionPolicyUserTarget;
  actor: SaasRequestScope;
  actionIds: string[];
}
function policyFixture(label: string, count = 3): PolicyFixture {
  const service = `policy_${label}`;
  const actionIds = Array.from({ length: count }, (_, index) => `${service}.action_${index}`);
  const catalog = createCatalogStore([
    {
      service,
      displayName: service,
      categories: [],
      authTypes: ["no_auth"],
      auth: [{ type: "no_auth" }],
      actions: actionIds.map((id) => ({
        id,
        service,
        name: id,
        description: id,
        operationType: "read",
        requiredScopes: [],
        providerPermissions: [],
        inputSchema: {},
        outputSchema: {},
      })),
    },
  ]);
  const target: ActionPolicyUserTarget = {
    kind: "user",
    tenantId: randomUUID(),
    workspaceId: randomUUID(),
    userId: randomUUID(),
  };
  return {
    store: new PostgresActionPolicyStore(runtimePool, catalog),
    target,
    actionIds,
    actor: {
      tenantId: target.tenantId,
      workspaceId: target.workspaceId,
      actorUserId: target.userId,
      subjectUserId: target.userId,
      workspaceRole: "member",
      purpose: "action:search",
      permissions: ["action:search"],
    },
  };
}
function policyControl(
  target: ActionPolicyTarget,
  purpose: ActionPolicyControlPrincipal["purpose"] = "action-policy:write",
): ActionPolicyControlPrincipal {
  return {
    subjectKind: "policy_control",
    subject: "verified-operator",
    target,
    purpose,
    permissions: [purpose],
    requestId: randomUUID(),
    requestHash: purpose === "action-policy:write" ? "a".repeat(43) : undefined,
  };
}
function policyService(
  target: ActionPolicyTarget,
  purpose: ActionPolicyServicePrincipal["purpose"],
): ActionPolicyServicePrincipal {
  return {
    subjectKind: "service",
    subject: "lifecycle-coordinator",
    target,
    purpose,
    permissions: [purpose],
    requestId: randomUUID(),
    requestHash: purpose === "action-policy:purge" ? "a".repeat(43) : undefined,
  };
}
