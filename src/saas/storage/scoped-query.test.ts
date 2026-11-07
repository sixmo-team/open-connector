import type { SaasRequestScope } from "../contracts.ts";
import type { PostgresTestDatabase } from "../testing/postgres-test-database.ts";
import type { PoolClient } from "pg";

import { randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createPostgresTestDatabase, postgresTestUrl } from "../testing/postgres-test-database.ts";
import {
  assertLocalConnectionIdentityBackfillComplete,
  backfillLocalConnectionIdentities,
  parseLocalConnectionIdentityMappings,
} from "./connection-identity-backfill.ts";
import { migratePostgres } from "./postgres-migrator.ts";
import { withScopedClient } from "./scoped-query.ts";

const testPostgresUrl = postgresTestUrl();
let adminPool: Pool;
let runtimePool: Pool;
let runtimeConnectionString: string;
let testDatabase: PostgresTestDatabase;
let runtimeRole: string;
const createdConnections: Array<{ scope: SaasRequestScope; id: string }> = [];
const scopeNonce = randomBytes(6).toString("hex");
const sameAlias = `same-${scopeNonce}`;

const tenantAWorkspaceAUserA = scope(`tenant-a-${scopeNonce}`, `workspace-a-${scopeNonce}`, "user-a");
const tenantAWorkspaceAUserB = scope(`tenant-a-${scopeNonce}`, `workspace-a-${scopeNonce}`, "user-b");
const tenantAWorkspaceBUserA = scope(`tenant-a-${scopeNonce}`, `workspace-b-${scopeNonce}`, "user-a");
const tenantBWorkspaceAUserA = scope(`tenant-b-${scopeNonce}`, `workspace-a-${scopeNonce}`, "user-a");

describe.skipIf(!testPostgresUrl)("PostgreSQL transaction-scoped RLS", () => {
  beforeAll(async () => {
    if (!testPostgresUrl) throw new Error("TEST_POSTGRES_URL is required");
    testDatabase = await createPostgresTestDatabase(testPostgresUrl);
    runtimeRole = testDatabase.runtimeRole;
    adminPool = new Pool({ connectionString: testDatabase.adminConnectionString });
    runtimeConnectionString = testDatabase.runtimeConnectionString;
    await migratePostgres({
      migratorConnectionString: testDatabase.migratorConnectionString,
      runtimeConnectionString,
    });
    runtimePool = new Pool({ connectionString: runtimeConnectionString, max: 1 });
  }, 30_000);

  afterAll(async () => {
    try {
      if (runtimePool) {
        for (const created of createdConnections.reverse()) {
          await withScopedClient(runtimePool, created.scope, async (client) => {
            await client.query("DELETE FROM integration_runtime.connections WHERE id = $1", [created.id]);
          });
        }
      }
    } finally {
      await runtimePool?.end();
      await adminPool?.end();
      await testDatabase?.dispose();
    }
  });

  it("forces RLS without runtime ownership, bypass, or plaintext secret columns", async () => {
    const boundary = await adminPool.query<{
      owner: string;
      relrowsecurity: boolean;
      relforcerowsecurity: boolean;
    }>(
      `SELECT pg_get_userbyid(class.relowner) AS owner,
              class.relrowsecurity,
              class.relforcerowsecurity
       FROM pg_class AS class
       JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
       WHERE namespace.nspname = 'integration_runtime' AND class.relkind = 'r'`,
    );
    expect(boundary.rows.length).toBeGreaterThanOrEqual(10);
    expect(boundary.rows.every((row) => row.owner !== runtimeRole)).toBe(true);
    expect(boundary.rows.every((row) => row.relrowsecurity && row.relforcerowsecurity)).toBe(true);

    const role = await adminPool.query<{ rolsuper: boolean; rolbypassrls: boolean }>(
      "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1",
      [runtimeRole],
    );
    expect(role.rows[0]).toEqual({ rolsuper: false, rolbypassrls: false });

    const columns = await adminPool.query<{ column_name: string }>(
      "SELECT column_name FROM information_schema.columns WHERE table_schema = 'integration_runtime'",
    );
    expect(columns.rows.map((row) => row.column_name)).not.toEqual(
      expect.arrayContaining([
        "access_token",
        "refresh_token",
        "api_key",
        "client_secret",
        "pkce_verifier",
        "raw_state",
        "credentials",
      ]),
    );
  });

  it("migrates current and expand-state schemas through backfill and contract", async () => {
    const migrationName = "0006_contract_connection_identity.sql";
    const connectorConnectionId = randomUUID();
    const legacyConnectionId = randomUUID();
    const localConnectionId = randomUUID();
    const auditor = await adminPool.connect();
    try {
      expect(
        await migratePostgres({
          migratorConnectionString: testDatabase.migratorConnectionString,
          runtimeConnectionString,
        }),
      ).toEqual([]);

      await auditor.query("DELETE FROM integration_runtime_migrations.schema_migrations WHERE name = $1", [
        migrationName,
      ]);
      await auditor.query("ALTER TABLE integration_runtime.connections ALTER COLUMN local_connection_id DROP NOT NULL");
      await withScopedClient(runtimePool, tenantAWorkspaceAUserA, async (client) => {
        await client.query(
          `INSERT INTO integration_runtime.connections
            (id, tenant_id, workspace_id, subject_user_id, visibility, service,
             connection_name, auth_type, revision, secret_ref)
           VALUES ($1, $2, $3, $4, 'user', 'gmail', $5, 'oauth2', $6, 'bao:connection')`,
          [
            legacyConnectionId,
            tenantAWorkspaceAUserA.tenantId,
            tenantAWorkspaceAUserA.workspaceId,
            tenantAWorkspaceAUserA.subjectUserId,
            `legacy-${scopeNonce}`,
            randomUUID(),
          ],
        );
        expect(
          (
            await client.query(
              "UPDATE integration_runtime.connections SET display_name = 'old-image-update' WHERE id = $1",
              [legacyConnectionId],
            )
          ).rowCount,
        ).toBe(1);
      });

      await expect(assertLocalConnectionIdentityBackfillComplete(auditor)).rejects.toThrow(
        "Local connection identity backfill is incomplete",
      );
      await expect(
        migratePostgres({
          migratorConnectionString: testDatabase.migratorConnectionString,
          runtimeConnectionString,
        }),
      ).rejects.toThrow(/local_connection_id.*null/i);
      expect(
        (
          await auditor.query("SELECT 1 FROM integration_runtime_migrations.schema_migrations WHERE name = $1", [
            migrationName,
          ])
        ).rows,
      ).toEqual([]);
      expect(
        (
          await auditor.query<{ is_nullable: string }>(
            `SELECT is_nullable
             FROM information_schema.columns
             WHERE table_schema = 'integration_runtime'
               AND table_name = 'connections'
               AND column_name = 'local_connection_id'`,
          )
        ).rows,
      ).toEqual([{ is_nullable: "YES" }]);

      expect(
        await backfillLocalConnectionIdentities(
          runtimePool,
          adminPool,
          parseLocalConnectionIdentityMappings([
            {
              tenantId: tenantAWorkspaceAUserA.tenantId,
              workspaceId: tenantAWorkspaceAUserA.workspaceId,
              subjectUserId: tenantAWorkspaceAUserA.subjectUserId,
              connectorConnectionId: legacyConnectionId,
              localConnectionId,
            },
          ]),
        ),
      ).toBe(1);
      await expect(assertLocalConnectionIdentityBackfillComplete(auditor)).resolves.toBeUndefined();
      await expect(
        migratePostgres({
          migratorConnectionString: testDatabase.migratorConnectionString,
          runtimeConnectionString,
        }),
      ).resolves.toEqual([migrationName]);

      const column = await auditor.query<{ is_nullable: string }>(
        `SELECT is_nullable
         FROM information_schema.columns
         WHERE table_schema = 'integration_runtime'
           AND table_name = 'connections'
           AND column_name = 'local_connection_id'`,
      );
      expect(column.rows).toEqual([{ is_nullable: "NO" }]);
      await expect(
        withScopedClient(runtimePool, tenantAWorkspaceAUserA, (client) =>
          client.query("UPDATE integration_runtime.connections SET local_connection_id = $1 WHERE id = $2", [
            randomUUID(),
            legacyConnectionId,
          ]),
        ),
      ).rejects.toThrow(/lineage is immutable/);
      await expect(
        withScopedClient(runtimePool, tenantAWorkspaceAUserA, (client) =>
          client.query(
            `INSERT INTO integration_runtime.connections
              (id, tenant_id, workspace_id, subject_user_id, visibility, service,
               connection_name, auth_type, revision, secret_ref)
             VALUES ($1, $2, $3, $4, 'user', 'gmail', $5, 'oauth2', $6, 'bao:connection')`,
            [
              connectorConnectionId,
              tenantAWorkspaceAUserA.tenantId,
              tenantAWorkspaceAUserA.workspaceId,
              tenantAWorkspaceAUserA.subjectUserId,
              `post-contract-${scopeNonce}`,
              randomUUID(),
            ],
          ),
        ),
      ).rejects.toThrow();
    } finally {
      try {
        await withScopedClient(runtimePool, tenantAWorkspaceAUserA, (client) =>
          client.query("DELETE FROM integration_runtime.connections WHERE id = ANY($1::uuid[])", [
            [connectorConnectionId, legacyConnectionId],
          ]),
        );
        await auditor.query(
          "ALTER TABLE integration_runtime.connections ALTER COLUMN local_connection_id SET NOT NULL",
        );
      } finally {
        auditor.release();
      }
      await migratePostgres({
        migratorConnectionString: testDatabase.migratorConnectionString,
        runtimeConnectionString,
      });
    }
  });

  it("cleans stale runtime default table privileges", async () => {
    const migratorPool = new Pool({ connectionString: testDatabase.migratorConnectionString, max: 1 });
    await migratorPool.query(
      `ALTER DEFAULT PRIVILEGES IN SCHEMA integration_runtime
       GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "${runtimeRole}"`,
    );
    try {
      await migratePostgres({
        migratorConnectionString: testDatabase.migratorConnectionString,
        runtimeConnectionString,
      });
      const stalePrivileges = await migratorPool.query<{ privilege_type: string }>(
        `SELECT acl.privilege_type
         FROM pg_default_acl AS defaults
         JOIN pg_namespace AS namespace ON namespace.oid = defaults.defaclnamespace
         CROSS JOIN LATERAL aclexplode(defaults.defaclacl) AS acl
         JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
         WHERE defaults.defaclrole = (SELECT oid FROM pg_roles WHERE rolname = current_user)
           AND namespace.nspname = 'integration_runtime'
           AND defaults.defaclobjtype = 'r'
           AND grantee.rolname = $1
           AND acl.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')`,
        [runtimeRole],
      );
      expect(stalePrivileges.rows).toEqual([]);
    } finally {
      await migratorPool.query(
        `ALTER DEFAULT PRIVILEGES IN SCHEMA integration_runtime
         REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM "${runtimeRole}"`,
      );
      await migratorPool.end();
    }
  });

  it("rejects a runtime role that can assume the migrator role", async () => {
    const memberRole = `integration_member_test_${process.pid}_${randomBytes(4).toString("hex")}`;
    const memberPassword = randomBytes(24).toString("hex");
    const migratorRole = testDatabase.migratorRole;
    const memberUrl = new URL(testDatabase.adminConnectionString);
    memberUrl.username = memberRole;
    memberUrl.password = memberPassword;
    await adminPool.query(`CREATE ROLE "${memberRole}" LOGIN PASSWORD '${memberPassword}'`);
    await adminPool.query(`GRANT "${migratorRole.replaceAll('"', '""')}" TO "${memberRole}"`);
    try {
      await expect(
        migratePostgres({
          migratorConnectionString: testDatabase.migratorConnectionString,
          runtimeConnectionString: memberUrl.href,
        }),
      ).rejects.toThrow("must not be a member of the migrator role");
    } finally {
      await adminPool.query(`REVOKE "${migratorRole.replaceAll('"', '""')}" FROM "${memberRole}"`);
      await adminPool.query(`DROP OWNED BY "${memberRole}"`);
      await adminPool.query(`DROP ROLE "${memberRole}"`);
    }
  });

  it("does not record a migration that exposes a relation without forced RLS", async () => {
    if (!testPostgresUrl) throw new Error("TEST_POSTGRES_URL is required");
    const directory = await mkdtemp(join(tmpdir(), "open-connector-migration-"));
    const name = `9999_invalid_${scopeNonce}.sql`;
    await writeFile(
      join(directory, name),
      `CREATE TABLE integration_runtime.invalid_boundary (id text);
       GRANT SELECT ON integration_runtime.invalid_boundary TO "${runtimeRole}";\n`,
    );
    try {
      await expect(
        migratePostgres({
          migratorConnectionString: testDatabase.migratorConnectionString,
          runtimeConnectionString,
          migrationsDirectory: directory,
        }),
      ).rejects.toThrow("RLS must be enabled and forced");
      expect(
        (
          await adminPool.query("SELECT 1 FROM integration_runtime_migrations.schema_migrations WHERE name = $1", [
            name,
          ])
        ).rows,
      ).toEqual([]);
      expect(
        (await adminPool.query("SELECT to_regclass('integration_runtime.invalid_boundary')::text AS relation")).rows[0],
      ).toEqual({ relation: null });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("isolates identical aliases across tenants and workspaces for select, update, and delete", async () => {
    const tenantAId = randomUUID();
    const workspaceBId = randomUUID();
    const tenantBId = randomUUID();
    await insertConnection(runtimePool, tenantAWorkspaceAUserA, tenantAId, sameAlias, "user");
    await insertConnection(runtimePool, tenantAWorkspaceBUserA, workspaceBId, sameAlias, "user");
    await insertConnection(runtimePool, tenantBWorkspaceAUserA, tenantBId, sameAlias, "user");

    await withScopedClient(runtimePool, tenantAWorkspaceAUserA, async (client) => {
      expect(
        (
          await client.query<{ id: string }>(
            "SELECT id FROM integration_runtime.connections WHERE connection_name = $1",
            [sameAlias],
          )
        ).rows,
      ).toEqual([{ id: tenantAId }]);
      expect(
        (
          await client.query("UPDATE integration_runtime.connections SET display_name = 'leak' WHERE id = $1", [
            tenantBId,
          ])
        ).rowCount,
      ).toBe(0);
      expect(
        (
          await client.query("UPDATE integration_runtime.connections SET display_name = 'leak' WHERE id = $1", [
            workspaceBId,
          ])
        ).rowCount,
      ).toBe(0);
      expect(
        (await client.query("DELETE FROM integration_runtime.connections WHERE id = $1", [tenantBId])).rowCount,
      ).toBe(0);
      expect(
        (await client.query("DELETE FROM integration_runtime.connections WHERE id = $1", [workspaceBId])).rowCount,
      ).toBe(0);
    });

    await withScopedClient(runtimePool, tenantBWorkspaceAUserA, async (client) => {
      expect(
        (await client.query("SELECT id FROM integration_runtime.connections WHERE id = $1", [tenantBId])).rows,
      ).toEqual([{ id: tenantBId }]);
    });

    await withScopedClient(runtimePool, tenantAWorkspaceBUserA, async (client) => {
      expect(
        (await client.query("SELECT id FROM integration_runtime.connections WHERE id = $1", [workspaceBId])).rows,
      ).toEqual([{ id: workspaceBId }]);
    });
  });

  it("allows workspace reads while keeping private and shared writes owner-only", async () => {
    const privateId = randomUUID();
    const sharedId = randomUUID();
    await insertConnection(runtimePool, tenantAWorkspaceAUserA, privateId, "private", "user");
    await insertConnection(runtimePool, tenantAWorkspaceAUserA, sharedId, "shared", "workspace");

    await withScopedClient(runtimePool, tenantAWorkspaceAUserB, async (client) => {
      expect(
        (
          await client.query<{ id: string }>(
            "SELECT id FROM integration_runtime.connections WHERE id = ANY($1::uuid[])",
            [[privateId, sharedId]],
          )
        ).rows,
      ).toEqual([{ id: sharedId }]);
      expect(
        (
          await client.query(
            "UPDATE integration_runtime.connections SET display_name = 'not-owner' WHERE id = ANY($1::uuid[])",
            [[privateId, sharedId]],
          )
        ).rowCount,
      ).toBe(0);
      expect(
        (
          await client.query("DELETE FROM integration_runtime.connections WHERE id = ANY($1::uuid[])", [
            [privateId, sharedId],
          ])
        ).rowCount,
      ).toBe(0);
    });

    await expect(
      withScopedClient(runtimePool, tenantAWorkspaceAUserB, (client) =>
        client.query(
          `INSERT INTO integration_runtime.refresh_leases
            (tenant_id, workspace_id, subject_user_id, visibility, connection_id, lease_holder, expires_at)
           VALUES ($1, $2, $3, 'workspace', $4, 'forged', now() + interval '1 minute')`,
          [
            tenantAWorkspaceAUserB.tenantId,
            tenantAWorkspaceAUserB.workspaceId,
            tenantAWorkspaceAUserB.subjectUserId,
            privateId,
          ],
        ),
      ),
    ).rejects.toThrow();

    await withScopedClient(runtimePool, tenantAWorkspaceAUserA, async (client) => {
      expect(
        (
          await client.query("UPDATE integration_runtime.connections SET display_name = 'owner' WHERE id = $1", [
            sharedId,
          ])
        ).rowCount,
      ).toBe(1);
    });

    await withScopedClient(runtimePool, tenantAWorkspaceAUserA, (client) =>
      client.query("UPDATE integration_runtime.connections SET visibility = 'user' WHERE id = $1", [sharedId]),
    );
    await withScopedClient(runtimePool, tenantAWorkspaceAUserB, async (client) => {
      expect(
        (await client.query("SELECT id FROM integration_runtime.connections WHERE id = $1", [sharedId])).rows,
      ).toEqual([]);
    });
  });

  it("rolls back callback failures and clears local scope before pool reuse", async () => {
    const rolledBackId = randomUUID();
    await expect(
      withScopedClient(runtimePool, tenantAWorkspaceAUserA, async (client) => {
        await insertConnectionRow(client, tenantAWorkspaceAUserA, rolledBackId, "rolled-back", "user");
        throw new Error("callback failed");
      }),
    ).rejects.toThrow("callback failed");

    await withScopedClient(runtimePool, tenantAWorkspaceAUserA, async (client) => {
      expect(
        (await client.query("SELECT id FROM integration_runtime.connections WHERE id = $1", [rolledBackId])).rows,
      ).toEqual([]);
    });

    const unscoped = await runtimePool.connect();
    try {
      const settings = await unscoped.query(`SELECT
        NULLIF(current_setting('integration.tenant_id', true), '') AS tenant_id,
        NULLIF(current_setting('integration.workspace_id', true), '') AS workspace_id,
        NULLIF(current_setting('integration.subject_user_id', true), '') AS subject_user_id,
        NULLIF(current_setting('integration.actor_user_id', true), '') AS actor_user_id,
        NULLIF(current_setting('integration.purpose', true), '') AS purpose,
        NULLIF(current_setting('integration.principal_kind', true), '') AS principal_kind,
        NULLIF(current_setting('integration.policy_target_kind', true), '') AS target_kind`);
      expect(settings.rows[0]).toEqual({
        tenant_id: null,
        workspace_id: null,
        subject_user_id: null,
        actor_user_id: null,
        purpose: null,
        principal_kind: null,
        target_kind: null,
      });
      expect((await unscoped.query("SELECT id FROM integration_runtime.connections")).rows).toEqual([]);
    } finally {
      unscoped.release();
    }
  });
});

async function insertConnection(
  pool: Pool,
  requestScope: SaasRequestScope,
  id: string,
  connectionName: string,
  visibility: "user" | "workspace",
): Promise<void> {
  await withScopedClient(pool, requestScope, (client) =>
    insertConnectionRow(client, requestScope, id, connectionName, visibility),
  );
  createdConnections.push({ scope: requestScope, id });
}

async function insertConnectionRow(
  client: PoolClient,
  requestScope: SaasRequestScope,
  id: string,
  connectionName: string,
  visibility: "user" | "workspace",
): Promise<void> {
  await client.query(
    `INSERT INTO integration_runtime.connections
      (id, tenant_id, workspace_id, subject_user_id, local_connection_id, visibility, service,
       connection_name, auth_type, revision, secret_ref)
     VALUES ($1, $2, $3, $4, $5, $6, 'gmail', $7, 'oauth2', $8, 'bao:connection')`,
    [
      id,
      requestScope.tenantId,
      requestScope.workspaceId,
      requestScope.subjectUserId,
      randomUUID(),
      visibility,
      connectionName,
      randomUUID(),
    ],
  );
}

function scope(tenantId: string, workspaceId: string, subjectUserId: string): SaasRequestScope {
  return {
    tenantId,
    workspaceId,
    actorUserId: subjectUserId,
    subjectUserId,
    workspaceRole: "member",
    purpose: "connection:write",
    permissions: [],
  };
}
