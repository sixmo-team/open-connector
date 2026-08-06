import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Client } from "pg";

const MIGRATION_LOCK_ID = "7234017283807667";
const baselineRuntimeTables = [
  "connections",
  "oauth_states",
  "run_intents",
  "idempotency_records",
  "refresh_leases",
  "transit_files",
] as const;
const runtimeTables = [...baselineRuntimeTables, "connection_revocation_receipts"] as const;

export interface PostgresMigrationOptions {
  migratorConnectionString: string;
  runtimeConnectionString: string;
  migrationsDirectory?: string | URL;
}

interface DatabaseRole {
  rolname: string;
  rolsuper: boolean;
  rolbypassrls: boolean;
  rolcreaterole: boolean;
}

/** Apply SaaS migrations as an owner role and grant only DML to the distinct runtime role. */
export async function migratePostgres(options: PostgresMigrationOptions): Promise<string[]> {
  if (!options.migratorConnectionString || !options.runtimeConnectionString) {
    throw new Error("Separate migrator and runtime PostgreSQL URLs are required");
  }

  const migrator = new Client({ connectionString: options.migratorConnectionString });
  const runtime = new Client({ connectionString: options.runtimeConnectionString });

  let locked = false;
  try {
    await Promise.all([migrator.connect(), runtime.connect()]);
    const [migratorRoleResult, runtimeRoleResult] = await Promise.all([
      migrator.query<DatabaseRole>(
        "SELECT rolname, rolsuper, rolbypassrls, rolcreaterole FROM pg_roles WHERE rolname = current_user",
      ),
      runtime.query<DatabaseRole>(
        "SELECT rolname, rolsuper, rolbypassrls, rolcreaterole FROM pg_roles WHERE rolname = current_user",
      ),
    ]);
    const migratorRole = migratorRoleResult.rows[0];
    const runtimeRole = runtimeRoleResult.rows[0];
    if (!migratorRole || !runtimeRole) {
      throw new Error("Could not resolve PostgreSQL roles");
    }
    if (migratorRole.rolname === runtimeRole.rolname) {
      throw new Error("The PostgreSQL migrator and runtime roles must be distinct");
    }
    if (runtimeRole.rolsuper || runtimeRole.rolbypassrls || runtimeRole.rolcreaterole) {
      throw new Error("The PostgreSQL runtime role must not be superuser, BYPASSRLS, or CREATEROLE");
    }

    const migratorMembership = await migrator.query<{ is_member: boolean }>(
      "SELECT pg_has_role($1, $2, 'MEMBER') AS is_member",
      [runtimeRole.rolname, migratorRole.rolname],
    );
    if (migratorMembership.rows[0]?.is_member) {
      throw new Error("The PostgreSQL runtime role must not be a member of the migrator role");
    }

    const privilegedMembership = await migrator.query<{ privileged_role: string }>(
      `SELECT role.rolname AS privileged_role
       FROM pg_roles AS role
       WHERE (role.rolsuper OR role.rolbypassrls OR role.rolcreaterole)
         AND pg_has_role($1, role.oid, 'MEMBER')
       LIMIT 1`,
      [runtimeRole.rolname],
    );
    if (privilegedMembership.rowCount) {
      throw new Error(
        `The PostgreSQL runtime role inherits privileged role ${privilegedMembership.rows[0]?.privileged_role}`,
      );
    }

    await migrator.query("SELECT pg_advisory_lock($1::bigint)", [MIGRATION_LOCK_ID]);
    locked = true;
    await assertExistingSaasOwners(migrator, migratorRole.rolname);
    await assertRuntimeCannotAssumeOwners(migrator, runtimeRole.rolname, migratorRole.rolname);
    await ensureMigrationLedger(migrator);
    await assertExistingSaasOwners(migrator, migratorRole.rolname);
    await assertRuntimeCannotAssumeOwners(migrator, runtimeRole.rolname, migratorRole.rolname);

    const directory = options.migrationsDirectory ?? new URL("./migrations/", import.meta.url);
    const entries = await readdir(directory, { withFileTypes: true });
    const names = entries
      .filter((entry) => entry.isFile() && /^\d+.*\.sql$/.test(entry.name))
      .map((entry) => entry.name)
      .sort();
    const applied: string[] = [];
    const runtimeRoleIdentifier = quoteIdentifier(runtimeRole.rolname);
    const migratorRoleIdentifier = quoteIdentifier(migratorRole.rolname);

    for (const name of names) {
      const sql = await readFile(new URL(name, directoryUrl(directory)), "utf8");
      const checksum = createHash("sha256").update(sql).digest("hex");
      const existing = await migrator.query<{ checksum: string }>(
        "SELECT checksum FROM integration_runtime_migrations.schema_migrations WHERE name = $1",
        [name],
      );
      if (existing.rows[0]) {
        if (existing.rows[0].checksum !== checksum) {
          throw new Error(`Applied migration ${name} has changed`);
        }
        continue;
      }

      await migrator.query("BEGIN");
      try {
        await migrator.query(sql);
        await verifyRuntimeBoundary(migrator, migratorRole.rolname, runtimeRole.rolname);
        await grantRuntimeAccess(migrator, runtimeRoleIdentifier, migratorRoleIdentifier);
        await verifyRuntimeBoundary(migrator, migratorRole.rolname, runtimeRole.rolname);
        await migrator.query(
          "INSERT INTO integration_runtime_migrations.schema_migrations (name, checksum) VALUES ($1, $2)",
          [name, checksum],
        );
        await migrator.query("COMMIT");
        applied.push(name);
      } catch (error) {
        await migrator.query("ROLLBACK");
        throw error;
      }
    }

    await verifyRuntimeBoundary(migrator, migratorRole.rolname, runtimeRole.rolname, runtimeTables);
    await grantRuntimeAccess(migrator, runtimeRoleIdentifier, migratorRoleIdentifier);
    await verifyRuntimeBoundary(migrator, migratorRole.rolname, runtimeRole.rolname, runtimeTables);
    return applied;
  } finally {
    if (locked) {
      await migrator.query("SELECT pg_advisory_unlock($1::bigint)", [MIGRATION_LOCK_ID]).catch(() => undefined);
    }
    await Promise.allSettled([migrator.end(), runtime.end()]);
  }
}

async function ensureMigrationLedger(client: Client): Promise<void> {
  await client.query("BEGIN");
  try {
    await client.query(`
      CREATE SCHEMA IF NOT EXISTS integration_runtime_migrations;
      REVOKE ALL ON SCHEMA integration_runtime_migrations FROM PUBLIC;
      CREATE TABLE IF NOT EXISTS integration_runtime_migrations.schema_migrations (
        name text PRIMARY KEY,
        checksum text NOT NULL CHECK (length(checksum) = 64),
        applied_at timestamptz NOT NULL DEFAULT now()
      );
      REVOKE ALL ON integration_runtime_migrations.schema_migrations FROM PUBLIC;
    `);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  }
}

async function grantRuntimeAccess(
  client: Client,
  runtimeRoleIdentifier: string,
  migratorRoleIdentifier: string,
): Promise<void> {
  const available = await client.query<{ relname: string }>(
    `SELECT class.relname
     FROM pg_class AS class
     JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
     WHERE namespace.nspname = 'integration_runtime'
       AND class.relkind IN ('r', 'p')
       AND class.relname = ANY($1::text[])`,
    [runtimeTables],
  );
  const tables = available.rows.map(({ relname }) => `integration_runtime.${quoteIdentifier(relname)}`).join(", ");
  await client.query(`
    REVOKE ALL ON SCHEMA integration_runtime FROM PUBLIC;
    REVOKE CREATE ON SCHEMA integration_runtime FROM ${runtimeRoleIdentifier};
    GRANT USAGE ON SCHEMA integration_runtime TO ${runtimeRoleIdentifier};
    GRANT SELECT, INSERT, UPDATE, DELETE ON ${tables} TO ${runtimeRoleIdentifier};
    REVOKE ALL ON SCHEMA integration_runtime_migrations FROM PUBLIC;
    GRANT USAGE ON SCHEMA integration_runtime_migrations TO ${runtimeRoleIdentifier};
    REVOKE ALL ON integration_runtime_migrations.schema_migrations FROM ${runtimeRoleIdentifier};
    GRANT SELECT (name, checksum) ON integration_runtime_migrations.schema_migrations TO ${runtimeRoleIdentifier};
    ALTER DEFAULT PRIVILEGES FOR ROLE ${migratorRoleIdentifier} IN SCHEMA integration_runtime
      REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM ${runtimeRoleIdentifier};
  `);
}

async function verifyRuntimeBoundary(
  client: Client,
  migratorRole: string,
  runtimeRole: string,
  requiredTables: readonly string[] = baselineRuntimeTables,
): Promise<void> {
  await assertExistingSaasOwners(client, migratorRole);
  const tables = await client.query<{
    relname: string;
    owner_name: string;
    relrowsecurity: boolean;
    relforcerowsecurity: boolean;
  }>(
    `SELECT class.relname,
            pg_get_userbyid(class.relowner) AS owner_name,
            class.relrowsecurity,
            class.relforcerowsecurity
     FROM pg_class AS class
     JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
     WHERE namespace.nspname = 'integration_runtime'
       AND class.relkind IN ('r', 'p')`,
  );
  const byName = new Map(tables.rows.map((table) => [table.relname, table]));
  for (const table of tables.rows) {
    if (!table.relrowsecurity || !table.relforcerowsecurity) {
      throw new Error(`RLS must be enabled and forced on integration_runtime.${table.relname}`);
    }
  }

  for (const name of requiredTables) {
    const table = byName.get(name);
    if (!table) {
      throw new Error(`Runtime migration did not create integration_runtime.${name}`);
    }
    if (table.owner_name !== migratorRole || table.owner_name === runtimeRole) {
      throw new Error(`Runtime role must not own integration_runtime.${name}`);
    }
    if (!table.relrowsecurity || !table.relforcerowsecurity) {
      throw new Error(`RLS must be enabled and forced on integration_runtime.${name}`);
    }
  }

  await assertRuntimeCannotAssumeOwners(client, runtimeRole, migratorRole);
  const unsafeAccess = await client.query<{ relname: string }>(
    `SELECT class.relname
     FROM pg_class AS class
     JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
     WHERE namespace.nspname = 'integration_runtime'
       AND class.relkind IN ('r', 'p', 'v', 'm', 'f')
       AND (
         has_table_privilege($1, class.oid, 'SELECT')
         OR has_table_privilege($1, class.oid, 'INSERT')
         OR has_table_privilege($1, class.oid, 'UPDATE')
         OR has_table_privilege($1, class.oid, 'DELETE')
       )
       AND (
         NOT (class.relname = ANY($2::text[]))
         OR class.relkind NOT IN ('r', 'p')
         OR NOT class.relrowsecurity
         OR NOT class.relforcerowsecurity
       )
     LIMIT 1`,
    [runtimeRole, runtimeTables],
  );
  if (unsafeAccess.rows[0]) {
    throw new Error(`Runtime role can access unapproved relation ${unsafeAccess.rows[0].relname}`);
  }

  const schemaOwners = await client.query<{ nspname: string; owner_name: string }>(
    `SELECT nspname, pg_get_userbyid(nspowner) AS owner_name
     FROM pg_namespace
     WHERE nspname IN ('integration_runtime', 'integration_runtime_migrations')`,
  );
  for (const schema of schemaOwners.rows) {
    if (schema.owner_name !== migratorRole || schema.owner_name === runtimeRole) {
      throw new Error(`Migrator role must own schema ${schema.nspname}`);
    }
  }

  const runtimeCreate = await client.query<{ can_create: boolean }>(
    "SELECT has_schema_privilege($1, 'integration_runtime', 'CREATE') AS can_create",
    [runtimeRole],
  );
  if (runtimeCreate.rows[0]?.can_create) {
    throw new Error("Runtime role must not be able to create integration_runtime tables");
  }

  const ledgerOwner = await client.query<{ owner_name: string }>(
    `SELECT pg_get_userbyid(class.relowner) AS owner_name
     FROM pg_class AS class
     JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
     WHERE namespace.nspname = 'integration_runtime_migrations'
       AND class.relname = 'schema_migrations'
       AND class.relkind = 'r'`,
  );
  if (ledgerOwner.rows[0]?.owner_name !== migratorRole) {
    throw new Error("Migrator role must own the SaaS migration ledger");
  }
}

async function assertExistingSaasOwners(client: Client, migratorRole: string): Promise<void> {
  const unexpectedOwner = await client.query<{ object_name: string; owner_name: string }>(
    `SELECT namespace.nspname AS object_name, pg_get_userbyid(namespace.nspowner) AS owner_name
     FROM pg_namespace AS namespace
     WHERE namespace.nspname IN ('integration_runtime', 'integration_runtime_migrations')
       AND pg_get_userbyid(namespace.nspowner) <> $1
     UNION ALL
     SELECT namespace.nspname || '.' || class.relname AS object_name,
            pg_get_userbyid(class.relowner) AS owner_name
     FROM pg_class AS class
     JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
     WHERE namespace.nspname IN ('integration_runtime', 'integration_runtime_migrations')
       AND class.relkind IN ('r', 'p', 'v', 'm', 'f')
       AND pg_get_userbyid(class.relowner) <> $1
     LIMIT 1`,
    [migratorRole],
  );
  if (unexpectedOwner.rows[0]) {
    throw new Error(
      `Migrator role must own ${unexpectedOwner.rows[0].object_name}; found ${unexpectedOwner.rows[0].owner_name}`,
    );
  }
}

async function assertRuntimeCannotAssumeOwners(
  client: Client,
  runtimeRole: string,
  migratorRole: string,
): Promise<void> {
  const membership = await client.query<{ owner_name: string }>(
    `SELECT owners.owner_name
     FROM (
       SELECT $2::text AS owner_name
       UNION
       SELECT pg_get_userbyid(namespace.nspowner)
       FROM pg_namespace AS namespace
       WHERE namespace.nspname IN ('integration_runtime', 'integration_runtime_migrations')
       UNION
       SELECT pg_get_userbyid(class.relowner)
       FROM pg_class AS class
       JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
       WHERE namespace.nspname IN ('integration_runtime', 'integration_runtime_migrations')
         AND class.relkind IN ('r', 'p', 'v', 'm', 'f')
     ) AS owners
     WHERE pg_has_role($1, owners.owner_name, 'MEMBER')
     LIMIT 1`,
    [runtimeRole, migratorRole],
  );
  if (membership.rows[0]) {
    throw new Error(`Runtime role must not be a member of SaaS owner role ${membership.rows[0].owner_name}`);
  }
}

function quoteIdentifier(identifier: string): string {
  return `"${identifier.replaceAll('"', '""')}"`;
}

function directoryUrl(directory: string | URL): URL {
  if (directory instanceof URL) {
    return directory.href.endsWith("/") ? directory : new URL(`${directory.href}/`);
  }
  return pathToFileURL(`${resolve(directory)}/`);
}
