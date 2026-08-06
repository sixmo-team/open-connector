import { randomBytes } from "node:crypto";
import { Client } from "pg";

export interface PostgresTestDatabase {
  migratorRole: string;
  runtimeRole: string;
  adminConnectionString: string;
  migratorConnectionString: string;
  runtimeConnectionString: string;
  dispose(): Promise<void>;
}
export function postgresTestUrl(): string | undefined {
  const value = process.env.TEST_POSTGRES_URL?.trim();
  if (process.env.RLS_TEST_GATE === "1" && !value) {
    throw new Error("TEST_POSTGRES_URL is required for the RLS test gate");
  }
  return value || undefined;
}

/** Creates one database and distinct owner/runtime roles for a real PostgreSQL test suite. */
export async function createPostgresTestDatabase(baseConnectionString: string): Promise<PostgresTestDatabase> {
  const suffix = `${process.pid}_${randomBytes(6).toString("hex")}`;
  const database = `oc_test_${suffix}`;
  const migratorRole = `oc_migrator_${suffix}`;
  const runtimeRole = `oc_runtime_${suffix}`;
  const migratorPassword = randomBytes(24).toString("hex");
  const runtimePassword = randomBytes(24).toString("hex");
  const base = new Client({ connectionString: baseConnectionString });
  let databaseCreated = false;
  let migratorCreated = false;
  let runtimeCreated = false;

  await base.connect();
  try {
    await base.query(`CREATE ROLE ${quoteIdentifier(migratorRole)} LOGIN PASSWORD '${migratorPassword}'`);
    migratorCreated = true;
    await base.query(`CREATE ROLE ${quoteIdentifier(runtimeRole)} LOGIN PASSWORD '${runtimePassword}'`);
    runtimeCreated = true;
    await base.query(`CREATE DATABASE ${quoteIdentifier(database)} OWNER ${quoteIdentifier(migratorRole)}`);
    databaseCreated = true;
  } catch (error) {
    await cleanup(base, database, migratorRole, runtimeRole, databaseCreated, migratorCreated, runtimeCreated);
    throw error;
  } finally {
    await base.end();
  }

  let disposed = false;
  return {
    migratorRole,
    runtimeRole,
    adminConnectionString: connectionString(baseConnectionString, database),
    migratorConnectionString: connectionString(baseConnectionString, database, migratorRole, migratorPassword),
    runtimeConnectionString: connectionString(baseConnectionString, database, runtimeRole, runtimePassword),
    async dispose(): Promise<void> {
      if (disposed) return;
      disposed = true;
      const client = new Client({ connectionString: baseConnectionString });
      await client.connect();
      try {
        await cleanup(client, database, migratorRole, runtimeRole, true, true, true);
      } finally {
        await client.end();
      }
    },
  };
}

function connectionString(base: string, database: string, username?: string, password?: string): string {
  const url = new URL(base);
  url.pathname = `/${database}`;
  if (username) url.username = username;
  if (password) url.password = password;
  return url.href;
}

async function cleanup(
  client: Client,
  database: string,
  migratorRole: string,
  runtimeRole: string,
  databaseCreated: boolean,
  migratorCreated: boolean,
  runtimeCreated: boolean,
): Promise<void> {
  if (databaseCreated) {
    await client.query(
      "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
      [database],
    );
    await client.query(`DROP DATABASE IF EXISTS ${quoteIdentifier(database)}`);
  }
  if (runtimeCreated) {
    await client.query(`DROP OWNED BY ${quoteIdentifier(runtimeRole)}`);
    await client.query(`DROP ROLE IF EXISTS ${quoteIdentifier(runtimeRole)}`);
  }
  if (migratorCreated) {
    await client.query(`DROP OWNED BY ${quoteIdentifier(migratorRole)}`);
    await client.query(`DROP ROLE IF EXISTS ${quoteIdentifier(migratorRole)}`);
  }
}

function quoteIdentifier(value: string): string {
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(value)) throw new Error(`Unsafe PostgreSQL test identifier: ${value}`);
  return `"${value}"`;
}
