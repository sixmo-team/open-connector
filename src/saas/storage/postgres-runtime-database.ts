import type { IConnectionStore, StoredConnection } from "../../connection-service.ts";
import type { IOAuthStateStore } from "../../oauth/oauth-flow-service.ts";
import type { ExecutionJournal, SaasActionIdempotencyStore } from "../actions/saas-action-runner.ts";
import type {
  ProviderCredentialRevocationOutcome,
  SaasProviderCredentialRevoker,
} from "../connections/provider-credential-revoker.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { SeaweedFsTransitFileOptions } from "../files/seaweedfs-transit-files.ts";
import type { ITransitFileService } from "../files/transit-file-store.ts";
import type { ConnectionSecretStore, SafeStoredConnection } from "./postgres-connection-store.ts";
import type { OAuthStateSecretStore } from "./postgres-oauth-state-store.ts";
import type { RefreshLeaseStore } from "./postgres-refresh-lease-store.ts";
import type { TransitFileMetadataStore } from "./postgres-transit-file-store.ts";
import type { IRunLogStore } from "./run-store.ts";
import type { Pool } from "pg";

import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { SeaweedFsTransitFileService } from "../files/seaweedfs-transit-files.ts";
import { ScopedLifecycleService } from "../lifecycle/scoped-lifecycle-service.ts";
import { PostgresRefreshCoordinator } from "../oauth/postgres-refresh-coordinator.ts";
import { PostgresConnectionStore } from "./postgres-connection-store.ts";
import { PostgresIdempotencyStore } from "./postgres-idempotency-store.ts";
import { PostgresOAuthStateStore } from "./postgres-oauth-state-store.ts";
import { PostgresRefreshLeaseStore } from "./postgres-refresh-lease-store.ts";
import { PostgresRunStore } from "./postgres-run-store.ts";
import { PostgresTransitFileStore } from "./postgres-transit-file-store.ts";

const requiredRuntimeTables = [
  "connections",
  "oauth_states",
  "run_intents",
  "idempotency_records",
  "refresh_leases",
  "transit_files",
  "connection_revocation_receipts",
] as const;

/** Fail startup unless the connected PostgreSQL role is constrained by forced RLS. */
export async function probeSaasRuntimeDatabase(pool: Pool): Promise<void> {
  const roleResult = await pool.query<{
    rolname: string;
    rolsuper: boolean;
    rolbypassrls: boolean;
    rolcreaterole: boolean;
  }>("SELECT rolname, rolsuper, rolbypassrls, rolcreaterole FROM pg_roles WHERE rolname = current_user");
  const role = roleResult.rows[0];
  if (!role || role.rolsuper || role.rolbypassrls || role.rolcreaterole) {
    throw new Error("The SaaS PostgreSQL runtime role is privileged or unavailable");
  }

  const privilegedMembership = await pool.query(
    `SELECT 1
     FROM pg_roles AS inherited
     WHERE inherited.rolname <> current_user
       AND (inherited.rolsuper OR inherited.rolbypassrls OR inherited.rolcreaterole)
       AND pg_has_role(current_user, inherited.oid, 'MEMBER')
     LIMIT 1`,
  );
  if (privilegedMembership.rowCount) {
    throw new Error("The SaaS PostgreSQL runtime role inherits a privileged role");
  }

  const tableResult = await pool.query<{
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
       AND class.relname = ANY($1::text[])
       AND class.relkind IN ('r', 'p')`,
    [requiredRuntimeTables],
  );
  const tables = new Map(tableResult.rows.map((table) => [table.relname, table]));
  for (const name of requiredRuntimeTables) {
    const table = tables.get(name);
    if (!table || table.owner_name === role.rolname || !table.relrowsecurity || !table.relforcerowsecurity) {
      throw new Error(`Unsafe SaaS PostgreSQL runtime boundary for integration_runtime.${name}`);
    }
  }

  const identityColumn = await pool.query<{ attnotnull: boolean }>(
    `SELECT attribute.attnotnull
     FROM pg_attribute AS attribute
     JOIN pg_class AS class ON class.oid = attribute.attrelid
     JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
     WHERE namespace.nspname = 'integration_runtime'
       AND class.relname = 'connections'
       AND attribute.attname = 'local_connection_id'
       AND NOT attribute.attisdropped`,
  );
  if (!identityColumn.rows[0]?.attnotnull) {
    throw new Error("Unsafe SaaS PostgreSQL runtime boundary for integration_runtime.connections.local_connection_id");
  }

  const migrationEntries = await readdir(new URL("./migrations/", import.meta.url), { withFileTypes: true });
  const migrationNames = migrationEntries
    .filter((entry) => entry.isFile() && /^\d+.*\.sql$/.test(entry.name))
    .map((entry) => entry.name)
    .sort();
  const expectedMigrations = await Promise.all(
    migrationNames.map(async (name) => ({
      name,
      checksum: createHash("sha256")
        .update(await readFile(new URL(`./migrations/${name}`, import.meta.url), "utf8"))
        .digest("hex"),
    })),
  );
  const migrationResult = await pool.query<{ name: string; checksum: string }>(
    "SELECT name, checksum FROM integration_runtime_migrations.schema_migrations",
  );
  const appliedMigrations = new Map(migrationResult.rows.map((migration) => [migration.name, migration.checksum]));
  for (const migration of expectedMigrations) {
    if (appliedMigrations.get(migration.name) !== migration.checksum) {
      throw new Error(`SaaS PostgreSQL schema version is missing or changed at ${migration.name}`);
    }
  }

  const ownerMembership = await pool.query(
    `WITH owner_oids(owner_oid) AS (
       SELECT namespace.nspowner
       FROM pg_namespace AS namespace
       WHERE namespace.nspname IN ('integration_runtime', 'integration_runtime_migrations')
       UNION
       SELECT class.relowner
       FROM pg_class AS class
       JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
       WHERE namespace.nspname IN ('integration_runtime', 'integration_runtime_migrations')
         AND class.relkind IN ('r', 'p')
     )
     SELECT pg_get_userbyid(owner_oid) AS owner_name
     FROM owner_oids
     WHERE pg_has_role(current_user, owner_oid, 'MEMBER')
     LIMIT 1`,
  );
  if (ownerMembership.rowCount) {
    throw new Error("The SaaS PostgreSQL runtime role can assume a SaaS schema or table owner");
  }
}

export interface SaasRuntimeConnectionStore extends IConnectionStore {
  listSafeConnections(): Promise<SafeStoredConnection[]>;
  getSafeConnection(connectionId: string): Promise<SafeStoredConnection | undefined>;
  getCredentialReplacementTarget(connectionId: string): Promise<StoredConnection | undefined>;
  hasRevocationReceipt(connectionId: string): Promise<boolean>;
  resumeRevocation(connectionId: string): Promise<boolean>;
  blockForRevocation(connectionId: string): Promise<StoredConnection | undefined>;
  deleteById(connectionId: string, outcome: Exclude<ProviderCredentialRevocationOutcome, "failed">): Promise<boolean>;
  transferById(connectionId: string, targetSubjectUserId: string): Promise<SafeStoredConnection | undefined>;
  updateVisibilityById(
    connectionId: string,
    visibility: SafeStoredConnection["visibility"],
  ): Promise<SafeStoredConnection | undefined>;
}

export interface SaasRuntimeDatabase {
  connectionStore: SaasRuntimeConnectionStore;
  oauthStateStore: IOAuthStateStore;
  runLogStore: IRunLogStore;
  executionJournal: ExecutionJournal;
  saasIdempotencyStore: SaasActionIdempotencyStore;
  refreshLeaseStore: RefreshLeaseStore;
  refreshCoordinator: PostgresRefreshCoordinator;
  transitFileStore: TransitFileMetadataStore;
  transitFiles?: ITransitFileService;
}

export interface SaasRuntimeDatabaseFactoryOptions {
  pool: Pool;
  connectionSecrets: ConnectionSecretStore;
  oauthStateSecrets: OAuthStateSecretStore;
  runLimit?: number;
  oauthStateMaxAgeMs?: number;
  transitFiles?: Omit<SeaweedFsTransitFileOptions, "metadata" | "scope">;
}

/** Creates fresh upstream-compatible store adapters for each verified request. */
export class SaasRuntimeDatabaseFactory {
  private readonly options: SaasRuntimeDatabaseFactoryOptions;

  constructor(options: SaasRuntimeDatabaseFactoryOptions) {
    this.options = options;
  }

  forScope(scope: Readonly<SaasRequestScope>): SaasRuntimeDatabase {
    const capturedScope = freezeScope(scope);
    const refreshLeaseStore = new PostgresRefreshLeaseStore(this.options.pool, capturedScope);
    const transitFileStore = new PostgresTransitFileStore(this.options.pool, capturedScope);
    const runStore = new PostgresRunStore(this.options.pool, capturedScope, this.options.runLimit);
    const idempotencyStore = new PostgresIdempotencyStore(this.options.pool, capturedScope);
    return {
      connectionStore: new PostgresConnectionStore(this.options.pool, capturedScope, this.options.connectionSecrets),
      oauthStateStore: new PostgresOAuthStateStore(
        this.options.pool,
        capturedScope,
        this.options.oauthStateSecrets,
        this.options.oauthStateMaxAgeMs,
      ),
      runLogStore: runStore,
      executionJournal: runStore,
      saasIdempotencyStore: idempotencyStore,
      refreshLeaseStore,
      refreshCoordinator: new PostgresRefreshCoordinator(refreshLeaseStore),
      transitFileStore,
      transitFiles: this.options.transitFiles
        ? new SeaweedFsTransitFileService({
            ...this.options.transitFiles,
            metadata: transitFileStore,
            scope: capturedScope,
          })
        : undefined,
    };
  }

  lifecycleForScope(
    scope: Readonly<SaasRequestScope>,
    credentialRevoker?: SaasProviderCredentialRevoker,
  ): ScopedLifecycleService {
    const capturedScope = freezeScope(scope);
    const connections = new PostgresConnectionStore(this.options.pool, capturedScope, this.options.connectionSecrets);
    const oauthStates = new PostgresOAuthStateStore(
      this.options.pool,
      capturedScope,
      this.options.oauthStateSecrets,
      this.options.oauthStateMaxAgeMs,
    );
    const runLogs = new PostgresRunStore(this.options.pool, capturedScope, this.options.runLimit);
    const transitMetadata = new PostgresTransitFileStore(this.options.pool, capturedScope);
    const transitFiles = this.options.transitFiles
      ? new SeaweedFsTransitFileService({
          ...this.options.transitFiles,
          metadata: transitMetadata,
          scope: capturedScope,
        })
      : undefined;
    return new ScopedLifecycleService({
      pool: this.options.pool,
      scope: capturedScope,
      connections,
      oauthStates,
      runLogs,
      transitMetadata,
      ...(transitFiles ? { transitFiles } : {}),
      ...(credentialRevoker ? { credentialRevoker } : {}),
    });
  }
}

function freezeScope(scope: Readonly<SaasRequestScope>): Readonly<SaasRequestScope> {
  const permissions = [...scope.permissions];
  Object.freeze(permissions);
  return Object.freeze({ ...scope, permissions });
}
