import type { CatalogStore } from "../../catalog-store.ts";
import type { IConnectionStore, StoredConnection } from "../../connection-store.ts";
import type { IOAuthStateStore } from "../../oauth/oauth-flow-service.ts";
import type { ExecutionJournal, SaasActionIdempotencyStore } from "../actions/saas-action-runner.ts";
import type {
  ProviderCredentialRevocationOutcome,
  SaasProviderCredentialRevoker,
} from "../connections/provider-credential-revoker.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { SeaweedFsTransitFileOptions } from "../files/seaweedfs-transit-files.ts";
import type { ITransitFileService } from "../files/transit-file-store.ts";
import type { ISecretCodec, NativeSecretScope } from "../secrets/secret-codec.ts";
import type { TriggerLifecycleCleanup } from "../triggers/postgres-trigger-store.ts";
import type {
  ConnectionSecretStore,
  SafeStoredConnection,
  LifecycleConnectionRetirement,
} from "./postgres-connection-store.ts";
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
import { SaasCleanupService } from "../saas-cleanup-service.ts";
import { PostgresTriggerStore } from "../triggers/postgres-trigger-store.ts";
import { PostgresActionPolicyStore } from "./postgres-action-policy-store.ts";
import { PostgresConnectionRequestStore } from "./postgres-connection-request-store.ts";
import { PostgresConnectionStore } from "./postgres-connection-store.ts";
import { PostgresIdempotencyStore } from "./postgres-idempotency-store.ts";
import { scopedRuntimeFunctions, nativeManagedFenceSequence } from "./postgres-migrator.ts";
import { PostgresNativeConfigurationStore } from "./postgres-native-configuration-store.ts";
import { PostgresNativeLifecycleInventory } from "./postgres-native-lifecycle-inventory.ts";
import { PostgresOAuthStateStore } from "./postgres-oauth-state-store.ts";
import { PostgresRefreshLeaseStore } from "./postgres-refresh-lease-store.ts";
import { PostgresRunStore } from "./postgres-run-store.ts";
import { PostgresSaasProjectStore } from "./postgres-saas-project-store.ts";
import { PostgresTransitFileStore } from "./postgres-transit-file-store.ts";

const requiredRuntimeTables = [
  "connections",
  "oauth_states",
  "run_intents",
  "idempotency_records",
  "refresh_leases",
  "transit_files",
  "connection_revocation_receipts",
  "connection_retirements",
  "connection_requests",
  "managed_projects",
  "oauth_sources",
  "saas_cleanup",
  "managed_account_retirements",
  "trigger_subscriptions",
  "trigger_source_applications",
  "trigger_secret_cleanup",
  "trigger_execution_leases",
  "action_defaults",
  "action_grants",
  "action_policy_audit",
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

  for (const { signature, definer } of scopedRuntimeFunctions) {
    const result = await pool.query<{
      owner_name: string;
      prosecdef: boolean;
      proconfig: string[] | null;
      executable: boolean;
      public_executable: boolean;
    }>(
      `SELECT pg_get_userbyid(p.proowner) AS owner_name,p.prosecdef,p.proconfig,
        has_function_privilege(current_user,p.oid,'EXECUTE') AS executable,
        EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
          WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_executable
       FROM pg_proc p WHERE p.oid=to_regprocedure($1)`,
      [signature],
    );
    const fn = result.rows[0];
    if (
      !fn ||
      fn.owner_name !== tables.get("connections")!.owner_name ||
      fn.prosecdef !== definer ||
      !fn.executable ||
      fn.public_executable ||
      !fn.proconfig?.some((setting) => setting.replaceAll(" ", "") === "search_path=pg_catalog,pg_temp")
    )
      throw new Error(`Unsafe scoped runtime function boundary for ${signature}`);
  }
  const sequence = (
    await pool.query<{ owner_name: string; usage: boolean; update: boolean; public_access: boolean }>(
      `SELECT pg_get_userbyid(c.relowner) AS owner_name,
       has_sequence_privilege(current_user,c.oid,'USAGE') AS usage,
       has_sequence_privilege(current_user,c.oid,'UPDATE') AS update,
       EXISTS (SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('s',c.relowner))) a
         WHERE a.grantee=0) AS public_access
     FROM pg_class c WHERE c.oid=to_regclass($1) AND c.relkind='S'`,
      [nativeManagedFenceSequence],
    )
  ).rows[0];
  if (
    !sequence ||
    sequence.owner_name !== tables.get("connections")!.owner_name ||
    !sequence.usage ||
    sequence.update ||
    sequence.public_access
  )
    throw new Error("Unsafe managed account monotonic sequence boundary");

  const policyPrivileges = await pool.query<{
    relname: string;
    can_select: boolean;
    can_insert: boolean;
    can_update: boolean;
    can_delete: boolean;
    can_truncate: boolean;
  }>(
    `SELECT class.relname,
      has_table_privilege(current_user, class.oid, 'SELECT') AS can_select,
      has_table_privilege(current_user, class.oid, 'INSERT') AS can_insert,
      has_table_privilege(current_user, class.oid, 'UPDATE') AS can_update,
      has_table_privilege(current_user, class.oid, 'DELETE') AS can_delete,
      has_table_privilege(current_user, class.oid, 'TRUNCATE') AS can_truncate
    FROM pg_class AS class JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'integration_runtime' AND class.relname = ANY($1::text[])`,
    [["action_defaults", "action_grants", "action_policy_audit"]],
  );
  for (const table of policyPrivileges.rows) {
    if (
      !table.can_select ||
      !table.can_insert ||
      table.can_truncate ||
      table.can_update !== (table.relname !== "action_policy_audit") ||
      table.can_delete !== (table.relname !== "action_defaults")
    ) {
      throw new Error(`Unsafe SaaS PostgreSQL policy privileges for integration_runtime.${table.relname}`);
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
  listExactOwnedRetirementsForLifecycle(
    cursor: string | undefined,
    limit: number,
  ): Promise<{ items: LifecycleConnectionRetirement[]; nextCursor?: string }>;
  countExactOwnedRetirementsForLifecycle(): Promise<number>;
  purgeExactOwnedRetirementsForLifecycle(): Promise<number>;
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
  actionPolicy: PostgresActionPolicyStore;
  oauthStateStore: IOAuthStateStore;
  connectionRequests: PostgresConnectionRequestStore;
  saasProjects: PostgresSaasProjectStore;
  triggers: PostgresTriggerStore;
  secretCodec: ISecretCodec;
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
  catalog: Pick<CatalogStore, "actionsById" | "providers">;
  connectionSecrets: ConnectionSecretStore;
  oauthStateSecrets: OAuthStateSecretStore;
  secretCodecForScope: (scope: Readonly<NativeSecretScope>) => ISecretCodec;
  runLimit?: number;
  oauthStateMaxAgeMs?: number;
  transitFiles?: Omit<SeaweedFsTransitFileOptions, "metadata" | "scope">;
}

/** Creates fresh upstream-compatible store adapters for each verified request. */
export class SaasRuntimeDatabaseFactory {
  private readonly options: SaasRuntimeDatabaseFactoryOptions;
  readonly actionPolicy: PostgresActionPolicyStore;
  readonly nativeConfiguration: PostgresNativeConfigurationStore;
  readonly nativeLifecycleInventory: PostgresNativeLifecycleInventory;

  constructor(options: SaasRuntimeDatabaseFactoryOptions) {
    this.options = options;
    this.actionPolicy = new PostgresActionPolicyStore(options.pool, options.catalog);
    this.nativeConfiguration = new PostgresNativeConfigurationStore(options.pool, options.secretCodecForScope);
    this.nativeLifecycleInventory = new PostgresNativeLifecycleInventory(options.pool);
  }

  forScope(scope: Readonly<SaasRequestScope>): SaasRuntimeDatabase {
    const capturedScope = freezeScope(scope);
    const refreshLeaseStore = new PostgresRefreshLeaseStore(this.options.pool, capturedScope);
    const transitFileStore = new PostgresTransitFileStore(this.options.pool, capturedScope);
    const runStore = new PostgresRunStore(this.options.pool, capturedScope, this.options.runLimit);
    const idempotencyStore = new PostgresIdempotencyStore(this.options.pool, capturedScope);
    const connectionStore = new PostgresConnectionStore(
      this.options.pool,
      capturedScope,
      this.options.connectionSecrets,
    );
    const secretCodec = this.options.secretCodecForScope(capturedScope);
    return {
      actionPolicy: this.actionPolicy,
      connectionRequests: new PostgresConnectionRequestStore(
        this.options.pool,
        capturedScope,
        secretCodec,
        connectionStore,
      ),
      saasProjects: new PostgresSaasProjectStore(this.options.pool, capturedScope, secretCodec),
      triggers: new PostgresTriggerStore(this.options.pool, capturedScope, secretCodec),
      secretCodec,
      connectionStore,
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
    triggerCleanup?: TriggerLifecycleCleanup,
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
    const secretCodec = this.options.secretCodecForScope(capturedScope);
    const connectionRequests = new PostgresConnectionRequestStore(
      this.options.pool,
      capturedScope,
      secretCodec,
      connections,
    );
    const saasProjects = new PostgresSaasProjectStore(this.options.pool, capturedScope, secretCodec);
    const triggers = new PostgresTriggerStore(this.options.pool, capturedScope, secretCodec);
    return new ScopedLifecycleService({
      pool: this.options.pool,
      scope: capturedScope,
      connections,
      actionPolicy: this.actionPolicy,
      connectionRequests,
      saasProjects,
      triggers,
      ...(triggerCleanup ? { triggerCleanup } : {}),
      runSaasCleanup: async () => {
        const cleanup = new SaasCleanupService({ ...capturedScope, store: saasProjects, requests: connectionRequests });
        try {
          await cleanup.run();
        } finally {
          await cleanup.close();
        }
      },
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
