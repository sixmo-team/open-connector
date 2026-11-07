import type { IConnectionStore, StoredLocalConnection } from "../../connection-store.ts";
import type { ResolvedCredential } from "../../core/types.ts";
import type { OAuthAuthorizationState } from "../../oauth/oauth-flow-service.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { ISecretCodec } from "../secrets/secret-codec.ts";
import type { PendingConnectionRequest, ConnectionRequest } from "../storage/connection-request-store.ts";
import type { ConnectionSecret, ConnectionSecretStore } from "../storage/postgres-connection-store.ts";
import type { SaasRuntimeDatabase } from "../storage/postgres-runtime-database.ts";
import type { PostgresTestDatabase } from "./postgres-test-database.ts";

import { randomUUID } from "node:crypto";
import { Pool } from "pg";
import { beforeAll, afterAll } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import { migratePostgres } from "../storage/postgres-migrator.ts";
import { SaasRuntimeDatabaseFactory } from "../storage/postgres-runtime-database.ts";
import { createPostgresTestDatabase, postgresTestUrl } from "./postgres-test-database.ts";

/** Test-only external-secret stand-in: the serialized SQL value is a reference, not plaintext. */
export class MemorySecretCodec implements ISecretCodec {
  failDelete = false;
  private readonly values = new Map<string, string>();
  readonly encrypted: boolean;
  constructor(encrypted = true) {
    this.encrypted = encrypted;
  }
  async encode(value: string): Promise<string> {
    const ref = `secret:${randomUUID()}`;
    this.values.set(ref, value);
    return ref;
  }
  async decode(ref: string): Promise<string> {
    const value = this.values.get(ref);
    if (value === undefined) throw new Error("Secret missing");
    return value;
  }
  async delete(ref: string): Promise<boolean> {
    if (this.failDelete) throw new Error("Secret cleanup unavailable");
    return this.values.delete(ref);
  }
}
/** Native flow unit fixture; database atomicity and tenant/session fencing are tested against PostgreSQL separately. */
export class MemoryLocalConnectionRequests {
  private readonly pending = new Map<string, PendingConnectionRequest>();
  private readonly statuses = new Map<string, ConnectionRequest>();
  private readonly connections: IConnectionStore;
  constructor(connections: IConnectionStore) {
    this.connections = connections;
  }
  async create(value: PendingConnectionRequest): Promise<void> {
    this.pending.set(value.state, value);
    this.statuses.set(value.connectionRequestId, {
      connectionRequestId: value.connectionRequestId,
      service: value.service,
      status: "initiated",
      appId: null,
      errorCode: null,
      errorMessage: null,
      expiresAt: value.expiresAt,
      createdAt: Date.parse(value.createdAt),
      updatedAt: Date.now(),
    });
  }
  async claim(state: string): Promise<PendingConnectionRequest | undefined> {
    const value = this.pending.get(state);
    this.pending.delete(state);
    return value && Date.parse(value.expiresAt) > Date.now() ? value : undefined;
  }
  async get(id: string, owner: string): Promise<ConnectionRequest | undefined> {
    const pending = [...this.pending.values()].find((value) => value.connectionRequestId === id);
    return !pending || pending.owner === owner ? this.statuses.get(id) : undefined;
  }
  async fail(id: string, errorCode: string, errorMessage: string): Promise<void> {
    const value = this.statuses.get(id);
    if (value) this.statuses.set(id, { ...value, status: "failed", errorCode, errorMessage });
  }
  async complete(
    pending: PendingConnectionRequest,
    credential: ResolvedCredential,
    signal?: AbortSignal,
  ): Promise<string | undefined> {
    signal?.throwIfAborted();
    if (
      (await this.connections.getRetirementGeneration(pending.service, pending.connectionName)) !==
      pending.retirementGeneration
    )
      return undefined;
    let connection: StoredLocalConnection | undefined;
    if (pending.target) {
      const existing = await this.connections.getById(pending.target.id);
      if (!existing || existing.source === "saas" || existing.revision !== pending.target.revision) return undefined;
      if (!(await this.connections.updateCredential({ ...existing, credential }))) return undefined;
      const updated = await this.connections.getById(existing.id);
      if (updated?.source === "saas") return undefined;
      connection = updated;
    } else
      connection = await this.connections.setIfCurrentGeneration(
        pending.service,
        pending.connectionName,
        credential,
        pending.retirementGeneration,
      );
    if (!connection) return undefined;
    const status = this.statuses.get(pending.connectionRequestId);
    if (status)
      this.statuses.set(pending.connectionRequestId, { ...status, status: "connected", appId: connection.id });
    return connection.id;
  }
}
export class MemoryConnectionSecrets implements ConnectionSecretStore {
  private readonly values = new Map<string, ConnectionSecret>();
  private key(scope: Readonly<SaasRequestScope>, id: string): string {
    return `${scope.tenantId}/${scope.workspaceId}/${id}`;
  }
  async create(
    scope: Readonly<SaasRequestScope>,
    id: string,
    provider: string,
    credential: ResolvedCredential,
  ): Promise<{ secretRef: string; secretRevision: number }> {
    const key = this.key(scope, id);
    this.values.set(`${key}/1`, toSecret(provider, credential, 1));
    return { secretRef: key, secretRevision: 1 };
  }
  async read(scope: Readonly<SaasRequestScope>, id: string, revision: number): Promise<ConnectionSecret | undefined> {
    return this.values.get(`${this.key(scope, id)}/${revision}`);
  }
  async update(
    scope: Readonly<SaasRequestScope>,
    id: string,
    provider: string,
    revision: number,
    credential: ResolvedCredential,
  ): Promise<number | false> {
    const key = this.key(scope, id);
    if (!this.values.has(`${key}/${revision}`) || this.values.has(`${key}/${revision + 1}`)) return false;
    this.values.set(`${key}/${revision + 1}`, toSecret(provider, credential, revision + 1));
    return revision + 1;
  }
  async delete(scope: Readonly<SaasRequestScope>, id: string): Promise<void> {
    const prefix = `${this.key(scope, id)}/`;
    for (const key of this.values.keys()) if (key.startsWith(prefix)) this.values.delete(key);
  }
}
function toSecret(provider: string, credential: ResolvedCredential, revision: number): ConnectionSecret {
  const base = { provider, revision, metadata: "metadata" in credential ? credential.metadata : {} };
  switch (credential.authType) {
    case "no_auth":
      return { ...base, authType: "no_auth", value: {} };
    case "api_key":
      return { ...base, authType: "api_key", value: { apiKey: credential.apiKey, values: credential.values } };
    case "custom_credential":
      return { ...base, authType: "custom_credential", value: { values: credential.values } };
    case "oauth2":
      return {
        ...base,
        authType: "oauth2",
        value: {
          accessToken: credential.accessToken,
          tokenType: credential.tokenType,
          expiresAt: credential.expiresAt,
          refreshToken: credential.refreshToken,
          providerSecret: credential.providerSecret,
        },
      };
  }
}
/** Uses the parent's configured isolated PostgreSQL service; never starts a database service. */
export interface NativePostgresFixture extends SaasRuntimeDatabase {
  scope: SaasRequestScope;
}
export interface NativePostgresHarness {
  enabled: boolean;
  codec: MemorySecretCodec;
  readonly pool: Pool;
  readonly factory: SaasRuntimeDatabaseFactory;
  forScope(overrides?: Partial<SaasRequestScope>): NativePostgresFixture;
  setCleanupDeletePermission(enabled: boolean): Promise<void>;
}
export function createNativePostgresHarness(): NativePostgresHarness {
  const url = postgresTestUrl();
  let database: PostgresTestDatabase;
  let pool: Pool;
  const codec = new MemorySecretCodec();
  let factory: SaasRuntimeDatabaseFactory;
  beforeAll(async () => {
    if (!url) return;
    database = await createPostgresTestDatabase(url);
    await migratePostgres({
      migratorConnectionString: database.migratorConnectionString,
      runtimeConnectionString: database.runtimeConnectionString,
    });
    pool = new Pool({ connectionString: database.runtimeConnectionString, max: 2 });
    const states = new Map<string, { pkceCodeVerifier?: string; authorizationState?: OAuthAuthorizationState }>();
    factory = new SaasRuntimeDatabaseFactory({
      pool,
      catalog: createCatalogStore([]),
      connectionSecrets: new MemoryConnectionSecrets(),
      secretCodecForScope: () => codec,
      oauthStateSecrets: {
        async put(scope, id, pkceCodeVerifier, _expiresAt, authorizationState) {
          const key = `${scope.tenantId}/${scope.workspaceId}/${id}`;
          states.set(key, { pkceCodeVerifier, authorizationState });
          return { secretRef: key, secretRevision: 1 };
        },
        async take(scope, id) {
          const key = `${scope.tenantId}/${scope.workspaceId}/${id}`;
          const state = states.get(key);
          states.delete(key);
          return state;
        },
        async delete(scope, id) {
          states.delete(`${scope.tenantId}/${scope.workspaceId}/${id}`);
        },
      },
    });
  }, 30000);
  afterAll(async () => {
    await pool?.end();
    await database?.dispose();
  });
  return {
    enabled: !!url,
    codec,
    get pool() {
      return pool;
    },
    get factory() {
      return factory;
    },
    async setCleanupDeletePermission(enabled: boolean) {
      const admin = new Pool({ connectionString: database.adminConnectionString, max: 1 });
      try {
        const role = `"${database.runtimeRole.replaceAll('"', '""')}"`;
        await admin.query(
          enabled
            ? `GRANT DELETE ON integration_runtime.saas_cleanup TO ${role}`
            : `REVOKE DELETE ON integration_runtime.saas_cleanup FROM ${role}`,
        );
      } finally {
        await admin.end();
      }
    },
    forScope(overrides: Partial<SaasRequestScope> = {}) {
      const user = randomUUID();
      const scope: SaasRequestScope = {
        tenantId: randomUUID(),
        workspaceId: randomUUID(),
        actorUserId: user,
        subjectUserId: user,
        workspaceRole: "owner",
        purpose: "oauth:start",
        permissions: ["oauth:start", "oauth:complete", "connection:write"],
        localConnectionId: randomUUID(),
        oauthSessionId: randomUUID(),
        ...overrides,
      };
      return { ...factory.forScope(scope), scope };
    },
  };
}
