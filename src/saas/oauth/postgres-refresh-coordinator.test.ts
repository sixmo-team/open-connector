import type { IConnectionStore, StoredConnection } from "../../connection-service.ts";
import type { ProviderDefinition, ResolvedCredential } from "../../core/types.ts";
import type { IOAuthCredentialRefresher } from "../../oauth/oauth-credential-refresh-service.ts";
import type { IProviderLoader } from "../../providers/provider-loader.ts";
import type { RefreshLeaseAcquireResult, RefreshLeaseStore } from "../storage/postgres-refresh-lease-store.ts";
import type { PostgresTestDatabase } from "../testing/postgres-test-database.ts";

import { randomBytes, randomUUID } from "node:crypto";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import { createScopedConnectionService } from "../connections/scoped-connection-service.ts";
import { migratePostgres } from "../storage/postgres-migrator.ts";
import { PostgresRefreshLeaseStore } from "../storage/postgres-refresh-lease-store.ts";
import { withScopedClient } from "../storage/scoped-query.ts";
import { createPostgresTestDatabase, postgresTestUrl } from "../testing/postgres-test-database.ts";
import { PostgresRefreshCoordinator } from "./postgres-refresh-coordinator.ts";

const provider: ProviderDefinition = {
  service: "refresh_example",
  displayName: "Refresh Example",
  categories: ["Developer Tools"],
  authTypes: ["oauth2"],
  auth: [
    {
      type: "oauth2",
      authorizationUrl: "https://example.com/oauth/authorize",
      tokenUrl: "https://example.com/oauth/token",
      scopes: ["read"],
      tokenEndpointAuthMethod: "client_secret_post",
    },
  ],
  actions: [],
};

const expiredCredential: Extract<ResolvedCredential, { authType: "oauth2" }> = {
  authType: "oauth2",
  tokenType: "Bearer",
  accessToken: "expired",
  refreshToken: "refresh-token",
  expiresAt: new Date(0).toISOString(),
  profile: { accountId: "account", displayName: "Account", grantedScopes: [] },
  metadata: {},
};

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

describe("PostgresRefreshCoordinator", () => {
  it("composes the OAuth refresher into two replicas for one refresh and one CAS update", async () => {
    const connectionStore = new MemoryConnectionStore(expiredCredential);
    const leaseStore = new MemoryRefreshLeaseStore();
    const refreshStarted = Promise.withResolvers<void>();
    const finishRefresh = Promise.withResolvers<void>();
    let refreshCalls = 0;
    const refresher: IOAuthCredentialRefresher = {
      async refresh(_service, credential) {
        refreshCalls += 1;
        refreshStarted.resolve();
        await finishRefresh.promise;
        return {
          ...credential,
          accessToken: "fresh",
          expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
          metadata: { revision: "credential-revision-2" },
        };
      },
    };
    const makeService = () =>
      createScopedConnectionService({
        catalog: createCatalogStore([provider]),
        providerLoader,
        store: connectionStore,
        oauthCredentials: refresher,
        refreshCoordinator: new PostgresRefreshCoordinator(leaseStore, {
          leaseDurationMs: 1_000,
          maxWaitMs: 2_000,
          pollIntervalMs: 1,
        }),
      });

    const first = makeService().getCredential(provider.service, "account-a");
    const second = makeService().getCredential(provider.service, "account-a");
    await refreshStarted.promise;
    await Promise.resolve();
    finishRefresh.resolve();
    const credentials = await Promise.all([first, second]);

    expect(refreshCalls).toBe(1);
    expect(connectionStore.updateCalls).toBe(1);
    expect(connectionStore.current.revision).toBe("revision-2");
    expect(credentials).toEqual([
      expect.objectContaining({ accessToken: "fresh", metadata: { revision: "credential-revision-2" } }),
      expect.objectContaining({ accessToken: "fresh", metadata: { revision: "credential-revision-2" } }),
    ]);
  });

  it("recovers after a crashed holder expires and releases in finally", async () => {
    let now = 1_000;
    const leaseStore = new MemoryRefreshLeaseStore(() => now);
    expect(await leaseStore.acquire("connection", "crashed", 10)).toEqual({ kind: "acquired" });
    const coordinator = new PostgresRefreshCoordinator(leaseStore, {
      leaseDurationMs: 10,
      maxWaitMs: 100,
      pollIntervalMs: 5,
      now: () => now,
      sleep: async (milliseconds) => {
        now += milliseconds;
      },
    });

    await expect(
      coordinator.runExclusive("connection", async () => {
        throw new Error("provider failed");
      }),
    ).rejects.toThrow("provider failed");
    expect(leaseStore.has("connection")).toBe(false);
  });
});

class MemoryConnectionStore implements IConnectionStore {
  updateCalls = 0;
  current: StoredConnection;

  constructor(credential: ResolvedCredential) {
    this.current = {
      id: "7fe0db83-9b29-4af8-936e-99ff2f41f121",
      revision: "revision-1",
      service: provider.service,
      connectionName: "account-a",
      credential,
    };
  }

  async get(service: string, connectionName: string): Promise<StoredConnection | undefined> {
    return service === this.current.service && connectionName === this.current.connectionName
      ? { ...this.current }
      : undefined;
  }

  async set(service: string, connectionName: string, credential: ResolvedCredential): Promise<StoredConnection> {
    this.current = { ...this.current, service, connectionName, credential };
    return this.current;
  }

  async updateCredential(input: StoredConnection): Promise<boolean> {
    if (input.id !== this.current.id || input.revision !== this.current.revision) return false;
    this.updateCalls += 1;
    this.current = { ...input, revision: `revision-${this.updateCalls + 1}` };
    return true;
  }

  async delete(): Promise<void> {}

  async list(): Promise<StoredConnection[]> {
    return [{ ...this.current }];
  }
}

class MemoryRefreshLeaseStore implements RefreshLeaseStore {
  private readonly leases = new Map<string, { holder: string; expiresAt: number }>();
  private readonly now: () => number;

  constructor(now: () => number = Date.now) {
    this.now = now;
  }

  async acquire(connectionId: string, holder: string, leaseDurationMs: number): Promise<RefreshLeaseAcquireResult> {
    const current = this.leases.get(connectionId);
    const now = this.now();
    if (!current || current.expiresAt <= now) {
      this.leases.set(connectionId, { holder, expiresAt: now + leaseDurationMs });
      return { kind: "acquired" };
    }
    return { kind: "busy", retryAfterMs: current.expiresAt - now };
  }

  async release(connectionId: string, holder: string): Promise<void> {
    if (this.leases.get(connectionId)?.holder === holder) this.leases.delete(connectionId);
  }

  has(connectionId: string): boolean {
    return this.leases.has(connectionId);
  }
}

const testPostgresUrl = postgresTestUrl();
const nonce = randomBytes(6).toString("hex");
const scope = {
  tenantId: `tenant-${nonce}`,
  workspaceId: `workspace-${nonce}`,
  actorUserId: "user-a",
  subjectUserId: "user-a",
  workspaceRole: "member" as const,
  purpose: "action:execute" as const,
  permissions: ["action:execute"],
};
let adminPool: Pool;
let runtimePool: Pool;
let testDatabase: PostgresTestDatabase;
let connectionId: string;

describe.skipIf(!testPostgresUrl)("PostgresRefreshLeaseStore real PostgreSQL semantics", () => {
  beforeAll(async () => {
    if (!testPostgresUrl) throw new Error("TEST_POSTGRES_URL is required");
    testDatabase = await createPostgresTestDatabase(testPostgresUrl);
    adminPool = new Pool({ connectionString: testDatabase.adminConnectionString });
    await migratePostgres({
      migratorConnectionString: testDatabase.migratorConnectionString,
      runtimeConnectionString: testDatabase.runtimeConnectionString,
    });
    runtimePool = new Pool({ connectionString: testDatabase.runtimeConnectionString, max: 2 });
    connectionId = randomUUID();
    await withScopedClient(adminPool, scope, async (client) => {
      await client.query(
        `INSERT INTO integration_runtime.connections (
           id, tenant_id, workspace_id, subject_user_id, local_connection_id, visibility, service,
           connection_name, auth_type, revision, secret_ref, status
         ) VALUES ($1, $2, $3, $4, $5, 'user', $6, $7, 'oauth2', $8, $9, 'active')`,
        [
          connectionId,
          scope.tenantId,
          scope.workspaceId,
          scope.subjectUserId,
          randomUUID(),
          provider.service,
          "account-a",
          randomUUID(),
          `secret-${nonce}`,
        ],
      );
    });
  }, 30_000);

  afterAll(async () => {
    try {
      if (adminPool && connectionId) {
        await withScopedClient(adminPool, scope, async (client) => {
          await client.query("DELETE FROM integration_runtime.refresh_leases WHERE connection_id = $1", [connectionId]);
          await client.query("DELETE FROM integration_runtime.connections WHERE id = $1", [connectionId]);
        });
      }
    } finally {
      await runtimePool?.end();
      await adminPool?.end();
      await testDatabase?.dispose();
    }
  });

  it("atomically excludes peers and recovers after database lease expiry", async () => {
    const first = new PostgresRefreshLeaseStore(runtimePool, scope);
    const second = new PostgresRefreshLeaseStore(runtimePool, scope);
    expect(await first.acquire(connectionId, "holder-a", 60_000)).toEqual({ kind: "acquired" });
    const leaseScope = await withScopedClient(adminPool, scope, async (client) => {
      return (
        await client.query<{ subject_user_id: string; visibility: string }>(
          `SELECT subject_user_id, visibility
           FROM integration_runtime.refresh_leases
           WHERE connection_id = $1`,
          [connectionId],
        )
      ).rows[0];
    });
    expect(leaseScope).toEqual({ subject_user_id: scope.subjectUserId, visibility: "user" });
    expect(await second.acquire(connectionId, "holder-b", 60_000)).toMatchObject({ kind: "busy" });
    await adminPool.query(
      "UPDATE integration_runtime.refresh_leases SET expires_at = now() - interval '1 second' WHERE connection_id = $1",
      [connectionId],
    );
    expect(await second.acquire(connectionId, "holder-b", 60_000)).toEqual({ kind: "acquired" });
    await second.release(connectionId, "holder-b");
  });
});
