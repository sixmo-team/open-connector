import type { ConnectionService, IConnectionStore, StoredConnection } from "../../connection-service.ts";
import type { ResolvedCredential } from "../../core/types.ts";
import type { PostgresRefreshCoordinator } from "../oauth/postgres-refresh-coordinator.ts";

import { describe, expect, it, vi } from "vitest";
import { ScopedConnectionService } from "./scoped-connection-service.ts";

const credential: ResolvedCredential = {
  authType: "api_key",
  apiKey: "secret",
  values: { apiKey: "secret" },
  profile: { accountId: "account", displayName: "Account", grantedScopes: [] },
  metadata: {},
};

const stored: StoredConnection = {
  id: "018f7a66-9f17-7c91-aee7-54a83b3d743f",
  revision: "revision-1",
  service: "example",
  connectionName: "account-a",
  credential,
};

describe("ScopedConnectionService", () => {
  it("locates the scoped connection, acquires its lease, then makes upstream reload under the lease", async () => {
    const calls: string[] = [];
    const store = {
      get: vi.fn(async () => {
        calls.push("locate");
        return stored;
      }),
    } as unknown as IConnectionStore;
    const upstream = {
      getCredential: vi.fn(async () => {
        calls.push("reload");
        return credential;
      }),
    } as unknown as ConnectionService;
    const refreshes = {
      runExclusive: vi.fn(async (connectionId: string, operation: () => Promise<unknown>) => {
        expect(connectionId).toBe(stored.id);
        calls.push("lease");
        return await operation();
      }),
    } as unknown as PostgresRefreshCoordinator;

    const service = new ScopedConnectionService(upstream, store, refreshes);
    await expect(service.getCredential("example", "account-a")).resolves.toBe(credential);
    expect(calls).toEqual(["locate", "lease", "reload"]);
    expect(store.get).toHaveBeenCalledTimes(1);
    expect(upstream.getCredential).toHaveBeenCalledTimes(1);
  });

  it("does not cache a scoped service or credential between calls", async () => {
    const store = { get: vi.fn().mockResolvedValue(stored) } as unknown as IConnectionStore;
    const upstream = { getCredential: vi.fn().mockResolvedValue(credential) } as unknown as ConnectionService;
    const refreshes = {
      runExclusive: vi.fn(async (_connectionId: string, operation: () => Promise<unknown>) => await operation()),
    } as unknown as PostgresRefreshCoordinator;
    const service = new ScopedConnectionService(upstream, store, refreshes);

    await service.getCredential("example", "account-a");
    await service.getCredential("example", "account-a");
    expect(store.get).toHaveBeenCalledTimes(2);
    expect(refreshes.runExclusive).toHaveBeenCalledTimes(2);
    expect(upstream.getCredential).toHaveBeenCalledTimes(2);
  });
});
