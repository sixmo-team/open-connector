import type { IConnectionStore, StoredLocalConnection } from "../../connection-store.ts";
import type { ProviderDefinition, ResolvedCredential } from "../../core/types.ts";
import type { PostgresRefreshCoordinator } from "../oauth/postgres-refresh-coordinator.ts";

import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import { resolveExecutionTarget } from "../../execution-target.ts";
import { ProviderLoader } from "../../providers/provider-loader.ts";
import { createScopedConnectionService } from "./scoped-connection-service.ts";

const provider: ProviderDefinition = {
  service: "example",
  displayName: "Example",
  categories: ["Developer Tools"],
  authTypes: ["api_key", "no_auth"],
  auth: [{ type: "api_key" }, { type: "no_auth" }],
  actions: [],
};
const credential: ResolvedCredential = {
  authType: "api_key",
  apiKey: "secret",
  values: { apiKey: "secret" },
  profile: { accountId: "account", displayName: "Account", grantedScopes: [] },
  metadata: {},
};

function fixture(initial?: ResolvedCredential) {
  let row: StoredLocalConnection | undefined = initial
    ? {
        source: "local",
        id: randomUUID(),
        revision: randomUUID(),
        service: provider.service,
        connectionName: "account-a",
        credential: initial,
      }
    : undefined;
  let generation = 0;
  const store: IConnectionStore = {
    async get(service, name) {
      return row?.service === service && row.connectionName === name ? row : undefined;
    },
    async getById(id) {
      return row?.id === id ? row : undefined;
    },
    async getRetirementGeneration() {
      return String(generation);
    },
    async setIfCurrentGeneration(service, name, value, expected) {
      return expected === String(generation) ? store.set(service, name, value) : undefined;
    },
    async set(service, name, value) {
      row = {
        source: "local",
        id: row?.id ?? randomUUID(),
        revision: randomUUID(),
        service,
        connectionName: name,
        credential: value,
      };
      return row;
    },
    async updateCredential(value) {
      if (value.id !== row?.id || value.revision !== row.revision) return false;
      row = { ...value, revision: randomUUID() };
      return true;
    },
    async delete(service, name, target) {
      if (row?.service !== service || row.connectionName !== name) return;
      if (target && (target.id !== row.id || target.revision !== row.revision)) return;
      row = undefined;
      generation += 1;
    },
    async list() {
      return row ? [row] : [];
    },
  };
  const service = createScopedConnectionService({
    catalog: createCatalogStore([provider]),
    providerLoader: new ProviderLoader({}),
    store,
    oauthCredentials: {
      async refresh(_provider, value) {
        return value;
      },
    },
    refreshCoordinator: {
      async runExclusive(_id: string, work: () => Promise<unknown>) {
        return work();
      },
    } as PostgresRefreshCoordinator,
  });
  return { service, store };
}

describe("scoped native connection execution", () => {
  it("resolves the exact stored connection through the upstream execution target contract", async () => {
    const { service, store } = fixture(credential);
    const stored = (await store.get(provider.service, "account-a"))!;
    const target = await resolveExecutionTarget({
      connections: service,
      service: provider.service,
      connectionName: stored.connectionName,
      connectionId: stored.id,
      operation: "action",
      actionId: "example.read",
    });
    expect(target.kind).toBe("local");
    expect(target.summary).toMatchObject({ id: stored.id, configured: true, virtual: false });
    if (target.kind !== "local") throw new Error("Expected local execution");
    expect(await target.getCredential(provider.service)).toEqual(credential);
    expect(await target.getCredential("another_provider")).toBeUndefined();
  });

  it("creates a real individually stored connection for a public provider", async () => {
    const { service, store } = fixture();
    const summary = await service.connectWithoutAuth(provider.service, { connectionName: "public-a" });
    expect(await store.get(provider.service, "public-a")).toMatchObject({
      id: summary.id,
      credential: { authType: "no_auth" },
    });
    expect(summary).toMatchObject({ configured: true, virtual: false, connectionName: "public-a" });
  });
});
