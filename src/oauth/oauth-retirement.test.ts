import type { ProviderDefinition } from "../core/types.ts";
import type { NativePostgresFixture } from "../saas/testing/native-store-fixtures.ts";
import type { OAuthClientConfig } from "./oauth-client-config-service.ts";
import type { ProviderOAuthRuntime } from "./oauth-token.ts";

import { afterEach, describe, expect, it, vi } from "vitest";
import { createCatalogStore } from "../catalog-store.ts";
import { ConnectionService } from "../connection-service.ts";
import { ProviderLoader } from "../providers/provider-loader.ts";
import { createNativePostgresHarness } from "../saas/testing/native-store-fixtures.ts";
import { OAuthClientConfigService } from "./oauth-client-config-service.ts";
import { OAuthCredentialRefreshService } from "./oauth-credential-refresh-service.ts";
import { OAuthFlowService } from "./oauth-flow-service.ts";
const harness = createNativePostgresHarness();
const provider: ProviderDefinition = {
  service: "example",
  displayName: "Example",
  categories: ["Developer Tools"],
  authTypes: ["oauth2"],
  auth: [
    {
      type: "oauth2",
      authorizationUrl: "https://example.com/authorize",
      tokenUrl: "https://example.com/token",
      scopes: ["read"],
      tokenEndpointAuthMethod: "client_secret_post",
    },
  ],
  actions: [],
};
afterEach(() => vi.restoreAllMocks());

describe.skipIf(!harness.enabled)("OAuth retirement across scoped native PostgreSQL sessions", () => {
  it.each([undefined, false, true])(
    "cannot persist or automatically revoke a late refresh after disconnect (revoke: %s)",
    async (revoke) => {
      const db = harness.forScope();
      const entered = Promise.withResolvers<void>();
      const released = Promise.withResolvers<void>();
      const revoked: string[] = [];
      let refreshes = 0;
      const runtime: ProviderOAuthRuntime = {
        async refreshAccessToken() {
          const attempt = ++refreshes;
          entered.resolve();
          await released.promise;
          return {
            accessToken: `rotated-access-${attempt}`,
            refreshToken: `rotated-refresh-${attempt}`,
            tokenType: "Bearer",
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
            metadata: {},
          };
        },
        async revokeAccessToken(input) {
          revoked.push(input.accessToken);
          throw new Error("Provider revocation failed");
        },
      };
      const first = createServices(db, runtime);
      const second = createServices(harness.forScope(db.scope), runtime);
      await db.connectionStore.set("example", "work", {
        authType: "oauth2",
        accessToken: "old-access",
        refreshToken: "old-refresh",
        tokenType: "Bearer",
        expiresAt: new Date(Date.now() - 1000).toISOString(),
        profile: { accountId: "account", displayName: "Account", grantedScopes: [] },
        metadata: {},
      });
      const execution = first.connections.getCredential("example", "work").catch((error: unknown) => error);
      await entered.promise;
      const disconnection = second.connections.disconnect("example", "work", { revoke });
      await vi.waitFor(async () => expect(await db.connectionStore.get("example", "work")).toBeUndefined());
      released.resolve();
      await expect(disconnection).resolves.toMatchObject({
        configured: false,
        revoked: revoke === true ? "failed" : "skipped",
      });
      await expect(execution).resolves.toMatchObject({ code: "connection_not_found" });
      expect(revoked).toEqual(revoke === true ? ["rotated-access-2"] : []);
      expect(await db.connectionStore.get("example", "work")).toBeUndefined();
    },
  );

  it.each(["classic", "request"] as const)(
    "%s cannot resurrect a disconnected or absent lineage after delayed exchange",
    async (mode) => {
      for (const configured of [true, false]) {
        const db = harness.forScope();
        const entered = Promise.withResolvers<void>();
        const released = Promise.withResolvers<void>();
        const exchange = vi.fn(async () => {
          entered.resolve();
          await released.promise;
          return { accessToken: "late-token", tokenType: "Bearer", metadata: {} };
        });
        const first = createServices(db, { exchangeCode: exchange });
        const name = configured ? "configured-lineage" : "never-published-lineage";
        if (configured)
          await db.connectionStore.set("example", name, {
            authType: "oauth2",
            accessToken: "old",
            refreshToken: "refresh",
            tokenType: "Bearer",
            profile: { accountId: "account", displayName: "Account", grantedScopes: [] },
            metadata: {},
          });
        const started =
          mode === "classic"
            ? await first.flow.startAuthorization({ service: "example", connectionName: name })
            : await first.flow.startConnectionRequest({
                service: "example",
                connectionName: name,
                owner: db.scope.subjectUserId,
                target: configured ? await db.connectionStore.get("example", name) : undefined,
              });
        const state = "state" in started ? started.state : started.stateHandle;
        const generation = await db.connectionStore.getRetirementGeneration("example", name);
        const callback = first.flow
          .completeAuthorization({ state, code: "late-code" })
          .catch((error: unknown) => error);
        await entered.promise;
        const other = harness.forScope(db.scope);
        const second = createServices(other, {});
        await second.connections.disconnect("example", name);
        const retired = await other.connectionStore.getRetirementGeneration("example", name);
        expect(retired).not.toBe(generation);
        await expect(
          other.oauthStateStore.set({
            service: "example",
            connectionName: name,
            retirementGeneration: generation,
            state: crypto.randomUUID(),
            createdAt: new Date().toISOString(),
          }),
        ).rejects.toThrow();
        released.resolve();
        expect(await callback).toMatchObject({
          code: mode === "classic" ? "connection_retired" : configured ? "app_not_found" : "request_key_conflict",
        });
        expect(await other.connectionStore.get("example", name)).toBeUndefined();
        expect(exchange).toHaveBeenCalledTimes(1);
        await second.connections.disconnect("example", name);
        expect(await other.connectionStore.getRetirementGeneration("example", name)).not.toBe(retired);
        const renewed = harness.forScope({ ...db.scope, oauthSessionId: crypto.randomUUID() });
        const fresh = createServices(renewed, {
          async exchangeCode() {
            return { accessToken: "fresh-token", tokenType: "Bearer", metadata: {} };
          },
        });
        const next =
          mode === "classic"
            ? await fresh.flow.startAuthorization({ service: "example", connectionName: name })
            : await fresh.flow.startConnectionRequest({
                service: "example",
                connectionName: name,
                owner: renewed.scope.subjectUserId,
              });
        await expect(
          fresh.flow.completeAuthorization({
            state: "state" in next ? next.state : next.stateHandle,
            code: "fresh-code",
          }),
        ).resolves.toMatchObject({ service: "example", connected: true });
        expect(await renewed.connectionStore.get("example", name)).toMatchObject({
          credential: { accessToken: "fresh-token" },
        });
        const isolated = harness.forScope({ ...db.scope, tenantId: crypto.randomUUID() });
        expect(await isolated.connectionStore.get("example", name)).toBeUndefined();
      }
    },
  );
});
function createServices(
  database: NativePostgresFixture,
  runtime: ProviderOAuthRuntime,
): { connections: ConnectionService; flow: OAuthFlowService } {
  const catalog = createCatalogStore([provider]);
  const providerLoader = new ProviderLoader({ example: async () => ({ executors: {}, oauth: runtime }) });
  const config: OAuthClientConfig = {
    service: "example",
    clientId: "client",
    clientSecret: "private-client",
    extra: {},
    secretExtra: {},
  };
  const clientConfigs = new OAuthClientConfigService({
    catalog,
    origin: "https://runtime.example.com",
    store: {
      async get() {
        return config;
      },
      async list() {
        return [config];
      },
      async set() {
        throw new Error("Fixture config is immutable");
      },
      async delete() {
        throw new Error("Fixture config is immutable");
      },
    },
  });
  const connections = new ConnectionService({
    catalog,
    providerLoader,
    store: database.connectionStore,
    oauthCredentials: new OAuthCredentialRefreshService(clientConfigs, providerLoader),
  });
  const flow = new OAuthFlowService({
    connections,
    clientConfigs,
    providerLoader,
    states: database.oauthStateStore,
    requests: database.connectionRequests,
    secretCodec: database.secretCodec,
    authorizationSessionId: database.scope.oauthSessionId,
  });
  return { connections, flow };
}
