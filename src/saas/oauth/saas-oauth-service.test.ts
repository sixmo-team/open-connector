import type { IConnectionStore, StoredConnection, StoredLocalConnection } from "../../connection-store.ts";
import type { ProviderDefinition, ResolvedCredential } from "../../core/types.ts";
import type { IOAuthClientConfigStore, OAuthClientConfig } from "../../oauth/oauth-client-config-service.ts";
import type { IOAuthStateStore, OAuthAuthorizationState } from "../../oauth/oauth-flow-service.ts";
import type { IProviderLoader } from "../../providers/provider-loader.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { SafeStoredConnection } from "../storage/postgres-connection-store.ts";

import { afterEach, describe, expect, it, vi } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import { OAuthFlowError } from "../../oauth/oauth-flow-service.ts";
import { SaasConnectServer } from "../server/saas-connect-server.ts";
import { MemoryLocalConnectionRequests } from "../testing/native-store-fixtures.ts";
import { SaasOAuthService, connectorAlias } from "./saas-oauth-service.ts";

const provider: ProviderDefinition = {
  service: "example",
  displayName: "Example",
  categories: ["Developer Tools"],
  authTypes: ["oauth2"],
  auth: [
    {
      type: "oauth2",
      authorizationUrl: "https://provider.example/authorize",
      tokenUrl: "https://provider.example/token",
      scopes: ["read"],
      authorizationOptions: [
        {
          id: "read",
          label: "Read",
          description: "Read account data",
          required: true,
          defaultSelected: true,
          risk: "standard",
        },
        {
          id: "write",
          label: "Write",
          description: "Update account data",
          required: false,
          defaultSelected: false,
          risk: "sensitive",
        },
      ],
      tokenEndpointAuthMethod: "client_secret_post",
    },
  ],
  actions: [],
};
const catalog = createCatalogStore([provider]);
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
const clientConfigs: IOAuthClientConfigStore = {
  async get(service) {
    return service === "example"
      ? { service, clientId: "client-id", clientSecret: "client-secret", extra: {}, secretExtra: {} }
      : undefined;
  },
  async set() {},
  async delete() {},
  async list(): Promise<OAuthClientConfig[]> {
    return [];
  },
};

interface Stores {
  connections: MemoryConnectionStore;
  states: MemoryOAuthStateStore;
}

describe("SaasOAuthService", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });
  it("rejects forged callback provenance without consuming the authorization", async () => {
    const scoped = stores();
    const state = await startState(service("oauth:start", scoped));
    await expect(
      service("oauth:complete", scoped).complete({
        state,
        code: "trusted",
        callbackQuery: `state=${state}&code=forged`,
        callbackParameters: { state, code: "trusted" },
      }),
    ).rejects.toMatchObject({ code: "invalid_oauth_state" });
    expect(await scoped.states.take(state)).toMatchObject({ state });
  });

  it("honors selected provider scopes over HTTP and rejects a forged callback without consuming valid authorization", async () => {
    const scoped = stores();
    const app = new SaasConnectServer({
      catalog,
      providerLoader,
      verifyJwt: async (authorization) => {
        const purpose = authorization === "Bearer complete" ? "oauth:complete" : "oauth:start";
        return {
          tenantId: "tenant-a",
          workspaceId: "workspace-a",
          actorUserId: "user-a",
          subjectUserId: "user-a",
          workspaceRole: "member",
          purpose,
          permissions: [purpose],
          localConnectionId: "11111111-1111-4111-8111-111111111111",
          oauthSessionId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        };
      },
      readiness: async () => ({
        postgres: true,
        openBao: true,
        jwks: true,
        seaweedFs: true,
        providerRegistry: true,
        catalogFingerprint: true,
      }),
      oauthServiceFactory: { forScope: (scope) => service(scope.purpose, scoped, scope) },
    }).createApp();
    const binding = {
      localConnectionId: "11111111-1111-4111-8111-111111111111",
      oauthSessionId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    };
    const start = await app.request("/internal/saas/oauth/start", {
      method: "POST",
      headers: { authorization: "Bearer start", "content-type": "application/json" },
      body: JSON.stringify({ ...binding, service: "example", authorizationOptionIds: ["write"] }),
    });
    expect(start.status).toBe(200);
    const authorize = new URL((await start.json()).authorizeUrl);
    expect(new Set(authorize.searchParams.get("scope")!.split(" "))).toEqual(new Set(["read", "write"]));
    const state = authorize.searchParams.get("state")!;
    const complete = (callbackQuery: string) =>
      app.request("/internal/saas/oauth/complete", {
        method: "POST",
        headers: { authorization: "Bearer complete", "content-type": "application/json" },
        body: JSON.stringify({
          ...binding,
          state,
          code: "trusted",
          callbackQuery,
          callbackParameters: { state, code: "trusted" },
        }),
      });
    expect((await complete(new URLSearchParams({ state, code: "forged" }).toString())).status).toBe(400);
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () => Response.json({ access_token: "native-http-access", token_type: "Bearer" })),
    );
    expect((await complete(new URLSearchParams({ state, code: "trusted" }).toString())).status).toBe(200);
    expect(await scoped.connections.get("example", connectorAlias(binding.localConnectionId))).toMatchObject({
      credential: { accessToken: "native-http-access" },
    });
    expect(await scoped.states.take(state)).toBeUndefined();
  });

  it("does not let a different verified session consume a pending state", async () => {
    const scoped = stores();
    const state = await startState(service("oauth:start", scoped));
    await expect(
      service("oauth:complete", scoped, { oauthSessionId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" }).complete({
        state,
        code: "trusted",
      }),
    ).rejects.toMatchObject({ code: "invalid_oauth_state" });
    expect(await scoped.states.take(state)).toMatchObject({
      state,
      oauthSessionId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    });
  });

  it("keeps tenant and user state isolated", async () => {
    const tenantA = stores();
    const tenantB = stores();
    const userB = stores();
    const state = await startState(service("oauth:start", tenantA));

    await expect(
      service("oauth:complete", tenantB, { tenantId: "tenant-b" }).complete({ state, code: "code" }),
    ).rejects.toBeInstanceOf(OAuthFlowError);
    await expect(
      service("oauth:complete", userB, { actorUserId: "user-b", subjectUserId: "user-b" }).complete({
        state,
        code: "code",
      }),
    ).rejects.toBeInstanceOf(OAuthFlowError);
  });

  it("rejects expired and connection-mismatched state before token exchange", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-04T10:00:00.000Z"));
    const scoped = stores();
    const state = await startState(service("oauth:start", scoped));
    vi.setSystemTime(new Date("2026-08-04T10:16:00.000Z"));
    const tokenExchange = vi.fn();
    vi.stubGlobal("fetch", tokenExchange);

    await expect(service("oauth:complete", scoped).complete({ state, code: "code" })).rejects.toMatchObject({
      code: "invalid_oauth_state",
    });
    expect(tokenExchange).not.toHaveBeenCalled();

    const mismatchStores = stores();
    const mismatchState = await startState(service("oauth:start", mismatchStores));
    await expect(
      service("oauth:complete", mismatchStores, { localConnectionId: "22222222-2222-4222-8222-222222222222" }).complete(
        {
          state: mismatchState,
          code: "code",
        },
      ),
    ).rejects.toMatchObject({ code: "invalid_oauth_state" });
    expect(tokenExchange).not.toHaveBeenCalled();
  });

  it("consumes fresh reconnect state and replaces credentials for the same connector alias", async () => {
    const scoped = stores();
    const firstState = await startState(service("oauth:start", scoped));
    const tokenExchange = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "old-access", token_type: "Bearer" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "new-access", token_type: "Bearer" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", tokenExchange);

    await service("oauth:complete", scoped).complete({ state: firstState, code: "old-code" });
    await expect(
      scoped.connections.get("example", connectorAlias("11111111-1111-4111-8111-111111111111")),
    ).resolves.toMatchObject({ credential: { authType: "oauth2", accessToken: "old-access" } });
    const reconnectScope = { oauthSessionId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" };
    const reconnectState = await startState(service("oauth:start", scoped, reconnectScope));
    const completion = await service("oauth:complete", scoped, reconnectScope).complete({
      state: reconnectState,
      code: "new-code",
    });

    expect(reconnectState).not.toBe(firstState);
    expect(completion).toMatchObject({
      localConnectionId: "11111111-1111-4111-8111-111111111111",
      service: "example",
      connectionName: connectorAlias("11111111-1111-4111-8111-111111111111"),
      status: "active",
    });
    expect(tokenExchange).toHaveBeenCalledTimes(2);
    expect(String(tokenExchange.mock.calls[1]?.[1]?.body)).toContain("code=new-code");
    await expect(scoped.states.take(reconnectState)).resolves.toBeUndefined();
    await expect(
      scoped.connections.get("example", connectorAlias("11111111-1111-4111-8111-111111111111")),
    ).resolves.toMatchObject({ credential: { authType: "oauth2", accessToken: "new-access" } });
    await expect(
      service("oauth:complete", scoped, reconnectScope).complete({ state: reconnectState, code: "new-code" }),
    ).resolves.toEqual(completion);
    expect(tokenExchange).toHaveBeenCalledTimes(2);
    await expect(
      service("oauth:complete", scoped, {
        oauthSessionId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      }).complete({ state: reconnectState, code: "new-code" }),
    ).rejects.toMatchObject({ code: "invalid_oauth_state" });
  });
});

function stores(): Stores {
  return { connections: new MemoryConnectionStore(), states: new MemoryOAuthStateStore() };
}

function service(
  purpose: SaasRequestScope["purpose"],
  scoped: Stores,
  overrides: Partial<SaasRequestScope> = {},
): SaasOAuthService {
  const scope: Readonly<SaasRequestScope> = Object.freeze({
    tenantId: "tenant-a",
    workspaceId: "workspace-a",
    actorUserId: "user-a",
    subjectUserId: "user-a",
    workspaceRole: "member",
    purpose,
    permissions: Object.freeze([purpose]) as string[],
    localConnectionId: "11111111-1111-4111-8111-111111111111",
    oauthSessionId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    ...overrides,
  });
  return new SaasOAuthService({
    scope,
    catalog,
    providerLoader,
    connectionStore: scoped.connections,
    oauthStateStore: scoped.states,
    connectionRequests: new MemoryLocalConnectionRequests(scoped.connections),
    oauthClientConfigStore: clientConfigs,
    callbackOrigin: "https://api.example/integrations",
  });
}

async function startState(oauth: SaasOAuthService): Promise<string> {
  const { authorizeUrl } = await oauth.start("example");
  const url = new URL(authorizeUrl);
  expect(url.searchParams.get("redirect_uri")).toBe("https://api.example/integrations/oauth/callback");
  const state = url.searchParams.get("state");
  if (!state) throw new Error("Missing test OAuth state");
  return state;
}

class MemoryOAuthStateStore implements IOAuthStateStore {
  private readonly values = new Map<string, OAuthAuthorizationState>();
  async deleteCreatedBefore(cutoff: string): Promise<void> {
    for (const [key, state] of this.values) if (state.createdAt < cutoff) this.values.delete(key);
  }

  async set(state: OAuthAuthorizationState): Promise<void> {
    this.values.set(state.state, state);
  }

  async take(
    state: string,
    binding?: { connectionName: string; oauthSessionId: string },
  ): Promise<OAuthAuthorizationState | undefined> {
    const pending = this.values.get(state);
    if (
      binding &&
      (pending?.connectionName !== binding.connectionName || pending.oauthSessionId !== binding.oauthSessionId)
    )
      return undefined;
    this.values.delete(state);
    return pending;
  }
}

class MemoryConnectionStore implements IConnectionStore {
  private readonly values = new Map<string, StoredConnection>();
  private readonly generations = new Map<string, string>();
  async getById(id: string): Promise<StoredConnection | undefined> {
    return [...this.values.values()].find((connection) => connection.id === id);
  }
  async getSafeConnection(id: string): Promise<SafeStoredConnection | undefined> {
    const connection = await this.getById(id);
    return connection
      ? {
          id: connection.id,
          service: connection.service,
          connectionName: connection.connectionName,
          localConnectionId: "11111111-1111-4111-8111-111111111111",
          subjectUserId: "user-a",
          visibility: "user",
          status: "active",
          createdAt: "2026-11-06T00:00:00.000Z",
          updatedAt: "2026-11-06T00:00:00.000Z",
        }
      : undefined;
  }
  async getRetirementGeneration(service: string, name: string): Promise<string> {
    const key = `${service}:${name}`;
    let generation = this.generations.get(key);
    if (!generation) {
      generation = crypto.randomUUID();
      this.generations.set(key, generation);
    }
    return generation;
  }
  async setIfCurrentGeneration(
    service: string,
    name: string,
    credential: ResolvedCredential,
    generation: string,
  ): Promise<StoredLocalConnection | undefined> {
    if ((await this.getRetirementGeneration(service, name)) !== generation) return undefined;
    return this.set(service, name, credential);
  }

  async get(service: string, connectionName: string): Promise<StoredConnection | undefined> {
    return this.values.get(`${service}:${connectionName}`);
  }

  async set(service: string, connectionName: string, credential: ResolvedCredential): Promise<StoredLocalConnection> {
    const key = `${service}:${connectionName}`;
    const connection = {
      id: this.values.get(key)?.id ?? crypto.randomUUID(),
      revision: crypto.randomUUID(),
      service,
      connectionName,
      credential,
    };
    this.values.set(key, connection);
    return connection;
  }

  async updateCredential(input: StoredLocalConnection): Promise<boolean> {
    this.values.set(`${input.service}:${input.connectionName}`, input);
    return true;
  }

  async delete(service: string, connectionName: string): Promise<void> {
    this.generations.set(`${service}:${connectionName}`, crypto.randomUUID());
    this.values.delete(`${service}:${connectionName}`);
  }

  async list(): Promise<StoredConnection[]> {
    return [...this.values.values()];
  }
}
