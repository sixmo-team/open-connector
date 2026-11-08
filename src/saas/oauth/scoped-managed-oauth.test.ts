import type { ProviderDefinition } from "../../core/types.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { NativePostgresFixture } from "../testing/native-store-fixtures.ts";

import { afterEach, describe, expect, it, vi } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import { SaasClient } from "../saas-client.ts";
import { SaasOAuthService as ManagedOAuthService } from "../saas-oauth-service.ts";
import { SaasProjectService } from "../saas-project-service.ts";
import { createScopedNativeServices } from "../scoped-native-services.ts";
import { SaasConnectServer } from "../server/saas-connect-server.ts";
import { withScopedClient } from "../storage/scoped-query.ts";
import { createNativePostgresHarness } from "../testing/native-store-fixtures.ts";
import { SaasOAuthService, connectorAlias } from "./saas-oauth-service.ts";

const provider: ProviderDefinition = {
  service: "example",
  displayName: "Example",
  categories: [],
  authTypes: ["oauth2"],
  auth: [
    {
      type: "oauth2",
      authorizationUrl: "https://provider.example/authorize",
      tokenUrl: "https://provider.example/token",
      scopes: ["read"],
      tokenEndpointAuthMethod: "client_secret_post",
    },
  ],
  actions: [
    {
      id: "example.read",
      service: "example",
      name: "read",
      description: "Read",
      operationType: "read",
      requiredScopes: ["read"],
      providerPermissions: [],
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
    },
  ],
};
const catalog = createCatalogStore([provider], { executableActionIds: ["example.read"] });
const loader = {
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
const harness = createNativePostgresHarness();
afterEach(() => vi.restoreAllMocks());

/** Protocol fixture, not a real vendor account: real scoped PostgreSQL stores and native client parse every response. */
async function setup() {
  const db = harness.forScope();
  const project = {
    id: crypto.randomUUID(),
    projectId: crypto.randomUUID(),
    baseUrl: "https://saas.example",
    apiKey: "workspace-project-key",
  };
  await db.saasProjects.saveProject(project, null);
  await db.saasProjects.setSource("example", { managedProjectId: project.id, providerConfigId: "selected-config" });
  let link: { providerConfigId: string; userId: string; alias: string } | undefined;
  let connected = false;
  let accountStatus: "active" | "reauth_required" = "active";
  let polls = 0;
  const behavior = { beforePoll: async (_signal?: AbortSignal | null): Promise<void> => {} };
  const remote = () => ({
    id: "vendor-request",
    projectId: project.projectId,
    providerConfigId: link!.providerConfigId,
    externalUserId: link!.userId,
    alias: link!.alias,
    service: "example",
    status: connected ? "connected" : "initiated",
    authorizationUrl: "https://saas.example/authorize",
    connectedAccountId: connected ? "vendor-account" : null,
    errorCode: null,
    errorMessage: null,
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
    createdAt: Date.now(),
    updatedAt: Date.now(),
  });
  const fetcher: typeof fetch = async (url, init) => {
    const path = new URL(String(url)).pathname.replace(/^\/v1\/saas/, "");
    let data: unknown;
    if (path === "/oauth/provider-configs")
      data = {
        projectId: project.projectId,
        providerConfigs: [
          {
            id: "selected-config",
            service: "example",
            displayName: "Example",
            callbackUrl: "https://saas.example/callback",
            effectiveScopes: ["read"],
            actionIds: ["example.read"],
            proxyAvailable: false,
          },
        ],
      };
    else if (path === "/connected-accounts/link") {
      link = JSON.parse(String(init?.body));
      data = remote();
    } else if (path === "/connection-requests/vendor-request") {
      polls++;
      await behavior.beforePoll(init?.signal);
      data = remote();
    } else if (path === "/connected-accounts/vendor-account")
      data = {
        connectedAccountId: "vendor-account",
        projectId: project.projectId,
        providerConfigId: link!.providerConfigId,
        externalUserId: link!.userId,
        alias: link!.alias,
        service: "example",
        status: accountStatus,
        providerAccountId: "actual-provider-user",
        accountLabel: "Actual account",
        scopes: ["read"],
      };
    else throw new Error(`Unexpected native HTTP request: ${path}`);
    return Response.json({ success: true, data });
  };
  const client = new SaasClient(fetcher);
  function oauth(
    scoped: NativePostgresFixture,
    completionUri: string | undefined = "https://backend.example/managed-oauth/continue",
    allowCustom = false,
  ) {
    const projects = new SaasProjectService({
      catalog,
      store: scoped.saasProjects,
      secretCodec: scoped.secretCodec,
      configuredOrigin: "https://connect.example",
      client,
    });
    return new SaasOAuthService({
      scope: scoped.scope,
      catalog,
      providerLoader: loader,
      connectionStore: scoped.connectionStore,
      oauthStateStore: scoped.oauthStateStore,
      connectionRequests: scoped.connectionRequests,
      oauthClientConfigStore: {
        async get() {
          return undefined;
        },
        async list() {
          return [];
        },
        async set() {},
        async delete() {},
      },
      callbackOrigin: "https://connect.example",
      secretCodec: scoped.secretCodec,
      isCustomClientConfigAllowed: () => allowCustom,
      managedOAuth: new ManagedOAuthService({ projects, requests: scoped.connectionRequests, client, completionUri }),
    });
  }
  function http(overrides: Partial<SaasRequestScope> = {}) {
    const scope: SaasRequestScope = {
      ...db.scope,
      purpose: "oauth:complete",
      permissions: ["oauth:complete"],
      ...overrides,
    };
    return new SaasConnectServer({
      catalog,
      providerLoader: loader,
      verifyJwt: async () => scope,
      readiness: async () => ({
        postgres: true,
        openBao: true,
        jwks: true,
        seaweedFs: true,
        providerRegistry: true,
        catalogFingerprint: true,
      }),
      runtimeDatabaseFactory: harness.factory,
      credentialRevoker: {
        async revoke() {
          throw new Error("Managed accounts have no direct provider credential");
        },
      },
      oauthServiceFactory: { forScope: (signedScope) => oauth(harness.forScope(signedScope)) },
    }).createApp();
  }
  return {
    db,
    oauth,
    http,
    behavior,
    fetcher,
    connect(status: "active" | "reauth_required" = "active") {
      connected = true;
      accountStatus = status;
    },
    polls: () => polls,
    link: () => link,
  };
}

describe.skipIf(!harness.enabled)("scoped native managed OAuth", () => {
  it("starts the selected managed source instead of falling back to local OAuth", async () => {
    const f = await setup();
    const result = await f.oauth(f.db).start("example");
    expect(result).toMatchObject({
      authorizeUrl: "https://saas.example/authorize",
      connectionRequestId: expect.any(String),
      status: "initiated",
    });
    expect(f.link()?.userId).toBe(f.db.saasProjects.externalUserId());
    expect(await f.db.connectionStore.list()).toEqual([]);
  });
  it("polls only the original session and installs the authentic managed account", async () => {
    const f = await setup();
    const started = await f.oauth(f.db).start("example");
    const id = started.connectionRequestId!;
    const wrongSession = harness.forScope({
      ...f.db.scope,
      purpose: "oauth:complete",
      oauthSessionId: crypto.randomUUID(),
    });
    expect(await f.oauth(wrongSession).getRequest(id)).toBeUndefined();
    expect(f.polls()).toBe(0);
    f.connect();
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 3_000);
    const complete = harness.forScope({ ...f.db.scope, purpose: "oauth:complete" });
    const result = await f.oauth(complete).getRequest(id);
    expect(result).toMatchObject({
      request: { status: "connected" },
      connection: {
        id: expect.any(String),
        localConnectionId: f.db.scope.localConnectionId,
        connectionName: connectorAlias(f.db.scope.localConnectionId!),
        profile: { accountId: "actual-provider-user", displayName: "Actual account" },
      },
    });
    const stored = await complete.connectionStore.getById(result!.connection!.id);
    expect(stored).toMatchObject({
      source: "saas",
      reference: {
        externalUserId: f.db.saasProjects.externalUserId(),
        connectedAccountId: "vendor-account",
        localRequestId: id,
      },
    });
    expect(stored).not.toHaveProperty("credential");
  });
  it("disconnects a managed account durably without inventing a local credential or losing remote cleanup", async () => {
    const f = await setup();
    const started = await f.oauth(f.db).start("example");
    f.connect();
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 3000);
    const complete = harness.forScope({ ...f.db.scope, purpose: "oauth:complete" });
    const connected = await f.oauth(complete).getRequest(started.connectionRequestId!);
    const id = connected!.connection!.id;
    const app = f.http({ purpose: "connection:write", permissions: ["connection:write"], connectorConnectionId: id });
    const path = `/internal/saas/connections/${id}`;
    expect((await app.request(path, { method: "DELETE" })).status).toBe(204);
    expect(await complete.connectionStore.getById(id)).toBeUndefined();
    expect(await complete.connectionStore.hasRevocationReceipt(id)).toBe(true);
    expect(await complete.saasProjects.getCleanupStats()).toEqual({ pending: 1, manual: 0, paused: false });
    expect((await app.request(path, { method: "DELETE" })).status).toBe(204);
    expect(await complete.saasProjects.getCleanupStats()).toEqual({ pending: 1, manual: 0, paused: false });
  });
  it("cancels provider revocation at the owner's processing boundary while the HTTP client stays connected", async () => {
    const f = await setup();
    const connection = await f.db.connectionStore.set("example", "local-owned", {
      authType: "oauth2",
      accessToken: "private-owned-token",
      tokenType: "Bearer",
      profile: { accountId: "owned", displayName: "Owned", grantedScopes: [] },
      metadata: {},
    });
    const owner = new AbortController();
    const entered = Promise.withResolvers<void>(),
      released = Promise.withResolvers<void>(),
      finished = Promise.withResolvers<void>();
    let effects = 0;
    const scope: SaasRequestScope = {
      ...f.db.scope,
      purpose: "connection:write",
      permissions: ["connection:write"],
      connectorConnectionId: connection.id,
    };
    const app = new SaasConnectServer({
      catalog,
      providerLoader: loader,
      verifyJwt: async () => scope,
      readiness: async () => ({
        postgres: true,
        openBao: true,
        jwks: true,
        seaweedFs: true,
        providerRegistry: true,
        catalogFingerprint: true,
      }),
      runtimeDatabaseFactory: harness.factory,
      credentialRevoker: {
        async revoke({ signal }) {
          entered.resolve();
          try {
            await released.promise;
            signal?.throwIfAborted();
            effects++;
            return "revoked";
          } finally {
            finished.resolve();
          }
        },
      },
    }).createApp();
    vi.spyOn(AbortSignal, "timeout").mockReturnValueOnce(owner.signal);
    const pending = app.request(`/internal/saas/connections/${connection.id}`, { method: "DELETE" });
    await entered.promise;
    owner.abort(new DOMException("Owner processing expired", "TimeoutError"));
    try {
      expect((await pending).status).toBe(503);
    } finally {
      released.resolve();
      await finished.promise;
    }
    expect(effects).toBe(0);
    expect(await f.db.connectionStore.getSafeConnection(connection.id)).toBeUndefined();
    const retained = await withScopedClient(harness.pool, f.db.scope, (client) =>
      client.query<{ status: string }>("SELECT status FROM integration_runtime.connections WHERE id = $1", [
        connection.id,
      ]),
    );
    expect(retained.rows).toEqual([{ status: "reconnect_required" }]);
  });
  it("completes managed authorization through the private request endpoint without leaking another session", async () => {
    const f = await setup();
    const started = await f.oauth(f.db).start("example");
    const path = `/internal/saas/oauth/requests/${started.connectionRequestId}`;
    expect((await f.http({ oauthSessionId: crypto.randomUUID() }).request(path)).status).toBe(404);
    const app = f.http();
    const pending = await app.request(path);
    expect(pending.status).toBe(200);
    expect(await pending.json()).toMatchObject({ request: { status: "initiated" } });
    f.connect();
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 3000);
    const completed = await app.request(path);
    expect(completed.status).toBe(200);
    const result = await completed.json();
    expect(result).toMatchObject({
      request: { status: "connected" },
      connection: { profile: { accountId: "actual-provider-user" } },
    });
    expect(JSON.stringify(result)).not.toContain("workspace-project-key");
    expect((await app.request(`${path}?tenantId=foreign`)).status).toBe(400);
  });
  it("cancels the actual pending request through the private endpoint before a late vendor completion", async () => {
    const f = await setup();
    const started = await f.oauth(f.db).start("example");
    const path = `/internal/saas/oauth/requests/${started.connectionRequestId}/cancel`;
    const app = f.http();
    expect(
      (
        await app.request(path, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: '{"tenantId":"foreign"}',
        })
      ).status,
    ).toBe(400);
    const cancelled = await app.request(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(cancelled.status).toBe(200);
    expect(await cancelled.json()).toMatchObject({ request: { status: "failed", errorCode: "request_cancelled" } });
    f.connect();
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 3000);
    const complete = harness.forScope({ ...f.db.scope, purpose: "oauth:complete" });
    expect(await f.oauth(complete).getRequest(started.connectionRequestId!)).toMatchObject({
      request: { status: "failed" },
    });
    expect(await complete.connectionStore.list()).toEqual([]);
  });
  it("reports the current stored visibility instead of relabeling a shared managed account as personal", async () => {
    const f = await setup();
    const started = await f.oauth(f.db).start("example");
    f.connect();
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 3000);
    const complete = harness.forScope({ ...f.db.scope, purpose: "oauth:complete" });
    const first = await f.oauth(complete).getRequest(started.connectionRequestId!);
    await complete.connectionStore.updateVisibilityById(first!.connection!.id, "workspace");
    expect(await f.oauth(complete).getRequest(started.connectionRequestId!)).toMatchObject({
      connection: { visibility: "workspace" },
    });
  });
  it("maps native reauth_required to the canonical private reconnect_required status", async () => {
    const f = await setup();
    const started = await f.oauth(f.db).start("example");
    f.connect("reauth_required");
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 3_000);
    const complete = harness.forScope({ ...f.db.scope, purpose: "oauth:complete" });
    expect(await f.oauth(complete).getRequest(started.connectionRequestId!)).toMatchObject({
      request: { status: "connected" },
      connection: { status: "reconnect_required" },
    });
  });
  it("overlays selected workspace readiness without probing an unrelated local application", async () => {
    const f = await setup();
    const metadata = harness.forScope({ ...f.db.scope, purpose: "connection:read", permissions: ["connection:read"] });
    const projectReads = vi.spyOn(metadata.saasProjects, "getProject");
    const native = createScopedNativeServices({
      scope: metadata.scope,
      catalog,
      runtime: metadata,
      configuredOrigin: "https://connect.example",
      managedCompletionUri: "https://backend.example/managed/continue",
      fetcher: f.fetcher,
    });
    const localReadiness = new Map([
      ["example", { status: "unavailable" as const, reasonCode: "oauth_client_config_missing" as const }],
    ]);
    expect((await native.getOAuthReadiness(localReadiness)).get("example")).toEqual({ status: "operational" });
    expect(projectReads).toHaveBeenCalledOnce();
    const incomplete = createScopedNativeServices({
      scope: metadata.scope,
      catalog,
      runtime: metadata,
      configuredOrigin: "https://connect.example",
      fetcher: f.fetcher,
    });
    expect((await incomplete.getOAuthReadiness(localReadiness)).get("example")).toEqual({
      status: "unavailable",
      reasonCode: "oauth_client_config_invalid",
    });
    await f.db.saasProjects.setSource("example", undefined);
    expect((await native.getOAuthReadiness(localReadiness)).get("example")).toEqual(localReadiness.get("example"));
  });
  it("cancels only the original session and never adopts the cancelled remote account", async () => {
    const f = await setup();
    const started = await f.oauth(f.db).start("example");
    const id = started.connectionRequestId!;
    const wrongLineage = harness.forScope({
      ...f.db.scope,
      purpose: "oauth:complete",
      localConnectionId: crypto.randomUUID(),
    });
    expect(await f.oauth(wrongLineage).cancelRequest(id)).toBeUndefined();
    const complete = harness.forScope({ ...f.db.scope, purpose: "oauth:complete" });
    expect(await f.oauth(complete).cancelRequest(id)).toMatchObject({
      request: { status: "failed", errorCode: "request_cancelled" },
    });
    f.connect();
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 3_000);
    expect(await f.oauth(complete).getRequest(id)).toMatchObject({ request: { status: "failed" } });
    expect(await complete.connectionStore.list()).toEqual([]);
    expect(f.polls()).toBe(0);
  });
  it("rejects per-request custom credentials for an explicitly managed source", async () => {
    const f = await setup();
    await expect(
      f.oauth(f.db).start("example", {
        clientConfig: { clientId: "foreign", clientSecret: "foreign", extra: {}, secretExtra: {} },
      }),
    ).rejects.toMatchObject({ code: "invalid_input" });
    expect(f.link()).toBeUndefined();
  });
  it("does not create a remote link without a configured real browser continuation", async () => {
    const f = await setup();
    await expect(f.oauth(f.db, "").start("example")).rejects.toMatchObject({
      code: "oauth_source_configuration_error",
    });
    expect(f.link()).toBeUndefined();
  });
  it("preserves a local custom OAuth lineage when the workspace later selects a managed default", async () => {
    const f = await setup();
    const clientConfig = {
      service: "example",
      clientId: "actual-local-client",
      clientSecret: "actual-local-secret",
      extra: {},
      secretExtra: {},
    };
    await f.db.connectionStore.set("example", connectorAlias(f.db.scope.localConnectionId!), {
      authType: "oauth2",
      accessToken: "old-local-token",
      tokenType: "Bearer",
      profile: { accountId: "actual-local-account", displayName: "Local account", grantedScopes: ["read"] },
      metadata: { oauthClientConfig: clientConfig },
    });
    const result = await f.oauth(f.db, "https://backend.example/managed/continue", true).start("example");
    const authorize = new URL(result.authorizeUrl);
    expect(authorize.origin).toBe("https://provider.example");
    expect(authorize.searchParams.get("client_id")).toBe("actual-local-client");
    expect(result.connectionRequestId).toBeUndefined();
    expect(f.link()).toBeUndefined();
    const state = await f.db.oauthStateStore.take(authorize.searchParams.get("state")!);
    expect(state).toMatchObject({
      clientConfigSource: "connection",
      clientConfig,
      oauthSessionId: f.db.scope.oauthSessionId,
    });
  });
  it("aborts actual native polling instead of leaving detached vendor work running", async () => {
    const f = await setup();
    const started = await f.oauth(f.db).start("example");
    f.connect();
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 3_000);
    const controller = new AbortController();
    const { promise: polling, resolve: polled } = Promise.withResolvers<void>();
    let remoteSignal: AbortSignal | undefined;
    f.behavior.beforePoll = async (signal) => {
      remoteSignal = signal ?? undefined;
      const { promise, reject } = Promise.withResolvers<void>();
      remoteSignal!.addEventListener("abort", () => reject(remoteSignal!.reason), { once: true });
      polled();
      return promise;
    };
    const complete = harness.forScope({ ...f.db.scope, purpose: "oauth:complete", requestSignal: controller.signal });
    const result = f.oauth(complete).getRequest(started.connectionRequestId!);
    const rejected = expect(result).rejects.toBeDefined();
    await polling;
    controller.abort(new DOMException("Request ended", "AbortError"));
    await rejected;
    expect(remoteSignal?.aborted).toBe(true);
    expect(await f.db.connectionStore.list()).toEqual([]);
  });
});
