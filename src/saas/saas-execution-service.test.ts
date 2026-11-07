import type { ProviderDefinition } from "../core/types.ts";
import type { SaasRequestScope } from "./contracts.ts";

import { describe, expect, it } from "vitest";
import { createCatalogStore } from "../catalog-store.ts";
import { ConnectionService } from "../connection-service.ts";
import { resolveExecutionTarget } from "../execution-target.ts";
import { createScopedNativeServices } from "./scoped-native-services.ts";
import { createNativePostgresHarness } from "./testing/native-store-fixtures.ts";

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
const catalog = createCatalogStore([provider]);
const harness = createNativePostgresHarness();
const loader = {
  async loadActionExecutor() {
    throw new Error("No local fallback for a managed connection");
  },
  async loadProxyExecutor() {
    throw new Error("No local fallback for a managed connection");
  },
  async loadCredentialValidators() {
    throw new Error("Managed execution must not fetch local provider credentials");
  },
};
function nativePath(url: unknown): string {
  return new URL(String(url)).pathname.replace(/^\/v1\/saas/, "");
}

/** Real PG account lineage + native parsed HTTP protocol fixture, not a real provider account. */
async function setup() {
  const db = harness.forScope();
  const project = {
    id: crypto.randomUUID(),
    projectId: "actual-project",
    baseUrl: "https://saas.example",
    apiKey: "actual-workspace-key",
  };
  await db.saasProjects.saveProject(project);
  const pending = {
    connectionRequestId: crypto.randomUUID(),
    connectionId: crypto.randomUUID(),
    owner: db.scope.subjectUserId,
    service: "example",
    connectionName: "managed",
    managedProjectId: project.id,
    providerConfigId: "selected-config",
    externalUserId: db.saasProjects.externalUserId(),
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
  };
  const lease = await db.connectionRequests.createSaas(pending);
  await db.connectionRequests.saveSaasRequest(lease, "actual-request");
  await db.connectionRequests.saveSaasCandidate(lease, {
    connectedAccountId: "actual-account",
    profile: { accountId: "actual-provider-user", displayName: "Actual User", grantedScopes: ["read"] },
    status: "active",
    comment: null,
  });
  expect(await db.connectionRequests.completeSaas(lease)).toBe("connected");
  const reference = (await db.connectionStore.getById(pending.connectionId))!;
  if (reference.source !== "saas") throw new Error("Fixture must create native managed state");
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const behavior = {
    actions: ["example.read"],
    proxyAvailable: true,
    dispatch: async (_url: string, _init?: RequestInit): Promise<Response> =>
      Response.json({
        success: true,
        data: { executionId: "actual-execution", actionId: "example.read", output: { value: "remote-result" } },
      }),
  };
  const fetcher: typeof fetch = async (url, init) => {
    requests.push({ url: String(url), init });
    if (nativePath(url) === "/oauth/provider-configs")
      return Response.json({
        success: true,
        data: {
          projectId: project.projectId,
          providerConfigs: [
            {
              id: "selected-config",
              service: "example",
              displayName: "Example",
              callbackUrl: "https://saas.example/callback",
              effectiveScopes: ["read"],
              actionIds: behavior.actions,
              proxyAvailable: behavior.proxyAvailable,
            },
          ],
        },
      });
    return behavior.dispatch(String(url), init);
  };
  function execution(overrides: Partial<SaasRequestScope> = {}) {
    const scoped = harness.forScope({
      ...db.scope,
      purpose: "action:execute:v2",
      permissions: ["action:execute:v2"],
      connectorConnectionId: pending.connectionId,
      actionId: "example.read",
      ...overrides,
    });
    const native = createScopedNativeServices({
      scope: scoped.scope,
      catalog,
      runtime: scoped,
      configuredOrigin: "https://connect.example",
      managedCompletionUri: "https://backend.example/managed/continue",
      fetcher,
    });
    const connections = new ConnectionService({
      catalog,
      store: scoped.connectionStore,
      providerLoader: loader,
      marketplace: native.marketplace,
    });
    return {
      db: scoped,
      native,
      async run() {
        const target = await resolveExecutionTarget({
          connections,
          service: "example",
          connectionId: pending.connectionId,
          operation: "action",
          actionId: "example.read",
        });
        if (target.kind !== "saas") throw new Error("Wrong native execution target");
        return native.saasExecution.executeAction(target.reference, "example", "example.read", { value: "request" });
      },
    };
  }
  return { db, project, pending, reference: reference.reference, execution, requests, behavior };
}

describe.skipIf(!harness.enabled)("scoped native managed execution", () => {
  it("dispatches the actual persisted account through the configured workspace project", async () => {
    const f = await setup();
    expect(await f.execution().run()).toEqual({
      executionId: "actual-execution",
      actionId: "example.read",
      output: { value: "remote-result" },
    });
    const dispatch = f.requests.find((item) => nativePath(item.url) === "/actions/example.read")!;
    expect(new Headers(dispatch.init?.headers).get("authorization")).toBe("Bearer actual-workspace-key");
    expect(JSON.parse(String(dispatch.init?.body))).toEqual({
      providerConfigId: "selected-config",
      userId: f.db.saasProjects.externalUserId(),
      connectedAccountId: "actual-account",
      input: { value: "request" },
    });
    expect(f.requests.every((item) => !/credentials|profile/.test(new URL(item.url).pathname))).toBe(true);
  });
  it("does not dispatch an unbound caller supplied vendor account", async () => {
    const f = await setup();
    await expect(
      f
        .execution()
        .native.saasExecution.executeAction(
          { ...f.reference, connectedAccountId: "foreign-account" },
          "example",
          "example.read",
          {},
        ),
    ).rejects.toMatchObject({ code: "connection_not_found" });
    expect(f.requests).toEqual([]);
  });
  it("rejects a foreign namespace and revoked sharing without borrowing the credential owner's identity", async () => {
    const f = await setup();
    await expect(f.execution({ tenantId: crypto.randomUUID() }).run()).rejects.toMatchObject({
      code: "connection_not_found",
    });
    const actor = crypto.randomUUID();
    await expect(f.execution({ actorUserId: actor }).run()).rejects.toMatchObject({ code: "connection_not_found" });
    await f.db.connectionStore.updateVisibilityById(f.pending.connectionId, "workspace");
    const shared = f.execution({ actorUserId: actor });
    expect(shared.db.scope.subjectUserId).toBe(f.db.scope.subjectUserId);
    expect(await shared.run()).toMatchObject({ output: { value: "remote-result" } });
    await f.db.connectionStore.updateVisibilityById(f.pending.connectionId, "user");
    await expect(
      shared.native.saasExecution.executeAction(f.reference, "example", "example.read", {}),
    ).rejects.toMatchObject({ code: "connection_not_found" });
    expect(f.requests.filter((item) => nativePath(item.url).startsWith("/actions/"))).toHaveLength(1);
  });
  it("honors changed workspace configuration on a fresh request rather than a startup snapshot", async () => {
    const f = await setup();
    expect(await f.execution().run()).toMatchObject({ output: { value: "remote-result" } });
    f.behavior.actions = [];
    await expect(f.execution().run()).rejects.toMatchObject({ code: "oauth_source_unsupported" });
    expect(f.requests.filter((item) => nativePath(item.url).startsWith("/actions/"))).toHaveLength(1);
  });
  it("detects a rotated workspace key and never silently uses a local credential", async () => {
    const f = await setup();
    const execution = f.execution();
    await execution.run();
    await f.db.saasProjects.saveProject({ ...f.project, apiKey: "rotated-workspace-key" });
    await execution.run();
    const actions = f.requests.filter((item) => nativePath(item.url).startsWith("/actions/"));
    expect(new Headers(actions[1].init?.headers).get("authorization")).toBe("Bearer rotated-workspace-key");
  });
  it("preserves a native insufficient-credit rejection and does not replay it locally", async () => {
    const f = await setup();
    f.behavior.dispatch = async () =>
      Response.json(
        {
          errorCode: "insufficient_credit",
          errorMessage: "private vendor detail",
          executionId: "rejected-native-execution",
        },
        { status: 402 },
      );
    await expect(f.execution().run()).rejects.toMatchObject({
      code: "insufficient_credit",
      remoteExecutionId: "rejected-native-execution",
    });
    expect(f.requests.filter((item) => nativePath(item.url).startsWith("/actions/"))).toHaveLength(1);
  });
  it("propagates inherited cancellation into the active native HTTP dispatch", async () => {
    const f = await setup();
    const controller = new AbortController();
    const { promise: started, resolve: dispatched } = Promise.withResolvers<void>();
    let remoteSignal: AbortSignal | undefined;
    f.behavior.dispatch = async (_url, init) => {
      remoteSignal = init?.signal ?? undefined;
      dispatched();
      const { promise, reject } = Promise.withResolvers<Response>();
      remoteSignal!.addEventListener("abort", () => reject(remoteSignal!.reason), { once: true });
      return promise;
    };
    const result = f.execution({ requestSignal: controller.signal }).run();
    const rejected = expect(result).rejects.toBeDefined();
    await started;
    controller.abort(new DOMException("Request ended", "AbortError"));
    await rejected;
    expect(remoteSignal?.aborted).toBe(true);
    expect(f.requests.filter((item) => nativePath(item.url).startsWith("/actions/"))).toHaveLength(1);
  });
  it("does not discover or dispatch after the processing deadline", async () => {
    const f = await setup();
    await expect(
      f
        .execution({ processingDeadlineMs: Date.now() - 1 })
        .native.saasExecution.executeAction(f.reference, "example", "example.read", {}),
    ).rejects.toMatchObject({ name: "TimeoutError" });
    expect(f.requests).toEqual([]);
  });
  it("retains native proxy capability and account selectors without credential access", async () => {
    const f = await setup();
    f.behavior.dispatch = async () =>
      Response.json({
        success: true,
        data: { status: 200, headers: {}, data: { value: "proxy" } },
        meta: { executionId: "actual-proxy-execution", service: "example" },
      });
    const result = await f
      .execution()
      .native.saasExecution.executeProxy(f.reference, "example", { endpoint: "/items", method: "GET" });
    expect(result).toMatchObject({
      executionId: "actual-proxy-execution",
      response: { status: 200, data: { value: "proxy" } },
    });
    const request = f.requests.find((item) => nativePath(item.url).startsWith("/proxy/"))!;
    expect(JSON.parse(String(request.init?.body))).toMatchObject({
      providerConfigId: "selected-config",
      userId: f.db.saasProjects.externalUserId(),
      connectedAccountId: "actual-account",
    });
  });
});
