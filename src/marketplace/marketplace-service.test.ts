import type { ProviderDefinition } from "../core/types.ts";
import type { SaasRequestScope } from "../saas/contracts.ts";

import { afterEach, describe, expect, it } from "vitest";
import { createCatalogStore } from "../catalog-store.ts";
import { ConnectionService } from "../connection-service.ts";
import { setDefaultGuardedFetchDnsLookup } from "../core/guarded-fetch.ts";
import { withProviderNetworkPolicy } from "../core/provider-network-policy.ts";
import { resolveExecutionTarget } from "../execution-target.ts";
import { createNativePostgresHarness } from "../saas/testing/native-store-fixtures.ts";
import { MarketplaceService } from "./marketplace-service.ts";

const provider: ProviderDefinition = {
  service: "example",
  displayName: "Example",
  categories: [],
  authTypes: ["api_key"],
  auth: [{ type: "api_key" }],
  actions: [
    {
      id: "example.run",
      service: "example",
      name: "run",
      description: "Run",
      operationType: "write",
      requiredScopes: [],
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
    throw new Error("Marketplace must not execute the local provider");
  },
  async loadProxyExecutor() {
    return undefined;
  },
  async loadCredentialValidators() {
    return undefined;
  },
};
afterEach(() => setDefaultGuardedFetchDnsLookup(null));

/** Native protocol fixture only: no real Marketplace account or paid action is used by this test. */
function setup() {
  const db = harness.forScope({ purpose: "connection:write", permissions: ["connection:write"] });
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const behavior = {
    validationStatus: 204,
    result: () => Response.json({ success: true, data: { value: "vendor-result" } }),
    discovery: {
      version: 1,
      id: "actual-marketplace",
      name: "Actual Marketplace",
      pricing: "metered",
      validate: "/validate",
      endpoint: "/actions",
      actions: ["example.run"],
    },
  };
  const fetcher: typeof fetch = async (url, init) => {
    requests.push({ url: String(url), init });
    const path = new URL(String(url)).pathname;
    if (path === "/discovery") return Response.json(behavior.discovery);
    if (path === "/validate") return new Response(null, { status: behavior.validationStatus });
    if (path === "/actions/example.run") return behavior.result();
    throw new Error(`Unexpected Marketplace HTTP request ${path}`);
  };
  const service = new MarketplaceService({ scope: db.scope, catalog, store: db.connectionStore, fetcher });
  const connect = (input = {}) =>
    service.connect("example", {
      discoveryUrl: "https://marketplace.example/discovery",
      apiKey: "actual-vendor-key",
      connectionName: "market",
      actionIds: ["example.run"],
      ...input,
    });
  function execution(id: string, overrides: Partial<SaasRequestScope> = {}) {
    const scoped = harness.forScope({
      ...db.scope,
      purpose: "action:execute:v2",
      permissions: ["action:execute:v2"],
      connectorConnectionId: id,
      actionId: "example.run",
      ...overrides,
    });
    const marketplace = new MarketplaceService({
      scope: scoped.scope,
      catalog,
      store: scoped.connectionStore,
      fetcher,
    });
    const connections = new ConnectionService({
      catalog,
      store: scoped.connectionStore,
      providerLoader: loader,
      marketplace,
    });
    return {
      db: scoped,
      marketplace,
      connections,
      async run() {
        const target = await resolveExecutionTarget({
          connections,
          service: "example",
          connectionId: id,
          operation: "action",
          actionId: "example.run",
          marketplace,
        });
        expect(target.kind).toBe("marketplace");
        return marketplace.execute("example.run", { value: "request" });
      },
    };
  }
  return { db, service, connect, execution, behavior, requests };
}

describe.skipIf(!harness.enabled)("scoped native Marketplace", () => {
  it("persists a real scoped credential and executes only its explicit native action selection", async () => {
    const f = setup();
    const summary = await f.connect();
    expect(summary).toMatchObject({
      id: expect.any(String),
      virtual: false,
      authType: "marketplace",
      connectionName: "market",
      profile: { accountId: f.db.scope.localConnectionId },
    });
    expect(summary.id).not.toContain("marketplace:");
    const stored = await f.db.connectionStore.getById(summary.id);
    expect(stored).toMatchObject({
      credential: {
        authType: "api_key",
        metadata: {
          nativeMarketplace: {
            tenantId: f.db.scope.tenantId,
            workspaceId: f.db.scope.workspaceId,
            localConnectionId: f.db.scope.localConnectionId,
            actionIds: ["example.run"],
          },
        },
      },
    });
    expect(f.requests.map((item) => new URL(item.url).pathname)).toEqual(["/discovery", "/validate"]);
    const execution = f.execution(summary.id);
    expect(await execution.run()).toEqual({ ok: true, output: { value: "vendor-result" } });
    await expect(execution.connections.getCredential("example", "market")).rejects.toMatchObject({
      code: "unsupported_auth_type",
    });
    const dispatch = f.requests.find((item) => new URL(item.url).pathname === "/actions/example.run")!;
    expect(new Headers(dispatch.init?.headers).get("authorization")).toBe("Bearer actual-vendor-key");
    expect(JSON.parse(String(dispatch.init?.body))).toEqual({ input: { value: "request" } });
  });
  it("does not save a rejected key or probe authorization with a billable action", async () => {
    const f = setup();
    f.behavior.validationStatus = 401;
    await expect(f.connect()).rejects.toMatchObject({ code: "marketplace_auth_error" });
    expect(await f.db.connectionStore.list()).toEqual([]);
    expect(f.requests.map((item) => new URL(item.url).pathname)).toEqual(["/discovery", "/validate"]);
  });
  it.each([
    { actionIds: [] },
    { actionIds: ["*"] },
    { actionIds: ["example.run", "example.run"] },
    { actionIds: ["foreign.run"] },
  ])("requires explicit distinct current action IDs: %j", async ({ actionIds }) => {
    const f = setup();
    await expect(f.connect({ actionIds })).rejects.toMatchObject({ code: "invalid_input" });
    expect(await f.db.connectionStore.list()).toEqual([]);
    expect(f.requests.every((item) => new URL(item.url).pathname === "/discovery")).toBe(true);
  });
  it("never dispatches a cached credential after local disconnect", async () => {
    const f = setup();
    const summary = await f.connect();
    const execution = f.execution(summary.id);
    await execution.connections.getConnectionSummary("example", "market", summary.id);
    await f.db.connectionStore.delete("example", "market");
    await expect(execution.marketplace.execute("example.run", {})).rejects.toMatchObject({
      code: "connection_not_found",
    });
    expect(f.requests.some((item) => new URL(item.url).pathname.startsWith("/actions/"))).toBe(false);
  });
  it("rejects foreign tenants and a private credential used by another actor before dispatch", async () => {
    const f = setup();
    const summary = await f.connect();
    await expect(f.execution(summary.id, { tenantId: crypto.randomUUID() }).run()).rejects.toMatchObject({
      code: "connection_not_found",
    });
    await expect(f.execution(summary.id, { actorUserId: crypto.randomUUID() }).run()).rejects.toMatchObject({
      code: "connection_not_found",
    });
    expect(f.requests.some((item) => new URL(item.url).pathname.startsWith("/actions/"))).toBe(false);
  });
  it("preserves the real actor and credential owner for a genuinely shared connection", async () => {
    const f = setup();
    const summary = await f.connect();
    await f.db.connectionStore.updateVisibilityById(summary.id, "workspace");
    const actor = crypto.randomUUID();
    const execution = f.execution(summary.id, { actorUserId: actor });
    expect(execution.db.scope.subjectUserId).toBe(f.db.scope.subjectUserId);
    expect(execution.db.scope.actorUserId).toBe(actor);
    expect(await execution.run()).toMatchObject({ ok: true });
    await f.db.connectionStore.updateVisibilityById(summary.id, "user");
    await expect(execution.marketplace.execute("example.run", {})).rejects.toMatchObject({
      code: "connection_not_found",
    });
  });
  it("fails closed when the configured Marketplace identity or action capability changes", async () => {
    const f = setup();
    const summary = await f.connect();
    f.behavior.discovery.id = "replacement-marketplace";
    await expect(f.execution(summary.id).run()).rejects.toMatchObject({ code: "connection_changed" });
    expect(f.requests.some((item) => new URL(item.url).pathname.startsWith("/actions/"))).toBe(false);
  });
  it("does not dispatch after an inherited abort or expired processing deadline", async () => {
    const f = setup();
    const summary = await f.connect();
    const controller = new AbortController();
    controller.abort(new DOMException("Stopped", "AbortError"));
    await expect(
      f.execution(summary.id, { requestSignal: controller.signal }).marketplace.execute("example.run", {}),
    ).rejects.toMatchObject({ name: "AbortError" });
    await expect(
      f.execution(summary.id, { processingDeadlineMs: Date.now() - 1 }).marketplace.execute("example.run", {}),
    ).rejects.toMatchObject({ name: "TimeoutError" });
    expect(f.requests.some((item) => new URL(item.url).pathname.startsWith("/actions/"))).toBe(false);
  });
  it("preserves structured vendor business rejection without local fallback", async () => {
    const f = setup();
    const summary = await f.connect();
    f.behavior.result = () =>
      Response.json({
        success: false,
        errorCode: "insufficient_credit",
        message: "No credit",
        data: { retryAfter: "later" },
      });
    expect(await f.execution(summary.id).run()).toMatchObject({
      ok: false,
      error: { code: "insufficient_credit", details: { retryAfter: "later" } },
    });
  });
  it("rejects successful-looking redirected action output", async () => {
    const f = setup();
    const summary = await f.connect();
    f.behavior.result = () =>
      new Response(JSON.stringify({ success: true, data: {} }), {
        status: 302,
        headers: { location: "https://foreign.example/action" },
      });
    expect(await f.execution(summary.id).run()).toMatchObject({
      ok: false,
      error: { code: "marketplace_unavailable" },
    });
  });
  it("rejects malformed or cross-origin native discovery endpoints", async () => {
    const f = setup();
    f.behavior.discovery.endpoint = "//foreign.example/actions";
    await expect(f.connect()).rejects.toMatchObject({ code: "invalid_marketplace_discovery" });
    expect(await f.db.connectionStore.list()).toEqual([]);
  });
  it.each(["http", "https"])("retains %s pure outbound transport on explicitly trusted VPN hosts", async (protocol) => {
    const f = setup();
    await withProviderNetworkPolicy({ trustedHosts: ["marketplace.example"] }, async () => {
      setDefaultGuardedFetchDnsLookup(async () => [{ address: "10.0.0.2", family: 4 }]);
      const summary = await f.connect({ discoveryUrl: `${protocol}://marketplace.example/discovery` });
      expect(await f.execution(summary.id).run()).toMatchObject({ ok: true });
    });
  });
});
