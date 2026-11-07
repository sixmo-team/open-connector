import type { ProviderDefinition } from "../../core/types.ts";
import type { ActionPolicyTarget, SaasRequestScope } from "../contracts.ts";
import type { ServerType } from "@hono/node-server";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { serve } from "@hono/node-server";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import { setDefaultGuardedFetchDnsLookup } from "../../core/guarded-fetch.ts";
import { provider as shopifyProvider } from "../../providers/shopify/definition.ts";
import {
  credentialValidators as shopifyValidators,
  executors as shopifyExecutors,
} from "../../providers/shopify/executors.ts";
import { canonicalActionPolicyRequestHash, canonicalActionRequestHash } from "../actions/canonical-request.ts";
import { createSaasJwtVerifier } from "../auth/saas-jwt-verifier.ts";
import { createScopedNativeServices } from "../scoped-native-services.ts";
import { PostgresActionPolicyStore } from "../storage/postgres-action-policy-store.ts";
import { withScopedClient } from "../storage/scoped-query.ts";
import { createNativePostgresHarness } from "../testing/native-store-fixtures.ts";
import { SaasConnectServer } from "./saas-connect-server.ts";

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
const catalog = createCatalogStore([provider, shopifyProvider], { executableActionIds: ["shopify.get_shop"] });
const harness = createNativePostgresHarness();
const path = "/internal/saas/connections/marketplace";
const requests: Array<{ path: string; init?: RequestInit }> = [];
let privateKey: CryptoKey;
let baseUrl: string;
let policy: PostgresActionPolicyStore;
let listener: ServerType;
let jwks: Server;

// Only the remote vendor protocol is simulated; auth, private TCP HTTP, native connect, RLS and execution are real.
const vendor: typeof fetch = async (url, init) => {
  const remotePath = new URL(String(url)).pathname;
  requests.push({ path: remotePath, init });
  if (remotePath === "/discovery")
    return Response.json({
      version: 1,
      id: "vendor-marketplace",
      name: "Vendor",
      pricing: "metered",
      validate: "/validate",
      endpoint: "/actions",
      actions: ["example.run"],
    });
  if (new Headers(init?.headers).get("authorization") !== "Bearer vendor-key")
    return new Response(null, { status: 401 });
  if (remotePath === "/validate") return new Response(null, { status: 204 });
  if (remotePath === "/actions/example.run")
    return Response.json({ success: true, data: { result: "native-vendor-result" } });
  throw new Error("Unexpected native vendor request");
};

beforeAll(async () => {
  if (!harness.enabled) return;
  const keys = await generateKeyPair("EdDSA");
  privateKey = keys.privateKey;
  const publicKey = { ...(await exportJWK(keys.publicKey)), alg: "EdDSA", kid: "current", use: "sig" };
  jwks = createServer((request, response) => {
    if (request.headers.authorization !== "Bearer bootstrap") {
      response.writeHead(401).end();
      return;
    }
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ keys: [publicKey] }));
  });
  const jwksListening = Promise.withResolvers<void>();
  jwks.listen(0, "127.0.0.1", jwksListening.resolve);
  await jwksListening.promise;
  const verifyJwt = createSaasJwtVerifier(
    {
      jwksUrl: `http://127.0.0.1:${(jwks.address() as AddressInfo).port}/jwks`,
      jwtIssuer: "integration-backend",
      jwtAudience: "open-connector-saas",
      jwtActiveKid: "current",
    },
    "bootstrap",
  ).verify;
  policy = new PostgresActionPolicyStore(harness.pool, catalog);
  const app = new SaasConnectServer({
    catalog,
    providerLoader: {
      async loadActionExecutor(service, actionId) {
        if (service === "shopify" && actionId === "shopify.get_shop") return shopifyExecutors["shopify.get_shop"];
        throw new Error("Marketplace cannot fall back to local execution");
      },
      async loadProxyExecutor() {
        return undefined;
      },
      async loadCredentialValidators(service) {
        return service === "shopify" ? shopifyValidators : undefined;
      },
    },
    verifyJwt,
    readiness: async () => ({
      postgres: true,
      openBao: true,
      jwks: true,
      seaweedFs: true,
      providerRegistry: true,
      catalogFingerprint: true,
    }),
    oauthCredentials: {
      async refresh() {
        throw new Error("Marketplace cannot refresh local OAuth");
      },
    },
    runtimeDatabaseFactory: {
      actionPolicy: policy,
      forScope(scope) {
        return { ...harness.factory.forScope(scope), actionPolicy: policy };
      },
    },
    nativeExecutionForScope: (scope, runtime) =>
      createScopedNativeServices({ scope, runtime, catalog, fetcher: vendor }),
  }).createApp();
  const listening = Promise.withResolvers<void>();
  listener = serve({ fetch: app.fetch, hostname: "127.0.0.1", port: 0 }, (address) => {
    baseUrl = `http://127.0.0.1:${address.port}`;
    listening.resolve();
  });
  await listening.promise;
  setDefaultGuardedFetchDnsLookup(async () => [{ address: "93.184.216.34", family: 4 }]);
});
afterAll(async () => {
  setDefaultGuardedFetchDnsLookup(null);
  for (const server of [listener, jwks])
    if (server) {
      const closed = Promise.withResolvers<void>();
      server.close((error?: Error) => (error ? closed.reject(error) : closed.resolve()));
      await closed.promise;
    }
});

function input(scope: SaasRequestScope) {
  return {
    localConnectionId: scope.localConnectionId!,
    service: "example",
    connectionName: "market",
    apiKey: "vendor-key",
    discoveryUrl: "https://marketplace.example/discovery",
    actionIds: ["example.run"],
  };
}
async function signed(scope: SaasRequestScope): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iss: "integration-backend",
    aud: "open-connector-saas",
    sub: scope.subjectUserId,
    jti: crypto.randomUUID(),
    iat: now,
    nbf: now,
    exp: now + 60,
    tenant_id: scope.tenantId,
    workspace_id: scope.workspaceId,
    actor_user_id: scope.actorUserId,
    subject_user_id: scope.subjectUserId,
    workspace_role: scope.workspaceRole,
    purpose: scope.purpose,
    permissions: scope.permissions,
    local_connection_id: scope.localConnectionId,
    connector_connection_id: scope.connectorConnectionId,
    action_id: scope.actionId,
    max_output_bytes: scope.maxOutputBytes,
    request_hash: scope.requestHash,
  })
    .setProtectedHeader({ alg: "EdDSA", kid: "current" })
    .sign(privateKey);
}
async function connect(
  scope: SaasRequestScope,
  body: object = input(scope),
  changes: Partial<SaasRequestScope> = {},
  suffix = "",
) {
  const serialized = JSON.stringify(body);
  const raw: unknown = JSON.parse(serialized);
  const token = await signed({
    ...scope,
    requestHash: canonicalActionPolicyRequestHash(
      "POST",
      path,
      { kind: "user", tenantId: scope.tenantId, workspaceId: scope.workspaceId, userId: scope.subjectUserId },
      raw,
    ),
    ...changes,
  });
  return fetch(`${baseUrl}${path}${suffix}`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: serialized,
  });
}
async function execute(scope: SaasRequestScope, id: string, changes: Partial<SaasRequestScope> = {}) {
  const value = { value: "request" };
  const token = await signed({
    ...scope,
    purpose: "action:execute:v2",
    permissions: ["action:execute:v2"],
    connectorConnectionId: id,
    actionId: "example.run",
    maxOutputBytes: 4096,
    requestHash: canonicalActionRequestHash("example.run", id, value),
    ...changes,
  });
  return fetch(`${baseUrl}/internal/saas/actions/example.run`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      "idempotency-key": crypto.randomUUID(),
    },
    body: JSON.stringify({ connectorConnectionId: id, input: value }),
  });
}

describe.skipIf(!harness.enabled)("private native Marketplace connect over HTTP", () => {
  it("connects through authenticated discovery to a real row without granting action permission, then executes that exact identity", async () => {
    requests.length = 0;
    const db = harness.forScope({ purpose: "connection:write", permissions: ["connection:write"] });
    const response = await connect(db.scope);
    expect(response.status).toBe(201);
    const result = await response.json();
    expect(result).toEqual({
      id: expect.any(String),
      localConnectionId: db.scope.localConnectionId,
      service: "example",
      connectionName: "market",
      visibility: "user",
      status: "active",
      profile: { accountId: db.scope.localConnectionId, displayName: "Vendor", grantedScopes: [] },
      createdAt: expect.any(String),
      updatedAt: expect.any(String),
    });
    expect(JSON.stringify(result)).not.toContain("vendor-key");
    expect(JSON.stringify(result)).not.toContain("nativeMarketplace");
    expect(await db.connectionStore.getById(result.id)).toMatchObject({
      id: result.id,
      credential: {
        authType: "api_key",
        apiKey: "vendor-key",
        metadata: {
          nativeMarketplace: {
            tenantId: db.scope.tenantId,
            workspaceId: db.scope.workspaceId,
            localConnectionId: db.scope.localConnectionId,
            actionIds: ["example.run"],
          },
        },
      },
    });
    expect(requests.map((item) => item.path)).toEqual(["/discovery", "/validate"]);
    const denied = await execute(db.scope, result.id);
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({ errorCode: "action_not_granted" });
    expect(requests.map((item) => item.path)).toEqual(["/discovery", "/validate"]);
    const target: ActionPolicyTarget = {
      kind: "user",
      tenantId: db.scope.tenantId,
      workspaceId: db.scope.workspaceId,
      userId: db.scope.actorUserId,
    };
    const mutation = { actionIds: ["example.run"], enabled: true, reason: "Explicit test permission" };
    await policy.applyForControl(
      {
        subjectKind: "policy_control",
        subject: "operator:marketplace-test",
        purpose: "action-policy:write",
        permissions: ["action-policy:write"],
        target,
        requestId: crypto.randomUUID(),
        requestHash: canonicalActionPolicyRequestHash("PUT", "/internal/saas/action-policy/grants", target, mutation),
      },
      mutation,
    );
    for (const changes of [
      { actorUserId: crypto.randomUUID() },
      { localConnectionId: crypto.randomUUID() },
      { tenantId: crypto.randomUUID() },
    ]) {
      const refused = await execute(db.scope, result.id, changes);
      expect(refused.status).toBe(403);
      expect(await refused.json()).toMatchObject({ errorCode: "connection_provider_mismatch" });
    }
    expect(requests.some((item) => item.path.startsWith("/actions/"))).toBe(false);
    const executed = await execute(db.scope, result.id);
    expect(executed.status).toBe(200);
    const receipt = await executed.json();
    expect(receipt).toMatchObject({ executionId: expect.any(String), output: { result: "native-vendor-result" } });
    const dispatch = requests.find((item) => item.path === "/actions/example.run")!;
    expect(new Headers(dispatch.init?.headers).get("authorization")).toBe("Bearer vendor-key");
    expect(JSON.parse(String(dispatch.init?.body))).toEqual({ input: { value: "request" } });
    const identity = await withScopedClient(
      harness.pool,
      { ...db.scope, purpose: "admin:read", permissions: ["admin:read"] },
      async (client) =>
        (
          await client.query(
            "SELECT r.actor_user_id, r.subject_user_id, c.local_connection_id, r.connection_id FROM integration_runtime.run_intents r JOIN integration_runtime.connections c ON c.id=r.connection_id WHERE r.id=$1",
            [receipt.executionId],
          )
        ).rows[0],
    );
    expect(identity).toMatchObject({
      actor_user_id: db.scope.actorUserId,
      subject_user_id: db.scope.subjectUserId,
      local_connection_id: db.scope.localConnectionId,
      connection_id: result.id,
    });
  });

  it("rejects wrong signed lineage, another actor, unselected actions and non-strict transport without external effects", async () => {
    requests.length = 0;
    const db = harness.forScope({ purpose: "connection:write", permissions: ["connection:write"] });
    const body = input(db.scope);
    for (const [payload, changes, suffix, status] of [
      [{ ...body, localConnectionId: crypto.randomUUID() }, {}, "", 403],
      [body, { actorUserId: crypto.randomUUID() }, "", 403],
      [body, { connectorConnectionId: crypto.randomUUID() }, "", 403],
      [
        body,
        {
          requestHash: canonicalActionPolicyRequestHash(
            "POST",
            path,
            {
              kind: "user",
              tenantId: db.scope.tenantId,
              workspaceId: db.scope.workspaceId,
              userId: db.scope.subjectUserId,
            },
            { ...body, service: "foreign" },
          ),
        },
        "",
        403,
      ],
      [{ ...body, actionIds: [] }, {}, "", 400],
      [{ ...body, actionIds: ["example.run", "example.run"] }, {}, "", 400],
      [{ ...body, actionIds: undefined }, {}, "", 400],
      [{ ...body, subjectUserId: db.scope.subjectUserId }, {}, "", 400],
      [body, {}, "?service=example", 400],
      [{ ...body, apiKey: "x".repeat(65_537) }, {}, "", 413],
    ] as Array<[object, Partial<SaasRequestScope>, string, number]>) {
      const response = await connect(db.scope, payload, changes, suffix);
      expect(response.status).toBe(status);
      await response.arrayBuffer();
    }
    expect(requests).toEqual([]);
    expect(await db.connectionStore.list()).toEqual([]);
    const unauthenticated = await fetch(`${baseUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    expect(unauthenticated.status).toBe(401);
    await unauthenticated.arrayBuffer();
  });

  it("maps native credential rejection safely and never persists the rejected credential", async () => {
    requests.length = 0;
    const db = harness.forScope({ purpose: "connection:write", permissions: ["connection:write"] });
    const response = await connect(db.scope, { ...input(db.scope), apiKey: "rejected-vendor-key" });
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "marketplace_auth_error" });
    expect(requests.map((item) => item.path)).toEqual(["/discovery", "/validate"]);
    expect(await db.connectionStore.list()).toEqual([]);
  });
});

describe.skipIf(!harness.enabled)("native provider ownership over authenticated HTTP and PostgreSQL", () => {
  it("keeps Shopify tokens private across tenants and reuses the actual credential owner's token for a shared actor", async () => {
    const nativeFetch = globalThis.fetch;
    let minted = 0;
    const used: string[] = [];
    vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.hostname !== "store.myshopify.com") return nativeFetch(input, init);
      if (url.pathname.endsWith("/oauth/access_token"))
        return Response.json({ access_token: `private-token-${++minted}`, scope: "read_products", expires_in: 3600 });
      used.push(new Headers(init?.headers).get("x-shopify-access-token") ?? "missing");
      return Response.json({
        data: { shop: { id: "gid://shopify/Shop/1", name: "Store", myshopifyDomain: url.hostname } },
      });
    });
    try {
      const target: ActionPolicyTarget = { kind: "platform" };
      const mutation = { actionIds: ["shopify.get_shop"], enabled: true, reason: "Reviewed native owner smoke" };
      await policy.applyForControl(
        {
          subjectKind: "policy_control",
          subject: "operator:owner-smoke",
          purpose: "action-policy:write",
          permissions: ["action-policy:write"],
          target,
          requestId: crypto.randomUUID(),
          requestHash: canonicalActionPolicyRequestHash(
            "PUT",
            "/internal/saas/action-policy/defaults",
            target,
            mutation,
          ),
        },
        mutation,
      );
      const created: Array<{ scope: SaasRequestScope; id: string }> = [];
      for (let index = 0; index < 2; index++) {
        const db = harness.forScope({ purpose: "connection:write", permissions: ["connection:write"] });
        const response = await fetch(`${baseUrl}/internal/saas/connections/credentials`, {
          method: "POST",
          headers: { authorization: `Bearer ${await signed(db.scope)}`, "content-type": "application/json" },
          body: JSON.stringify({
            localConnectionId: db.scope.localConnectionId,
            service: "shopify",
            connectionName: "shop",
            authType: "custom_credential",
            credentials: {
              shopDomain: "store.myshopify.com",
              clientId: "identical-client",
              clientSecret: "identical-secret",
            },
          }),
        });
        expect(response.status, JSON.stringify({ response: await response.clone().json(), minted, used })).toBe(201);
        const connection = await response.json();
        expect(JSON.stringify(connection)).not.toContain("identical-secret");
        created.push({ scope: db.scope, id: connection.id });
      }
      const send = async (scope: SaasRequestScope, id: string) => {
        const executionScope: SaasRequestScope = {
          ...scope,
          purpose: "action:execute:v2",
          permissions: ["action:execute:v2"],
          connectorConnectionId: id,
          actionId: "shopify.get_shop",
          maxOutputBytes: 65536,
          requestHash: canonicalActionRequestHash("shopify.get_shop", id, {}),
        };
        const response = await fetch(`${baseUrl}/internal/saas/actions/shopify.get_shop`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${await signed(executionScope)}`,
            "content-type": "application/json",
            "idempotency-key": crypto.randomUUID(),
          },
          body: JSON.stringify({ connectorConnectionId: id, input: {} }),
        });
        expect(response.status).toBe(200);
        expect(await response.json()).toMatchObject({ output: { shop: { id: "gid://shopify/Shop/1" } } });
      };
      const [first, second] = created;
      await send(first!.scope, first!.id);
      await send(second!.scope, second!.id);
      await harness.factory.forScope(first!.scope).connectionStore.updateVisibilityById(first!.id, "workspace");
      await send({ ...first!.scope, actorUserId: crypto.randomUUID(), workspaceRole: "member" }, first!.id);
      expect(minted).toBe(2);
      expect(used).toEqual([
        "private-token-1",
        "private-token-2",
        "private-token-1",
        "private-token-2",
        "private-token-1",
      ]);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
