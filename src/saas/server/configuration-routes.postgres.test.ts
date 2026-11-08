import type { ProviderDefinition } from "../../core/types.ts";
import type { SaasConfig } from "../config.ts";
import type { ConfigurationControlPrincipal } from "../contracts.ts";
import type { ServerType } from "@hono/node-server";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { PoolClient } from "pg";

import { serve } from "@hono/node-server";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { createCatalogStore } from "../../catalog-store.ts";
import { setDefaultGuardedFetchDnsLookup } from "../../core/guarded-fetch.ts";
import { ProviderLoader } from "../../providers/provider-loader.ts";
import { canonicalActionPolicyRequestHash } from "../actions/canonical-request.ts";
import { createControlJwtVerifier, createSaasJwtVerifier } from "../auth/saas-jwt-verifier.ts";
import { SaasClient } from "../saas-client.ts";
import { SaasProjectService } from "../saas-project-service.ts";
import { OpenBaoClient } from "../secrets/openbao-client.ts";
import { OpenBaoSecretCodec } from "../secrets/secret-codec.ts";
import * as projectAdmission from "../storage/managed-project-admission.ts";
import { PostgresSaasProjectStore } from "../storage/postgres-saas-project-store.ts";
import * as scopedQuery from "../storage/scoped-query.ts";
import { createNativePostgresHarness } from "../testing/native-store-fixtures.ts";
import { SaasConnectServer } from "./saas-connect-server.ts";

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
      tokenEndpointAuthMethod: "client_secret_post",
      scopes: ["read"],
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
const discovery = {
  projectId: "native-project",
  providerConfigs: [
    {
      id: "config",
      service: "example",
      displayName: "Example",
      callbackUrl: "https://vendor.example/callback",
      effectiveScopes: ["read"],
      actionIds: ["example.read", "unknown.action"],
      proxyAvailable: false,
    },
  ],
};
const input = { baseUrl: "https://vendor.example", projectApiKey: "native-secret" };
const prefix = "/internal/saas/configuration";
const harness = createNativePostgresHarness();
let privateKey: CryptoKey;
let baseUrl: string;
let listener: ServerType;
let jwks: Server;
let rejectedDiscovery = false;
let vendorProjectId = "native-project";
let pausedRotationDiscovery: { entered(): void; released: Promise<void> } | undefined;
const vendor: typeof fetch = async (_url, init) => {
  if (
    new Headers(init?.headers).get("authorization") !== "Bearer native-secret" &&
    new Headers(init?.headers).get("authorization") !== "Bearer rotated-secret"
  )
    return new Response(null, { status: 401 });
  if (pausedRotationDiscovery && new Headers(init?.headers).get("authorization") === "Bearer rotated-secret") {
    pausedRotationDiscovery.entered();
    await pausedRotationDiscovery.released;
  }
  return rejectedDiscovery
    ? new Response(null, { status: 401 })
    : Response.json({ success: true, data: { ...discovery, projectId: vendorProjectId } });
};

beforeAll(async () => {
  if (!harness.enabled) return;
  const keys = await generateKeyPair("EdDSA");
  privateKey = keys.privateKey;
  const publicKey = { ...(await exportJWK(keys.publicKey)), alg: "EdDSA", kid: "control", use: "sig" };
  const executionKey = { ...publicKey, kid: "execution" };
  jwks = createServer((_request, response) => {
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ keys: [publicKey, executionKey] }));
  });
  const ready = Promise.withResolvers<void>();
  jwks.listen(0, "127.0.0.1", ready.resolve);
  await ready.promise;
  const config: Pick<
    SaasConfig,
    | "jwksUrl"
    | "jwtIssuer"
    | "jwtAudience"
    | "jwtActiveKid"
    | "policyControlJwksUrl"
    | "policyControlActiveKid"
    | "policyControlIssuer"
    | "policyControlAudience"
  > = {
    jwksUrl: `http://127.0.0.1:${(jwks.address() as AddressInfo).port}/jwks`,
    jwtIssuer: "integration-backend",
    jwtAudience: "open-connector-saas",
    jwtActiveKid: "execution",
    policyControlJwksUrl: `http://127.0.0.1:${(jwks.address() as AddressInfo).port}/jwks`,
    policyControlActiveKid: "control",
    policyControlIssuer: "configuration-control",
    policyControlAudience: "open-connector-control",
  };
  const verifyJwt = createSaasJwtVerifier(config, "bootstrap").verify;
  const verifyControlJwt = createControlJwtVerifier(config).verify;
  const app = new SaasConnectServer({
    catalog,
    verifyJwt,
    verifyControlJwt,
    providerLoader: new ProviderLoader({}),
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
        throw new Error("Configuration cannot refresh customer OAuth");
      },
    },
    runtimeDatabaseFactory: harness.factory,
    projectsForControl: (principal) => {
      const runtime = harness.factory.forConfigurationControl(principal);
      return new SaasProjectService({
        catalog,
        store: runtime.saasProjects,
        secretCodec: runtime.secretCodec,
        configuredOrigin: "https://connector.example",
        client: new SaasClient(vendor),
      });
    },
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
function target() {
  return { kind: "workspace" as const, tenantId: crypto.randomUUID(), workspaceId: crypto.randomUUID() };
}
async function request(
  scope: ConfigurationControlPrincipal["target"],
  method: string,
  path: string,
  body?: unknown,
  claims: Record<string, unknown> = {},
  kid = "control",
  suffix = "",
) {
  const now = Math.floor(Date.now() / 1000);
  const purpose = method === "GET" ? "configuration:read" : "configuration:write";
  const token = await new SignJWT({
    iss: "configuration-control",
    aud: "open-connector-control",
    sub: "operator-real",
    jti: crypto.randomUUID(),
    iat: now,
    nbf: now,
    exp: now + 60,
    subject_kind: "policy_control",
    purpose,
    permissions: [purpose],
    policy_target: scope,
    ...(method === "GET" ? {} : { request_hash: canonicalActionPolicyRequestHash(method, path, scope, body) }),
    ...claims,
  })
    .setProtectedHeader({ alg: "EdDSA", kid })
    .sign(privateKey);
  return fetch(`${baseUrl}${path}${suffix}`, {
    method,
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}
function principal(scope: ConfigurationControlPrincipal["target"]): Readonly<ConfigurationControlPrincipal> {
  return {
    subjectKind: "policy_control",
    subject: "operator-real",
    purpose: "configuration:read",
    permissions: ["configuration:read"],
    target: scope,
    requestId: crypto.randomUUID(),
  };
}
function writer(scope: ConfigurationControlPrincipal["target"]): Readonly<ConfigurationControlPrincipal> {
  return {
    ...principal(scope),
    purpose: "configuration:write",
    permissions: ["configuration:write"],
    requestHash: canonicalActionPolicyRequestHash("PUT", `${prefix}/project`, scope, input),
  };
}

describe.skipIf(!harness.enabled)("private native workspace configuration", () => {
  it("settles only authoritative native no-write failures and fences indeterminate HTTP outcomes", async () => {
    let mode: number | "accepted" | "network" | "malformed" | "oversized-response" = "accepted";
    const records = new Map<string, string>();
    const bao = createServer(async (incoming, response) => {
      const path = incoming.url!.slice("/v1/".length);
      response.setHeader("content-type", "application/json");
      if (incoming.method === "GET") {
        const payload = records.get(path);
        response.statusCode = payload === undefined ? 404 : 200;
        response.end(JSON.stringify({ data: { data: { payload }, metadata: { version: 1 } } }));
        return;
      }
      if (incoming.method === "DELETE") {
        records.delete(path.replace("/metadata/", "/data/"));
        response.end("{}");
        return;
      }
      let body = "";
      for await (const chunk of incoming) body += chunk.toString();
      const {
        data: { payload },
      } = z.object({ data: z.object({ payload: z.string() }) }).parse(JSON.parse(body));
      if (typeof mode === "number" && [400, 401, 403, 404, 409, 412].includes(mode)) {
        response.statusCode = mode;
        response.end("{}");
        return;
      }
      // Each indeterminate reply follows a real side effect, including the dropped connection.
      records.set(path, payload);
      if (mode === "network") incoming.socket.destroy();
      else if (mode === "malformed") response.end("{");
      else if (mode === "oversized-response") response.end("x".repeat(2048));
      else {
        response.statusCode = typeof mode === "number" ? mode : 200;
        response.end(JSON.stringify({ data: { version: 1 } }));
      }
    });
    const ready = Promise.withResolvers<void>();
    bao.listen(0, "127.0.0.1", ready.resolve);
    await ready.promise;
    const origin = `http://127.0.0.1:${(bao.address() as AddressInfo).port}`;
    const fetchFn: typeof fetch = (url, init) => fetch(new URL(new URL(String(url)).pathname, origin), init);
    try {
      for (const { fault, settled } of [
        { fault: 400, settled: true },
        { fault: 401, settled: true },
        { fault: 403, settled: true },
        { fault: 404, settled: true },
        { fault: 409, settled: true },
        { fault: 412, settled: true },
        { fault: "oversized-request", settled: true },
        { fault: 429, settled: false },
        { fault: 503, settled: false },
        { fault: "network", settled: false },
        { fault: "malformed", settled: false },
        { fault: "oversized-response", settled: false },
      ] as const) {
        const scope = target();
        const control = writer(scope);
        mode = fault === "oversized-request" ? "accepted" : fault;
        const codec = new OpenBaoSecretCodec(
          new OpenBaoClient({
            address: "https://openbao.test",
            token: "test-token",
            fetchFn,
            maxRequestBytes: fault === "oversized-request" ? 1 : 262144,
            maxResponseBytes: 1024,
          }),
          { tenantId: scope.tenantId, workspaceId: scope.workspaceId },
        );
        const store = new PostgresSaasProjectStore(harness.pool, control, codec);
        const project = {
          id: crypto.randomUUID(),
          projectId: "native-project",
          baseUrl: input.baseUrl,
          apiKey: input.projectApiKey,
        };
        await expect(store.saveProject(project, null), String(fault)).rejects.toThrow();
        expect(await store.getProject()).toBeUndefined();
        expect(await store.getCleanupStats()).toEqual({ pending: 0, manual: 0, paused: !settled });
        const row = await scopedQuery.withConfigurationControlClient(
          harness.pool,
          principal(scope),
          async (client) =>
            (
              await client.query(
                "SELECT secret_ref,pending_secret_ref,retired_secret_refs FROM integration_runtime.managed_projects",
              )
            ).rows[0],
        );
        if (settled) expect(row).toBeUndefined();
        else {
          expect(row).toMatchObject({ secret_ref: null, retired_secret_refs: [] });
          expect(records.get(row.pending_secret_ref)).toBe("native-secret");
          expect(await store.deleteProject()).toBe(false);
          expect(await store.saveProject({ ...project, apiKey: "rotated-secret" }, null)).toBe(false);
          expect(records.get(row.pending_secret_ref)).toBe("native-secret");
          expect(JSON.stringify(row)).not.toContain("native-secret");
        }
      }
      const scope = target();
      const control = writer(scope);
      const codec = new OpenBaoSecretCodec(
        new OpenBaoClient({
          address: "https://openbao.test",
          token: "test-token",
          fetchFn,
        }),
        { tenantId: scope.tenantId, workspaceId: scope.workspaceId },
      );
      const store = new PostgresSaasProjectStore(harness.pool, control, codec);
      const project = {
        id: crypto.randomUUID(),
        projectId: "native-project",
        baseUrl: input.baseUrl,
        apiKey: input.projectApiKey,
      };
      mode = "accepted";
      expect(await store.saveProject(project, null)).toBe(true);
      await scopedQuery.withConfigurationControlClient(harness.pool, control, (client) =>
        client.query("UPDATE integration_runtime.managed_projects SET cleanup_paused=true"),
      );
      mode = 401;
      await expect(store.saveProject({ ...project, apiKey: "rotated-secret" }, project.id)).rejects.toThrow();
      expect((await store.getProject())?.apiKey).toBe("native-secret");
      expect(await store.getCleanupStats()).toEqual({ pending: 0, manual: 0, paused: true });
      const row = await scopedQuery.withConfigurationControlClient(
        harness.pool,
        principal(scope),
        async (client) =>
          (
            await client.query(
              "SELECT pending_secret_ref,retired_secret_refs FROM integration_runtime.managed_projects",
            )
          ).rows[0],
      );
      expect(row).toEqual({ pending_secret_ref: null, retired_secret_refs: [] });
    } finally {
      bao.closeAllConnections();
      const closed = Promise.withResolvers<void>();
      bao.close((error) => (error ? closed.reject(error) : closed.resolve()));
      await closed.promise;
    }
  });

  it("commits one initial reservation before writing and fences only its actual workspace", async () => {
    const scope = target();
    const adjacent = { ...scope, workspaceId: crypto.randomUUID() };
    const reserved = Promise.withResolvers<string>();
    const released = Promise.withResolvers<void>();
    const encode = harness.codec.encode.bind(harness.codec);
    const paused = vi.spyOn(harness.codec, "encode").mockImplementation((value, beforeWrite) =>
      encode(value, async (ref) => {
        await beforeWrite?.(ref);
        if (value === "native-secret") {
          reserved.resolve(ref);
          await released.promise;
        }
      }),
    );
    const first = request(scope, "PUT", `${prefix}/project`, input);
    try {
      const ref = await reserved.promise;
      await expect(harness.codec.decode(ref)).rejects.toThrow("Secret missing");
      const row = await scopedQuery.withConfigurationControlClient(
        harness.pool,
        principal(scope),
        async (client) =>
          (await client.query("SELECT id,secret_ref,pending_secret_ref FROM integration_runtime.managed_projects"))
            .rows[0],
      );
      expect(row).toMatchObject({ secret_ref: null, pending_secret_ref: ref });
      expect(await (await request(scope, "GET", `${prefix}/project`)).json()).toMatchObject({
        configured: false,
        status: "unconfigured",
        cleanup: { paused: true },
      });
      expect(
        (await request(scope, "PUT", `${prefix}/project`, { ...input, projectApiKey: "rotated-secret" })).status,
      ).toBe(409);
      expect((await request(scope, "DELETE", `${prefix}/project`, {})).status).toBe(409);
      expect(
        (await request(adjacent, "PUT", `${prefix}/project`, { ...input, projectApiKey: "rotated-secret" })).status,
      ).toBe(200);
      const customer = harness.forScope({ tenantId: scope.tenantId, workspaceId: scope.workspaceId });
      expect(await customer.saasProjects.getProject()).toBeUndefined();
      expect(await customer.saasProjects.deleteProject()).toBe(false);
      expect(
        await customer.saasProjects.setSource("example", { managedProjectId: row.id, providerConfigId: "config" }),
      ).toBe(false);
      await scopedQuery.withScopedClient(harness.pool, customer.scope, (client) =>
        client.query(
          `INSERT INTO integration_runtime.saas_cleanup
           (id,tenant_id,workspace_id,subject_user_id,managed_project_id,provider_config_id,external_user_id,status)
           VALUES ('pending-key',$1,$2,$3,$4,'config','external','pending'),('manual-key',$1,$2,$3,$4,'config','external','manual')`,
          [scope.tenantId, scope.workspaceId, customer.scope.subjectUserId, row.id],
        ),
      );
      expect(await customer.saasProjects.getCleanupStats()).toEqual({ pending: 1, manual: 1, paused: true });
      expect(await customer.saasProjects.claimCleanup(Date.now())).toBeUndefined();
      await expect(
        customer.saasProjects.pauseCleanup(
          {
            id: "pending-key",
            managedProjectId: row.id,
            providerConfigId: "config",
            externalUserId: "external",
            remoteRequestId: null,
            connectedAccountId: null,
            leaseId: crypto.randomUUID(),
            attempts: 0,
            service: null,
            requestExpiresAt: null,
          },
          "rejected",
        ),
      ).resolves.toBeUndefined();
      expect(await (await request(scope, "GET", `${prefix}/project`)).json()).toMatchObject({
        cleanup: { pending: 1, manual: 1, paused: true },
      });
      // The tenant-wide removal owner must inspect every project before erasing any ready neighbour.
      await expect(
        harness.factory.nativeConfiguration.purgeForLifecycle(
          {
            subjectKind: "service",
            subject: "backend-system",
            purpose: "lifecycle:configuration:purge",
            permissions: ["lifecycle:configuration:purge"],
            target: { kind: "tenant", tenantId: scope.tenantId },
            requestId: crypto.randomUUID(),
            requestHash: "a".repeat(43),
          },
          crypto.randomUUID(),
        ),
      ).rejects.toThrow();
      expect(await (await request(adjacent, "GET", `${prefix}/project`)).json()).toMatchObject({
        configured: true,
        status: "available",
      });
    } finally {
      released.resolve();
      paused.mockRestore();
    }
    expect((await first).status).toBe(200);
  });

  it("does not dispatch when the durable reservation acknowledgement is lost", async () => {
    const scope = target();
    const store = harness.factory.forConfigurationControl(writer(scope)).saasProjects;
    const encode = harness.codec.encode.bind(harness.codec);
    let allocatedRef = "";
    const allocation = vi.spyOn(harness.codec, "encode").mockImplementation((value, beforeWrite) =>
      encode(value, async (ref) => {
        allocatedRef = ref;
        await beforeWrite?.(ref);
      }),
    );
    const transaction = scopedQuery.withConfigurationControlClient;
    const lostAck = vi.spyOn(scopedQuery, "withConfigurationControlClient").mockImplementationOnce(async (...args) => {
      await transaction(...args);
      throw new Error("Reservation commit acknowledgement lost");
    });
    try {
      await expect(
        store.saveProject(
          { id: crypto.randomUUID(), projectId: "native-project", baseUrl: input.baseUrl, apiKey: input.projectApiKey },
          null,
        ),
      ).rejects.toThrow("Reservation commit acknowledgement lost");
    } finally {
      allocation.mockRestore();
      lostAck.mockRestore();
    }
    expect(allocatedRef).not.toBe("");
    await expect(harness.codec.decode(allocatedRef)).rejects.toThrow("Secret missing");
    expect(await store.getProject()).toBeUndefined();
    expect(await store.getCleanupStats()).toEqual({ pending: 0, manual: 0, paused: true });
    expect(await store.deleteProject()).toBe(false);
  });

  it.each(["published", "compensated"] as const)(
    "fences a %s write when publication acknowledgement is uncertain",
    async (winner) => {
      const scope = target();
      const control = writer(scope);
      const store = harness.factory.forConfigurationControl(control).saasProjects;
      const project = {
        id: crypto.randomUUID(),
        projectId: "native-project",
        baseUrl: input.baseUrl,
        apiKey: input.projectApiKey,
      };
      expect(await store.saveProject(project, null)).toBe(true);
      const transaction = scopedQuery.withConfigurationControlClient;
      let calls = 0;
      let latePublication: (() => Promise<unknown>) | undefined;
      const uncertain = vi.spyOn(scopedQuery, "withConfigurationControlClient").mockImplementation(async (...args) => {
        if (++calls === 2) {
          if (winner === "published") await transaction(...args);
          else latePublication = () => transaction(...args);
          throw new Error("Publication acknowledgement lost");
        }
        return transaction(...args);
      });
      try {
        await expect(store.saveProject({ ...project, apiKey: "rotated-secret" }, project.id)).rejects.toThrow(
          "Publication acknowledgement lost",
        );
        await latePublication?.();
      } finally {
        uncertain.mockRestore();
      }
      const row = await scopedQuery.withConfigurationControlClient(
        harness.pool,
        principal(scope),
        async (client) =>
          (
            await client.query(
              "SELECT secret_ref,pending_secret_ref,retired_secret_refs FROM integration_runtime.managed_projects",
            )
          ).rows[0],
      );
      expect(row.pending_secret_ref).toBeNull();
      expect(row.retired_secret_refs).toHaveLength(1);
      expect(row.retired_secret_refs).not.toContain(row.secret_ref);
      expect((await store.getProject())?.apiKey).toBe(winner === "published" ? "rotated-secret" : "native-secret");
      await expect(harness.codec.decode(row.retired_secret_refs[0])).resolves.toBe(
        winner === "published" ? "native-secret" : "rotated-secret",
      );
      expect(await store.deleteProject(project.id)).toBe(true);
      await expect(harness.codec.decode(row.secret_ref)).rejects.toThrow("Secret missing");
      await expect(harness.codec.decode(row.retired_secret_refs[0])).rejects.toThrow("Secret missing");
    },
  );

  it("retains the exact pending fence if confirmed-write compensation also fails", async () => {
    const scope = target();
    const store = harness.factory.forConfigurationControl(writer(scope)).saasProjects;
    const project = {
      id: crypto.randomUUID(),
      projectId: "native-project",
      baseUrl: input.baseUrl,
      apiKey: input.projectApiKey,
    };
    expect(await store.saveProject(project, null)).toBe(true);
    const transaction = scopedQuery.withConfigurationControlClient;
    let calls = 0;
    const failure = vi.spyOn(scopedQuery, "withConfigurationControlClient").mockImplementation(async (...args) => {
      calls++;
      if (calls === 2) throw new Error("Publication unavailable");
      if (calls === 3) throw new Error("Compensation unavailable");
      return transaction(...args);
    });
    try {
      await expect(store.saveProject({ ...project, apiKey: "rotated-secret" }, project.id)).rejects.toThrow(
        "Compensation unavailable",
      );
    } finally {
      failure.mockRestore();
    }
    const row = await scopedQuery.withConfigurationControlClient(
      harness.pool,
      principal(scope),
      async (client) =>
        (
          await client.query(
            "SELECT secret_ref,pending_secret_ref,retired_secret_refs FROM integration_runtime.managed_projects",
          )
        ).rows[0],
    );
    expect(row.retired_secret_refs).toEqual([]);
    expect(row.pending_secret_ref).not.toBe(row.secret_ref);
    expect(await harness.codec.decode(row.pending_secret_ref)).toBe("rotated-secret");
    expect((await store.getProject())?.apiKey).toBe("native-secret");
    expect(await store.getCleanupStats()).toEqual({ pending: 0, manual: 0, paused: true });
    expect(await store.saveProject({ ...project, apiKey: "third-secret" }, project.id)).toBe(false);
    expect(await store.deleteProject()).toBe(false);
  });

  it("does not restore a removed project when an earlier rotation finishes discovery", async () => {
    const scope = target();
    expect((await request(scope, "PUT", `${prefix}/project`, input)).status).toBe(200);
    const entered = Promise.withResolvers<void>();
    const released = Promise.withResolvers<void>();
    pausedRotationDiscovery = { entered: entered.resolve, released: released.promise };
    const rotation = request(scope, "PUT", `${prefix}/project`, { ...input, projectApiKey: "rotated-secret" });
    try {
      await entered.promise;
      expect((await request(scope, "DELETE", `${prefix}/project`, {})).status).toBe(204);
    } finally {
      pausedRotationDiscovery = undefined;
      released.resolve();
    }
    expect((await rotation).status).toBe(409);
    expect(await (await request(scope, "GET", `${prefix}/project`)).json()).toMatchObject({ configured: false });
  });

  it("preserves unresolved key custody against both optional and lifecycle removal", async () => {
    const scope = target();
    expect((await request(scope, "PUT", `${prefix}/project`, input)).status).toBe(200);
    const encode = harness.codec.encode.bind(harness.codec);
    const uncertain = vi.spyOn(harness.codec, "encode").mockImplementation(async (...args) => {
      await encode(...args);
      throw new Error("Lost acknowledgement after the key write");
    });
    try {
      expect(
        (await request(scope, "PUT", `${prefix}/project`, { ...input, projectApiKey: "rotated-secret" })).status,
      ).toBe(503);
    } finally {
      uncertain.mockRestore();
    }
    expect((await request(scope, "DELETE", `${prefix}/project`, {})).status).toBe(409);
    await expect(
      harness.factory.nativeConfiguration.purgeForLifecycle(
        {
          subjectKind: "service",
          subject: "backend-system",
          purpose: "lifecycle:configuration:purge",
          permissions: ["lifecycle:configuration:purge"],
          target: scope,
          requestId: crypto.randomUUID(),
          requestHash: "a".repeat(43),
        },
        crypto.randomUUID(),
      ),
    ).rejects.toThrow();
    const customer = harness.forScope({ tenantId: scope.tenantId, workspaceId: scope.workspaceId });
    const project = await customer.saasProjects.getProject();
    if (!project) throw new Error("The original project key was lost");
    await scopedQuery.withScopedClient(harness.pool, customer.scope, (client) =>
      client.query(
        `INSERT INTO integration_runtime.saas_cleanup
         (id,tenant_id,workspace_id,subject_user_id,managed_project_id,provider_config_id,external_user_id,status)
         VALUES ('fenced-rotation',$1,$2,$3,$4,'config','external','pending')`,
        [scope.tenantId, scope.workspaceId, customer.scope.subjectUserId, project.id],
      ),
    );
    expect(await customer.saasProjects.claimCleanup(Date.now())).toBeUndefined();
    expect(await customer.saasProjects.getCleanupStats()).toEqual({ pending: 1, manual: 0, paused: true });
    expect(await customer.saasProjects.deleteProject()).toBe(false);
    expect(await (await request(scope, "GET", `${prefix}/project`)).json()).toMatchObject({
      configured: true,
      status: "available",
      cleanup: { paused: true },
    });
  });

  it.each(["optional", "lifecycle"] as const)(
    "does not promote an encoded initial key after publication is cancelled (%s removal)",
    async (removal) => {
      const scope = target();
      const controller = new AbortController();
      const runtime = harness.factory.forConfigurationControl({
        ...principal(scope),
        purpose: "configuration:write",
        permissions: ["configuration:write"],
        requestHash: canonicalActionPolicyRequestHash("PUT", `${prefix}/project`, scope, input),
        requestSignal: controller.signal,
        processingDeadlineMs: Date.now() + 120_000,
      });
      const projects = new SaasProjectService({
        catalog,
        store: runtime.saasProjects,
        secretCodec: runtime.secretCodec,
        configuredOrigin: "https://connector.example",
        client: new SaasClient(vendor),
      });
      const encode = harness.codec.encode.bind(harness.codec);
      let encodedReference: string | undefined;
      const cancelled = vi.spyOn(harness.codec, "encode").mockImplementation(async (...args) => {
        encodedReference = await encode(...args);
        controller.abort(new DOMException("Caller cancelled", "AbortError"));
        return encodedReference;
      });
      try {
        await expect(projects.configure(input, controller.signal)).rejects.toThrow();
      } finally {
        cancelled.mockRestore();
      }
      expect(await (await request(scope, "GET", `${prefix}/project`)).json()).toMatchObject({
        configured: false,
        status: "unconfigured",
        cleanup: { paused: true },
      });
      const row = await scopedQuery.withConfigurationControlClient(
        harness.pool,
        principal(scope),
        async (client) =>
          (
            await client.query(
              "SELECT id,secret_ref,pending_secret_ref,retired_secret_refs FROM integration_runtime.managed_projects",
            )
          ).rows[0],
      );
      expect(row).toMatchObject({
        secret_ref: null,
        pending_secret_ref: null,
        retired_secret_refs: [encodedReference],
      });
      expect(
        await harness.factory.forConfigurationControl(writer(scope)).saasProjects.setSource("example", {
          managedProjectId: row.id,
          providerConfigId: "config",
        }),
      ).toBe(false);
      expect((await request(scope, "PUT", `${prefix}/project`, input)).status).toBe(409);
      if (removal === "optional") expect((await request(scope, "DELETE", `${prefix}/project`, {})).status).toBe(204);
      else {
        const correlationId = crypto.randomUUID();
        expect(
          await harness.factory.nativeConfiguration.purgeForLifecycle(
            {
              subjectKind: "service",
              subject: "backend-system",
              purpose: "lifecycle:configuration:purge",
              permissions: ["lifecycle:configuration:purge"],
              target: scope,
              requestId: crypto.randomUUID(),
              requestHash: "a".repeat(43),
            },
            correlationId,
          ),
        ).toEqual({ correlationId, deletedProjects: 1, deletedSources: 0, deletedSecrets: 1 });
      }
      if (!encodedReference) throw new Error("Fault injection did not reach the actual key write");
      await expect(harness.codec.decode(encodedReference)).rejects.toThrow();
    },
  );

  it("provisions an empty workspace through signed HTTP without inventing a customer", async () => {
    const scope = target();
    const adjacentWorkspace = { ...scope, workspaceId: crypto.randomUUID() };
    const adjacentTenant = { ...scope, tenantId: crypto.randomUUID() };
    const empty = await request(scope, "GET", `${prefix}/project`);
    expect(empty.status).toBe(200);
    expect(await empty.json()).toMatchObject({
      configured: false,
      status: "unconfigured",
      cleanup: { pending: 0, manual: 0, paused: false },
    });
    const saved = await request(scope, "PUT", `${prefix}/project`, input);
    expect(saved.status).toBe(200);
    const state = await saved.json();
    expect(state).toMatchObject({ configured: true, projectId: "native-project", baseUrl: input.baseUrl });
    expect(JSON.stringify(state)).not.toMatch(/native-secret|secret_ref|apiKey|projectApiKey/);
    const configs = await request(scope, "GET", `${prefix}/provider-configs`);
    expect(configs.status).toBe(200);
    expect(await configs.json()).toEqual({
      projectId: "native-project",
      providerConfigs: [{ ...discovery.providerConfigs[0], actionIds: ["example.read"] }],
    });
    const selected = await request(scope, "PUT", `${prefix}/sources/example`, {
      mode: "saas",
      providerConfigId: "config",
    });
    expect(selected.status).toBe(200);
    const source = await selected.json();
    expect(source).toEqual({
      mode: "saas",
      managedProjectId: state.managedProjectId,
      projectId: "native-project",
      providerConfigId: "config",
    });
    expect(await (await request(scope, "GET", `${prefix}/sources/example`)).json()).toEqual(source);
    for (const adjacent of [adjacentWorkspace, adjacentTenant]) {
      expect(await (await request(adjacent, "GET", `${prefix}/project`)).json()).toMatchObject({ configured: false });
      expect((await request(adjacent, "PUT", `${prefix}/project`, input)).status).toBe(200);
    }
    const rows = await scopedQuery.withConfigurationControlClient(harness.pool, principal(scope), async (client) => ({
      projects: (await client.query("SELECT subject_user_id FROM integration_runtime.managed_projects")).rows,
      sources: (await client.query("SELECT subject_user_id FROM integration_runtime.oauth_sources")).rows,
      customer: (await client.query("SELECT * FROM integration_runtime.connections")).rows,
      queue: (await client.query("SELECT * FROM integration_runtime.saas_cleanup")).rows,
    }));
    expect(rows).toEqual({
      projects: [{ subject_user_id: null }],
      sources: [{ subject_user_id: null }],
      customer: [],
      queue: [],
    });
    expect((await request(scope, "DELETE", `${prefix}/project`, {})).status).toBe(409);
    expect((await request(scope, "PUT", `${prefix}/sources/example`, { mode: "local" })).status).toBe(200);
    expect((await request(scope, "DELETE", `${prefix}/project`, {})).status).toBe(204);
    expect((await request(scope, "DELETE", `${prefix}/project`, {})).status).toBe(204);
  });

  it("rejects wrong authorities and raw mutation tampering before changing configuration", async () => {
    const scope = target();
    const path = `${prefix}/project`;
    for (const claims of [
      { purpose: "configuration:read", permissions: ["configuration:read"] },
      { purpose: "action-policy:write", permissions: ["action-policy:write"] },
      { purpose: "catalog:read", permissions: ["catalog:read"] },
      { purpose: "action:execute:v2", permissions: ["action:execute:v2"] },
      { request_hash: undefined },
      { workspace_role: "owner", actor_user_id: "synthetic", subject_user_id: "synthetic" },
      { policy_target: { ...scope, workspaceId: crypto.randomUUID() } },
      { request_hash: canonicalActionPolicyRequestHash("DELETE", path, scope, input) },
      { request_hash: canonicalActionPolicyRequestHash("PUT", path, scope, { ...input, projectApiKey: "different" }) },
    ])
      expect([401, 403]).toContain((await request(scope, "PUT", path, input, claims)).status);
    expect([401, 403]).toContain((await request(scope, "PUT", path, input, {}, "execution")).status);
    expect((await request(scope, "PUT", path, { ...input, tenantId: scope.tenantId })).status).toBe(400);
    expect((await request(scope, "PUT", path, { ...input, projectApiKey: "x".repeat(262_144) })).status).toBe(413);
    expect((await request(scope, "DELETE", path, { extra: true })).status).toBe(400);
    expect((await request(scope, "PUT", path, { ...input, projectApiKey: "bad\nkey" })).status).toBe(400);
    expect((await request(scope, "GET", path, undefined, {}, "control", "?workspaceId=other")).status).toBe(400);
    expect((await request(scope, "GET", `${prefix}/sources/unknown`)).status).toBe(404);
    expect((await request(scope, "PUT", path, input)).status).toBe(200);
    expect(
      (await request(scope, "PUT", `${prefix}/sources/example`, { mode: "saas", providerConfigId: "unknown" })).status,
    ).toBe(409);
    rejectedDiscovery = true;
    try {
      expect((await request(scope, "PUT", path, { ...input, projectApiKey: "rotated-secret" })).status).toBe(503);
    } finally {
      rejectedDiscovery = false;
    }
    expect(await (await request(scope, "GET", path)).json()).toMatchObject({
      configured: true,
      status: "available",
      projectId: "native-project",
    });
    expect((await request(scope, "PUT", path, { ...input, baseUrl: "https://other.example" })).status).toBe(409);
    vendorProjectId = "different-project";
    try {
      expect((await request(scope, "PUT", path, input)).status).toBe(409);
    } finally {
      vendorProjectId = "native-project";
    }
    expect(await (await request(scope, "GET", path)).json()).toMatchObject({
      projectId: "native-project",
      status: "available",
    });
  });

  it("reports hidden workspace cleanup dependencies and blocks removal without queue visibility", async () => {
    const scope = target();
    const saved = await request(scope, "PUT", `${prefix}/project`, input);
    expect(saved.status).toBe(200);
    const state = await saved.json();
    const customer = harness.forScope({ tenantId: scope.tenantId, workspaceId: scope.workspaceId });
    await scopedQuery.withScopedClient(harness.pool, customer.scope, (client) =>
      client.query(
        "INSERT INTO integration_runtime.saas_cleanup (id,tenant_id,workspace_id,subject_user_id,managed_project_id,provider_config_id,external_user_id,status) VALUES ('hidden-cleanup',$1,$2,$3,$4,'config','real-external','manual')",
        [scope.tenantId, scope.workspaceId, customer.scope.subjectUserId, state.managedProjectId],
      ),
    );
    expect(await (await request(scope, "GET", `${prefix}/project`)).json()).toMatchObject({
      cleanup: { pending: 0, manual: 1, paused: false },
    });
    expect((await request(scope, "DELETE", `${prefix}/project`, {})).status).toBe(409);
    await scopedQuery.withConfigurationControlClient(harness.pool, principal(scope), async (client) => {
      expect((await client.query("SELECT * FROM integration_runtime.saas_cleanup")).rows).toEqual([]);
      expect((await client.query("DELETE FROM integration_runtime.saas_cleanup")).rowCount).toBe(0);
      expect(
        (
          await client.query("SELECT * FROM integration_runtime.managed_projects WHERE workspace_id=$1", [
            crypto.randomUUID(),
          ])
        ).rows,
      ).toEqual([]);
    });
  });

  it("preserves historical real creators during operator replacement and denies customer-only methods", async () => {
    const customer = harness.forScope();
    const scope = {
      kind: "workspace" as const,
      tenantId: customer.scope.tenantId,
      workspaceId: customer.scope.workspaceId,
    };
    const original = new SaasProjectService({
      catalog,
      store: customer.saasProjects,
      secretCodec: harness.codec,
      configuredOrigin: "https://connector.example",
      client: new SaasClient(vendor),
    });
    await original.configure(input);
    await original.setSource("example", { mode: "saas", providerConfigId: "config" });
    expect(
      (await request(scope, "PUT", `${prefix}/project`, { ...input, projectApiKey: "rotated-secret" })).status,
    ).toBe(200);
    expect(
      (await request(scope, "PUT", `${prefix}/sources/example`, { mode: "saas", providerConfigId: "config" })).status,
    ).toBe(200);
    const control = principal(scope);
    const store = harness.factory.forConfigurationControl(control).saasProjects;
    expect(() => store.externalUserId()).toThrow();
    await expect(store.claimCleanup(Date.now())).rejects.toThrow();
    await expect(store.countExactOwnedCleanupForLifecycle()).rejects.toThrow();
    await scopedQuery.withConfigurationControlClient(harness.pool, control, async (client) => {
      expect((await client.query("SELECT subject_user_id FROM integration_runtime.managed_projects")).rows).toEqual([
        { subject_user_id: customer.scope.subjectUserId },
      ]);
      expect((await client.query("SELECT subject_user_id FROM integration_runtime.oauth_sources")).rows).toEqual([
        { subject_user_id: customer.scope.subjectUserId },
      ]);
      expect((await client.query("UPDATE integration_runtime.managed_projects SET cleanup_paused=true")).rowCount).toBe(
        0,
      );
      expect((await client.query("DELETE FROM integration_runtime.oauth_sources")).rowCount).toBe(0);
    });
    await expect(
      scopedQuery.withConfigurationControlClient(harness.pool, control, (client) =>
        client.query("SELECT * FROM integration_runtime.configuration_workspace_state($1,$2)", [
          scope.tenantId,
          crypto.randomUUID(),
        ]),
      ),
    ).rejects.toThrow();
  });

  it("blocks removal for native pending requests and connected private accounts without disclosing either", async () => {
    const scope = target();
    const saved = await request(scope, "PUT", `${prefix}/project`, input);
    expect(saved.status).toBe(200);
    const state = await saved.json();
    const customer = harness.forScope({ tenantId: scope.tenantId, workspaceId: scope.workspaceId });
    const pending = {
      connectionRequestId: crypto.randomUUID(),
      connectionId: crypto.randomUUID(),
      owner: customer.scope.subjectUserId,
      service: "example",
      connectionName: "native-private",
      managedProjectId: state.managedProjectId,
      providerConfigId: "config",
      externalUserId: customer.saasProjects.externalUserId(),
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
    };
    const lease = await customer.connectionRequests.createSaas(pending);
    expect((await request(scope, "DELETE", `${prefix}/project`, {})).status).toBe(409);
    expect(await customer.connectionRequests.saveSaasRequest(lease, "remote-request")).toBe(true);
    expect(
      await customer.connectionRequests.saveSaasCandidate(lease, {
        connectedAccountId: "real-private-account",
        profile: { accountId: "vendor-user", displayName: "Vendor user", grantedScopes: ["read"] },
        status: "active",
        comment: null,
      }),
    ).toBe(true);
    expect(await customer.connectionRequests.completeSaas(lease)).toBe("connected");
    expect(await customer.connectionStore.getById(pending.connectionId)).toMatchObject({ source: "saas" });
    expect((await request(scope, "DELETE", `${prefix}/project`, {})).status).toBe(409);
    await scopedQuery.withConfigurationControlClient(harness.pool, principal(scope), async (client) => {
      expect((await client.query("SELECT * FROM integration_runtime.connections")).rows).toEqual([]);
      expect((await client.query("SELECT * FROM integration_runtime.connection_requests")).rows).toEqual([]);
    });
  });

  it.each(["optional", "lifecycle"] as const)(
    "never erases settled keys without an acknowledged %s inactive fence",
    async (owner) => {
      const scope = target();
      expect((await request(scope, "PUT", `${prefix}/project`, input)).status).toBe(200);
      expect(
        (await request(scope, "PUT", `${prefix}/project`, { ...input, projectApiKey: "rotated-secret" })).status,
      ).toBe(200);
      const store = harness.factory.forConfigurationControl(writer(scope)).saasProjects;
      const project = await store.getProject();
      if (!project) throw new Error("Project fixture was not published");
      const row = await scopedQuery.withConfigurationControlClient(
        harness.pool,
        principal(scope),
        async (client) =>
          (
            await client.query<{ secret_ref: string; retired_secret_refs: string[] }>(
              "SELECT secret_ref,retired_secret_refs FROM integration_runtime.managed_projects",
            )
          ).rows[0]!,
      );
      const lifecycle = {
        subjectKind: "service" as const,
        subject: "backend-system",
        purpose: "lifecycle:configuration:purge" as const,
        permissions: ["lifecycle:configuration:purge"],
        target: scope,
        requestId: crypto.randomUUID(),
        requestHash: "a".repeat(43),
      };
      if (owner === "optional") {
        const transaction = scopedQuery.withConfigurationControlClient;
        const lost = vi.spyOn(scopedQuery, "withConfigurationControlClient").mockImplementationOnce(async (...args) => {
          await transaction(...args);
          throw new Error("Inactive fence acknowledgement lost");
        });
        try {
          await expect(store.deleteProject(project.id)).rejects.toThrow();
        } finally {
          lost.mockRestore();
        }
      } else {
        const transaction = scopedQuery.withNativeLifecycleClient;
        const lost = vi.spyOn(scopedQuery, "withNativeLifecycleClient").mockImplementationOnce(async (...args) => {
          await transaction(...args);
          throw new Error("Inactive fence acknowledgement lost");
        });
        try {
          await expect(
            harness.factory.nativeConfiguration.purgeForLifecycle(lifecycle, crypto.randomUUID()),
          ).rejects.toThrow();
        } finally {
          lost.mockRestore();
        }
      }
      expect(await harness.codec.decode(row.secret_ref)).toBe("rotated-secret");
      expect(await harness.codec.decode(row.retired_secret_refs[0]!)).toBe("native-secret");
      expect(await store.getProject()).toBeUndefined();
      expect(await store.getCleanupStats()).toEqual({ pending: 0, manual: 0, paused: true });
      expect(await store.setSource("example", { managedProjectId: project.id, providerConfigId: "config" })).toBe(
        false,
      );
      if (owner === "optional") expect(await store.deleteProject(project.id)).toBe(true);
      else
        expect(
          await harness.factory.nativeConfiguration.purgeForLifecycle(lifecycle, crypto.randomUUID()),
        ).toMatchObject({
          deletedProjects: 1,
          deletedSecrets: 2,
        });
    },
  );

  it("keeps partial lifecycle erasure inactive, preserves adjacent targets, and retries the exact custody", async () => {
    const scope = target();
    const neighbours = [
      { ...scope, workspaceId: crypto.randomUUID() },
      { ...scope, tenantId: crypto.randomUUID() },
    ];
    for (const selected of [scope, ...neighbours])
      expect((await request(selected, "PUT", `${prefix}/project`, input)).status).toBe(200);
    expect(
      (await request(scope, "PUT", `${prefix}/project`, { ...input, projectApiKey: "rotated-secret" })).status,
    ).toBe(200);
    const store = harness.factory.forConfigurationControl(writer(scope)).saasProjects;
    const project = await store.getProject();
    if (!project) throw new Error("Project fixture was not published");
    expect(await store.setSource("example", { managedProjectId: project.id, providerConfigId: "config" })).toBe(true);
    const lifecycle = {
      subjectKind: "service" as const,
      subject: "backend-system",
      purpose: "lifecycle:configuration:purge" as const,
      permissions: ["lifecycle:configuration:purge"],
      target: scope,
      requestId: crypto.randomUUID(),
      requestHash: "a".repeat(43),
    };
    const neighbour = await harness.factory.forConfigurationControl(writer(neighbours[0]!)).saasProjects.getProject();
    if (!neighbour) throw new Error("Adjacent project fixture was not published");
    await scopedQuery.withNativeLifecycleClient(harness.pool, lifecycle, async (client) => {
      expect((await client.query("UPDATE integration_runtime.managed_projects SET cleanup_paused=true")).rowCount).toBe(
        0,
      );
      expect(
        (
          await client.query<{ fenced: boolean }>(
            "SELECT integration_runtime.fence_managed_project_removal($1::uuid) AS fenced",
            [neighbour.id],
          )
        ).rows[0]?.fenced,
      ).toBe(false);
    });
    await expect(
      scopedQuery.withNativeLifecycleClient(
        harness.pool,
        {
          ...lifecycle,
          purpose: "lifecycle:configuration:read",
          permissions: ["lifecycle:configuration:read"],
          requestHash: undefined,
        },
        (client) => client.query("SELECT integration_runtime.fence_managed_project_removal($1::uuid)", [project.id]),
      ),
    ).rejects.toThrow();
    const remove = harness.codec.delete.bind(harness.codec);
    let count = 0;
    const failure = vi.spyOn(harness.codec, "delete").mockImplementation(async (ref) => {
      if (++count === 2) throw new Error("Retired secret unavailable");
      return remove(ref);
    });
    try {
      await expect(
        harness.factory.nativeConfiguration.purgeForLifecycle(lifecycle, crypto.randomUUID()),
      ).rejects.toThrow();
    } finally {
      failure.mockRestore();
    }
    expect(await store.getProject()).toBeUndefined();
    expect(await store.getCleanupStats()).toEqual({ pending: 0, manual: 0, paused: true });
    expect(await store.listSources()).toEqual([]);
    expect(await store.setSource("example", { managedProjectId: project.id, providerConfigId: "config" })).toBe(false);
    expect((await request(scope, "PUT", `${prefix}/project`, input)).status).toBe(409);
    for (const neighbour of neighbours)
      expect(await (await request(neighbour, "GET", `${prefix}/project`)).json()).toMatchObject({
        configured: true,
        status: "available",
      });
    expect(await harness.factory.nativeConfiguration.purgeForLifecycle(lifecycle, crypto.randomUUID())).toMatchObject({
      deletedProjects: 1,
      deletedSources: 0,
      deletedSecrets: 1,
    });
    expect(await store.getCleanupStats()).toEqual({ pending: 0, manual: 0, paused: false });
  });

  it("admits the genuine active member project during pending rotation but never an adjacent scope", async () => {
    const scope = target();
    expect((await request(scope, "PUT", `${prefix}/project`, input)).status).toBe(200);
    const project = await harness.factory.forConfigurationControl(writer(scope)).saasProjects.getProject();
    if (!project) throw new Error("Project fixture was not published");
    const encode = harness.codec.encode.bind(harness.codec);
    const uncertain = vi.spyOn(harness.codec, "encode").mockImplementation(async (...args) => {
      await encode(...args);
      throw new Error("Key-write acknowledgement lost");
    });
    try {
      expect(
        (await request(scope, "PUT", `${prefix}/project`, { ...input, projectApiKey: "rotated-secret" })).status,
      ).toBe(503);
    } finally {
      uncertain.mockRestore();
    }
    const member = harness.forScope({
      tenantId: scope.tenantId,
      workspaceId: scope.workspaceId,
      workspaceRole: "member",
    });
    expect(
      await scopedQuery.withScopedClient(harness.pool, member.scope, (client) =>
        projectAdmission.lockActiveManagedProject(client, project.id),
      ),
    ).toBe(true);
    for (const adjacent of [
      { ...member.scope, workspaceId: crypto.randomUUID() },
      { ...member.scope, tenantId: crypto.randomUUID() },
    ])
      expect(
        await scopedQuery.withScopedClient(harness.pool, adjacent, (client) =>
          projectAdmission.lockActiveManagedProject(client, project.id),
        ),
      ).toBe(false);
  });

  it("holds active source admission until publication so a concurrent removal cannot erase its key", async () => {
    const scope = target();
    expect((await request(scope, "PUT", `${prefix}/project`, input)).status).toBe(200);
    const store = harness.factory.forConfigurationControl(writer(scope)).saasProjects;
    const project = await store.getProject();
    if (!project) throw new Error("Project fixture was not published");
    const entered = Promise.withResolvers<void>();
    const released = Promise.withResolvers<void>();
    const lock = projectAdmission.lockActiveManagedProject;
    let held: PoolClient | undefined;
    let pid = 0;
    const admission = vi.spyOn(projectAdmission, "lockActiveManagedProject").mockImplementation(async (client, id) => {
      const admitted = await lock(client, id);
      if (admitted && id === project.id) {
        held = client;
        pid = (await client.query<{ pid: number }>("SELECT pg_backend_pid() AS pid")).rows[0]!.pid;
        entered.resolve();
        await released.promise;
      }
      return admitted;
    });
    const source = store.setSource("example", { managedProjectId: project.id, providerConfigId: "config" });
    await entered.promise;
    const removal = store.deleteProject(project.id);
    try {
      await vi.waitFor(async () => {
        if (!held) throw new Error("Active source admission was not reached");
        // pg_stat_activity caches its session set within this deliberately held transaction.
        await held.query("SELECT pg_stat_clear_snapshot()");
        const blocked = (
          await held.query<{ blocked: boolean }>(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1::integer=ANY(pg_blocking_pids(pid))) AS blocked",
            [pid],
          )
        ).rows[0]!.blocked;
        expect(blocked).toBe(true);
      });
    } finally {
      released.resolve();
      admission.mockRestore();
    }
    expect(await source).toBe(true);
    expect(await removal).toBe(false);
    expect((await store.getProject())?.apiKey).toBe("native-secret");
    expect(await store.getSource("example")).toMatchObject({
      managedProjectId: project.id,
      providerConfigId: "config",
    });
  });

  it.each(["optional", "lifecycle"] as const)(
    "retains changed inactive custody instead of finalizing a stale %s snapshot",
    async (owner) => {
      const scope = target();
      expect((await request(scope, "PUT", `${prefix}/project`, input)).status).toBe(200);
      const store = harness.factory.forConfigurationControl(writer(scope)).saasProjects;
      const project = await store.getProject();
      if (!project) throw new Error("Project fixture was not published");
      const extra = await harness.codec.encode("additional-settled-custody");
      const remove = harness.codec.delete.bind(harness.codec);
      let appended = false;
      const changed = vi.spyOn(harness.codec, "delete").mockImplementation(async (ref) => {
        const erased = await remove(ref);
        if (!appended) {
          appended = true;
          await scopedQuery.withConfigurationControlClient(harness.pool, writer(scope), (client) =>
            client.query(
              "UPDATE integration_runtime.managed_projects SET retired_secret_refs=array_append(retired_secret_refs,$1) WHERE id=$2 AND secret_ref IS NULL",
              [extra, project.id],
            ),
          );
        }
        return erased;
      });
      const lifecycle = {
        subjectKind: "service" as const,
        subject: "backend-system",
        purpose: "lifecycle:configuration:purge" as const,
        permissions: ["lifecycle:configuration:purge"],
        target: scope,
        requestId: crypto.randomUUID(),
        requestHash: "a".repeat(43),
      };
      try {
        if (owner === "optional") expect(await store.deleteProject(project.id)).toBe(false);
        else
          await expect(
            harness.factory.nativeConfiguration.purgeForLifecycle(lifecycle, crypto.randomUUID()),
          ).rejects.toThrow();
      } finally {
        changed.mockRestore();
      }
      expect(await store.getProject()).toBeUndefined();
      expect(await store.getCleanupStats()).toEqual({ pending: 0, manual: 0, paused: true });
      expect(await harness.codec.decode(extra)).toBe("additional-settled-custody");
      if (owner === "optional") expect(await store.deleteProject(project.id)).toBe(true);
      else
        expect(
          await harness.factory.nativeConfiguration.purgeForLifecycle(lifecycle, crypto.randomUUID()),
        ).toMatchObject({
          deletedProjects: 1,
          deletedSecrets: 1,
        });
      await expect(harness.codec.decode(extra)).rejects.toThrow();
    },
  );

  it("retries removal after the current secret was deleted but a retired secret deletion failed", async () => {
    const scope = target();
    expect((await request(scope, "PUT", `${prefix}/project`, input)).status).toBe(200);
    const rotated = await request(scope, "PUT", `${prefix}/project`, { ...input, projectApiKey: "rotated-secret" });
    expect(rotated.status).toBe(200);
    const { managedProjectId } = z.object({ managedProjectId: z.guid() }).parse(await rotated.json());
    const remove = harness.codec.delete.bind(harness.codec);
    let count = 0;
    const failure = vi.spyOn(harness.codec, "delete").mockImplementation(async (ref) => {
      if (++count === 2) throw new Error("Retired secret unavailable");
      return remove(ref);
    });
    try {
      expect((await request(scope, "DELETE", `${prefix}/project`, {})).status).toBe(503);
    } finally {
      failure.mockRestore();
    }
    const inactive = await request(scope, "GET", `${prefix}/project`);
    expect(inactive.status).toBe(200);
    expect(await inactive.json()).toMatchObject({ configured: false, cleanup: { paused: true } });
    expect(
      await harness.factory.forConfigurationControl(writer(scope)).saasProjects.setSource("example", {
        managedProjectId,
        providerConfigId: "config",
      }),
    ).toBe(false);
    const customer = harness.forScope({ tenantId: scope.tenantId, workspaceId: scope.workspaceId });
    await expect(
      customer.connectionRequests.createSaas({
        connectionRequestId: crypto.randomUUID(),
        connectionId: crypto.randomUUID(),
        owner: customer.scope.subjectUserId,
        service: "example",
        connectionName: "stale-captured-project",
        managedProjectId,
        providerConfigId: "config",
        externalUserId: customer.saasProjects.externalUserId(),
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 600_000).toISOString(),
      }),
    ).rejects.toThrow();
    const references = await scopedQuery.withScopedClient(
      harness.pool,
      customer.scope,
      async (client) =>
        (
          await client.query<{ count: string }>(
            "SELECT count(*) FROM integration_runtime.connection_requests WHERE managed_project_id=$1",
            [managedProjectId],
          )
        ).rows[0]!.count,
    );
    expect(Number(references)).toBe(0);
    expect((await request(scope, "DELETE", `${prefix}/project`, {})).status).toBe(204);
    expect(await (await request(scope, "GET", `${prefix}/project`)).json()).toMatchObject({ configured: false });
  });
});
