import type { SaasJwtVerifier } from "../auth/saas-jwt-verifier.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { NativePostgresFixture } from "../testing/native-store-fixtures.ts";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import { createSaasJwtVerifier } from "../auth/saas-jwt-verifier.ts";
import { SaasCleanupService } from "../saas-cleanup-service.ts";
import { SaasClient } from "../saas-client.ts";
import { withScopedClient } from "../storage/scoped-query.ts";
import { createNativePostgresHarness } from "../testing/native-store-fixtures.ts";
import { SaasConnectServer } from "./saas-connect-server.ts";

const harness = createNativePostgresHarness();
const path = "/internal/saas/maintenance";
let privateKey: CryptoKey;
let jwks: Server;
let verifyJwt: SaasJwtVerifier;
beforeAll(async () => {
  if (!harness.enabled) return;
  const keys = await generateKeyPair("EdDSA");
  privateKey = keys.privateKey;
  const key = { ...(await exportJWK(keys.publicKey)), alg: "EdDSA", kid: "current", use: "sig" };
  jwks = createServer((_request, response) => {
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ keys: [key] }));
  });
  const listening = Promise.withResolvers<void>();
  jwks.listen(0, "127.0.0.1", listening.resolve);
  await listening.promise;
  verifyJwt = createSaasJwtVerifier(
    {
      jwksUrl: `http://127.0.0.1:${(jwks.address() as AddressInfo).port}/jwks`,
      jwtIssuer: "integration-backend",
      jwtAudience: "open-connector-saas",
      jwtActiveKid: "current",
    },
    "bootstrap",
  ).verify;
});
afterAll(async () => {
  if (!jwks) return;
  const closed = Promise.withResolvers<void>();
  jwks.close((error) => (error ? closed.reject(error) : closed.resolve()));
  await closed.promise;
});
async function signed(scope: SaasRequestScope, extra: Record<string, unknown> = {}) {
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
    ...extra,
  })
    .setProtectedHeader({ alg: "EdDSA", kid: "current" })
    .sign(privateKey);
}
function maintenanceScope(scope: SaasRequestScope): SaasRequestScope {
  return {
    tenantId: scope.tenantId,
    workspaceId: scope.workspaceId,
    actorUserId: scope.actorUserId,
    subjectUserId: scope.subjectUserId,
    workspaceRole: scope.workspaceRole,
    purpose: "maintenance:run" as SaasRequestScope["purpose"],
    permissions: ["maintenance:run"],
  };
}
async function queued(db: NativePostgresFixture, connected: boolean) {
  db = harness.forScope({ ...db.scope, localConnectionId: crypto.randomUUID(), oauthSessionId: crypto.randomUUID() });
  const project = await db.saasProjects.getProject();
  const id = crypto.randomUUID(),
    connectionId = crypto.randomUUID();
  const lease = await db.connectionRequests.createSaas({
    connectionRequestId: id,
    connectionId,
    owner: db.scope.subjectUserId,
    service: "example",
    connectionName: `managed-${id}`,
    managedProjectId: project!.id,
    providerConfigId: "config",
    externalUserId: db.saasProjects.externalUserId(),
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
  });
  await db.connectionRequests.saveSaasRequest(lease, `remote-${id}`);
  if (connected) {
    await db.connectionRequests.saveSaasCandidate(lease, {
      connectedAccountId: `account-${id}`,
      profile: { accountId: id, displayName: "Managed", grantedScopes: [] },
      status: "active",
      comment: null,
    });
    expect(await db.connectionRequests.completeSaas(lease)).toBe("connected");
  } else await db.connectionRequests.releaseSaas(lease, Date.now());
  return {
    id,
    connectionId,
    accountId: `account-${id}`,
    localConnectionId: db.scope.localConnectionId!,
    oauthSessionId: db.scope.oauthSessionId!,
    externalUserId: db.saasProjects.externalUserId(),
    projectId: project!.projectId,
  };
}

describe.skipIf(!harness.enabled)("authenticated native maintenance against PostgreSQL", () => {
  it("drains durable disconnect and cancelled-request tasks without a user purge and retries the same failed task", async () => {
    const db = harness.forScope();
    await db.saasProjects.saveProject({
      id: crypto.randomUUID(),
      projectId: crypto.randomUUID(),
      baseUrl: "https://saas.example",
      apiKey: "project-key",
    });
    const disconnected = await queued(db, true),
      cancelled = await queued(db, false);
    const neighborUser = crypto.randomUUID();
    const neighbor = harness.forScope({ ...db.scope, actorUserId: neighborUser, subjectUserId: neighborUser });
    const untouched = await queued(neighbor, true);
    await harness
      .forScope({ ...neighbor.scope, localConnectionId: untouched.localConnectionId })
      .connectionStore.delete("example", `managed-${untouched.id}`);
    const removed: string[] = [];
    let fail = true;
    const client = new SaasClient(async (url, init) => {
      const remote = new URL(String(url)).pathname;
      if (init?.method === "DELETE") {
        if (fail) return new Response(null, { status: 503 });
        removed.push(remote.split("/").at(-1)!);
        return Response.json({ success: true, data: { connectedAccountId: remote.split("/").at(-1)!, deleted: true } });
      }
      if (remote.endsWith(`/connection-requests/remote-${cancelled.id}`))
        return Response.json({
          success: true,
          data: {
            id: `remote-${cancelled.id}`,
            projectId: cancelled.projectId,
            providerConfigId: "config",
            externalUserId: cancelled.externalUserId,
            alias: `connect-${cancelled.id}`,
            service: "example",
            status: "connected",
            connectedAccountId: cancelled.accountId,
            authorizationUrl: "https://saas.example/authorize",
            errorCode: null,
            errorMessage: null,
            expiresAt: new Date(Date.now() + 600_000).toISOString(),
            createdAt: Date.now(),
            updatedAt: Date.now(),
          },
        });
      throw new Error(`Maintenance invoked an unexpected provider operation: ${remote}`);
    });
    const options = {
      catalog: createCatalogStore([]),
      verifyJwt,
      runtimeDatabaseFactory: harness.factory,
      providerLoader: {
        async loadActionExecutor() {
          throw new Error("Maintenance must not execute actions");
        },
        async loadProxyExecutor() {
          return undefined;
        },
        async loadCredentialValidators() {
          return undefined;
        },
      },
      oauthCredentials: {
        async refresh() {
          throw new Error("Maintenance must not refresh credentials");
        },
      },
      readiness: async () => ({
        postgres: true,
        openBao: true,
        jwks: true,
        seaweedFs: true,
        providerRegistry: true,
        catalogFingerprint: true,
      }),
      maintenanceForScope: async (scope: Readonly<SaasRequestScope>) => {
        const runtime = harness.factory.forScope(scope);
        await new SaasCleanupService({
          ...scope,
          store: runtime.saasProjects,
          requests: runtime.connectionRequests,
          client,
        }).run();
      },
    };
    const app = new SaasConnectServer(options).createApp();
    const disconnectToken = await signed(
      { ...db.scope, purpose: "connection:write", permissions: ["connection:write"] },
      { local_connection_id: disconnected.localConnectionId, connector_connection_id: disconnected.connectionId },
    );
    expect(
      (
        await app.request(`/internal/saas/connections/${disconnected.connectionId}`, {
          method: "DELETE",
          headers: { authorization: `Bearer ${disconnectToken}` },
        })
      ).status,
    ).toBe(204);
    await harness
      .forScope({
        ...db.scope,
        localConnectionId: cancelled.localConnectionId,
        oauthSessionId: cancelled.oauthSessionId,
      })
      .connectionRequests.cancelSaas(cancelled.id, db.scope.subjectUserId);
    expect(await db.saasProjects.getCleanupStats()).toMatchObject({ pending: 2 });
    const rows = () =>
      withScopedClient(
        harness.pool,
        db.scope,
        async (sql) => (await sql.query("SELECT id,attempts FROM integration_runtime.saas_cleanup ORDER BY id")).rows,
      );
    const before = await rows();
    const pass = async () =>
      app.request(path, {
        method: "POST",
        headers: {
          authorization: `Bearer ${await signed(maintenanceScope(db.scope))}`,
          "content-type": "application/json",
        },
        body: "{}",
      });
    expect((await pass()).status).toBe(204);
    expect((await rows()).map((row) => row.id)).toEqual(before.map((row) => row.id));
    expect((await rows()).every((row) => Number(row.attempts) > 0)).toBe(true);
    fail = false;
    await withScopedClient(harness.pool, db.scope, async (sql) => {
      await sql.query("UPDATE integration_runtime.saas_cleanup SET next_attempt_at=$1", [Date.now() - 1000]);
    });
    expect((await pass()).status).toBe(204);
    expect(await db.saasProjects.getCleanupStats()).toEqual({ pending: 0, manual: 0, paused: false });
    expect(new Set(removed)).toEqual(new Set([disconnected.accountId, cancelled.accountId]));
    expect(await neighbor.saasProjects.getCleanupStats()).toMatchObject({ pending: 1 });
  });

  it("returns safe HTTP503 on batch SQL failure while retaining the actual queued task without remote work", async () => {
    const db = harness.forScope();
    await db.saasProjects.saveProject({
      id: crypto.randomUUID(),
      projectId: crypto.randomUUID(),
      baseUrl: "https://saas.example",
      apiKey: "private-project-key",
    });
    const account = await queued(db, true);
    await harness
      .forScope({ ...db.scope, localConnectionId: account.localConnectionId })
      .connectionStore.delete("example", `managed-${account.id}`);
    expect(await db.saasProjects.getCleanupStats()).toMatchObject({ pending: 1 });
    let externalCalls = 0;
    const options = {
      catalog: createCatalogStore([]),
      verifyJwt,
      providerLoader: {
        async loadActionExecutor() {
          return undefined;
        },
        async loadProxyExecutor() {
          return undefined;
        },
        async loadCredentialValidators() {
          return undefined;
        },
      },
      oauthCredentials: {
        async refresh() {
          throw new Error("No refresh");
        },
      },
      readiness: async () => ({
        postgres: true,
        openBao: true,
        jwks: true,
        seaweedFs: true,
        providerRegistry: true,
        catalogFingerprint: true,
      }),
      maintenanceForScope: async (scope: Readonly<SaasRequestScope>) => {
        const runtime = harness.factory.forScope(scope);
        const requests = Object.assign(Object.create(runtime.connectionRequests), {
          expireSaas: async () =>
            withScopedClient(harness.pool, scope, async (sql) => {
              await sql.query("SELECT 1 / 0");
            }),
        });
        await new SaasCleanupService({
          ...scope,
          store: runtime.saasProjects,
          requests,
          client: new SaasClient(async () => {
            externalCalls++;
            return new Response(null, { status: 503 });
          }),
        }).run();
      },
    };
    const app = new SaasConnectServer(options).createApp();
    const response = await app.request(path, {
      method: "POST",
      headers: {
        authorization: `Bearer ${await signed(maintenanceScope(db.scope))}`,
        "content-type": "application/json",
      },
      body: "{}",
    });
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "maintenance_unavailable" });
    expect(await db.saasProjects.getCleanupStats()).toMatchObject({ pending: 1, manual: 0 });
    expect(externalCalls).toBe(0);
  });

  it("rejects foreign actors, wrong profiles, execution bindings and nonempty transport before native work", async () => {
    const scope = maintenanceScope(harness.forScope().scope);
    let calls = 0;
    const options = {
      catalog: createCatalogStore([]),
      verifyJwt,
      providerLoader: {
        async loadActionExecutor() {
          return undefined;
        },
        async loadProxyExecutor() {
          return undefined;
        },
        async loadCredentialValidators() {
          return undefined;
        },
      },
      oauthCredentials: {
        async refresh() {
          throw new Error("No refresh");
        },
      },
      readiness: async () => ({
        postgres: true,
        openBao: true,
        jwks: true,
        seaweedFs: true,
        providerRegistry: true,
        catalogFingerprint: true,
      }),
      maintenanceForScope: async () => {
        calls++;
      },
    };
    const app = new SaasConnectServer(options).createApp();
    for (const extra of [
      { actor_user_id: crypto.randomUUID() },
      { subject_kind: "policy_control" },
      { purpose: "catalog:read", permissions: ["catalog:read"] },
      { connector_connection_id: crypto.randomUUID() },
      { request_hash: "a".repeat(43) },
      { action_id: "example.run" },
    ]) {
      const response = await app.request(path, {
        method: "POST",
        headers: { authorization: `Bearer ${await signed(scope, extra)}`, "content-type": "application/json" },
        body: "{}",
      });
      expect([401, 403]).toContain(response.status);
    }
    for (const [suffix, body, expected] of [
      ["?owner=other", "{}", 400],
      ["", '{"owner":"other"}', 400],
      ["", "[]", 400],
      ["", " ".repeat(65_537), 413],
    ] as const) {
      expect(
        (
          await app.request(`${path}${suffix}`, {
            method: "POST",
            headers: { authorization: `Bearer ${await signed(scope)}`, "content-type": "application/json" },
            body,
          })
        ).status,
      ).toBe(expected);
    }
    expect(
      (
        await app.request("/internal/saas/actions/example.run", {
          method: "POST",
          headers: { authorization: `Bearer ${await signed(scope)}`, "content-type": "application/json" },
          body: JSON.stringify({ connectorConnectionId: crypto.randomUUID(), input: {} }),
        })
      ).status,
    ).toBe(403);
    expect(calls).toBe(0);
  });
});
