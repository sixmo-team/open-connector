import type { SaasJwtVerifier } from "../auth/saas-jwt-verifier.ts";
import type { SaasHonoEnvironment } from "../auth/scoped-request.ts";
import type { SaasConfig } from "../config.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { NativePostgresFixture } from "../testing/native-store-fixtures.ts";
import type { S3Client } from "@aws-sdk/client-s3";
import type { Hono } from "hono";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import * as catalogModule from "../../catalog-store.ts";
import * as authenticationModule from "../auth/saas-jwt-verifier.ts";
import { createSaasJwtVerifier } from "../auth/saas-jwt-verifier.ts";
import * as configurationModule from "../config.ts";
import { createSeaweedFsS3Client, SeaweedFsTransitFileService } from "../files/seaweedfs-transit-files.ts";
import * as transitModule from "../files/seaweedfs-transit-files.ts";
import { SaasCleanupService } from "../saas-cleanup-service.ts";
import { SaasClient } from "../saas-client.ts";
import { OpenBaoClient } from "../secrets/openbao-client.ts";
import { OpenBaoSecretCodec } from "../secrets/secret-codec.ts";
import * as poolModule from "../storage/postgres-pool.ts";
import { PostgresSecretCustodyStore } from "../storage/postgres-secret-custody.ts";
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
  it("runs production maintenance for actor-owned objects and settled orphan secrets without settling unknown writes", async () => {
    const objects = new Map<string, Buffer>();
    const secrets = new Map<string, string>();
    let failSecret: string | undefined;
    const deleted: string[] = [];
    let failDelete: string | undefined;
    let stalledDelete: string | undefined;
    const deletionStarted = Promise.withResolvers<void>();
    const deletionClosed = Promise.withResolvers<void>();
    const s3 = createServer(async (request, response) => {
      const key = new URL(request.url!, "http://fixture").pathname;
      if (request.method === "HEAD") response.writeHead(200).end();
      else if (request.method === "PUT") {
        const chunks: Buffer[] = [];
        for await (const chunk of request) chunks.push(Buffer.from(chunk));
        objects.set(key, Buffer.concat(chunks));
        response.writeHead(200, { etag: '"fixture"' }).end();
      } else if (request.method === "DELETE") {
        if (key === stalledDelete) {
          response.once("close", deletionClosed.resolve);
          deletionStarted.resolve();
          return;
        }
        if (key === failDelete) {
          response
            .writeHead(403, { "content-type": "application/xml" })
            .end("<Error><Code>AccessDenied</Code></Error>");
          return;
        }
        objects.delete(key);
        deleted.push(key);
        response.writeHead(204).end();
      } else response.writeHead(405).end();
    });
    let client: S3Client | undefined;
    const listener = createServer();
    try {
      const listening = Promise.withResolvers<void>();
      s3.listen(0, "127.0.0.1", listening.resolve);
      await listening.promise;
      const endpoint = `http://127.0.0.1:${(s3.address() as AddressInfo).port}`;
      const jwksUrl = `http://127.0.0.1:${(jwks.address() as AddressInfo).port}/jwks`;
      const config: SaasConfig = {
        postgresUrl: "postgresql://unused/startup-seam",
        openBaoAddress: "https://openbao.example",
        openBaoTokenFile: "/unused/openbao-token",
        openBaoRequestTimeoutMs: 1_000,
        openBaoMaxRequestBytes: 262_144,
        openBaoMaxResponseBytes: 1_048_576,
        internalOrigin: "https://connector.internal",
        oauthCallbackOrigin: "https://connector.example",
        jwksUrl,
        jwksBearerTokenFile: "/unused/jwks-token",
        jwtIssuer: "integration-backend",
        jwtAudience: "open-connector-saas",
        jwtActiveKid: "current",
        policyControlJwksUrl: jwksUrl,
        policyControlIssuer: "policy-control",
        policyControlAudience: "policy-control",
        policyControlActiveKid: "current",
        allowedCustomOAuth: [],
        egressTrustedHosts: [],
        seaweedFsEndpoint: endpoint,
        seaweedFsBucket: "transit",
        seaweedFsAccessKeyId: "fixture-key",
        seaweedFsSecretAccessKey: "fixture-secret",
        host: "127.0.0.1",
        port: 0,
      };
      // Only startup infrastructure is substituted. The route, JWT verifier, factory,
      // maintenance composition, restricted PostgreSQL and native S3 transport are real.
      vi.spyOn(configurationModule, "readSaasConfig").mockReturnValue(config);
      vi.spyOn(authenticationModule, "readJwksBearerTokenFile").mockResolvedValue("bootstrap");
      vi.spyOn(poolModule, "createPostgresPool").mockReturnValue(harness.pool);
      vi.spyOn(catalogModule, "loadCatalog").mockResolvedValue(createCatalogStore([]));
      vi.doMock("../../providers/registry.generated.ts", () => ({ executorModules: {} }));
      const vault = new OpenBaoClient({
        address: config.openBaoAddress,
        token: "fixture-token",
        fetchFn: async (input, init) => {
          const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
          const ref = url.pathname.slice(4).replace("/metadata/", "/data/");
          if (init?.method === "POST") {
            const value = JSON.parse(String(init.body));
            secrets.set(ref, value.data.payload);
            return Response.json({ errors: ["Original write outcome is unknown"] }, { status: 503 });
          }
          if (init?.method === "DELETE") {
            if (ref === failSecret) return Response.json({ errors: ["Unavailable"] }, { status: 503 });
            return secrets.delete(ref) ? Response.json({}) : Response.json({ errors: ["Missing"] }, { status: 404 });
          }
          const payload = secrets.get(ref);
          return payload === undefined
            ? Response.json({ errors: ["Missing"] }, { status: 404 })
            : Response.json({ data: { data: { payload }, metadata: { version: 1 } } });
        },
      });
      vi.spyOn(OpenBaoClient, "fromTokenFile").mockResolvedValue(vault);
      vi.spyOn(OpenBaoClient.prototype, "probeCapabilities").mockResolvedValue({ checkedPaths: [] });
      vi.doMock("@hono/node-server", () => ({ serve: () => listener }));
      client = createSeaweedFsS3Client(config);
      vi.spyOn(transitModule, "createSeaweedFsS3Client").mockReturnValue(client);
      const createApp = SaasConnectServer.prototype.createApp;
      const applications: Hono<SaasHonoEnvironment>[] = [];
      vi.spyOn(SaasConnectServer.prototype, "createApp").mockImplementation(function (this: SaasConnectServer) {
        const app = createApp.call(this);
        applications.push(app);
        return app;
      });
      // Loading the side-effecting production entrypoint must follow the startup seams above.
      await import("../index.ts");
      const application = applications[0];
      if (!application) throw new Error("Production composition did not create its private application");
      const owner = harness.forScope().scope;
      const otherUser = crypto.randomUUID();
      const neighbor = { ...owner, actorUserId: otherUser, subjectUserId: otherUser };
      const foreign = { ...owner, tenantId: crypto.randomUUID() };
      const queuedSecret = async (scope: SaasRequestScope) => {
        const ref = `client-secrets/data/tenants/${scope.tenantId}/workspaces/${scope.workspaceId}/integrations/oauth-sessions/${crypto.randomUUID()}`;
        secrets.set(ref, `settled-${crypto.randomUUID()}`);
        const custody = new PostgresSecretCustodyStore(harness.pool, scope, new OpenBaoSecretCodec(vault, scope));
        await withScopedClient(harness.pool, scope, (sql) =>
          custody.adoptDeleting(sql, [ref], {
            kind: "trigger-source",
            id: crypto.randomUUID(),
            dataUserId: scope.actorUserId,
            credentialOwnerId: scope.subjectUserId,
            identity: { actorUserId: scope.actorUserId },
          }),
        );
        return ref;
      };
      const ownedSecret = await queuedSecret(owner);
      const neighborSecret = await queuedSecret(neighbor);
      const foreignSecret = await queuedSecret(foreign);
      const unknownTarget = {
        kind: "trigger-source" as const,
        id: crypto.randomUUID(),
        dataUserId: owner.actorUserId,
        credentialOwnerId: owner.subjectUserId,
        identity: { actorUserId: owner.actorUserId },
      };
      await expect(
        new PostgresSecretCustodyStore(harness.pool, owner, new OpenBaoSecretCodec(vault, owner)).encode(
          "unresolved-private-payload",
          unknownTarget,
        ),
      ).rejects.toMatchObject({ code: "OPENBAO_UNAVAILABLE" });
      const unknownSecret = await withScopedClient(
        harness.pool,
        owner,
        async (sql) =>
          (
            await sql.query<{ secret_ref: string }>(
              "SELECT secret_ref FROM integration_runtime.secret_custody WHERE target_id=$1 AND state='pending'",
              [unknownTarget.id],
            )
          ).rows[0]?.secret_ref,
      );
      if (!unknownSecret) throw new Error("The original uncertain write was not reserved");
      const sharedInvocation: SaasRequestScope = {
        ...owner,
        subjectUserId: neighbor.subjectUserId,
        purpose: "action:execute:v2",
        permissions: ["action:execute:v2"],
      };
      const service = (scope: SaasRequestScope) =>
        new SeaweedFsTransitFileService({
          client: client!,
          bucket: config.seaweedFsBucket,
          scope,
          metadata: harness.forScope(scope).transitFileStore,
          publicOrigin: config.internalOrigin,
          ttlSeconds: 60,
          maxBytes: 100,
          requestTimeoutMs: 2_000,
        });
      const expired = await service(sharedInvocation).create(new File(["old"], "expired.txt"));
      const live = await service(owner).create(new File(["live"], "live.txt"));
      const retry = await service(sharedInvocation).create(new File(["retry"], "retry.txt"));
      const neighborFile = await service(neighbor).create(new File(["neighbor"], "neighbor.txt"));
      const foreignFile = await service(foreign).create(new File(["foreign"], "foreign.txt"));
      for (const [scope, ids] of [
        [owner, [expired.fileId, retry.fileId]],
        [neighbor, [neighborFile.fileId]],
        [foreign, [foreignFile.fileId]],
      ] as const) {
        await withScopedClient(harness.pool, scope, (sql) =>
          sql.query(
            "UPDATE integration_runtime.transit_files SET expires_at=clock_timestamp()-interval '1 second' WHERE id=ANY($1::uuid[])",
            [ids],
          ),
        );
      }
      const key = (scope: SaasRequestScope, id: string) => `/transit/${scope.tenantId}/${scope.workspaceId}/${id}`;
      const pass = async (signal?: AbortSignal) =>
        application.request(path, {
          method: "POST",
          signal,
          headers: {
            authorization: `Bearer ${await signed(maintenanceScope(owner))}`,
            "content-type": "application/json",
          },
          body: "{}",
        });
      failDelete = key(owner, retry.fileId);
      const failed = await pass();
      expect(failed.status).toBe(503);
      expect(await failed.json()).toEqual({ error: "maintenance_unavailable" });
      expect(await harness.forScope(owner).transitFileStore.get(retry.fileId)).toMatchObject({ status: "reconcile" });
      expect(objects.has(key(owner, retry.fileId))).toBe(true);
      expect(secrets.has(ownedSecret)).toBe(false);
      expect(secrets.has(neighborSecret)).toBe(true);
      expect(secrets.has(foreignSecret)).toBe(true);
      expect(secrets.has(unknownSecret)).toBe(true);
      failDelete = undefined;
      expect((await pass()).status).toBe(204);
      const metadata = harness.forScope(owner).transitFileStore;
      expect(await metadata.get(expired.fileId)).toBeUndefined();
      expect(await metadata.get(retry.fileId)).toBeUndefined();
      expect(await metadata.get(live.fileId)).toMatchObject({ status: "available" });
      expect(await harness.forScope(neighbor).transitFileStore.get(neighborFile.fileId)).toMatchObject({
        status: "available",
      });
      expect(await harness.forScope(foreign).transitFileStore.get(foreignFile.fileId)).toMatchObject({
        status: "available",
      });
      expect(new Set(deleted)).toEqual(new Set([key(owner, expired.fileId), key(owner, retry.fileId)]));
      expect(new Set(objects.keys())).toEqual(
        new Set([key(owner, live.fileId), key(neighbor, neighborFile.fileId), key(foreign, foreignFile.fileId)]),
      );
      const cancelled = await service(sharedInvocation).create(new File(["cancel"], "cancelled.txt"));
      await withScopedClient(harness.pool, owner, (sql) =>
        sql.query(
          "UPDATE integration_runtime.transit_files SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
          [cancelled.fileId],
        ),
      );
      stalledDelete = key(owner, cancelled.fileId);
      const controller = new AbortController();
      const interrupted = pass(controller.signal);
      await deletionStarted.promise;
      controller.abort();
      expect((await interrupted).status).toBe(503);
      await deletionClosed.promise;
      expect(objects.has(stalledDelete)).toBe(true);
      expect(await metadata.get(cancelled.fileId)).toMatchObject({ status: "deleting" });
      stalledDelete = undefined;
      expect((await pass()).status).toBe(204);
      expect(await metadata.get(cancelled.fileId)).toBeUndefined();
      expect(objects.has(key(owner, cancelled.fileId))).toBe(false);
      const retrySecret = await queuedSecret(owner);
      failSecret = retrySecret;
      expect((await pass()).status).toBe(503);
      expect(secrets.has(retrySecret)).toBe(true);
      failSecret = undefined;
      expect((await pass()).status).toBe(204);
      expect(secrets.has(retrySecret)).toBe(false);
      expect(secrets.has(neighborSecret)).toBe(true);
      expect(secrets.has(foreignSecret)).toBe(true);
      expect(secrets.has(unknownSecret)).toBe(true);
    } finally {
      vi.restoreAllMocks();
      vi.doUnmock("../../providers/registry.generated.ts");
      vi.doUnmock("@hono/node-server");
      client?.destroy();
      s3.closeAllConnections();
      if (s3.listening) {
        const closed = Promise.withResolvers<void>();
        s3.close((error) => (error ? closed.reject(error) : closed.resolve()));
        await closed.promise;
      }
    }
  });

  it("drains durable disconnect and cancelled-request tasks without a user purge and retries the same failed task", async () => {
    const db = harness.forScope();
    await db.saasProjects.saveProject(
      {
        id: crypto.randomUUID(),
        projectId: crypto.randomUUID(),
        baseUrl: "https://saas.example",
        apiKey: "project-key",
      },
      null,
    );
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
    await db.saasProjects.saveProject(
      {
        id: crypto.randomUUID(),
        projectId: crypto.randomUUID(),
        baseUrl: "https://saas.example",
        apiKey: "private-project-key",
      },
      null,
    );
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
