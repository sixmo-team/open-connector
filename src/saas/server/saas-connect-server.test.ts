import type { StoredConnection } from "../../connection-service.ts";
import type { IProviderLoader } from "../../providers/provider-loader.ts";
import type { SaasJwtVerifier } from "../auth/saas-jwt-verifier.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { SafeStoredConnection } from "../storage/postgres-connection-store.ts";
import type { SaasRuntimeConnectionStore, SaasRuntimeDatabase } from "../storage/postgres-runtime-database.ts";
import type { RunLog, RunLogListInput } from "../storage/run-store.ts";

import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import { canonicalActionRequestHash, canonicalRequestHash } from "../actions/canonical-request.ts";
import { SaasAuthorizationError } from "../auth/saas-jwt-verifier.ts";
import {
  LifecyclePurgeConflictError,
  LifecycleReconciliationRequiredError,
} from "../lifecycle/scoped-lifecycle-service.ts";
import { decodeRunLogCursor, encodeRunLogCursor } from "../storage/run-store.ts";
import { SaasConnectServer } from "./saas-connect-server.ts";

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

const verifyJwt: SaasJwtVerifier = async (authorization) => {
  const token = authorization?.replace(/^Bearer /, "");
  if (token === "catalog") return catalogPrincipal();
  if (token === "tenant-catalog") return scope("catalog:read");
  if (token === "wrong-permission") return scope("connection:read", { permissions: ["catalog:read"] });
  if (token === "execute") {
    const input = { query: "inbox" };
    return scope("action:execute", {
      localConnectionId: "local-1",
      connectorConnectionId: "connector-1",
      actionId: "gmail.messages_list",
      maxOutputBytes: 8_388_608,
      requestHash: canonicalActionRequestHash("gmail.messages_list", "connector-1", input),
    });
  }
  if (token === "oauth") {
    return scope("oauth:start", { localConnectionId: "local-1", oauthSessionId: "oauth-1" });
  }
  throw new SaasAuthorizationError(401);
};

function completeReadiness() {
  return {
    postgres: true,
    openBao: true,
    jwks: true,
    seaweedFs: true,
    providerRegistry: true,
    catalogFingerprint: true,
  };
}
const app = new SaasConnectServer({
  catalog: createCatalogStore([]),
  providerLoader,
  verifyJwt,
  readiness: completeReadiness(),
}).createApp();

describe("SaasConnectServer", () => {
  it("exposes process health and readiness", async () => {
    expect((await app.request("/health")).status).toBe(200);
    expect((await app.request("/ready")).status).toBe(200);
  });
  it("reports unavailable until every startup dependency is checked", async () => {
    const unready = new SaasConnectServer({
      catalog: createCatalogStore([]),
      providerLoader,
      verifyJwt,
      readiness: { ...completeReadiness(), openBao: false },
    }).createApp();
    expect((await unready.request("/health")).status).toBe(200);
    expect((await unready.request("/ready")).status).toBe(503);
  });

  it.each([
    "/api",
    "/api/providers",
    "/v1/proxy",
    "/v1/proxy/gmail",
    "/mcp",
    "/oauth/callback",
    "/api/oauth/callback/gmail",
    "/v1/actions",
  ])("does not mount upstream public surface %s", async (path) => {
    const response = await app.request(path, { headers: { authorization: "Bearer static-runtime-token" } });
    expect(response.status).toBe(404);
  });

  it("returns a generic forbidden response for the wrong purpose", async () => {
    const response = await app.request("/internal/saas/connections", {
      headers: { authorization: "Bearer catalog" },
    });
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "forbidden" });
  });

  it.each([
    ["GET", "/internal/saas/catalog/actions/search?q=gmail"],
    ["GET", "/internal/saas/connections"],
    ["POST", "/internal/saas/connections/credentials"],
    ["PATCH", "/internal/saas/connections/connection-1/visibility"],
    ["PUT", "/internal/saas/connections/connection-1/credentials"],
    ["POST", "/internal/saas/connections/connection-1/transfer"],
    ["DELETE", "/internal/saas/connections/connection-1"],
    ["POST", "/internal/saas/oauth/start"],
    ["POST", "/internal/saas/oauth/complete"],
    ["POST", "/internal/saas/actions/gmail.messages_list"],
    ["GET", "/internal/saas/files/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
    ["GET", "/internal/saas/runs"],
    ["GET", "/internal/saas/runs/execution-1"],
    ["GET", "/internal/saas/lifecycle/export"],
    ["POST", "/internal/saas/lifecycle/purge"],
  ])("denies the catalog service principal on %s %s", async (method, path) => {
    const response = await app.request(path, {
      method,
      headers: { authorization: "Bearer catalog" },
    });
    expect(response.status).toBe(403);
  });

  it("returns a generic forbidden response when the exact permission is absent", async () => {
    const response = await app.request("/internal/saas/connections", {
      headers: { authorization: "Bearer wrong-permission" },
    });
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "forbidden" });
  });

  it("serves only the file bound to the exact scoped token", async () => {
    const fileId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const fileApp = new SaasConnectServer({
      catalog: createCatalogStore([]),
      providerLoader,
      verifyJwt: async () => scope("file:read", { fileId }),
      readiness: completeReadiness(),
      runtimeDatabaseFactory: {
        forScope() {
          return {
            transitFiles: {
              async response(id: string) {
                return new Response(`bytes:${id}`, {
                  headers: { "content-type": "text/plain", "content-disposition": 'attachment; filename="file"' },
                });
              },
            },
          } as unknown as SaasRuntimeDatabase;
        },
      },
    }).createApp();

    const allowed = await fileApp.request(`/internal/saas/files/${fileId}`, {
      headers: { authorization: "Bearer file" },
    });
    expect(allowed.status).toBe(200);
    expect(await allowed.text()).toBe(`bytes:${fileId}`);
    expect(allowed.headers.get("content-disposition")).toBe('attachment; filename="file"');
    expect(
      (
        await fileApp.request("/internal/saas/files/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", {
          headers: { authorization: "Bearer file" },
        })
      ).status,
    ).toBe(403);
  });

  it("returns a generic unauthorized response for invalid authentication", async () => {
    const response = await app.request("/internal/saas/connections");
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "unauthorized" });
  });

  it("serves catalog data only through the scoped internal route", async () => {
    const response = await app.request("/internal/saas/catalog/providers", {
      headers: { authorization: "Bearer catalog" },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual([]);
  });

  it("retains tenant-scoped catalog access", async () => {
    const response = await app.request("/internal/saas/catalog/actions", {
      headers: { authorization: "Bearer tenant-catalog" },
    });
    expect(response.status).toBe(200);
  });

  it("serves safe provider form metadata, paginated schemas, and bounded search", async () => {
    const catalog = createCatalogStore([
      {
        service: "example",
        displayName: "Example",
        categories: ["Developer Tools"],
        authTypes: ["api_key", "custom_credential", "oauth2", "no_auth"],
        auth: [
          { type: "no_auth" },
          {
            type: "api_key",
            label: "Access token",
            description: "Create a token in Example.",
            extraFields: [
              {
                key: "region",
                label: "Region",
                inputType: "text",
                required: true,
                secret: false,
              },
            ],
          },
          {
            type: "custom_credential",
            fields: [
              {
                key: "password",
                label: "Password",
                inputType: "textarea",
                required: true,
                secret: true,
              },
            ],
          },
          {
            type: "oauth2",
            authorizationUrl: "https://example.test/authorize",
            tokenUrl: "https://example.test/token",
            scopes: ["read"],
            tokenEndpointAuthMethod: "client_secret_post",
          },
        ],
        actions: ["first", "second"].map((name) => ({
          id: `example.${name}`,
          service: "example",
          name,
          description: `${name} action`,
          requiredScopes: ["read"],
          providerPermissions: ["read"],
          inputSchema: { type: "object", properties: { query: { type: "string" } } },
          outputSchema: { type: "object", properties: { ok: { type: "boolean" } } },
        })),
      },
    ]);
    const catalogApp = new SaasConnectServer({
      catalog,
      providerLoader,
      verifyJwt: async (authorization) =>
        authorization === "Bearer search" ? scope("action:search") : catalogPrincipal(),
      readiness: completeReadiness(),
      oauthClientReadiness: new Map([["example", { status: "operational" as const }]]),
    }).createApp();

    const providers = await (
      await catalogApp.request("/internal/saas/catalog/providers", {
        headers: { authorization: "Bearer catalog" },
      })
    ).json();
    expect(providers).toEqual([
      expect.objectContaining({
        service: "example",
        connectionMethods: [
          { type: "no_auth", fields: [], status: "operational" },
          {
            type: "api_key",
            fields: [
              {
                name: "apiKey",
                label: "Access token",
                description: "Create a token in Example.",
                inputType: "password",
                required: true,
              },
              { name: "region", label: "Region", inputType: "text", required: true },
            ],
            status: "operational",
          },
          {
            type: "custom_credential",
            fields: [{ name: "password", label: "Password", inputType: "password", required: true }],
            status: "operational",
          },
          { type: "oauth2", fields: [], status: "operational" },
        ],
      }),
    ]);
    expect(JSON.stringify(providers)).not.toContain("authorizationUrl");
    expect(JSON.stringify(providers)).not.toContain("tokenUrl");
    const unavailableApp = new SaasConnectServer({
      catalog,
      providerLoader,
      verifyJwt,
      readiness: completeReadiness(),
      oauthClientReadiness: new Map([
        ["example", { status: "unavailable" as const, reasonCode: "oauth_client_config_access_denied" as const }],
      ]),
    }).createApp();
    const unavailableProviders = await (
      await unavailableApp.request("/internal/saas/catalog/providers", {
        headers: { authorization: "Bearer catalog" },
      })
    ).json();
    expect(unavailableProviders[0].authTypes).toContain("oauth2");
    expect(unavailableProviders[0].connectionMethods).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: "api_key", status: "operational" }),
        {
          type: "oauth2",
          fields: [],
          status: "unavailable",
          reasonCode: "oauth_client_config_access_denied",
        },
      ]),
    );
    expect(JSON.stringify(unavailableProviders)).not.toContain("OpenBao");
    expect(JSON.stringify(unavailableProviders)).not.toContain("client-id");

    const first = await (
      await catalogApp.request("/internal/saas/catalog/actions?limit=1", {
        headers: { authorization: "Bearer catalog" },
      })
    ).json();
    expect(first.items).toHaveLength(1);
    const unavailableFirst = await (
      await unavailableApp.request("/internal/saas/catalog/actions?limit=1", {
        headers: { authorization: "Bearer catalog" },
      })
    ).json();
    expect(unavailableFirst.catalogFingerprint).toBe(first.catalogFingerprint);
    expect(first.items[0]).toHaveProperty("inputSchema");
    expect(first.nextCursor).toEqual(expect.any(String));
    const second = await (
      await catalogApp.request(`/internal/saas/catalog/actions?limit=1&cursor=${first.nextCursor}`, {
        headers: { authorization: "Bearer catalog" },
      })
    ).json();
    expect(second.items).toHaveLength(1);
    expect(second.nextCursor).toBeNull();
    expect(second.catalogFingerprint).toBe(first.catalogFingerprint);

    const search = await (
      await catalogApp.request("/internal/saas/catalog/actions/search?q=first", {
        headers: { authorization: "Bearer search" },
      })
    ).json();
    expect(search).toEqual([
      expect.objectContaining({ id: "example.first", requiredScopes: ["read"], providerPermissions: ["read"] }),
    ]);
    expect(search[0]).not.toHaveProperty("inputSchema");
    expect(
      (
        await catalogApp.request("/internal/saas/catalog/actions?cursor=invalid", {
          headers: { authorization: "Bearer catalog" },
        })
      ).status,
    ).toBe(400);
  });

  it("rejects declared JSON bodies above the SaaS limit", async () => {
    const response = await app.request("/internal/saas/oauth/start", {
      method: "POST",
      headers: {
        authorization: "Bearer oauth",
        "content-type": "application/json",
        "content-length": "262145",
      },
      body: "{}",
    });
    expect(response.status).toBe(413);
  });

  it("creates, shares, unshares, transfers, and revokes safe credential connections", async () => {
    interface MemoryRow {
      stored: StoredConnection;
      owner: string;
      localConnectionId: string;
      visibility: "user" | "workspace";
      createdAt: string;
      updatedAt: string;
      blocked: boolean;
    }
    const rows: MemoryRow[] = [];
    const revocationEvents: string[] = [];
    const revocationReceipts = new Set<string>();
    const revocationReceiptKey = (connectionId: string) =>
      `${requestScope.tenantId}/${requestScope.workspaceId}/${requestScope.subjectUserId}/${requestScope.localConnectionId}/${connectionId}`;
    let revocationMode: "revoked" | "unsupported" | "failed" = "failed";
    let failCredentialUpdate = false;
    let requestScope = scope("connection:read");
    const visible = (row: MemoryRow) =>
      !row.blocked && (row.visibility === "workspace" || row.owner === requestScope.subjectUserId);
    const safe = (row: MemoryRow): SafeStoredConnection => ({
      id: row.stored.id,
      localConnectionId: row.localConnectionId,
      service: row.stored.service,
      connectionName: row.stored.connectionName,
      visibility: row.visibility,
      status: "active",
      ...("profile" in row.stored.credential ? { profile: row.stored.credential.profile } : {}),
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    });
    const connectionStore: SaasRuntimeConnectionStore = {
      async get(service, connectionName) {
        return rows.find(
          (row) => visible(row) && row.stored.service === service && row.stored.connectionName === connectionName,
        )?.stored;
      },
      async set(service, connectionName, credential) {
        const existing = rows.find(
          (row) =>
            row.owner === requestScope.subjectUserId &&
            row.localConnectionId === requestScope.localConnectionId &&
            row.stored.service === service &&
            row.stored.connectionName === connectionName,
        );
        if (existing) {
          existing.stored = { ...existing.stored, revision: `${Number(existing.stored.revision) + 1}`, credential };
          existing.updatedAt = "2026-08-04T00:01:00.000Z";
          return existing.stored;
        }
        if (
          rows.some(
            (row) =>
              row.owner === requestScope.subjectUserId &&
              row.stored.service === service &&
              row.stored.connectionName === connectionName,
          )
        ) {
          throw Object.assign(new Error("alias conflict"), { code: "23505" });
        }
        const row: MemoryRow = {
          stored: {
            id: `connector-${rows.length + 1}`,
            revision: "1",
            service,
            connectionName,
            credential,
          },
          owner: requestScope.subjectUserId,
          localConnectionId: requestScope.localConnectionId!,
          visibility: "user",
          createdAt: "2026-08-04T00:00:00.000Z",
          blocked: false,
          updatedAt: "2026-08-04T00:00:00.000Z",
        };
        rows.push(row);
        return row.stored;
      },
      async updateCredential(input) {
        const row = rows.find(
          (candidate) =>
            candidate.owner === requestScope.subjectUserId &&
            candidate.localConnectionId === requestScope.localConnectionId &&
            candidate.stored.id === input.id &&
            candidate.stored.revision === input.revision &&
            !candidate.blocked,
        );
        if (failCredentialUpdate) return false;
        if (!row) return false;
        row.stored = { ...input, revision: `${Number(input.revision) + 1}` };
        row.updatedAt = "2026-08-04T00:04:00.000Z";
        return true;
      },
      async delete(service, connectionName) {
        const index = rows.findIndex(
          (row) =>
            row.owner === requestScope.subjectUserId &&
            row.stored.service === service &&
            row.stored.connectionName === connectionName,
        );
        if (index >= 0) rows.splice(index, 1);
      },
      async list() {
        return rows.filter(visible).map((row) => row.stored);
      },
      async listSafeConnections() {
        return rows.filter(visible).map(safe);
      },
      async getSafeConnection(connectionId) {
        const row = rows.find(
          (candidate) =>
            visible(candidate) &&
            candidate.stored.id === connectionId &&
            candidate.localConnectionId === requestScope.localConnectionId,
        );
        return row ? safe(row) : undefined;
      },
      async getCredentialReplacementTarget(connectionId) {
        const row = rows.find(
          (candidate) =>
            candidate.owner === requestScope.subjectUserId &&
            candidate.localConnectionId === requestScope.localConnectionId &&
            candidate.stored.id === connectionId &&
            !candidate.blocked,
        );
        return row?.stored;
      },
      async hasRevocationReceipt(connectionId) {
        return revocationReceipts.has(revocationReceiptKey(connectionId));
      },
      async resumeRevocation() {
        return false;
      },
      async blockForRevocation(connectionId) {
        revocationEvents.push("block");
        const row = rows.find(
          (candidate) =>
            candidate.owner === requestScope.subjectUserId &&
            candidate.stored.id === connectionId &&
            candidate.localConnectionId === requestScope.localConnectionId,
        );
        if (!row) return undefined;
        row.blocked = true;
        return row.stored;
      },
      async deleteById(connectionId, outcome) {
        const index = rows.findIndex(
          (row) =>
            row.owner === requestScope.subjectUserId &&
            row.stored.id === connectionId &&
            row.localConnectionId === requestScope.localConnectionId,
        );
        if (index < 0 || !rows[index]!.blocked) return false;
        revocationEvents.push(`delete:${outcome}`);
        revocationReceipts.add(revocationReceiptKey(connectionId));
        rows.splice(index, 1);
        return true;
      },
      async transferById(connectionId, targetSubjectUserId) {
        const row = rows.find(
          (candidate) =>
            candidate.stored.id === connectionId &&
            candidate.localConnectionId === requestScope.localConnectionId &&
            candidate.visibility === "workspace",
        );
        if (!row || (row.owner !== requestScope.subjectUserId && row.owner !== targetSubjectUserId)) return undefined;
        row.owner = targetSubjectUserId;
        row.updatedAt = "2026-08-04T00:02:00.000Z";
        return safe(row);
      },
      async updateVisibilityById(connectionId, visibility) {
        if (requestScope.actorUserId === "fail") throw new Error("database unavailable");
        const row = rows.find(
          (candidate) =>
            candidate.owner === requestScope.subjectUserId &&
            candidate.stored.id === connectionId &&
            candidate.localConnectionId === requestScope.localConnectionId &&
            !candidate.blocked,
        );
        if (!row) return undefined;
        if (row.visibility !== visibility) {
          row.visibility = visibility;
          row.updatedAt = "2026-08-04T00:03:00.000Z";
        }
        return safe(row);
      },
    };
    const runtime = {
      connectionStore,
      refreshCoordinator: {
        async runExclusive(_id: string, operation: () => Promise<unknown>) {
          return operation();
        },
      },
    } as unknown as SaasRuntimeDatabase;
    const localA = "00000000-0000-4000-8000-000000000001";
    const localB = "00000000-0000-4000-8000-000000000002";
    const localC = "00000000-0000-4000-8000-000000000003";
    const owner = "00000000-0000-4000-8000-000000000010";
    const target = "00000000-0000-4000-8000-000000000011";
    const connectionApp = new SaasConnectServer({
      catalog: createCatalogStore(
        [
          {
            service: "example",
            displayName: "Example",
            categories: ["Developer Tools"],
            authTypes: ["api_key", "custom_credential"],
            auth: [
              { type: "api_key" },
              {
                type: "custom_credential",
                fields: [
                  { key: "clientSecret", label: "Client secret", inputType: "password", required: true, secret: true },
                ],
              },
            ],
            actions: [
              {
                id: "example.ping",
                service: "example",
                name: "ping",
                description: "Ping",
                requiredScopes: [],
                providerPermissions: [],
                inputSchema: { type: "object" },
                outputSchema: { type: "object" },
              },
            ],
          },
        ],
        { executableActionIds: ["example.ping"] },
      ),
      providerLoader,
      verifyJwt: async (authorization) => {
        const token = authorization?.replace("Bearer ", "");
        if (token === "read") return scope("connection:read", { subjectUserId: owner });
        if (token === "read-other") return scope("connection:read", { subjectUserId: target });
        if (token === "write-a") {
          return scope("connection:write", { subjectUserId: owner, localConnectionId: localA });
        }
        if (token === "write-c") {
          return scope("connection:write", { subjectUserId: owner, localConnectionId: localC });
        }
        if (token === "write-b") {
          return scope("connection:write", { subjectUserId: owner, localConnectionId: localB });
        }
        if (token === "replace-a") {
          return scope("connection:write", {
            subjectUserId: owner,
            localConnectionId: localA,
            connectorConnectionId: "connector-1",
          });
        }
        if (token === "replace-foreign") {
          return scope("connection:write", {
            subjectUserId: target,
            localConnectionId: localA,
            connectorConnectionId: "connector-1",
          });
        }
        if (token === "replace-c") {
          return scope("connection:write", {
            subjectUserId: owner,
            localConnectionId: localC,
            connectorConnectionId: "connector-3",
          });
        }
        if (token === "delete-b") {
          return scope("connection:write", {
            subjectUserId: owner,
            localConnectionId: localB,
            connectorConnectionId: "connector-2",
          });
        }
        if (token === "delete-transferred") {
          return scope("connection:write", {
            subjectUserId: target,
            localConnectionId: localA,
            connectorConnectionId: "connector-1",
          });
        }
        if (token === "transfer-a") {
          return scope("connection:write", {
            subjectUserId: owner,
            workspaceRole: "owner",
            localConnectionId: localA,
            connectorConnectionId: "connector-1",
            requestHash: canonicalActionRequestHash("connection.transfer", "connector-1", {
              targetSubjectUserId: target,
            }),
          });
        }
        const visibility = token?.endsWith("-user") ? "user" : "workspace";
        const visibilityBindings = {
          subjectUserId: owner,
          workspaceRole: "owner" as const,
          localConnectionId: localA,
          connectorConnectionId: "connector-1",
          requestHash: canonicalActionRequestHash("connection.visibility", "connector-1", { visibility }),
        };
        if (token === "visibility-owner" || token === "visibility-owner-user") {
          return scope("connection:write", visibilityBindings);
        }
        if (token === "visibility-admin" || token === "visibility-admin-user") {
          return scope("connection:write", { ...visibilityBindings, workspaceRole: "admin" });
        }
        if (token === "visibility-member") {
          return scope("connection:write", { ...visibilityBindings, workspaceRole: "member" });
        }
        if (token === "visibility-other") {
          return scope("connection:write", {
            ...visibilityBindings,
            subjectUserId: target,
            workspaceRole: "admin",
          });
        }
        if (token === "visibility-local-mismatch") {
          return scope("connection:write", { ...visibilityBindings, localConnectionId: localB });
        }
        if (token === "visibility-connector-mismatch") {
          return scope("connection:write", {
            ...visibilityBindings,
            connectorConnectionId: "connector-2",
            requestHash: canonicalActionRequestHash("connection.visibility", "connector-2", { visibility }),
          });
        }
        if (token === "visibility-hash-mismatch") {
          return scope("connection:write", { ...visibilityBindings, requestHash: "invalid" });
        }
        if (token === "visibility-failure") {
          return scope("connection:write", { ...visibilityBindings, actorUserId: "fail" });
        }
        throw new SaasAuthorizationError(401);
      },
      readiness: completeReadiness(),
      oauthCredentials: {
        async refresh(_service, credential) {
          return credential;
        },
      },
      credentialRevoker: {
        async revoke() {
          revocationEvents.push("provider");
          return revocationMode;
        },
      },
      runtimeDatabaseFactory: {
        forScope(nextScope) {
          requestScope = nextScope;
          return runtime;
        },
      },
    }).createApp();
    const create = (token: string, localConnectionId: string, connectionName: string, apiKey: string) =>
      connectionApp.request("/internal/saas/connections/credentials", {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({
          localConnectionId,
          service: "example",
          connectionName,
          authType: "api_key",
          credentials: { apiKey },
        }),
      });
    const replaceCredential = (token: string, body: Record<string, unknown> = {}, connectionId = "connector-1") =>
      connectionApp.request(`/internal/saas/connections/${connectionId}/credentials`, {
        method: "PUT",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({
          connectorConnectionId: connectionId,
          localConnectionId: localA,
          service: "example",
          connectionName: "account-a",
          authType: "api_key",
          credentials: { apiKey: "rotated-secret" },
          ...body,
        }),
      });
    const updateVisibility = (
      token: string,
      body: unknown = { visibility: "workspace" },
      connectionId = "connector-1",
    ) =>
      connectionApp.request(`/internal/saas/connections/${connectionId}/visibility`, {
        method: "PATCH",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify(body),
      });

    const createdA = await create("write-a", localA, "account-a", "secret-a");
    expect(createdA.status).toBe(201);
    const createdJson = await createdA.json();
    expect(createdJson).toMatchObject({ id: "connector-1", localConnectionId: localA, service: "example" });
    expect(JSON.stringify(createdJson)).not.toMatch(/secret-a|credential|reference/i);
    expect((await create("write-b", localB, "account-b", "secret-b")).status).toBe(201);
    const createdCustom = await connectionApp.request("/internal/saas/connections/credentials", {
      method: "POST",
      headers: { authorization: "Bearer write-c", "content-type": "application/json" },
      body: JSON.stringify({
        localConnectionId: localC,
        service: "example",
        connectionName: "account-c",
        authType: "custom_credential",
        credentials: { clientSecret: "custom-secret" },
      }),
    });
    expect(createdCustom.status).toBe(201);
    const rotatedCustom = await replaceCredential(
      "replace-c",
      {
        localConnectionId: localC,
        connectionName: "account-c",
        authType: "custom_credential",
        credentials: { clientSecret: "rotated-custom-secret" },
      },
      "connector-3",
    );
    expect(rotatedCustom.status).toBe(200);
    expect(JSON.stringify(await rotatedCustom.json())).not.toContain("rotated-custom-secret");
    expect((rows[2]?.stored.credential as { values?: Record<string, string> }).values?.clientSecret).toBe(
      "rotated-custom-secret",
    );
    const replacedA = await create("write-a", localA, "account-a", "replacement-secret");
    expect(replacedA.status).toBe(201);
    expect((await replacedA.json()).id).toBe("connector-1");
    expect((await create("replace-a", localA, "account-a", "scoped-create-secret")).status).toBe(403);
    expect((rows[0]?.stored.credential as { apiKey?: string }).apiKey).toBe("replacement-secret");

    const rotated = await replaceCredential("replace-a");
    expect(rotated.status).toBe(200);
    expect(await rotated.json()).toMatchObject({
      id: "connector-1",
      localConnectionId: localA,
      service: "example",
      connectionName: "account-a",
    });
    expect((rows[0]?.stored.credential as { apiKey?: string }).apiKey).toBe("rotated-secret");
    const redactedRotation = await replaceCredential("replace-a");
    expect(JSON.stringify(await redactedRotation.json())).not.toMatch(/rotated-secret|credential|reference/i);
    const revisionAfterRotation = rows[0]?.stored.revision;
    expect((await replaceCredential("replace-a", { connectorConnectionId: "connector-2" })).status).toBe(403);
    expect((await replaceCredential("replace-foreign")).status).toBe(404);
    expect((await replaceCredential("replace-a", { connectionName: "other-alias" })).status).toBe(409);
    expect((await replaceCredential("replace-a", { service: "other-provider" })).status).toBe(409);
    failCredentialUpdate = true;
    expect((await replaceCredential("replace-a")).status).toBe(409);
    failCredentialUpdate = false;
    expect(rows[0]?.stored.revision).toBe(revisionAfterRotation);
    expect((rows[0]?.stored.credential as { apiKey?: string }).apiKey).toBe("rotated-secret");

    const listed = await (
      await connectionApp.request("/internal/saas/connections", {
        headers: { authorization: "Bearer read" },
      })
    ).json();
    expect(listed).toHaveLength(3);
    expect(JSON.stringify(listed)).not.toMatch(
      /secret-a|secret-b|custom-secret|rotated-custom-secret|replacement-secret|scoped-create-secret|secretRef|credentialReference/i,
    );
    expect(
      await (
        await connectionApp.request("/internal/saas/connections", {
          headers: { authorization: "Bearer read-other" },
        })
      ).json(),
    ).toEqual([]);
    expect(
      (
        await connectionApp.request("/internal/saas/connections/connector-1", {
          method: "DELETE",
          headers: { authorization: "Bearer delete-b" },
        })
      ).status,
    ).toBe(403);

    expect((await updateVisibility("visibility-owner", { visibility: "workspace", extra: true })).status).toBe(400);
    expect((await updateVisibility("visibility-owner", { visibility: "tenant" })).status).toBe(400);
    expect((await updateVisibility("visibility-member")).status).toBe(403);
    expect((await updateVisibility("visibility-connector-mismatch")).status).toBe(403);
    expect((await updateVisibility("visibility-hash-mismatch")).status).toBe(403);
    expect((await updateVisibility("visibility-local-mismatch")).status).toBe(404);
    expect((await updateVisibility("visibility-other")).status).toBe(404);
    expect((await updateVisibility("visibility-failure")).status).toBe(503);

    const sharedResponse = await updateVisibility("visibility-owner");
    expect(sharedResponse.status).toBe(200);
    const sharedJson = await sharedResponse.json();
    expect(sharedJson).toMatchObject({
      id: "connector-1",
      localConnectionId: localA,
      visibility: "workspace",
      status: "active",
    });
    expect(JSON.stringify(sharedJson)).not.toMatch(/secret|credential|reference/i);
    expect(
      await (
        await connectionApp.request("/internal/saas/connections", {
          headers: { authorization: "Bearer read-other" },
        })
      ).json(),
    ).toHaveLength(1);
    const repeated = await updateVisibility("visibility-admin");
    expect(repeated.status).toBe(200);
    expect((await repeated.json()).updatedAt).toBe(sharedJson.updatedAt);
    expect((await updateVisibility("visibility-admin-user", { visibility: "user" })).status).toBe(200);
    expect(
      await (
        await connectionApp.request("/internal/saas/connections", {
          headers: { authorization: "Bearer read-other" },
        })
      ).json(),
    ).toEqual([]);
    expect((await updateVisibility("visibility-owner")).status).toBe(200);
    const transfer = await connectionApp.request("/internal/saas/connections/connector-1/transfer", {
      method: "POST",
      headers: { authorization: "Bearer transfer-a", "content-type": "application/json" },
      body: JSON.stringify({ targetSubjectUserId: target }),
    });
    expect(transfer.status).toBe(200);
    expect(await transfer.json()).toMatchObject({
      id: "connector-1",
      localConnectionId: localA,
      visibility: "workspace",
    });
    expect(
      (
        await connectionApp.request("/internal/saas/connections/connector-1/transfer", {
          method: "POST",
          headers: { authorization: "Bearer transfer-a", "content-type": "application/json" },
          body: JSON.stringify({ targetSubjectUserId: target }),
        })
      ).status,
    ).toBe(200);
    const deleteRequest = () =>
      connectionApp.request("/internal/saas/connections/connector-2", {
        method: "DELETE",
        headers: { authorization: "Bearer delete-b" },
      });
    expect((await deleteRequest()).status).toBe(503);
    expect(rows.find((row) => row.stored.id === "connector-2")).toMatchObject({ blocked: true });
    revocationMode = "revoked";
    expect((await deleteRequest()).status).toBe(204);
    expect((await deleteRequest()).status).toBe(204);
    revocationMode = "unsupported";
    const unsupportedDelete = () =>
      connectionApp.request("/internal/saas/connections/connector-1", {
        method: "DELETE",
        headers: { authorization: "Bearer delete-transferred" },
      });
    expect((await unsupportedDelete()).status).toBe(204);
    expect((await unsupportedDelete()).status).toBe(204);
    expect(revocationEvents).toEqual([
      "block",
      "provider",
      "block",
      "provider",
      "delete:revoked",
      "block",
      "provider",
      "delete:unsupported",
    ]);
  });

  it.each([
    [
      "action substitution",
      "/internal/saas/actions/gmail.messages_get",
      { connectorConnectionId: "connector-1", input: { query: "inbox" } },
    ],
    [
      "connector connection substitution",
      "/internal/saas/actions/gmail.messages_list",
      { connectorConnectionId: "connector-2", input: { query: "inbox" } },
    ],
    [
      "approved-body replay",
      "/internal/saas/actions/gmail.messages_list",
      { connectorConnectionId: "connector-1", input: { query: "sent" } },
    ],
  ])("rejects an action token after %s", async (_label, path, body) => {
    const response = await app.request(path, {
      method: "POST",
      headers: { authorization: "Bearer execute", "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "forbidden" });
  });

  it("fails closed before action composition when OAuth refresh is unavailable", async () => {
    const response = await app.request("/internal/saas/actions/gmail.messages_list", {
      method: "POST",
      headers: {
        authorization: "Bearer execute",
        "content-type": "application/json",
        "idempotency-key": "request-1",
      },
      body: JSON.stringify({ connectorConnectionId: "connector-1", input: { query: "inbox" } }),
    });
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "service_unavailable" });
  });

  it("rejects an OAuth token whose session binding differs", async () => {
    const response = await app.request("/internal/saas/oauth/start", {
      method: "POST",
      headers: { authorization: "Bearer oauth", "content-type": "application/json" },
      body: JSON.stringify({ localConnectionId: "local-1", oauthSessionId: "other" }),
    });
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "forbidden" });
  });

  it("lists and reads only bounded, redacted runs in the exact JWT scope", async () => {
    const owner = scope("admin:read");
    const scopedRuns: Array<{
      tenantId: string;
      workspaceId: string;
      subjectUserId: string;
      run: RunLog;
    }> = [];
    const addRun = (bindings: Pick<SaasRequestScope, "tenantId" | "workspaceId" | "subjectUserId">, run: RunLog) =>
      scopedRuns.push({ ...bindings, run });
    const makeRun = (id: string, startedAt: string, overrides: Partial<RunLog> = {}): RunLog => ({
      id,
      service: "gmail",
      actionId: "gmail.messages_list",
      caller: "http",
      startedAt,
      completedAt: startedAt,
      durationMs: 5,
      ok: true,
      ...overrides,
    });
    addRun(
      owner,
      makeRun("run-3", "2026-08-05T00:00:03.000Z", {
        caller: "mcp",
        ok: false,
        connectionId: "00000000-0000-4000-8000-000000000001",
        connectionProfile: {
          accountId: "account-1",
          displayName: "Primary",
          grantedScopes: ["messages.read"],
        },
        runtimeTokenId: "runtime-token-1",
        policy: {
          allowed: false,
          code: "action_blocked",
          message: "Blocked by policy",
          checks: [{ source: "runtime", outcome: "block_match", rule: "gmail.*" }],
        },
        errorCode: "action_blocked",
        inputSummary: { secret: "must not escape" },
        outputSummary: { providerBody: "must not escape" },
        errorMessage: "must not escape",
      }),
    );
    addRun(owner, makeRun("run-2", "2026-08-05T00:00:02.000Z"));
    addRun(owner, makeRun("run-1", "2026-08-05T00:00:01.000Z"));
    addRun({ ...owner, subjectUserId: "subject-2" }, makeRun("subject-run", "2026-08-05T00:00:04.000Z"));
    addRun({ ...owner, workspaceId: "workspace-2" }, makeRun("workspace-run", "2026-08-05T00:00:04.000Z"));
    addRun({ ...owner, tenantId: "tenant-2" }, makeRun("tenant-run", "2026-08-05T00:00:04.000Z"));

    let failStore = false;
    let lastListInput: RunLogListInput | undefined;
    const runtimeDatabaseFactory = {
      forScope(requestScope: Readonly<SaasRequestScope>) {
        const visible = () =>
          scopedRuns
            .filter(
              (row) =>
                row.tenantId === requestScope.tenantId &&
                row.workspaceId === requestScope.workspaceId &&
                row.subjectUserId === requestScope.subjectUserId,
            )
            .map((row) => row.run);
        return {
          runLogStore: {
            async get(id: string) {
              if (failStore) throw new Error("database unavailable");
              return visible().find((run) => run.id === id);
            },
            async list(input: RunLogListInput = {}) {
              if (failStore) throw new Error("database unavailable");
              lastListInput = { ...input };
              let runs = visible()
                .filter((run) => input.service === undefined || run.service === input.service)
                .filter((run) => input.actionId === undefined || run.actionId === input.actionId)
                .filter((run) => input.caller === undefined || run.caller === input.caller)
                .filter((run) => input.ok === undefined || run.ok === input.ok)
                .sort((left, right) =>
                  left.startedAt === right.startedAt
                    ? right.id.localeCompare(left.id)
                    : right.startedAt.localeCompare(left.startedAt),
                );
              const cursor = decodeRunLogCursor(input.cursor);
              if (cursor) {
                runs = runs.filter(
                  (run) =>
                    run.startedAt < cursor.startedAt || (run.startedAt === cursor.startedAt && run.id < cursor.id),
                );
              }
              const limit = input.limit ?? 50;
              const items = runs.slice(0, limit);
              return {
                items,
                nextCursor:
                  runs.length > limit && items.length > 0 ? encodeRunLogCursor(items[items.length - 1]!) : undefined,
              };
            },
          },
        } as unknown as SaasRuntimeDatabase;
      },
    };
    const runApp = new SaasConnectServer({
      catalog: createCatalogStore([]),
      providerLoader,
      verifyJwt: async (authorization) => {
        const token = authorization?.replace("Bearer ", "");
        if (token === "owner") return owner;
        if (token === "subject") return scope("admin:read", { subjectUserId: "subject-2" });
        if (token === "workspace") return scope("admin:read", { workspaceId: "workspace-2" });
        if (token === "tenant") return scope("admin:read", { tenantId: "tenant-2" });
        throw new SaasAuthorizationError(401);
      },
      readiness: completeReadiness(),
      runtimeDatabaseFactory,
    }).createApp();
    const request = (path: string, token = "owner") =>
      runApp.request(path, { headers: { authorization: `Bearer ${token}` } });

    const first = await (await request("/internal/saas/runs?limit=2")).json();
    expect(first.items.map((run: RunLog) => run.id)).toEqual(["run-3", "run-2"]);
    expect(first.nextCursor).toEqual(expect.any(String));
    const secondQuery = new URLSearchParams({ limit: "2", cursor: first.nextCursor });
    const second = await (await request(`/internal/saas/runs?${secondQuery}`)).json();
    expect(second).toEqual({ items: [expect.objectContaining({ id: "run-1" })], nextCursor: null });
    await request("/internal/saas/runs?service=missing");
    expect(lastListInput).toEqual({ limit: 50, service: "missing" });

    const filtered = await (
      await request("/internal/saas/runs?service=gmail&actionId=gmail.messages_list&caller=mcp&ok=false&limit=1")
    ).json();
    expect(lastListInput).toEqual({
      limit: 1,
      service: "gmail",
      actionId: "gmail.messages_list",
      caller: "mcp",
      ok: false,
    });
    expect(filtered).toEqual({
      items: [
        {
          id: "run-3",
          service: "gmail",
          actionId: "gmail.messages_list",
          caller: "mcp",
          startedAt: "2026-08-05T00:00:03.000Z",
          completedAt: "2026-08-05T00:00:03.000Z",
          durationMs: 5,
          ok: false,
          connectionId: "00000000-0000-4000-8000-000000000001",
          connectionProfile: {
            accountId: "account-1",
            displayName: "Primary",
            grantedScopes: ["messages.read"],
          },
          runtimeTokenId: "runtime-token-1",
          policy: {
            allowed: false,
            code: "action_blocked",
            message: "Blocked by policy",
            checks: [{ source: "runtime", outcome: "block_match", rule: "gmail.*" }],
          },
          errorCode: "action_blocked",
        },
      ],
      nextCursor: null,
    });
    expect(JSON.stringify(filtered)).not.toMatch(/secret|providerBody|errorMessage|inputSummary|outputSummary/);
    await expect((await request("/internal/saas/runs/run-3")).json()).resolves.toEqual(filtered.items[0]);
    expect((await request("/internal/saas/runs/missing")).status).toBe(404);
    for (const token of ["subject", "workspace", "tenant"]) {
      expect((await request("/internal/saas/runs/run-3", token)).status).toBe(404);
    }

    for (const path of [
      "/internal/saas/runs?subjectUserId=subject-1",
      "/internal/saas/runs?limit=1&limit=2",
      "/internal/saas/runs?limit=101",
      "/internal/saas/runs?service=",
      "/internal/saas/runs?actionId=",
      "/internal/saas/runs?caller=other",
      "/internal/saas/runs?ok=1",
      "/internal/saas/runs?cursor=not-json",
      `/internal/saas/runs?${new URLSearchParams({ cursor: "x".repeat(513) })}`,
      "/internal/saas/runs/run-3?scope=other",
    ]) {
      expect((await request(path)).status, path).toBe(400);
    }

    failStore = true;
    expect((await request("/internal/saas/runs")).status).toBe(503);
    expect((await request("/internal/saas/runs/run-3")).status).toBe(503);
    const unavailableApp = new SaasConnectServer({
      catalog: createCatalogStore([]),
      providerLoader,
      verifyJwt: async () => owner,
      readiness: completeReadiness(),
    }).createApp();
    expect(
      (
        await unavailableApp.request("/internal/saas/runs", {
          headers: { authorization: "Bearer owner" },
        })
      ).status,
    ).toBe(503);
    expect(
      (
        await unavailableApp.request("/internal/saas/runs/run-3", {
          headers: { authorization: "Bearer owner" },
        })
      ).status,
    ).toBe(503);
  });

  it("mounts strict exact-scope lifecycle export and purge routes with canonical hash binding", async () => {
    const input = { correlationId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" };
    const lifecycleReadScope = scope("lifecycle:read");
    const lifecycleDeleteScope = scope("lifecycle:delete", {
      requestHash: canonicalRequestHash("lifecycle.purge", input),
    });
    let receivedScope: Readonly<SaasRequestScope> | undefined;
    let receivedPurge: typeof input | undefined;
    let purgeFailure: Error | undefined;
    let purgeCalls = 0;
    const lifecycleService = {
      async exportPage({ cursor, limit }: { cursor?: string; limit: number }) {
        return {
          tenantId: lifecycleReadScope.tenantId,
          workspaceId: lifecycleReadScope.workspaceId,
          subjectUserId: lifecycleReadScope.subjectUserId,
          connections: [],
          runs: [],
          counts: {
            connections: 0,
            runs: 0,
            oauthStates: { total: 0, statuses: [] },
            idempotencyRecords: { total: 0, statuses: [] },
            transitFiles: { total: 0, statuses: [] },
          },
          nextCursor: cursor ? null : Buffer.from(JSON.stringify({ v: 1, phase: "runs" })).toString("base64url"),
        };
      },
      async purge(body: typeof input) {
        purgeCalls += 1;
        receivedPurge = body;
        if (purgeFailure) throw purgeFailure;
        return {
          tenantId: lifecycleDeleteScope.tenantId,
          workspaceId: lifecycleDeleteScope.workspaceId,
          subjectUserId: lifecycleDeleteScope.subjectUserId,
          correlationId: body.correlationId,
          status: "purged" as const,
          deleted: {
            connections: 0,
            runs: 0,
            oauthStates: 0,
            idempotencyRecords: 0,
            transitFiles: 0,
            connectionSecrets: 0,
            oauthStateSecrets: 0,
            transitObjects: 0,
          },
          remoteRevocations: { revoked: 0, unsupported: 0, unresolved: 0 },
        };
      },
    };
    const lifecycleApp = new SaasConnectServer({
      catalog: createCatalogStore([]),
      providerLoader,
      verifyJwt: async (authorization) => {
        if (authorization === "Bearer lifecycle-read") return lifecycleReadScope;
        if (authorization === "Bearer lifecycle-delete") return lifecycleDeleteScope;
        if (authorization === "Bearer lifecycle-delete-wrong-hash") {
          return scope("lifecycle:delete", { requestHash: "wrong" });
        }
        if (authorization === "Bearer wrong-purpose") return scope("admin:read");
        throw new SaasAuthorizationError(401);
      },
      readiness: completeReadiness(),
      runtimeDatabaseFactory: {
        forScope() {
          throw new Error("non-lifecycle runtime should not be used");
        },
        lifecycleForScope(requestScope) {
          receivedScope = requestScope;
          return lifecycleService;
        },
      },
    }).createApp();

    const exported = await lifecycleApp.request("/internal/saas/lifecycle/export?limit=1", {
      headers: { authorization: "Bearer lifecycle-read" },
    });
    expect(exported.status).toBe(200);
    expect(await exported.json()).toMatchObject({
      tenantId: lifecycleReadScope.tenantId,
      workspaceId: lifecycleReadScope.workspaceId,
      subjectUserId: lifecycleReadScope.subjectUserId,
      connections: [],
      runs: [],
    });
    expect(receivedScope).toEqual(lifecycleReadScope);

    const purged = await lifecycleApp.request("/internal/saas/lifecycle/purge", {
      method: "POST",
      headers: { authorization: "Bearer lifecycle-delete", "content-type": "application/json" },
      body: JSON.stringify(input),
    });
    expect(purged.status).toBe(200);
    expect(await purged.json()).toMatchObject({ correlationId: input.correlationId, status: "purged" });
    expect(receivedPurge).toEqual(input);
    expect(purgeCalls).toBe(1);
    expect(receivedScope).toEqual(lifecycleDeleteScope);

    for (const path of [
      "/internal/saas/lifecycle/export?unknown=1",
      "/internal/saas/lifecycle/export?limit=0",
      "/internal/saas/lifecycle/export?limit=101",
      `/internal/saas/lifecycle/export?${new URLSearchParams({ cursor: "x".repeat(513) })}`,
      "/internal/saas/lifecycle/purge?unexpected=1",
    ]) {
      const response = await lifecycleApp.request(path, {
        method: path.includes("/purge") ? "POST" : "GET",
        headers: {
          authorization: path.includes("/purge") ? "Bearer lifecycle-delete" : "Bearer lifecycle-read",
          "content-type": "application/json",
        },
        ...(path.includes("/purge") ? { body: JSON.stringify(input) } : {}),
      });
      expect(response.status, path).toBe(400);
    }

    const oversized = await lifecycleApp.request("/internal/saas/lifecycle/purge", {
      method: "POST",
      headers: { authorization: "Bearer lifecycle-delete", "content-type": "application/json" },
      body: "x".repeat(262_145),
    });
    expect(oversized.status).toBe(413);

    const extraBody = await lifecycleApp.request("/internal/saas/lifecycle/purge", {
      method: "POST",
      headers: { authorization: "Bearer lifecycle-delete", "content-type": "application/json" },
      body: JSON.stringify({ ...input, tenantId: "adjacent" }),
    });
    expect(extraBody.status).toBe(400);
    const hashMismatch = await lifecycleApp.request("/internal/saas/lifecycle/purge", {
      method: "POST",
      headers: { authorization: "Bearer lifecycle-delete-wrong-hash", "content-type": "application/json" },
      body: JSON.stringify(input),
    });
    expect(hashMismatch.status).toBe(403);
    expect(await hashMismatch.json()).toEqual({
      errorCode: "forbidden",
      message: "Lifecycle purge authorization does not match the body.",
    });
    expect(purgeCalls).toBe(1);
    const unauthorized = await lifecycleApp.request("/internal/saas/lifecycle/export");
    expect(unauthorized.status).toBe(401);
    expect(await unauthorized.json()).toEqual({
      errorCode: "unauthorized",
      message: "Lifecycle authentication is required.",
    });
    const wrongPurpose = await lifecycleApp.request("/internal/saas/lifecycle/export", {
      headers: { authorization: "Bearer wrong-purpose" },
    });
    expect(wrongPurpose.status).toBe(403);
    expect(await wrongPurpose.json()).toEqual({
      errorCode: "forbidden",
      message: "The exact lifecycle purpose is required.",
    });
    expect((await lifecycleApp.request("/lifecycle/export")).status).toBe(404);

    purgeFailure = new LifecyclePurgeConflictError();
    const conflict = await lifecycleApp.request("/internal/saas/lifecycle/purge", {
      method: "POST",
      headers: { authorization: "Bearer lifecycle-delete", "content-type": "application/json" },
      body: JSON.stringify(input),
    });
    expect(conflict.status).toBe(409);
    expect(await conflict.json()).toEqual({
      errorCode: "lifecycle_purge_conflict",
      message: "The lifecycle scope has another purge in progress.",
    });

    purgeFailure = new LifecycleReconciliationRequiredError();
    const reconciliation = await lifecycleApp.request("/internal/saas/lifecycle/purge", {
      method: "POST",
      headers: { authorization: "Bearer lifecycle-delete", "content-type": "application/json" },
      body: JSON.stringify(input),
    });
    expect(reconciliation.status).toBe(503);
    expect(await reconciliation.json()).toEqual({
      errorCode: "reconciliation_required",
      message: "Lifecycle cleanup requires reconciliation; retry with the same correlationId.",
    });
  });
});

function catalogPrincipal() {
  return Object.freeze({
    subjectKind: "service" as const,
    subject: "open-connector-catalog",
    purpose: "catalog:read" as const,
    permissions: ["catalog:read"] as ["catalog:read"],
  });
}

function scope(
  purpose: SaasRequestScope["purpose"],
  bindings: Partial<SaasRequestScope> = {},
): Readonly<SaasRequestScope> {
  const permissions = Object.freeze([purpose]) as string[];
  return Object.freeze({
    tenantId: "tenant-1",
    workspaceId: "workspace-1",
    actorUserId: "actor-1",
    subjectUserId: "subject-1",
    workspaceRole: "member",
    purpose,
    permissions,
    ...bindings,
  });
}
