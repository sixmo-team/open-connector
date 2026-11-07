import type { ResolvedCredential } from "../../core/types.ts";
import type { OAuth2AuthDefinition } from "../../core/types.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { Pool } from "pg";

import { describe, expect, it } from "vitest";
import {
  ConnectionMetadataReconciliationError,
  PostgresConnectionStore,
} from "../storage/postgres-connection-store.ts";
import { OpenBaoClient, OpenBaoError } from "./openbao-client.ts";
import { OpenBaoConnectionSecretStore } from "./openbao-connection-store.ts";
import { OpenBaoOAuthClientConfigStore } from "./openbao-oauth-client-config-store.ts";

const scope: Readonly<SaasRequestScope> = Object.freeze({
  tenantId: "tenant-a",
  workspaceId: "workspace-a",
  actorUserId: "user-a",
  subjectUserId: "user-a",
  workspaceRole: "owner",
  purpose: "connection:write",
  permissions: ["connection:write"],
  localConnectionId: "00000000-0000-4000-8000-000000000001",
});

const credential: ResolvedCredential = {
  authType: "oauth2",
  accessToken: "access-secret-value",
  refreshToken: "refresh-secret-value",
  tokenType: "Bearer",
  providerSecret: { apiKey: "api-secret-value" },
  profile: { accountId: "account-1", displayName: "Work", grantedScopes: ["mail.read"] },
  metadata: {
    scope: "mail.read",
    oauthClientId: "client-secret-value",
    nested: { raw_state: "state-secret-value", pkceVerifier: "pkce-secret-value" },
  },
};
const oauthDefinition: OAuth2AuthDefinition = {
  type: "oauth2",
  authorizationUrl: "https://provider.test/authorize",
  tokenUrl: "https://provider.test/token",
  scopes: [],
  tokenEndpointAuthMethod: "client_secret_post",
};

const expectedPath =
  "client-secrets/data/tenants/tenant-a/workspaces/workspace-a/integrations/connections/connection-1";

describe("OpenBaoConnectionSecretStore", () => {
  it("uses the exact scoped KV v2 path, versions metadata with credentials, and rejects stale CAS", async () => {
    const bao = new FakeOpenBao();
    const client = new OpenBaoClient({ address: "https://openbao.test", token: "test-token", fetchFn: bao.fetch });
    const store = new OpenBaoConnectionSecretStore(client);

    await expect(store.create(scope, "connection-1", "gmail", credential)).resolves.toEqual({
      secretRef: expectedPath,
      secretRevision: 1,
    });
    expect(bao.calls[0]).toMatchObject({ method: "POST", path: expectedPath });
    const stored = bao.records.get(expectedPath)?.data;
    expect(stored).toMatchObject({ provider: "gmail", authType: "oauth2", revision: 1 });
    expect(JSON.stringify(stored)).not.toContain("profile");
    expect(stored?.metadata).toEqual(credential.metadata);

    await expect(store.update(scope, "connection-1", "gmail", 1, credential)).resolves.toBe(2);
    await expect(store.read(scope, "connection-1", 1)).resolves.toMatchObject({
      revision: 1,
      metadata: credential.metadata,
    });
    await expect(store.update(scope, "connection-1", "gmail", 1, credential)).resolves.toBe(false);
    await expect(client.write(expectedPath, { revision: 99 }, 1)).rejects.toMatchObject({
      code: "OPENBAO_CONFLICT",
    });
    await expect(store.delete(scope, "connection-1")).resolves.toBeUndefined();
    await expect(store.delete(scope, "connection-1")).resolves.toBeUndefined();
  });

  it("rejects traversal, encoded separators, and every sibling OpenBao namespace", async () => {
    const bao = new FakeOpenBao();
    const client = new OpenBaoClient({ address: "https://openbao.test", token: "test-token", fetchFn: bao.fetch });
    const store = new OpenBaoConnectionSecretStore(client);
    await expect(
      store.create({ ...scope, tenantId: "../tenant" }, "connection-1", "gmail", credential),
    ).rejects.toThrow("invalid path characters");
    await expect(client.read("client-secrets/data/tenants/t/workspaces/w/integrations/unrelated/id")).rejects.toThrow(
      "outside the integration allowlist",
    );
    await expect(
      client.read("client-secrets/data/tenants/t/workspaces/w/integrations/connections/a%2Fb"),
    ).rejects.toThrow("outside the integration allowlist");
  });

  it("cleans up after a PostgreSQL metadata failure and serializes only a safe reconciliation marker", async () => {
    const bao = new FakeOpenBao();
    const client = new OpenBaoClient({ address: "https://openbao.test", token: "test-token", fetchFn: bao.fetch });
    const secretStore = new OpenBaoConnectionSecretStore(client);
    const queries: Array<{ text: string; values: unknown[] }> = [];
    let failedActiveInsert = false;
    const retirementGeneration = crypto.randomUUID();
    const pgClient = {
      async query(text: string, values: unknown[] = []): Promise<{ rows: unknown[]; rowCount: number }> {
        queries.push({ text, values });
        if (text.includes("SELECT generation FROM integration_runtime.connection_retirements"))
          return { rows: [{ generation: retirementGeneration }], rowCount: 1 };
        if (text.includes("SELECT id, revision")) return { rows: [], rowCount: 0 };
        if (
          text.includes("INSERT INTO integration_runtime.connections") &&
          text.includes("'active'") &&
          !failedActiveInsert
        ) {
          failedActiveInsert = true;
          throw new Error("metadata insert failed");
        }
        return { rows: [], rowCount: 1 };
      },
      release(): void {},
    };
    const pool = {
      async connect() {
        return pgClient;
      },
    } as unknown as Pool;
    const store = new PostgresConnectionStore(pool, scope, secretStore);

    let failure: unknown;
    try {
      await store.set("gmail", "opaque-connection", credential);
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(ConnectionMetadataReconciliationError);
    expect(failure).toMatchObject({ cleanup: "deleted", markerWritten: true });
    expect(bao.records.size).toBe(0);

    const serializedPostgres = JSON.stringify(queries);
    for (const secret of [
      "access-secret-value",
      "refresh-secret-value",
      "api-secret-value",
      "client-secret-value",
      "state-secret-value",
      "pkce-secret-value",
    ]) {
      expect(serializedPostgres).not.toContain(secret);
      expect(JSON.stringify(failure)).not.toContain(secret);
    }
  });

  it("stores platform OAuth applications only at the global provider path", async () => {
    const bao = new FakeOpenBao();
    const client = new OpenBaoClient({ address: "https://openbao.test", token: "test-token", fetchFn: bao.fetch });
    const store = new OpenBaoOAuthClientConfigStore(client);
    await store.set({
      service: "gmail_app",
      clientId: "platform-client-id",
      clientSecret: "platform-client-secret",
      extra: {},
      secretExtra: {},
    });
    const path = "service-secrets/data/integration-provider-applications/gmail_app";
    expect(bao.calls[0]).toEqual({ method: "GET", path });
    expect(bao.calls[1]).toEqual({ method: "POST", path });
    expect(path).not.toContain(scope.tenantId);
    await expect(store.get("gmail_app")).resolves.toMatchObject({
      service: "gmail_app",
      clientId: "platform-client-id",
      clientSecret: "platform-client-secret",
    });
  });
  it("probes exact OAuth app paths and safely classifies configured, missing, malformed, wrong-scope, and denied", async () => {
    const bao = new FakeOpenBao();
    const store = new OpenBaoOAuthClientConfigStore(
      new OpenBaoClient({ address: "https://openbao.test", token: "test-token", fetchFn: bao.fetch }),
    );
    const configuredPath = "service-secrets/data/integration-provider-applications/configured";
    await store.set({
      service: "configured",
      clientId: "platform-client-id",
      clientSecret: "platform-client-secret",
      extra: {},
      secretExtra: {},
    });
    await expect(store.probe("configured", oauthDefinition)).resolves.toEqual({ status: "operational" });
    await expect(store.probe("missing", oauthDefinition)).resolves.toEqual({
      status: "unavailable",
      reasonCode: "oauth_client_config_missing",
    });
    expect(bao.calls.at(-1)).toEqual({
      method: "GET",
      path: "service-secrets/data/integration-provider-applications/missing",
    });

    bao.records.get(configuredPath)!.data.clientId = " malformed ";
    await expect(store.probe("configured", oauthDefinition)).resolves.toEqual({
      status: "unavailable",
      reasonCode: "oauth_client_config_invalid",
    });
    bao.records.get(configuredPath)!.data.clientId = "platform-client-id";
    bao.records.get(configuredPath)!.data.service = "sibling";
    await expect(store.probe("configured", oauthDefinition)).resolves.toEqual({
      status: "unavailable",
      reasonCode: "oauth_client_config_invalid",
    });

    const secretText = "must-not-escape-openbao";
    const denied = new OpenBaoOAuthClientConfigStore(
      new OpenBaoClient({
        address: "https://openbao.test",
        token: "test-token",
        fetchFn: async () => Response.json({ errors: [secretText] }, { status: 403 }),
      }),
    );
    const deniedReadiness = await denied.probe("configured", oauthDefinition);
    expect(deniedReadiness).toEqual({
      status: "unavailable",
      reasonCode: "oauth_client_config_access_denied",
    });
    expect(JSON.stringify(deniedReadiness)).not.toContain(secretText);
  });
  it("bounds concurrent OAuth app probes to eight", async () => {
    let active = 0;
    let maximumActive = 0;
    const release = Promise.withResolvers<void>();
    const saturated = Promise.withResolvers<void>();
    const store = new OpenBaoOAuthClientConfigStore(
      new OpenBaoClient({
        address: "https://openbao.test",
        token: "test-token",
        fetchFn: async (input) => {
          active += 1;
          maximumActive = Math.max(maximumActive, active);
          if (active === 8) saturated.resolve();
          await release.promise;
          active -= 1;
          const path = new URL(typeof input === "string" || input instanceof URL ? input : input.url).pathname;
          const service = path.split("/").at(-1)!;
          const timestamp = "2026-08-05T00:00:00.000Z";
          return Response.json({
            data: {
              data: {
                service,
                clientId: "platform-client-id",
                clientSecret: "platform-client-secret",
                extra: {},
                secretExtra: {},
                revision: 1,
                createdAt: timestamp,
                updatedAt: timestamp,
              },
              metadata: { version: 1 },
            },
          });
        },
      }),
    );
    const readinessPromise = store.probeAll(
      Array.from({ length: 9 }, (_, index) => ({ service: `provider_${index}`, auth: oauthDefinition })),
    );
    await saturated.promise;
    expect(maximumActive).toBe(8);
    release.resolve();
    const readiness = await readinessPromise;

    expect(readiness.size).toBe(9);
    expect(maximumActive).toBeLessThanOrEqual(8);
    expect([...readiness.values()].every((value) => value.status === "operational")).toBe(true);
    expect(JSON.stringify([...readiness])).not.toContain("platform-client-secret");
  });

  it("rejects extra capabilities and probes sibling sentinels plus the exact LIST parent", async () => {
    let requestedPaths: string[] = [];
    const client = new OpenBaoClient({
      address: "https://openbao.test",
      token: "test-token",
      fetchFn: async (input, init) => {
        const path = new URL(typeof input === "string" || input instanceof URL ? input : input.url).pathname;
        if (path.endsWith("/sys/health")) return Response.json({ initialized: true, sealed: false });
        const body = JSON.parse(String(init?.body)) as { paths: string[] };
        requestedPaths = body.paths;
        const capabilities: Record<string, string[]> = {};
        for (const requestedPath of requestedPaths) {
          if (requestedPath === "service-secrets/metadata/integration-provider-applications") {
            capabilities[requestedPath] = ["list"];
          } else if (requestedPath.includes("/metadata/")) {
            capabilities[requestedPath] = ["delete"];
          } else if (requestedPath.includes("/unrelated/") || requestedPath.startsWith("sys/")) {
            capabilities[requestedPath] = ["deny"];
          } else {
            capabilities[requestedPath] = ["create", "read", "update", "sudo"];
          }
        }
        return Response.json(capabilities);
      },
    });
    await expect(client.probeCapabilities()).rejects.toMatchObject({ code: "OPENBAO_FORBIDDEN" });
    expect(requestedPaths).toContain("service-secrets/metadata/integration-provider-applications");
    expect(requestedPaths.some((path) => path.includes("/unrelated/"))).toBe(true);
  });

  it("never exposes an OpenBao response body in a loggable error", async () => {
    const leaked = "access-secret-from-openbao-error";
    const client = new OpenBaoClient({
      address: "https://openbao.test",
      token: "test-token",
      fetchFn: async () => Response.json({ errors: [leaked] }, { status: 500 }),
    });
    let failure: unknown;
    try {
      await client.read(expectedPath);
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(OpenBaoError);
    expect(String(failure)).not.toContain(leaked);
    expect(JSON.stringify(failure)).not.toContain(leaked);
  });
});

interface FakeRecord {
  data: Record<string, unknown>;
  revision: number;
}

class FakeOpenBao {
  readonly records = new Map<string, FakeRecord>();
  readonly history = new Map<string, Map<number, Record<string, unknown>>>();
  readonly calls: Array<{ method: string; path: string }> = [];

  readonly fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    const path = url.pathname.replace(/^\/v1\//, "");
    const method = init?.method ?? "GET";
    this.calls.push({ method, path });

    if (method === "POST") {
      const body = JSON.parse(String(init?.body)) as {
        data: Record<string, unknown>;
        options: { cas: number };
      };
      const current = this.records.get(path);
      if ((body.options.cas === 0 && current) || (body.options.cas !== 0 && current?.revision !== body.options.cas)) {
        return Response.json({ errors: ["CAS mismatch with secret body"] }, { status: 400 });
      }
      const revision = (current?.revision ?? 0) + 1;
      this.records.set(path, { data: body.data, revision });
      const versions = this.history.get(path) ?? new Map<number, Record<string, unknown>>();
      versions.set(revision, body.data);
      this.history.set(path, versions);
      return Response.json({ data: { version: revision } });
    }
    if (method === "DELETE") {
      const dataPath = path.replace("/metadata/", "/data/");
      const existed = this.records.delete(dataPath);
      this.history.delete(dataPath);
      return new Response(null, { status: existed ? 204 : 404 });
    }
    const current = this.records.get(path);
    const requestedRevision = Number(url.searchParams.get("version"));
    const versionedData = requestedRevision > 0 ? this.history.get(path)?.get(requestedRevision) : current?.data;
    const revision = requestedRevision > 0 ? requestedRevision : current?.revision;
    if (!versionedData || !revision) return Response.json({ errors: ["not found"] }, { status: 404 });
    return Response.json({ data: { data: versionedData, metadata: { version: revision } } });
  };
}
