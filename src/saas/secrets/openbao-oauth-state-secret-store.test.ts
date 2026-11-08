import type { OAuthAuthorizationState } from "../../oauth/oauth-flow-service.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { Pool } from "pg";

import { describe, expect, it, vi } from "vitest";
import { getRequestProcessing, withRequestProcessing } from "../../core/cancellation.ts";
import {
  OAuthStateMetadataReconciliationError,
  PostgresOAuthStateStore,
} from "../storage/postgres-oauth-state-store.ts";
import { OpenBaoClient } from "./openbao-client.ts";
import { OpenBaoOAuthStateSecretStore } from "./openbao-oauth-state-secret-store.ts";
import { OpenBaoSecretCodec, withSecretCleanup } from "./secret-codec.ts";

const scope: Readonly<SaasRequestScope> = Object.freeze({
  tenantId: "tenant-a",
  workspaceId: "workspace-a",
  actorUserId: "user-a",
  subjectUserId: "user-a",
  workspaceRole: "owner",
  purpose: "oauth:start",
  permissions: ["oauth:start"],
  oauthSessionId: "oauth-session-1",
  connectorConnectionId: "11111111-1111-4111-8111-111111111111",
  localConnectionId: "11111111-1111-4111-8111-111111111111",
});

const state: OAuthAuthorizationState = {
  service: "gmail",
  connectionName: "opaque-connection",
  retirementGeneration: "generation-fixture",
  state: "raw-oauth-state-secret",
  createdAt: new Date().toISOString(),
  pkceCodeVerifier: "pkce-verifier-secret",
};

const expectedPath =
  "client-secrets/data/tenants/tenant-a/workspaces/workspace-a/integrations/oauth-sessions/oauth-session-1";

describe("OpenBaoOAuthStateSecretStore", () => {
  it("awaits exact reference reservation acknowledgement before writing a private envelope", async () => {
    const bao = new FakeOpenBao();
    const codec = new OpenBaoSecretCodec(
      new OpenBaoClient({
        address: "https://openbao.test",
        token: "test-token",
        fetchFn: bao.fetch,
      }),
      scope,
    );
    const entered = Promise.withResolvers<string>();
    const acknowledged = Promise.withResolvers<void>();
    const encoded = codec.encode("reserved-private-payload", async (ref) => {
      entered.resolve(ref);
      await acknowledged.promise;
    });
    const ref = await entered.promise;
    expect(ref).toMatch(
      /^client-secrets\/data\/tenants\/tenant-a\/workspaces\/workspace-a\/integrations\/oauth-sessions\/[a-f0-9-]{36}$/,
    );
    expect(bao.records.has(ref)).toBe(false);
    acknowledged.resolve();
    expect(await encoded).toBe(ref);
    expect(await codec.decode(ref)).toBe("reserved-private-payload");
  });

  it.each(["rejected", "cancelled"] as const)("never dispatches after a %s reservation callback", async (failure) => {
    const bao = new FakeOpenBao();
    const controller = new AbortController();
    const codec = new OpenBaoSecretCodec(
      new OpenBaoClient({
        address: "https://openbao.test",
        token: "test-token",
        fetchFn: bao.fetch,
      }),
      { ...scope, requestSignal: controller.signal },
    );
    let ref = "";
    await expect(
      codec.encode("never-written", async (allocated) => {
        ref = allocated;
        if (failure === "rejected") throw new Error("Reservation rejected");
        controller.abort(new DOMException("Cancelled after reservation", "AbortError"));
      }),
    ).rejects.toThrow();
    expect(ref).not.toBe("");
    expect(bao.records.has(ref)).toBe(false);
  });

  it("stores only PKCE under the exact scoped path and atomically takes it once", async () => {
    const bao = new FakeOpenBao();
    const store = createStore(bao);
    await expect(
      store.put(scope, "oauth-session-1", state.pkceCodeVerifier, new Date(Date.now() + 60_000).toISOString()),
    ).resolves.toEqual({
      secretRef: expectedPath,
      secretRevision: 1,
    });
    expect(bao.calls[0]).toEqual({ method: "POST", path: expectedPath });
    const serializedSecret = JSON.stringify(bao.records.get(expectedPath)?.data);
    expect(serializedSecret).toContain("pkce-verifier-secret");
    expect(serializedSecret).not.toContain(state.state);
    expect(serializedSecret).not.toContain(state.service);
    expect(serializedSecret).not.toContain(state.connectionName);

    const [first, second] = await Promise.all([
      store.take(scope, "oauth-session-1"),
      store.take(scope, "oauth-session-1"),
    ]);
    expect([first, second].filter(Boolean)).toEqual([{ pkceCodeVerifier: state.pkceCodeVerifier }]);
    expect(bao.records.has(expectedPath)).toBe(false);
    await expect(store.take(scope, "oauth-session-1")).resolves.toBeUndefined();
  });

  it("round trips all native private state only through OpenBao and consumes captured client configuration once", async () => {
    const bao = new FakeOpenBao();
    const store = createStore(bao);
    const nativeState: OAuthAuthorizationState = {
      ...state,
      redirectUri: "app://captured-callback",
      authorizationScopes: ["read"],
      clientConfig: {
        service: "gmail",
        clientId: "client",
        clientSecret: "private-client-secret",
        extra: { tenant: "captured" },
        secretExtra: { appToken: "private-provider-token" },
      },
    };
    await store.put(
      scope,
      "oauth-session-1",
      nativeState.pkceCodeVerifier,
      new Date(Date.now() + 60000).toISOString(),
      nativeState,
    );
    expect(await store.take(scope, "oauth-session-1")).toMatchObject({ authorizationState: nativeState });
    expect(await store.take(scope, "oauth-session-1")).toBeUndefined();
    expect(bao.records.has(expectedPath)).toBe(false);
  });

  it("keeps private envelopes outside SQL and bounds compensation without inheriting or extending an aborted request", async () => {
    const bao = new FakeOpenBao();
    const client = new OpenBaoClient({ address: "https://openbao.test", token: "test-token", fetchFn: bao.fetch });
    const codec = new OpenBaoSecretCodec(client, scope);
    const payload = JSON.stringify({ clientSecret: "private-custom-client", pkceCodeVerifier: "private-custom-pkce" });
    const ref = await codec.encode(payload);
    expect(ref).not.toContain("private-custom");
    expect(await codec.decode(ref)).toBe(payload);
    await expect(
      new OpenBaoSecretCodec(client, { tenantId: "other-tenant", workspaceId: scope.workspaceId }).decode(ref),
    ).rejects.toThrow("scope");
    const controller = new AbortController();
    controller.abort();
    await expect(
      withRequestProcessing({ requestSignal: controller.signal }, () => codec.delete(ref)),
    ).rejects.toThrow();
    expect(bao.records.has(ref)).toBe(true);
    await withRequestProcessing({ requestSignal: controller.signal }, () =>
      withSecretCleanup(scope, async () => {
        const deadline = getRequestProcessing()!.processingDeadlineMs!;
        const clock = vi.spyOn(Date, "now").mockReturnValue(deadline + 1);
        try {
          await expect(withSecretCleanup(scope, () => codec.delete(ref))).rejects.toThrow("deadline");
        } finally {
          clock.mockRestore();
        }
        expect(bao.records.has(ref)).toBe(true);
        expect(await codec.delete(ref)).toBe(true);
      }),
    );
    expect(await codec.delete(ref)).toBe(false);
  });

  it("deletes an expired state without returning its PKCE verifier", async () => {
    const bao = new FakeOpenBao();
    const store = createStore(bao);
    await store.put(scope, "oauth-session-1", state.pkceCodeVerifier, new Date(Date.now() - 1).toISOString());
    await expect(store.take(scope, "oauth-session-1")).resolves.toBeUndefined();
    expect(bao.records.has(expectedPath)).toBe(false);
  });

  it("deletes only the exact OAuth-state secret and swallows only not-found", async () => {
    const bao = new FakeOpenBao();
    const store = createStore(bao);
    await store.put(scope, "oauth-session-1", state.pkceCodeVerifier, new Date(Date.now() + 60_000).toISOString());
    await expect(store.delete(scope, "oauth-session-1")).resolves.toBeUndefined();
    expect(bao.records.has(expectedPath)).toBe(false);
    bao.deleteStatus = 404;
    await expect(store.delete(scope, "oauth-session-1")).resolves.toBeUndefined();
    bao.deleteStatus = 500;
    await expect(store.delete(scope, "oauth-session-1")).rejects.toThrow();
    expect(
      bao.calls.filter(({ method }) => method === "DELETE").every(({ path }) => path.includes("oauth-session-1")),
    ).toBe(true);
  });

  it("rejects invalid OAuth-session path segments", async () => {
    const store = createStore(new FakeOpenBao());
    await expect(
      store.put({ ...scope, workspaceId: "bad%2Fworkspace" }, "oauth-session-1", undefined, new Date().toISOString()),
    ).rejects.toThrow("invalid path characters");
  });

  it("serializes only the state hash, secret reference, and safe metadata to PostgreSQL", async () => {
    const bao = new FakeOpenBao();
    const secretStore = createStore(bao);
    const queries: Array<{ text: string; values: unknown[] }> = [];
    const pgClient = {
      async query(text: string, values: unknown[] = []): Promise<{ rows: unknown[]; rowCount: number }> {
        queries.push({ text, values });
        return { rows: [], rowCount: 1 };
      },
      release(): void {},
    };
    const pool = {
      async connect() {
        return pgClient;
      },
    } as unknown as Pool;
    const metadataStore = new PostgresOAuthStateStore(pool, scope, secretStore);

    await metadataStore.set(state);
    const serialized = JSON.stringify(queries);
    expect(serialized).not.toContain(state.state);
    expect(serialized).not.toContain(state.pkceCodeVerifier);
    expect(serialized).toContain(expectedPath);
    expect(serialized).toContain("state_hash");
  });

  it("persists a hashed failed-state marker when PostgreSQL and secret cleanup both fail", async () => {
    const queries: Array<{ text: string; values: unknown[] }> = [];
    let failedPendingInsert = false;
    const pgClient = {
      async query(text: string, values: unknown[] = []): Promise<{ rows: unknown[]; rowCount: number }> {
        queries.push({ text, values });
        if (text.includes("SELECT id FROM integration_runtime.oauth_states")) return { rows: [], rowCount: 0 };
        if (
          text.includes("INSERT INTO integration_runtime.oauth_states") &&
          text.includes("'pending'") &&
          !failedPendingInsert
        ) {
          failedPendingInsert = true;
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
    const secretStore = {
      async put(): Promise<{ secretRef: string; secretRevision: number }> {
        return { secretRef: expectedPath, secretRevision: 1 };
      },
      async take(): Promise<OAuthAuthorizationState | undefined> {
        throw new Error("cleanup unavailable");
      },
      async delete(): Promise<void> {
        throw new Error("cleanup unavailable");
      },
    };
    const metadataStore = new PostgresOAuthStateStore(pool, scope, secretStore);

    let failure: unknown;
    try {
      await metadataStore.set(state);
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(OAuthStateMetadataReconciliationError);
    expect(failure).toMatchObject({ cleanupFailed: true, markerWritten: true });
    const serialized = JSON.stringify(queries);
    expect(serialized).toContain("'failed'");
    expect(serialized).not.toContain(state.state);
    expect(serialized).not.toContain(state.pkceCodeVerifier);
  });
});

function createStore(bao: FakeOpenBao): OpenBaoOAuthStateSecretStore {
  const client = new OpenBaoClient({ address: "https://openbao.test", token: "test-token", fetchFn: bao.fetch });
  return new OpenBaoOAuthStateSecretStore(client);
}

interface FakeRecord {
  data: Record<string, unknown>;
  revision: number;
}

class FakeOpenBao {
  readonly records = new Map<string, FakeRecord>();
  readonly calls: Array<{ method: string; path: string }> = [];
  deleteStatus?: number;

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
        return Response.json({ errors: ["CAS mismatch containing raw state"] }, { status: 400 });
      }
      const revision = (current?.revision ?? 0) + 1;
      this.records.set(path, { data: body.data, revision });
      return Response.json({ data: { version: revision } });
    }
    if (method === "DELETE") {
      if (this.deleteStatus) return Response.json({ errors: ["delete failed"] }, { status: this.deleteStatus });
      this.records.delete(path.replace("/metadata/", "/data/"));
      return new Response(null, { status: 204 });
    }
    const current = this.records.get(path);
    if (!current) return Response.json({ errors: ["not found"] }, { status: 404 });
    return Response.json({ data: { data: current.data, metadata: { version: current.revision } } });
  };
}
