import type { OAuthAuthorizationState } from "../../oauth/oauth-flow-service.ts";
import type { NativeLifecycleServicePrincipal, SaasRequestScope } from "../contracts.ts";
import type { ISecretCodec } from "../secrets/secret-codec.ts";
import type { PendingConnectionRequest, PendingSaasRequest } from "./connection-request-store.ts";

import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { SaasCleanupService } from "../saas-cleanup-service.ts";
import { SaasClient } from "../saas-client.ts";
import { OpenBaoError } from "../secrets/openbao-client.ts";
import { createNativePostgresHarness } from "../testing/native-store-fixtures.ts";
import { PostgresConnectionRequestStore } from "./postgres-connection-request-store.ts";
import { PostgresConnectionStore } from "./postgres-connection-store.ts";
import { scopedExternalUserId } from "./postgres-saas-project-store.ts";
import { withScopedClient } from "./scoped-query.ts";
const harness = createNativePostgresHarness();
const credential = {
  authType: "oauth2" as const,
  accessToken: "private-access-token",
  tokenType: "Bearer",
  refreshToken: "private-refresh-token",
  profile: { accountId: "verified-account", displayName: "Account", grantedScopes: ["read"] },
  metadata: { providerAccountVerified: true },
};

function delayedSecretWrite(base: ISecretCodec): { codec: ISecretCodec; land(): void } {
  const values = new Map<string, string>();
  let complete: (() => void) | undefined;
  return {
    codec: {
      encrypted: true,
      async encode(payload, beforeWrite) {
        const ref = `secret:${randomUUID()}`;
        await beforeWrite?.(ref);
        complete = () => {
          values.set(ref, payload);
        };
        throw new OpenBaoError("OPENBAO_UNAVAILABLE", ref);
      },
      async decode(ref) {
        const value = values.get(ref);
        return value === undefined ? base.decode(ref) : value;
      },
      async delete(ref) {
        return values.delete(ref) || (await base.delete(ref));
      },
    },
    land() {
      if (!complete) throw new Error("The fixture did not dispatch the original secret write");
      complete();
    },
  };
}

describe.skipIf(!harness.enabled)("native scoped OAuth/request persistence", () => {
  it("keeps an unknown initial write in native inventory after expiry without publishing an incomplete request", async () => {
    const db = harness.forScope();
    const late = delayedSecretWrite(harness.codec);
    if (!(db.connectionStore instanceof PostgresConnectionStore)) throw new Error("Expected native PostgreSQL fixture");
    const store = new PostgresConnectionRequestStore(harness.pool, db.scope, late.codec, db.connectionStore);
    const pending: PendingConnectionRequest = {
      service: "example",
      connectionName: "late-pending",
      state: randomUUID(),
      createdAt: new Date().toISOString(),
      retirementGeneration: await db.connectionStore.getRetirementGeneration("example", "late-pending"),
      connectionRequestId: randomUUID(),
      owner: db.scope.subjectUserId,
      expiresAt: new Date(Date.now() + 600000).toISOString(),
    };
    await expect(store.create(pending)).rejects.toMatchObject({ code: "OPENBAO_UNAVAILABLE" });
    late.land();
    await store.expireSaas(Date.now() + 2 * 86400000);
    expect(await store.countExactOwnedForLifecycle()).toMatchObject({ total: 0, secrets: 1 });
    await expect(store.purgeExactOwnedForLifecycle()).rejects.toThrow();
    expect(await store.countExactOwnedForLifecycle()).toMatchObject({ total: 0, secrets: 1 });
  });

  it("retains an unknown candidate independently of its expired parent and preserves the ordinary managed return URI", async () => {
    const db = harness.forScope();
    const project = {
      id: randomUUID(),
      projectId: "candidate-project",
      baseUrl: "https://saas.example",
      apiKey: "private-project-key",
    };
    await db.saasProjects.saveProject(project, null);
    const pending: PendingSaasRequest = {
      connectionRequestId: randomUUID(),
      connectionId: randomUUID(),
      owner: db.scope.subjectUserId,
      service: "example",
      connectionName: "late-candidate",
      managedProjectId: project.id,
      providerConfigId: "config",
      externalUserId: db.saasProjects.externalUserId(),
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600000).toISOString(),
      returnUri: "https://customer.example/finished",
    };
    const lease = await db.connectionRequests.createSaas(pending);
    expect(await db.connectionRequests.saveSaasRequest(lease, "remote-request")).toBe(true);
    const late = delayedSecretWrite(harness.codec);
    if (!(db.connectionStore instanceof PostgresConnectionStore)) throw new Error("Expected native PostgreSQL fixture");
    const store = new PostgresConnectionRequestStore(harness.pool, db.scope, late.codec, db.connectionStore);
    await expect(
      store.saveSaasCandidate(lease, {
        connectedAccountId: "late-account",
        profile: credential.profile,
        status: "active",
        comment: null,
      }),
    ).rejects.toMatchObject({ code: "OPENBAO_UNAVAILABLE" });
    late.land();
    await store.cancelSaas(pending.connectionRequestId, pending.owner);
    expect(await store.getSaasReturnUri(pending.connectionRequestId, pending.owner)).toBe(pending.returnUri);
    await store.expireSaas(Date.now() + 2 * 86400000);
    expect(await store.getSaasReturnUri(pending.connectionRequestId, pending.owner)).toBeUndefined();
    expect(await store.countExactOwnedForLifecycle()).toMatchObject({ total: 0, secrets: 1 });
    await expect(store.purgeExactOwnedForLifecycle()).rejects.toThrow();
  });

  it("binds a state to exact session, alias, owner and tenant before consuming private native state", async () => {
    const db = harness.forScope();
    const state: OAuthAuthorizationState = {
      service: "example",
      connectionName: "bound-alias",
      state: randomUUID(),
      createdAt: new Date().toISOString(),
      retirementGeneration: await db.connectionStore.getRetirementGeneration("example", "bound-alias"),
      pkceCodeVerifier: "private-pkce",
      redirectUri: "app://captured-callback",
      authorizationScopes: ["read"],
      clientConfig: {
        service: "example",
        clientId: "client",
        clientSecret: "private-client-secret",
        extra: { tenant: "captured" },
        secretExtra: { appToken: "private-provider-token" },
      },
      oauthSessionId: db.scope.oauthSessionId,
    };
    await db.oauthStateStore.set(state);
    const foreignOwner = randomUUID();
    for (const overrides of [
      { oauthSessionId: randomUUID() },
      { localConnectionId: randomUUID() },
      { tenantId: randomUUID() },
      { subjectUserId: foreignOwner, actorUserId: foreignOwner },
    ]) {
      expect(await harness.forScope({ ...db.scope, ...overrides }).oauthStateStore.take(state.state)).toBeUndefined();
    }
    expect(
      await db.oauthStateStore.take(state.state, {
        connectionName: "wrong-alias",
        oauthSessionId: db.scope.oauthSessionId!,
      }),
    ).toBeUndefined();
    const metadata = await withScopedClient(
      harness.pool,
      db.scope,
      async (client) =>
        (
          await client.query(`SELECT to_jsonb(s)::text AS value FROM integration_runtime.oauth_states s WHERE id=$1`, [
            db.scope.oauthSessionId,
          ])
        ).rows[0],
    );
    for (const secret of ["private-pkce", "private-client-secret", "private-provider-token"])
      expect(metadata.value).not.toContain(secret);
    expect(
      await db.oauthStateStore.take(state.state, {
        connectionName: "bound-alias",
        oauthSessionId: db.scope.oauthSessionId!,
      }),
    ).toEqual(state);
    expect(await db.oauthStateStore.take(state.state)).toBeUndefined();
  });

  it("completes a native request and connection atomically, exposes safe status, and fences late callbacks after disconnect", async () => {
    const db = harness.forScope();
    const pending: PendingConnectionRequest = {
      service: "example",
      connectionName: "native-request",
      state: randomUUID(),
      createdAt: new Date().toISOString(),
      retirementGeneration: await db.connectionStore.getRetirementGeneration("example", "native-request"),
      connectionRequestId: randomUUID(),
      owner: db.scope.subjectUserId,
      expiresAt: new Date(Date.now() + 600000).toISOString(),
      pkceCodeVerifier: "private-pending-pkce",
    };
    await db.connectionRequests.create(pending);
    expect(
      await harness.forScope({ ...db.scope, oauthSessionId: randomUUID() }).connectionRequests.claim(pending.state),
    ).toBeUndefined();
    const claimed = await db.connectionRequests.claim(pending.state);
    expect(claimed).toEqual(pending);
    const id = await db.connectionRequests.complete(claimed!, credential);
    expect(await db.connectionRequests.get(pending.connectionRequestId, db.scope.subjectUserId)).toMatchObject({
      status: "connected",
      appId: id,
    });
    expect(await db.connectionStore.getById(id!)).toMatchObject({
      credential: { accessToken: "private-access-token" },
    });
    const next: PendingConnectionRequest = {
      ...pending,
      state: randomUUID(),
      connectionRequestId: randomUUID(),
      target: { id: id!, revision: (await db.connectionStore.getById(id!))!.revision },
    };
    await db.connectionRequests.create(next);
    const late = await db.connectionRequests.claim(next.state);
    await db.connectionStore.delete("example", "native-request");
    expect(await db.connectionRequests.complete(late!, credential)).toBeUndefined();
    expect(await db.connectionStore.get("example", "native-request")).toBeUndefined();
    expect(await db.connectionRequests.get(next.connectionRequestId, db.scope.subjectUserId)).toMatchObject({
      status: "failed",
    });
  });

  it("does not partially replace credentials or report completion after a native reconnect CAS conflict", async () => {
    const db = harness.forScope();
    const original = await db.connectionStore.set("example", "cas-request", credential);
    const pending: PendingConnectionRequest = {
      service: "example",
      connectionName: "cas-request",
      state: randomUUID(),
      createdAt: new Date().toISOString(),
      retirementGeneration: await db.connectionStore.getRetirementGeneration("example", "cas-request"),
      connectionRequestId: randomUUID(),
      owner: db.scope.subjectUserId,
      expiresAt: new Date(Date.now() + 600000).toISOString(),
      target: { id: original.id, revision: original.revision },
    };
    await db.connectionRequests.create(pending);
    await db.connectionRequests.claim(pending.state);
    expect(
      await db.connectionStore.updateCredential({
        ...original,
        credential: { ...credential, accessToken: "newer-owner-token" },
      }),
    ).toBe(true);
    expect(await db.connectionRequests.complete(pending, credential)).toBeUndefined();
    expect(await db.connectionRequests.get(pending.connectionRequestId, db.scope.subjectUserId)).toMatchObject({
      status: "initiated",
      appId: null,
    });
    expect(await db.connectionStore.getById(original.id)).toMatchObject({
      credential: { accessToken: "newer-owner-token" },
    });
  });

  it("retains retryable request metadata when private cleanup fails and cannot resurrect it during purge retry", async () => {
    const db = harness.forScope();
    const pending: PendingConnectionRequest = {
      service: "example",
      connectionName: "purge-request",
      state: randomUUID(),
      createdAt: new Date().toISOString(),
      retirementGeneration: await db.connectionStore.getRetirementGeneration("example", "purge-request"),
      connectionRequestId: randomUUID(),
      owner: db.scope.subjectUserId,
      expiresAt: new Date(Date.now() + 600000).toISOString(),
    };
    await db.connectionRequests.create(pending);
    const claimed = await db.connectionRequests.claim(pending.state);
    harness.codec.failDelete = true;
    try {
      await expect(db.connectionRequests.purgeExactOwnedForLifecycle()).rejects.toThrow();
    } finally {
      harness.codec.failDelete = false;
    }
    expect(await db.connectionRequests.complete(claimed!, credential)).toBeUndefined();
    expect((await db.connectionRequests.listExactOwnedForLifecycle(undefined, 100)).items).toEqual([
      { id: pending.connectionRequestId, status: "failed" },
    ]);
    expect(await db.connectionRequests.purgeExactOwnedForLifecycle()).toEqual({
      deletedRequests: 1,
      deletedRequestSecrets: 1,
    });
  });

  it("lets an authorized lifecycle admin finish a user's failed terminal secret cleanup without replacing its audit actor", async () => {
    const db = harness.forScope();
    const pending: PendingConnectionRequest = {
      service: "example",
      connectionName: "admin-cleanup-retry",
      state: randomUUID(),
      createdAt: new Date().toISOString(),
      retirementGeneration: await db.connectionStore.getRetirementGeneration("example", "admin-cleanup-retry"),
      connectionRequestId: randomUUID(),
      owner: db.scope.subjectUserId,
      expiresAt: new Date(Date.now() + 600000).toISOString(),
    };
    await db.connectionRequests.create(pending);
    expect(await db.connectionRequests.claim(pending.state)).toEqual(pending);
    const admin = harness.forScope({
      ...db.scope,
      actorUserId: randomUUID(),
      purpose: "lifecycle:delete",
      permissions: ["lifecycle:delete"],
      requestHash: "a".repeat(43),
      localConnectionId: undefined,
      oauthSessionId: undefined,
    });
    harness.codec.failDelete = true;
    let ref = "";
    try {
      await expect(
        db.connectionRequests.fail(pending.connectionRequestId, "provider_rejected", "Authorization failed"),
      ).rejects.toThrow("Secret cleanup unavailable");
      const custody = await withScopedClient(
        harness.pool,
        admin.scope,
        async (client) =>
          (
            await client.query("SELECT * FROM integration_runtime.secret_custody WHERE target_id=$1", [
              pending.connectionRequestId,
            ])
          ).rows,
      );
      expect(custody).toMatchObject([
        {
          actor_user_id: db.scope.actorUserId,
          subject_user_id: db.scope.subjectUserId,
          credential_owner_id: db.scope.subjectUserId,
          state: "deleting",
        },
      ]);
      ref = custody[0].secret_ref;
      expect(JSON.parse(await harness.codec.decode(ref))).toEqual(pending);
      expect(
        await withScopedClient(
          harness.pool,
          admin.scope,
          async (client) =>
            (
              await client.query("SELECT phase,secret_ref FROM integration_runtime.connection_requests WHERE id=$1", [
                pending.connectionRequestId,
              ])
            ).rows,
        ),
      ).toEqual([{ phase: "purging", secret_ref: ref }]);
      await expect(admin.connectionRequests.purgeExactOwnedForLifecycle()).rejects.toThrow(
        "Secret cleanup unavailable",
      );
      expect(
        await withScopedClient(
          harness.pool,
          admin.scope,
          async (client) =>
            (
              await client.query("SELECT * FROM integration_runtime.secret_custody WHERE target_id=$1", [
                pending.connectionRequestId,
              ])
            ).rows,
        ),
      ).toEqual(custody);
    } finally {
      harness.codec.failDelete = false;
    }
    expect(await admin.connectionRequests.purgeExactOwnedForLifecycle()).toEqual({
      deletedRequests: 1,
      deletedRequestSecrets: 1,
    });
    await expect(harness.codec.decode(ref)).rejects.toThrow("Secret missing");
    expect(await admin.connectionRequests.countExactOwnedForLifecycle()).toMatchObject({ total: 0, secrets: 0 });
  });

  it("keeps real scoped managed identity stable on transfer and uses fenced leases without local credentials", async () => {
    const db = harness.forScope();
    const project = {
      id: randomUUID(),
      projectId: "remote-project",
      baseUrl: "https://saas.example",
      apiKey: "private-project-key",
    };
    await db.saasProjects.saveProject(project, null);
    const pending: PendingSaasRequest = {
      connectionRequestId: randomUUID(),
      connectionId: randomUUID(),
      owner: db.scope.subjectUserId,
      service: "example",
      connectionName: "managed-lineage",
      managedProjectId: project.id,
      providerConfigId: "config",
      externalUserId: db.saasProjects.externalUserId(),
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600000).toISOString(),
    };
    const lease = await db.connectionRequests.createSaas(pending);
    expect(
      await harness
        .forScope({ ...db.scope, localConnectionId: randomUUID() })
        .connectionRequests.claimSaas(pending.connectionRequestId, db.scope.subjectUserId),
    ).toBeUndefined();
    expect(await db.connectionRequests.saveSaasRequest(lease, "remote-request")).toBe(true);
    expect(
      await db.connectionRequests.saveSaasCandidate(lease, {
        connectedAccountId: "remote-account",
        profile: credential.profile,
        status: "active",
        comment: null,
      }),
    ).toBe(true);
    expect(await db.connectionRequests.completeSaas(lease)).toBe("connected");
    const stored = await db.connectionStore.getById(pending.connectionId);
    expect(stored).toMatchObject({
      source: "saas",
      reference: {
        managedProjectId: project.id,
        providerConfigId: "config",
        externalUserId: pending.externalUserId,
        connectedAccountId: "remote-account",
      },
    });
    expect(stored).not.toHaveProperty("credential");
    await db.connectionStore.updateVisibilityById(pending.connectionId, "workspace");
    const newOwner = randomUUID();
    await db.connectionStore.transferById(pending.connectionId, newOwner);
    const transferred = harness.forScope({
      ...db.scope,
      actorUserId: newOwner,
      subjectUserId: newOwner,
      oauthSessionId: randomUUID(),
    });
    expect(transferred.saasProjects.externalUserId()).toBe(pending.externalUserId);
    expect((await transferred.connectionStore.getById(pending.connectionId))?.source).toBe("saas");
    expect(await db.connectionStore.getById(pending.connectionId)).toBeUndefined();
    expect(scopedExternalUserId({ ...db.scope, workspaceId: randomUUID() })).not.toBe(pending.externalUserId);
  });

  it("refuses adopting an account queued for another owner even when config and external user differ", async () => {
    const oldOwner = harness.forScope();
    const project = {
      id: randomUUID(),
      projectId: "remote-project",
      baseUrl: "https://saas.example",
      apiKey: "private-project-key",
    };
    await oldOwner.saasProjects.saveProject(project, null);
    const pending: PendingSaasRequest = {
      connectionRequestId: randomUUID(),
      connectionId: randomUUID(),
      owner: oldOwner.scope.subjectUserId,
      service: "example",
      connectionName: "old-pending",
      managedProjectId: project.id,
      providerConfigId: "old-config",
      externalUserId: oldOwner.saasProjects.externalUserId(),
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600000).toISOString(),
    };
    const abandoned = await oldOwner.connectionRequests.createSaas(pending);
    await oldOwner.connectionRequests.saveSaasRequest(abandoned, "old-remote-request");
    await oldOwner.connectionRequests.saveSaasCandidate(abandoned, {
      connectedAccountId: "deleting-account",
      profile: credential.profile,
      status: "active",
      comment: null,
    });
    await oldOwner.connectionRequests.cancelSaas(pending.connectionRequestId, oldOwner.scope.subjectUserId);
    const user = randomUUID();
    const newOwner = harness.forScope({
      ...oldOwner.scope,
      actorUserId: user,
      subjectUserId: user,
      localConnectionId: randomUUID(),
      oauthSessionId: randomUUID(),
    });
    expect(
      await withScopedClient(
        harness.pool,
        newOwner.scope,
        async (client) => (await client.query("SELECT id FROM integration_runtime.saas_cleanup")).rows,
      ),
    ).toEqual([]);
    const replacement: PendingSaasRequest = {
      ...pending,
      connectionRequestId: randomUUID(),
      connectionId: randomUUID(),
      owner: user,
      connectionName: "different-lineage",
      providerConfigId: "new-config",
      externalUserId: newOwner.saasProjects.externalUserId(),
    };
    const lease = await newOwner.connectionRequests.createSaas(replacement);
    await newOwner.connectionRequests.saveSaasRequest(lease, "new-remote-request");
    await newOwner.connectionRequests.saveSaasCandidate(lease, {
      connectedAccountId: "deleting-account",
      profile: credential.profile,
      status: "active",
      comment: null,
    });
    expect(await newOwner.connectionRequests.completeSaas(lease)).toBe("conflict");
    expect(await newOwner.connectionStore.getById(replacement.connectionId)).toBeUndefined();
  });

  it("rejects a pre-deletion candidate after the other owner cleanup queue row has finished", async () => {
    const oldOwner = harness.forScope();
    const project = {
      id: randomUUID(),
      projectId: "remote-project",
      baseUrl: "https://saas.example",
      apiKey: "private-project-key",
    };
    await oldOwner.saasProjects.saveProject(project, null);
    const pending: PendingSaasRequest = {
      connectionRequestId: randomUUID(),
      connectionId: randomUUID(),
      owner: oldOwner.scope.subjectUserId,
      service: "example",
      connectionName: "old-pending",
      managedProjectId: project.id,
      providerConfigId: "config",
      externalUserId: oldOwner.saasProjects.externalUserId(),
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600000).toISOString(),
    };
    const abandoned = await oldOwner.connectionRequests.createSaas(pending);
    await oldOwner.connectionRequests.saveSaasRequest(abandoned, "old-remote-request");
    await oldOwner.connectionRequests.saveSaasCandidate(abandoned, {
      connectedAccountId: "deleted-account",
      profile: credential.profile,
      status: "active",
      comment: null,
    });
    const user = randomUUID();
    const newOwner = harness.forScope({
      ...oldOwner.scope,
      actorUserId: user,
      subjectUserId: user,
      localConnectionId: randomUUID(),
      oauthSessionId: randomUUID(),
    });
    const replacement: PendingSaasRequest = {
      ...pending,
      connectionRequestId: randomUUID(),
      connectionId: randomUUID(),
      owner: user,
      connectionName: "different-lineage",
      externalUserId: newOwner.saasProjects.externalUserId(),
    };
    const lease = await newOwner.connectionRequests.createSaas(replacement);
    await newOwner.connectionRequests.saveSaasRequest(lease, "new-remote-request");
    await newOwner.connectionRequests.saveSaasCandidate(lease, {
      connectedAccountId: "deleted-account",
      profile: credential.profile,
      status: "active",
      comment: null,
    });
    await oldOwner.connectionRequests.cancelSaas(pending.connectionRequestId, oldOwner.scope.subjectUserId);
    const remoteAccounts = new Set(["deleted-account"]);
    const cleanup = new SaasCleanupService({
      store: oldOwner.saasProjects,
      requests: oldOwner.connectionRequests,
      client: new SaasClient(async (input, init) => {
        if (init?.method !== "DELETE") throw new Error("Expected known account deletion");
        const id = new URL(String(input)).pathname.split("/").at(-1)!;
        remoteAccounts.delete(id);
        return Response.json({ success: true, data: { connectedAccountId: id, deleted: true } });
      }),
    });
    try {
      await cleanup.run();
    } finally {
      await cleanup.close();
    }
    expect(remoteAccounts.has("deleted-account")).toBe(false);
    expect((await oldOwner.saasProjects.getCleanupStats()).pending).toBe(0);
    expect(await newOwner.connectionRequests.completeSaas(lease)).toBe("conflict");
    expect(await newOwner.connectionStore.getById(replacement.connectionId)).toBeUndefined();
  });

  it("preserves a transferred private managed account during former-owner request cleanup", async () => {
    const oldOwner = harness.forScope();
    const project = {
      id: randomUUID(),
      projectId: "remote-project",
      baseUrl: "https://saas.example",
      apiKey: "private-project-key",
    };
    await oldOwner.saasProjects.saveProject(project, null);
    const pending: PendingSaasRequest = {
      connectionRequestId: randomUUID(),
      connectionId: randomUUID(),
      owner: oldOwner.scope.subjectUserId,
      service: "example",
      connectionName: "transferred-private",
      managedProjectId: project.id,
      providerConfigId: "config",
      externalUserId: oldOwner.saasProjects.externalUserId(),
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600000).toISOString(),
    };
    const first = await oldOwner.connectionRequests.createSaas(pending);
    await oldOwner.connectionRequests.saveSaasRequest(first, "remote-first");
    await oldOwner.connectionRequests.saveSaasCandidate(first, {
      connectedAccountId: "shared-remote-account",
      profile: credential.profile,
      status: "active",
      comment: null,
    });
    expect(await oldOwner.connectionRequests.completeSaas(first)).toBe("connected");
    await oldOwner.connectionStore.updateVisibilityById(pending.connectionId, "workspace");
    const current = (await oldOwner.connectionStore.getById(pending.connectionId))!;
    const reconnect = {
      ...pending,
      connectionRequestId: randomUUID(),
      target: { id: current.id, revision: current.revision },
    };
    const abandoned = await oldOwner.connectionRequests.createSaas(reconnect);
    await oldOwner.connectionRequests.saveSaasRequest(abandoned, "remote-abandoned");
    await oldOwner.connectionRequests.saveSaasCandidate(abandoned, {
      connectedAccountId: "shared-remote-account",
      profile: credential.profile,
      status: "active",
      comment: null,
    });
    const user = randomUUID();
    await oldOwner.connectionStore.transferById(pending.connectionId, user);
    const newOwner = harness.forScope({
      ...oldOwner.scope,
      actorUserId: user,
      subjectUserId: user,
      oauthSessionId: randomUUID(),
    });
    await newOwner.connectionStore.updateVisibilityById(pending.connectionId, "user");
    expect(await oldOwner.connectionStore.getById(pending.connectionId)).toBeUndefined();
    expect((await oldOwner.saasProjects.getCleanupStats()).pending).toBe(1);
    const remoteAccounts = new Set(["shared-remote-account"]);
    const client = new SaasClient(async (input, init) => {
      if (init?.method !== "DELETE") throw new Error("Known account cleanup must not query another authorization");
      const id = new URL(String(input)).pathname.split("/").at(-1)!;
      remoteAccounts.delete(id);
      return Response.json({ success: true, data: { connectedAccountId: id, deleted: true } });
    });
    const cleanup = new SaasCleanupService({
      store: oldOwner.saasProjects,
      requests: oldOwner.connectionRequests,
      client,
    });
    try {
      await cleanup.run();
    } finally {
      await cleanup.close();
    }
    expect(remoteAccounts.has("shared-remote-account")).toBe(true);
    expect((await newOwner.connectionStore.getById(pending.connectionId))?.source).toBe("saas");
    expect((await oldOwner.saasProjects.getCleanupStats()).pending).toBe(0);
  });

  for (const namespace of ["workspace", "tenant"] as const) {
    it(`preserves a physical managed account referenced in another ${namespace}`, async () => {
      const cleanupOwner = harness.forScope();
      const liveOwner = harness.forScope({
        tenantId: namespace === "workspace" ? cleanupOwner.scope.tenantId : randomUUID(),
      });
      const project = {
        id: randomUUID(),
        projectId: randomUUID(),
        baseUrl: "https://saas.example",
        apiKey: "private-project-key",
      };
      const peerProject = { ...project, id: randomUUID(), apiKey: "private-peer-key" };
      await cleanupOwner.saasProjects.saveProject(project, null);
      await liveOwner.saasProjects.saveProject(peerProject, null);
      const pending: PendingSaasRequest = {
        connectionRequestId: randomUUID(),
        connectionId: randomUUID(),
        owner: cleanupOwner.scope.subjectUserId,
        service: "example",
        connectionName: "abandoned-alias",
        managedProjectId: project.id,
        providerConfigId: "abandoned-config",
        externalUserId: cleanupOwner.saasProjects.externalUserId(),
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 600000).toISOString(),
      };
      const abandoned = await cleanupOwner.connectionRequests.createSaas(pending);
      await cleanupOwner.connectionRequests.saveSaasRequest(abandoned, "abandoned-request");
      await cleanupOwner.connectionRequests.saveSaasCandidate(abandoned, {
        connectedAccountId: "physical-account",
        profile: credential.profile,
        status: "active",
        comment: null,
      });
      const livePending = {
        ...pending,
        connectionRequestId: randomUUID(),
        connectionId: randomUUID(),
        owner: liveOwner.scope.subjectUserId,
        connectionName: "live-alias",
        managedProjectId: peerProject.id,
        providerConfigId: "live-config",
        externalUserId: liveOwner.saasProjects.externalUserId(),
      };
      const live = await liveOwner.connectionRequests.createSaas(livePending);
      await liveOwner.connectionRequests.saveSaasRequest(live, "live-request");
      await liveOwner.connectionRequests.saveSaasCandidate(live, {
        connectedAccountId: "physical-account",
        profile: credential.profile,
        status: "active",
        comment: null,
      });
      expect(await liveOwner.connectionRequests.completeSaas(live)).toBe("connected");
      await cleanupOwner.connectionRequests.cancelSaas(pending.connectionRequestId, pending.owner);
      expect(await cleanupOwner.connectionStore.getById(livePending.connectionId)).toBeUndefined();
      expect(
        await withScopedClient(
          harness.pool,
          cleanupOwner.scope,
          async (client) =>
            (await client.query("SELECT id FROM integration_runtime.managed_projects WHERE id=$1", [peerProject.id]))
              .rows,
        ),
      ).toEqual([]);
      const task = await cleanupOwner.saasProjects.claimCleanup(Date.now());
      let deleteDispatched = false;
      expect(
        await cleanupOwner.saasProjects.cleanupAccountIfUnreferenced(task!, "physical-account", async () => {
          deleteDispatched = true;
        }),
      ).toBe("referenced");
      expect(deleteDispatched).toBe(false);
      expect((await liveOwner.connectionStore.getById(livePending.connectionId))?.source).toBe("saas");
      expect((await cleanupOwner.saasProjects.getCleanupStats()).pending).toBe(0);
    });

    it(`refuses physical managed account adoption queued in another ${namespace}`, async () => {
      const oldOwner = harness.forScope();
      const newOwner = harness.forScope({
        tenantId: namespace === "workspace" ? oldOwner.scope.tenantId : randomUUID(),
      });
      const project = {
        id: randomUUID(),
        projectId: randomUUID(),
        baseUrl: "https://saas.example",
        apiKey: "private-project-key",
      };
      const peerProject = { ...project, id: randomUUID() };
      await oldOwner.saasProjects.saveProject(project, null);
      await newOwner.saasProjects.saveProject(peerProject, null);
      const pending: PendingSaasRequest = {
        connectionRequestId: randomUUID(),
        connectionId: randomUUID(),
        owner: oldOwner.scope.subjectUserId,
        service: "example",
        connectionName: "old-alias",
        managedProjectId: project.id,
        providerConfigId: "old-config",
        externalUserId: oldOwner.saasProjects.externalUserId(),
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 600000).toISOString(),
      };
      const abandoned = await oldOwner.connectionRequests.createSaas(pending);
      await oldOwner.connectionRequests.saveSaasRequest(abandoned, "old-request");
      await oldOwner.connectionRequests.saveSaasCandidate(abandoned, {
        connectedAccountId: "physical-account",
        profile: credential.profile,
        status: "active",
        comment: null,
      });
      await oldOwner.connectionRequests.cancelSaas(pending.connectionRequestId, pending.owner);
      const replacement = {
        ...pending,
        connectionRequestId: randomUUID(),
        connectionId: randomUUID(),
        owner: newOwner.scope.subjectUserId,
        connectionName: "new-alias",
        managedProjectId: peerProject.id,
        providerConfigId: "new-config",
        externalUserId: newOwner.saasProjects.externalUserId(),
      };
      const lease = await newOwner.connectionRequests.createSaas(replacement);
      await newOwner.connectionRequests.saveSaasRequest(lease, "new-request");
      await newOwner.connectionRequests.saveSaasCandidate(lease, {
        connectedAccountId: "physical-account",
        profile: credential.profile,
        status: "active",
        comment: null,
      });
      expect(
        await withScopedClient(
          harness.pool,
          newOwner.scope,
          async (client) => (await client.query("SELECT id FROM integration_runtime.saas_cleanup")).rows,
        ),
      ).toEqual([]);
      expect(await newOwner.connectionRequests.completeSaas(lease)).toBe("conflict");
      expect(await newOwner.connectionStore.getById(replacement.connectionId)).toBeUndefined();
    });

    it(`rejects a stale physical managed account candidate after another ${namespace} deletes its account and project`, async () => {
      const oldOwner = harness.forScope();
      const newOwner = harness.forScope({
        tenantId: namespace === "workspace" ? oldOwner.scope.tenantId : randomUUID(),
      });
      const project = {
        id: randomUUID(),
        projectId: randomUUID(),
        baseUrl: "https://saas.example",
        apiKey: "private-project-key",
      };
      const peerProject = { ...project, id: randomUUID() };
      await oldOwner.saasProjects.saveProject(project, null);
      await newOwner.saasProjects.saveProject(peerProject, null);
      const pending: PendingSaasRequest = {
        connectionRequestId: randomUUID(),
        connectionId: randomUUID(),
        owner: oldOwner.scope.subjectUserId,
        service: "example",
        connectionName: "old-alias",
        managedProjectId: project.id,
        providerConfigId: "old-config",
        externalUserId: oldOwner.saasProjects.externalUserId(),
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 600000).toISOString(),
      };
      const abandoned = await oldOwner.connectionRequests.createSaas(pending);
      await oldOwner.connectionRequests.saveSaasRequest(abandoned, "old-request");
      await oldOwner.connectionRequests.saveSaasCandidate(abandoned, {
        connectedAccountId: "physical-account",
        profile: credential.profile,
        status: "active",
        comment: null,
      });
      const replacement = {
        ...pending,
        connectionRequestId: randomUUID(),
        connectionId: randomUUID(),
        owner: newOwner.scope.subjectUserId,
        connectionName: "new-alias",
        managedProjectId: peerProject.id,
        providerConfigId: "new-config",
        externalUserId: newOwner.saasProjects.externalUserId(),
      };
      const lease = await newOwner.connectionRequests.createSaas(replacement);
      await newOwner.connectionRequests.saveSaasRequest(lease, "new-request");
      await newOwner.connectionRequests.saveSaasCandidate(lease, {
        connectedAccountId: "physical-account",
        profile: credential.profile,
        status: "active",
        comment: null,
      });
      await oldOwner.connectionRequests.cancelSaas(pending.connectionRequestId, pending.owner);
      const task = await oldOwner.saasProjects.claimCleanup(Date.now());
      // Controlled DELETE boundary only: no live vendor request is made.
      let deleteDispatched = false;
      expect(
        await oldOwner.saasProjects.cleanupAccountIfUnreferenced(task!, "physical-account", async () => {
          deleteDispatched = true;
        }),
      ).toBe("deleted");
      expect(deleteDispatched).toBe(true);
      expect((await oldOwner.saasProjects.getCleanupStats()).pending).toBe(0);
      await oldOwner.connectionRequests.purgeExactOwnedForLifecycle();
      expect(await oldOwner.saasProjects.deleteProject(project.id)).toBe(true);
      expect(await oldOwner.saasProjects.getProject()).toBeUndefined();
      expect(
        await withScopedClient(
          harness.pool,
          newOwner.scope,
          async (client) => (await client.query("SELECT * FROM integration_runtime.managed_account_retirements")).rows,
        ),
      ).toEqual([]);
      expect(await newOwner.connectionRequests.completeSaas(lease)).toBe("conflict");
      expect(await newOwner.connectionStore.getById(replacement.connectionId)).toBeUndefined();
    });
  }

  it("exports and purges workspace technical configuration under real SERVICE authority without a fake user", async () => {
    const db = harness.forScope();
    const project = {
      id: randomUUID(),
      projectId: "remote-project",
      baseUrl: "https://saas.example",
      apiKey: "private-technical-key",
    };
    await db.saasProjects.saveProject(project, null);
    await db.saasProjects.setSource("example", { managedProjectId: project.id, providerConfigId: "config" });
    const secretRef = await withScopedClient(
      harness.pool,
      db.scope,
      async (client) =>
        (
          await client.query<{ secret_ref: string }>(
            "SELECT secret_ref FROM integration_runtime.managed_projects WHERE id=$1",
            [project.id],
          )
        ).rows[0]!.secret_ref,
    );
    expect(await harness.codec.decode(secretRef)).toBe(project.apiKey);
    const read = technicalPrincipal(db.scope, "lifecycle:configuration:read");
    const page = await harness.factory.nativeConfiguration.readForLifecycle(read, { limit: 1 });
    expect(page.items).toHaveLength(1);
    expect(page.nextCursor).toBeDefined();
    expect(JSON.stringify(page)).not.toContain("private-technical-key");
    const remaining = await harness.factory.nativeConfiguration.readForLifecycle(read, {
      cursor: page.nextCursor,
      limit: 1,
    });
    expect(remaining.items).toHaveLength(1);
    expect(remaining.items[0]!.kind).not.toBe(page.items[0]!.kind);
    await expect(
      harness.factory.nativeConfiguration.readForLifecycle(
        { ...read, target: { ...read.target, tenantId: randomUUID() } },
        { cursor: page.nextCursor },
      ),
    ).rejects.toThrow("cursor");
    const purge = technicalPrincipal(db.scope, "lifecycle:configuration:purge");
    expect(
      await harness.factory.nativeConfiguration.purgeForLifecycle(purge, "00000000-0000-4000-8000-000000000321"),
    ).toEqual({
      correlationId: "00000000-0000-4000-8000-000000000321",
      deletedProjects: 1,
      deletedSources: 1,
      deletedSecrets: 1,
    });
    expect((await harness.factory.nativeConfiguration.readForLifecycle(read)).items).toEqual([]);
    await expect(harness.codec.decode(secretRef)).rejects.toThrow("Secret missing");
  });
});
function technicalPrincipal(
  scope: SaasRequestScope,
  purpose: NativeLifecycleServicePrincipal["purpose"],
): NativeLifecycleServicePrincipal {
  return {
    subjectKind: "service",
    subject: "verified-cleanup-service",
    purpose,
    permissions: [purpose],
    target: { kind: "workspace", tenantId: scope.tenantId, workspaceId: scope.workspaceId },
    requestId: randomUUID(),
    requestHash: purpose === "lifecycle:configuration:purge" ? "a".repeat(43) : undefined,
  };
}
