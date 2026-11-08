import type { SaasRequestScope, NativeLifecycleServicePrincipal } from "../contracts.ts";
import type { ISecretCodec } from "../secrets/secret-codec.ts";
import type { SecretCustodyTarget } from "./postgres-secret-custody.ts";

import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { OpenBaoError } from "../secrets/openbao-client.ts";
import { createNativePostgresHarness, MemorySecretCodec } from "../testing/native-store-fixtures.ts";
import { PostgresNativeLifecycleInventory } from "./postgres-native-lifecycle-inventory.ts";
import { PostgresSecretCustodyStore } from "./postgres-secret-custody.ts";
import { withNativeLifecycleClient, withScopedClient } from "./scoped-query.ts";

const harness = createNativePostgresHarness();
function target(scope: SaasRequestScope): SecretCustodyTarget {
  return {
    kind: "connection-request",
    id: randomUUID(),
    dataUserId: scope.subjectUserId,
    credentialOwnerId: scope.subjectUserId,
    identity: { session: scope.oauthSessionId ?? randomUUID() },
  };
}
async function rows(scope: SaasRequestScope) {
  return withScopedClient(
    harness.pool,
    scope,
    async (client) => (await client.query("SELECT * FROM integration_runtime.secret_custody")).rows,
  );
}

describe.skipIf(!harness.enabled)("exact native secret custody", () => {
  it("retains an unknown original write even when deletion would observe absence, then inventories its orphan", async () => {
    const { scope } = harness.forScope();
    let ref = "";
    const values = new Map<string, string>();
    const codec: ISecretCodec = {
      encrypted: true,
      async encode(value, reserve) {
        ref = `secret:${randomUUID()}`;
        await reserve!(ref);
        throw new Error("unknown original POST");
      },
      async decode(key) {
        return values.get(key)!;
      },
      async delete(key) {
        return values.delete(key);
      },
    };
    const store = new PostgresSecretCustodyStore(harness.pool, scope, codec);
    await expect(store.encode("private", target(scope))).rejects.toThrow("unknown original POST");
    expect(await store.drain(["connection-request"])).toBe(0);
    values.set(ref, "late original write");
    expect(await rows(scope)).toMatchObject([{ secret_ref: ref, state: "pending" }]);
    await expect(
      withScopedClient(harness.pool, scope, (client) => store.assertNoPending(client, ["connection-request"])),
    ).rejects.toThrow();
    const principal: NativeLifecycleServicePrincipal = {
      subjectKind: "service",
      subject: "inventory",
      requestId: randomUUID(),
      purpose: "lifecycle:subjects",
      permissions: ["lifecycle:subjects"],
      target: { kind: "workspace", tenantId: scope.tenantId, workspaceId: scope.workspaceId },
    };
    expect((await new PostgresNativeLifecycleInventory(harness.pool).listSubjects(principal)).items).toContainEqual({
      kind: "user",
      tenantId: scope.tenantId,
      workspaceId: scope.workspaceId,
      userId: scope.subjectUserId,
    });
    expect(
      await withNativeLifecycleClient(
        harness.pool,
        principal,
        async (client) => (await client.query("SELECT secret_ref FROM integration_runtime.secret_custody")).rows,
      ),
    ).toHaveLength(1);
    await expect(
      withNativeLifecycleClient(harness.pool, principal, (client) =>
        client.query("SELECT secret_ref FROM integration_runtime.secret_custody FOR UPDATE"),
      ),
    ).resolves.toMatchObject({ rowCount: 0 });
    expect(values.get(ref)).toBe("late original write");
  });

  it("settles only the exact authoritative original no-write rejection without erasing KV", async () => {
    const { scope } = harness.forScope();
    let deletes = 0;
    const codec: ISecretCodec = {
      encrypted: true,
      async encode(_value, reserve) {
        const ref = `secret:${randomUUID()}`;
        await reserve!(ref);
        throw new OpenBaoError("OPENBAO_FORBIDDEN", ref, 403);
      },
      async decode() {
        throw new Error("unused");
      },
      async delete() {
        deletes++;
        return false;
      },
    };
    await expect(
      new PostgresSecretCustodyStore(harness.pool, scope, codec).encode("private", target(scope)),
    ).rejects.toThrow("403");
    expect(await rows(scope)).toHaveLength(0);
    expect(deletes).toBe(0);
  });

  it("serializes publication and abandonment in both winner orders", async () => {
    const { scope } = harness.forScope();
    const codec = new MemorySecretCodec();
    const store = new PostgresSecretCustodyStore(harness.pool, scope, codec);
    const first = target(scope);
    const published = await store.encode("published", first);
    const locked = Promise.withResolvers<void>();
    const commit = Promise.withResolvers<void>();
    const publisher = withScopedClient(harness.pool, scope, async (client) => {
      await store.consume(client, published, first);
      locked.resolve();
      await commit.promise;
    });
    await locked.promise;
    const loser = store.abandonWritten(published, first);
    commit.resolve();
    await Promise.all([publisher, loser]);
    expect(await codec.decode(published)).toBe("published");
    const second = target(scope);
    const abandoned = await store.encode("abandoned", second);
    await store.abandonWritten(abandoned, second);
    await expect(
      withScopedClient(harness.pool, scope, (client) => store.consume(client, abandoned, second)),
    ).rejects.toThrow();
    await expect(codec.decode(abandoned)).rejects.toThrow();
  });

  it("commits deletion custody before erase failure and retries only deleting, never pending", async () => {
    const { scope } = harness.forScope();
    const codec = new MemorySecretCodec();
    const store = new PostgresSecretCustodyStore(harness.pool, scope, codec);
    const owner = target(scope);
    const ref = await store.encode("settled", owner);
    await withScopedClient(harness.pool, scope, (client) => store.consume(client, ref, owner));
    await withScopedClient(harness.pool, scope, (client) => store.adoptDeleting(client, [ref], owner));
    codec.failDelete = true;
    await expect(store.drain([owner.kind])).rejects.toThrow();
    expect(await rows(scope)).toMatchObject([{ state: "deleting", secret_ref: ref }]);
    codec.failDelete = false;
    expect(await store.drain(["trigger-source"])).toBe(0);
    expect(await store.drain([owner.kind])).toBe(1);
    await withScopedClient(harness.pool, scope, (client) => store.adoptDeleting(client, [ref], owner));
    expect(await store.drain([owner.kind])).toBe(0);
    expect(await rows(scope)).toHaveLength(0);
    const pending = await store.encode("unknown", owner);
    await expect(
      withScopedClient(harness.pool, scope, (client) => store.adoptDeleting(client, [pending], owner)),
    ).rejects.toThrow();
    expect(await rows(scope)).toMatchObject([{ state: "pending" }]);
  });

  it("denies foreign tenant, workspace, actor and credential-owner custody", async () => {
    const { scope } = harness.forScope();
    const codec = new MemorySecretCodec();
    const owner = target(scope);
    const store = new PostgresSecretCustodyStore(harness.pool, scope, codec);
    const ref = await store.encode("private", owner);
    for (const foreign of [
      { tenantId: randomUUID() },
      { workspaceId: randomUUID() },
      { actorUserId: randomUUID() },
      { subjectUserId: randomUUID() },
    ]) {
      const other = { ...scope, ...foreign };
      const denied = new PostgresSecretCustodyStore(harness.pool, other, codec);
      expect(await rows(other)).toHaveLength(0);
      await expect(
        withScopedClient(harness.pool, other, (client) => denied.consume(client, ref, owner)),
      ).rejects.toThrow();
      expect(await denied.drain([owner.kind])).toBe(0);
    }
    expect(await codec.decode(ref)).toBe("private");
  });

  it("releases the small SQL pool while two original KV writes are paused", async () => {
    const { scope } = harness.forScope();
    const paused = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    let reservations = 0;
    const codec: ISecretCodec = {
      encrypted: true,
      async encode(_value, reserve) {
        const ref = `secret:${randomUUID()}`;
        await reserve!(ref);
        if (++reservations === 2) paused.resolve();
        await release.promise;
        return ref;
      },
      async decode() {
        throw new Error("unused");
      },
      async delete() {
        return false;
      },
    };
    const store = new PostgresSecretCustodyStore(harness.pool, scope, codec);
    const owner = target(scope);
    const writes = [store.encode("first", owner), store.encode("second", owner)];
    await paused.promise;
    try {
      expect(await rows(scope)).toHaveLength(2);
    } finally {
      release.resolve();
      await Promise.all(writes);
    }
  });

  it("discovers a shared-credential pending orphan by both actual actor and credential owner", async () => {
    const { scope: base } = harness.forScope();
    const scope = { ...base, actorUserId: randomUUID() };
    const owner: SecretCustodyTarget = {
      kind: "trigger-source",
      id: randomUUID(),
      dataUserId: scope.actorUserId,
      credentialOwnerId: scope.subjectUserId,
      identity: { actorUserId: scope.actorUserId, ownerActorUserId: scope.actorUserId, namespace: ["captured"] },
    };
    const codec = new MemorySecretCodec();
    const store = new PostgresSecretCustodyStore(harness.pool, scope, codec);
    await store.encode("shared private", owner);
    const unrelated = { ...scope, actorUserId: randomUUID() };
    expect(await rows(unrelated)).toHaveLength(0);
    for (const user of [scope.actorUserId, scope.subjectUserId]) {
      const cleanup = { ...scope, actorUserId: user, subjectUserId: user, purpose: "lifecycle:delete" as const };
      const scoped = new PostgresSecretCustodyStore(harness.pool, cleanup, codec);
      await expect(
        withScopedClient(harness.pool, cleanup, (client) => scoped.assertNoPending(client, ["trigger-source"])),
      ).rejects.toThrow();
    }
    const principal: NativeLifecycleServicePrincipal = {
      subjectKind: "service",
      subject: "inventory",
      requestId: randomUUID(),
      purpose: "lifecycle:subjects",
      permissions: ["lifecycle:subjects"],
      target: { kind: "workspace", tenantId: scope.tenantId, workspaceId: scope.workspaceId },
    };
    const users = (await new PostgresNativeLifecycleInventory(harness.pool).listSubjects(principal)).items.map(
      (item) => item.userId,
    );
    expect(users).toContain(scope.actorUserId);
    expect(users).toContain(scope.subjectUserId);
  });

  it("keeps resource-set data with its credential owner, not its processing actor", async () => {
    const db = harness.forScope();
    const connection = await db.connectionStore.set("example", "shared", {
      authType: "oauth2",
      accessToken: "private-provider-token",
      tokenType: "Bearer",
      profile: { accountId: "verified-account", displayName: "Account", grantedScopes: [] },
      metadata: { providerAccountVerified: true },
    });
    await db.connectionStore.updateVisibilityById(connection.id, "workspace");
    const scope = { ...db.scope, actorUserId: randomUUID() };
    const owner: SecretCustodyTarget = {
      kind: "trigger-subscription",
      id: randomUUID(),
      dataUserId: scope.subjectUserId,
      credentialOwnerId: scope.subjectUserId,
      connectionId: connection.id,
      identity: { mode: "resource-set", actorUserId: scope.actorUserId, ownerActorUserId: scope.actorUserId },
    };
    const codec = new MemorySecretCodec();
    const store = new PostgresSecretCustodyStore(harness.pool, scope, codec);
    const ref = await store.encode("private-resource-set", owner);
    expect(await rows(scope)).toMatchObject([
      { subject_user_id: scope.subjectUserId, actor_user_id: scope.actorUserId, secret_ref: ref },
    ]);
    expect(JSON.stringify(await rows(scope))).not.toContain("private-resource-set");
    await expect(
      store.encode("wrong-data-owner", { ...owner, id: randomUUID(), dataUserId: scope.actorUserId }),
    ).rejects.toThrow();
    await expect(
      store.encode("foreign-credential", { ...owner, id: randomUUID(), credentialOwnerId: randomUUID() }),
    ).rejects.toThrow();
  });

  it("records the actual lifecycle operator without replacing immutable original-owner identity", async () => {
    const { scope } = harness.forScope();
    const codec = new MemorySecretCodec();
    const owner = { ...target(scope), identity: { actorUserId: scope.actorUserId } };
    const store = new PostgresSecretCustodyStore(harness.pool, scope, codec);
    const ref = await store.encode("settled-owner", owner);
    await withScopedClient(harness.pool, scope, (client) => store.consume(client, ref, owner));
    const cleanup = { ...scope, actorUserId: randomUUID(), purpose: "lifecycle:delete" as const };
    const lifecycle = new PostgresSecretCustodyStore(harness.pool, cleanup, codec);
    await withScopedClient(harness.pool, cleanup, (client) => lifecycle.adoptDeleting(client, [ref], owner));
    expect(await rows(cleanup)).toMatchObject([
      {
        actor_user_id: cleanup.actorUserId,
        subject_user_id: scope.subjectUserId,
        identity: { actorUserId: scope.actorUserId },
        state: "deleting",
      },
    ]);
    expect(await lifecycle.drain([owner.kind])).toBe(1);
  });

  it("refuses pending, mismatched, foreign-scope and ordinary foreign-actor custody during cross-actor adoption", async () => {
    const { scope } = harness.forScope();
    const codec = new MemorySecretCodec();
    const owner = target(scope);
    const store = new PostgresSecretCustodyStore(harness.pool, scope, codec);
    const ref = await store.encode("settled-private", owner);
    await withScopedClient(harness.pool, scope, (client) => store.consume(client, ref, owner));
    await withScopedClient(harness.pool, scope, (client) => store.adoptDeleting(client, [ref], owner));
    const cleanup: SaasRequestScope = {
      ...scope,
      actorUserId: randomUUID(),
      purpose: "lifecycle:delete",
      permissions: ["lifecycle:delete"],
      requestHash: "a".repeat(43),
      localConnectionId: undefined,
      oauthSessionId: undefined,
    };
    for (const deniedScope of [
      { ...cleanup, tenantId: randomUUID() },
      { ...cleanup, workspaceId: randomUUID() },
      { ...cleanup, subjectUserId: randomUUID() },
      { ...scope, actorUserId: randomUUID() },
    ]) {
      const denied = new PostgresSecretCustodyStore(harness.pool, deniedScope, codec);
      await expect(
        withScopedClient(harness.pool, deniedScope, (client) => store.adoptDeleting(client, [ref], owner)),
      ).rejects.toThrow();
      expect(await denied.drain([owner.kind])).toBe(0);
      if (deniedScope.tenantId === scope.tenantId && deniedScope.workspaceId === scope.workspaceId)
        await expect(
          withScopedClient(harness.pool, deniedScope, (client) => denied.adoptDeleting(client, [ref], owner)),
        ).rejects.toThrow();
    }
    const lifecycle = new PostgresSecretCustodyStore(harness.pool, cleanup, codec);
    for (const mismatched of [
      { ...owner, id: randomUUID() },
      { ...owner, kind: "connection-candidate" as const },
      { ...owner, dataUserId: randomUUID() },
      { ...owner, credentialOwnerId: randomUUID() },
      { ...owner, identity: { session: randomUUID() } },
      { ...owner, connectionId: randomUUID() },
    ]) {
      await expect(
        withScopedClient(harness.pool, cleanup, (client) => lifecycle.adoptDeleting(client, [ref], mismatched)),
      ).rejects.toThrow();
    }
    const pending = await store.encode("original-write-unsettled", owner);
    await expect(
      withScopedClient(harness.pool, cleanup, (client) => lifecycle.adoptDeleting(client, [pending], owner)),
    ).rejects.toThrow();
    await expect(
      withScopedClient(harness.pool, cleanup, (client) => lifecycle.consume(client, pending, owner)),
    ).rejects.toThrow();
    await lifecycle.abandonWritten(pending, owner);
    expect(await rows(cleanup)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ secret_ref: ref, actor_user_id: scope.actorUserId, state: "deleting" }),
        expect.objectContaining({ secret_ref: pending, actor_user_id: scope.actorUserId, state: "pending" }),
      ]),
    );
    expect(await codec.decode(ref)).toBe("settled-private");
    expect(await codec.decode(pending)).toBe("original-write-unsettled");
  });

  it.each(["connection:write", "maintenance:run"] as const)(
    "reuses exact settled resource-set custody under existing %s ownership without changing original lineage",
    async (purpose) => {
      const db = harness.forScope();
      const connection = await db.connectionStore.set("example", "shared-cleanup-retry", {
        authType: "oauth2",
        accessToken: "private-provider-token",
        tokenType: "Bearer",
        profile: { accountId: "verified-account", displayName: "Account", grantedScopes: [] },
        metadata: { providerAccountVerified: true },
      });
      await db.connectionStore.updateVisibilityById(connection.id, "workspace");
      const writer = { ...db.scope, actorUserId: randomUUID() };
      const owner: SecretCustodyTarget = {
        kind: "trigger-subscription",
        id: randomUUID(),
        dataUserId: db.scope.subjectUserId,
        credentialOwnerId: db.scope.subjectUserId,
        connectionId: connection.id,
        identity: { mode: "resource-set", actorUserId: writer.actorUserId, ownerActorUserId: writer.actorUserId },
      };
      const codec = new MemorySecretCodec();
      const store = new PostgresSecretCustodyStore(harness.pool, writer, codec);
      const ref = await store.encode("settled-shared-resource", owner);
      await withScopedClient(harness.pool, writer, (client) => store.consume(client, ref, owner));
      await withScopedClient(harness.pool, writer, (client) => store.adoptDeleting(client, [ref], owner));
      const cleanup = {
        ...db.scope,
        actorUserId: purpose === "maintenance:run" ? db.scope.subjectUserId : randomUUID(),
        purpose,
        permissions: [purpose],
        localConnectionId: undefined,
        oauthSessionId: undefined,
      };
      const original = await rows(cleanup);
      expect(original).toMatchObject([
        {
          subject_user_id: db.scope.subjectUserId,
          actor_user_id: writer.actorUserId,
          credential_owner_id: db.scope.subjectUserId,
          identity: owner.identity,
          connection_id: connection.id,
          state: "deleting",
        },
      ]);
      const retry = new PostgresSecretCustodyStore(harness.pool, cleanup, codec);
      await withScopedClient(harness.pool, cleanup, (client) => retry.adoptDeleting(client, [ref], owner));
      expect(await rows(cleanup)).toEqual(original);
      expect(await retry.drain([owner.kind])).toBe(1);
      await expect(codec.decode(ref)).rejects.toThrow("Secret missing");
      expect(await rows(cleanup)).toEqual([]);
    },
  );
});
