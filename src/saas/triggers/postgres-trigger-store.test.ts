import type { ResourceDefinition } from "../../triggers/common/integration.ts";
import type { ConnectorProxy } from "../../triggers/common/proxy.ts";
import type { TriggerSubscription } from "../../triggers/store.ts";
import type { ISecretCodec } from "../secrets/secret-codec.ts";
import type { PoolClient } from "pg";

import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import { ConnectionService } from "../../connection-service.ts";
import { ProviderLoader } from "../../providers/provider-loader.ts";
import { slackBotEvents } from "../../providers/slackbot/trigger-on-event.ts";
import { executeResourceSubscription } from "../../triggers/resources.ts";
import { executePersistentSource } from "../../triggers/sources/persistent.ts";
import { TriggerRunner } from "../../triggers/trigger-runner.ts";
import { canonicalActionRequestHash } from "../actions/canonical-request.ts";
import { OpenBaoError } from "../secrets/openbao-client.ts";
import { PostgresActionPolicyStore } from "../storage/postgres-action-policy-store.ts";
import { withScopedClient } from "../storage/scoped-query.ts";
import { createNativePostgresHarness } from "../testing/native-store-fixtures.ts";
import { PostgresTriggerStore, scopedTriggerOwner } from "./postgres-trigger-store.ts";
import { SaasTriggerRunner } from "./saas-trigger-runner.ts";

const db = createNativePostgresHarness();
const credential = {
  authType: "oauth2" as const,
  accessToken: "private-access",
  tokenType: "Bearer",
  profile: { accountId: "U0BOT", displayName: "Bot", grantedScopes: [] },
  metadata: { providerAccountVerified: true },
};
const triggerCatalog = createCatalogStore([
  {
    service: "slackbot",
    displayName: "Slack",
    categories: [],
    authTypes: ["oauth2"],
    auth: [],
    actions: [],
    triggers: [slackBotEvents.snapshot],
  },
]);
async function fixture() {
  const runtime = db.forScope();
  const connection = await runtime.connectionStore.set("slackbot", "trigger", credential);
  const scope = { ...runtime.scope, connectorConnectionId: connection.id };
  const store = new PostgresTriggerStore(db.pool, scope, db.codec);
  const record: TriggerSubscription = {
    id: randomUUID(),
    ownerId: scopedTriggerOwner(scope),
    mode: "webhook",
    service: "slackbot",
    connectionId: connection.id,
    connectionRevision: connection.revision,
    providerAccountId: "U0BOT",
    triggerId: slackBotEvents.snapshot.key,
    requestKey: "request",
    config: {},
    endpointUrl: "https://host.example/callback",
    callbackNonce: "private-nonce",
    callbackSecret: "private-callback",
    checkpoint: { cursor: "private-checkpoint" },
    subscription: { remote: "private-subscription" },
    reconcileAt: 0,
    status: "active",
  };
  return { runtime, scope, store, record };
}

describe.skipIf(!db.enabled)("native scoped trigger persistence", () => {
  it("retains unresolved private-state custody when the original write lands after a missing-secret cleanup", async () => {
    const { scope, record } = await fixture();
    const values = new Map<string, string>();
    let completeOriginalWrite: (() => void) | undefined;
    const codec: ISecretCodec = {
      encrypted: true,
      async encode(payload, beforeWrite) {
        const ref = `secret:${randomUUID()}`;
        await beforeWrite?.(ref);
        completeOriginalWrite = () => {
          values.set(ref, payload);
        };
        throw new OpenBaoError("OPENBAO_UNAVAILABLE", ref);
      },
      async decode(ref) {
        const value = values.get(ref);
        if (value === undefined) throw new Error("Secret missing");
        return value;
      },
      async delete(ref) {
        return values.delete(ref);
      },
    };
    const store = new PostgresTriggerStore(db.pool, scope, codec);
    await expect(store.insertFlowTrigger(record)).rejects.toMatchObject({ code: "OPENBAO_UNAVAILABLE" });
    if (!completeOriginalWrite) throw new Error("The fixture did not dispatch the original secret write");
    completeOriginalWrite();
    expect(await store.getFlowTrigger(record.id)).toBeNull();
    const lifecycle = new PostgresTriggerStore(
      db.pool,
      { ...scope, purpose: "lifecycle:delete", permissions: ["lifecycle:delete"] },
      codec,
    );
    expect(await lifecycle.countExactOwnedForLifecycle()).toMatchObject({ secrets: 1, pendingSecrets: 1 });
    await expect(lifecycle.purgeExactOwnedForLifecycle()).rejects.toThrow();
    expect(await lifecycle.countExactOwnedForLifecycle()).toMatchObject({ secrets: 1, pendingSecrets: 1 });
    const unrelated = randomUUID();
    for (const foreign of [
      { tenantId: randomUUID() },
      { workspaceId: randomUUID() },
      { subjectUserId: unrelated, actorUserId: unrelated },
    ]) {
      const foreignLifecycle = new PostgresTriggerStore(
        db.pool,
        { ...scope, ...foreign, purpose: "lifecycle:delete", permissions: ["lifecycle:delete"] },
        codec,
      );
      expect(await foreignLifecycle.countExactOwnedForLifecycle()).toMatchObject({ secrets: 0, pendingSecrets: 0 });
      await expect(foreignLifecycle.purgeExactOwnedForLifecycle()).resolves.toMatchObject({ deletedTriggerSecrets: 0 });
    }
    expect(await lifecycle.countExactOwnedForLifecycle()).toMatchObject({ secrets: 1, pendingSecrets: 1 });
  });

  it.each(["update", "source"] as const)(
    "keeps late unknown %s writes pending without erasing the active owner",
    async (operation) => {
      const { scope, record } = await fixture();
      const values = new Map<string, string>();
      let unknown = false;
      let land: (() => void) | undefined;
      let erases = 0;
      const codec: ISecretCodec = {
        encrypted: true,
        async encode(payload, beforeWrite) {
          const ref = `secret:${randomUUID()}`;
          await beforeWrite?.(ref);
          if (unknown) {
            land = () => {
              values.set(ref, payload);
            };
            throw new OpenBaoError("OPENBAO_UNAVAILABLE", ref);
          }
          values.set(ref, payload);
          return ref;
        },
        async decode(ref) {
          const value = values.get(ref);
          if (value === undefined) throw new Error("Secret missing");
          return value;
        },
        async delete(ref) {
          erases++;
          return values.delete(ref);
        },
      };
      const store = new PostgresTriggerStore(db.pool, scope, codec);
      const namespace = JSON.stringify([record.ownerId, "deployment", record.triggerId]);
      const application = { secrets: {}, state: {}, sources: {} };
      const lease = randomUUID();
      if (operation === "update") {
        await store.insertFlowTrigger(record);
        expect(await store.claimFlowTrigger(record.id, lease, Date.now(), Date.now() + 60000)).toBe(true);
      } else expect(await store.saveSourceApplication(namespace, record.id, null, application)).toBe(true);
      unknown = true;
      await expect(
        operation === "update"
          ? store.saveFlowTrigger({ ...record, checkpoint: { cursor: "unknown-next" } }, lease, Date.now())
          : store.saveSourceApplication(namespace, record.id, 1, { ...application, state: { next: true } }),
      ).rejects.toMatchObject({ code: "OPENBAO_UNAVAILABLE" });
      if (!land) throw new Error("Original write was not dispatched");
      land();
      expect(erases).toBe(0);
      if (operation === "update")
        expect(await store.getFlowTrigger(record.id)).toMatchObject({ checkpoint: record.checkpoint });
      else expect(await store.getSourceApplication(namespace, record.id)).toEqual({ revision: 1, application });
      const lifecycle = new PostgresTriggerStore(
        db.pool,
        { ...scope, purpose: "lifecycle:delete", permissions: ["lifecycle:delete"] },
        codec,
      );
      expect(await lifecycle.countExactOwnedForLifecycle()).toMatchObject({ secrets: 2, pendingSecrets: 1 });
      await expect(lifecycle.purgeExactOwnedForLifecycle()).rejects.toThrow();
      expect(erases).toBe(0);
    },
  );

  it("clears custody only on authoritative original write rejection without issuing an erase", async () => {
    const { scope, record } = await fixture();
    let erases = 0;
    const codec: ISecretCodec = {
      encrypted: true,
      async encode(_payload, beforeWrite) {
        const ref = `secret:${randomUUID()}`;
        await beforeWrite?.(ref);
        throw new OpenBaoError("OPENBAO_UNAVAILABLE", ref, 403);
      },
      async decode() {
        throw new Error("No private state was published");
      },
      async delete() {
        erases++;
        return false;
      },
    };
    const store = new PostgresTriggerStore(db.pool, scope, codec);
    await expect(store.insertFlowTrigger(record)).rejects.toMatchObject({ status: 403 });
    expect(erases).toBe(0);
    expect(await store.getFlowTrigger(record.id)).toBeNull();
    const lifecycle = new PostgresTriggerStore(
      db.pool,
      { ...scope, purpose: "lifecycle:delete", permissions: ["lifecycle:delete"] },
      codec,
    );
    expect(await lifecycle.countExactOwnedForLifecycle()).toMatchObject({ secrets: 0, pendingSecrets: 0 });
    await expect(lifecycle.purgeExactOwnedForLifecycle()).resolves.toMatchObject({ deletedTriggerSecrets: 0 });
  });

  it("releases the two-client pool while three private writes are paused and returns the complete concurrent insert winner", async () => {
    const { scope, record } = await fixture();
    const { promise: paused, resolve: allPaused } = Promise.withResolvers<void>();
    const { promise: resume, resolve: release } = Promise.withResolvers<void>();
    let dispatched = 0;
    const codec: ISecretCodec = {
      encrypted: true,
      encode: (payload, beforeWrite) =>
        db.codec.encode(payload, async (ref) => {
          await beforeWrite?.(ref);
          if (++dispatched === 3) allPaused();
          await resume;
        }),
      decode: (ref) => db.codec.decode(ref),
      delete: (ref) => db.codec.delete(ref),
    };
    const store = new PostgresTriggerStore(db.pool, scope, codec);
    const writes = [0, 1, 2].map((index) => store.insertFlowTrigger({ ...record, checkpoint: { contender: index } }));
    try {
      await paused;
      await withScopedClient(db.pool, scope, (client) => client.query("SELECT 1"));
    } finally {
      release();
    }
    const results = await Promise.all(writes);
    expect(results[1]).toEqual(results[0]);
    expect(results[2]).toEqual(results[0]);
    expect(await store.getFlowTrigger(record.id)).toEqual(results[0]);
    const lifecycle = new PostgresTriggerStore(
      db.pool,
      { ...scope, purpose: "lifecycle:delete", permissions: ["lifecycle:delete"] },
      codec,
    );
    expect(await lifecycle.countExactOwnedForLifecycle()).toMatchObject({ secrets: 1, pendingSecrets: 0 });
  });

  it.each(["revision", "lease", "binding"] as const)(
    "revalidates %s after an acknowledged private write without publishing stale state",
    async (change) => {
      const { scope, record, store: initial } = await fixture();
      await initial.insertFlowTrigger(record);
      const lease = randomUUID();
      expect(await initial.claimFlowTrigger(record.id, lease, Date.now(), Date.now() + 60000)).toBe(true);
      const { promise: paused, resolve: started } = Promise.withResolvers<void>();
      const { promise: resume, resolve: release } = Promise.withResolvers<void>();
      const codec: ISecretCodec = {
        encrypted: true,
        async encode(payload, beforeWrite) {
          const ref = await db.codec.encode(payload, beforeWrite);
          started();
          await resume;
          return ref;
        },
        decode: (ref) => db.codec.decode(ref),
        delete: (ref) => db.codec.delete(ref),
      };
      const store = new PostgresTriggerStore(db.pool, scope, codec);
      const write = store.saveFlowTrigger({ ...record, checkpoint: { cursor: "stale" } }, lease, Date.now());
      const outcome = write.then(
        (saved) => ({ saved }),
        (error: unknown) => ({ error }),
      );
      try {
        await paused;
        if (change === "revision")
          expect(
            await initial.saveFlowTrigger({ ...record, checkpoint: { cursor: "winner" } }, lease, Date.now()),
          ).toBe(true);
        else if (change === "lease") await initial.releaseFlowTrigger(record.id, lease);
        else
          await withScopedClient(db.pool, scope, (client) =>
            client.query("UPDATE integration_runtime.connections SET status='reconnect_required' WHERE id=$1", [
              record.connectionId,
            ]),
          );
      } finally {
        release();
      }
      const result = await outcome;
      if (change === "binding") expect(result).toHaveProperty("error");
      else expect(result).toEqual({ saved: false });
      if (change !== "binding")
        expect(await initial.getFlowTrigger(record.id)).toMatchObject({
          checkpoint: change === "revision" ? { cursor: "winner" } : record.checkpoint,
        });
      const lifecycle = new PostgresTriggerStore(
        db.pool,
        { ...scope, purpose: "lifecycle:delete", permissions: ["lifecycle:delete"] },
        codec,
      );
      expect(await lifecycle.countExactOwnedForLifecycle()).toMatchObject({ secrets: 1, pendingSecrets: 0 });
    },
  );

  it("isolates actual native state across tenant, workspace, owner and actor and fences concurrent claims", async () => {
    const { scope, store, record } = await fixture();
    await store.insertFlowTrigger(record);
    for (const override of [
      { tenantId: randomUUID() },
      { workspaceId: randomUUID() },
      { subjectUserId: randomUUID() },
      { actorUserId: randomUUID() },
    ]) {
      const foreign = new PostgresTriggerStore(db.pool, { ...scope, ...override }, db.codec);
      expect(await foreign.getFlowTrigger(record.id)).toBeNull();
      expect(await foreign.claimFlowTrigger(record.id, randomUUID(), Date.now(), Date.now() + 60000)).toBe(false);
    }
    const leaseA = randomUUID(),
      leaseB = randomUUID();
    const claims = await Promise.all([
      store.claimFlowTrigger(record.id, leaseA, Date.now(), Date.now() + 60000),
      store.claimFlowTrigger(record.id, leaseB, Date.now(), Date.now() + 60000),
    ]);
    expect(claims.filter(Boolean)).toHaveLength(1);
    const winner = claims[0] ? leaseA : leaseB,
      loser = claims[0] ? leaseB : leaseA;
    const changed = { ...record, checkpoint: { cursor: "next" } };
    expect(await store.saveFlowTrigger(changed, loser, Date.now())).toBe(false);
    expect(await store.saveFlowTrigger(changed, winner, Date.now())).toBe(true);
    expect(await store.getFlowTrigger(record.id)).toMatchObject({ checkpoint: { cursor: "next" } });
    const sql = await withScopedClient(
      db.pool,
      scope,
      async (client) =>
        (
          await client.query(
            "SELECT to_jsonb(t)::text AS value FROM integration_runtime.trigger_subscriptions t WHERE id=$1",
            [record.id],
          )
        ).rows[0],
    );
    for (const secret of ["private-callback", "private-nonce", "private-checkpoint", "private-subscription"])
      expect(sql.value).not.toContain(secret);
  });

  it("prevents account replacement, deletion, transfer and unsharing while bound but permits same-account reconnect and truthful reconnect status", async () => {
    const { runtime, scope, store, record } = await fixture();
    await runtime.connectionStore.updateVisibilityById(record.connectionId, "workspace");
    await store.insertFlowTrigger(record);
    const current = await runtime.connectionStore.getById(record.connectionId);
    if (!current || current.source === "saas") throw new Error("Missing local fixture");
    await expect(
      runtime.connectionStore.updateCredential({ ...current, credential: { ...credential, accessToken: "rotated" } }),
    ).resolves.toBe(true);
    const refreshed = await runtime.connectionStore.getById(record.connectionId);
    if (!refreshed || refreshed.source === "saas") throw new Error("Missing reconnect fixture");
    await expect(
      runtime.connectionStore.updateCredential({
        ...refreshed,
        credential: { ...credential, profile: { ...credential.profile, accountId: "different-account" } },
      }),
    ).rejects.toThrow();
    await expect(runtime.connectionStore.delete("slackbot", "trigger")).rejects.toThrow();
    await expect(runtime.connectionStore.updateVisibilityById(record.connectionId, "user")).rejects.toThrow();
    await expect(runtime.connectionStore.transferById(record.connectionId, randomUUID())).rejects.toThrow();
    await withScopedClient(db.pool, scope, (client) =>
      client.query("UPDATE integration_runtime.connections SET status='reconnect_required' WHERE id=$1", [
        record.connectionId,
      ]),
    );
    expect(await store.getFlowTrigger(record.id)).toBeNull();
  });

  it.each(["replace", "update", "disconnect", "revoke"] as const)(
    "keeps a bound working account intact after rejected %s",
    async (operation) => {
      const { runtime, store, record } = await fixture();
      await store.insertFlowTrigger(record);
      const current = await runtime.connectionStore.getById(record.connectionId);
      if (!current || current.source === "saas") throw new Error("Missing native connection");
      const replacement = { ...credential, profile: { ...credential.profile, accountId: "other-account" } };
      const pending =
        operation === "replace"
          ? runtime.connectionStore.set(record.service, "trigger", replacement)
          : operation === "update"
            ? runtime.connectionStore.updateCredential({ ...current, credential: replacement })
            : operation === "disconnect"
              ? runtime.connectionStore.delete(record.service, "trigger")
              : runtime.connectionStore.blockForRevocation(record.connectionId);
      await expect(pending).rejects.toThrow();
      expect(await runtime.connectionStore.getById(record.connectionId)).toMatchObject({
        id: current.id,
        revision: current.revision,
        credential: { accessToken: "private-access", profile: { accountId: "U0BOT" } },
      });
    },
  );

  it("runs native Slack source creation against private scoped CAS state and rejects stale source updates", async () => {
    const { runtime, scope, store, record } = await fixture();
    const owner = { scope: scopedTriggerOwner(scope), connectionId: record.connectionId };
    const proxy = {
      providerAccountId: "U0BOT",
      execute: async () => {
        throw new Error("Unexpected network");
      },
    };
    const input = {
      appId: "A0APP",
      workspaceId: "T0TEAM",
      signingSecret: "private-signing-secret",
      eventTypes: ["app_mention"],
    };
    const result = (await executePersistentSource(
      store,
      slackBotEvents,
      owner,
      { action: "create", deploymentId: "deployment", requestKey: "source", input },
      proxy,
      new AbortController().signal,
    )) as { source: { reference: { applicationId: string }; revision: number } };
    expect(result.source.revision).toBe(1);
    expect(JSON.stringify(result)).not.toContain("private-signing-secret");
    // This connection has a Source but no subscription row: source-only account protection is independent.
    await expect(runtime.connectionStore.delete("slackbot", "trigger")).rejects.toThrow();
    const current = await runtime.connectionStore.getById(record.connectionId);
    if (!current || current.source === "saas") throw new Error("Missing native source connection");
    await expect(
      runtime.connectionStore.updateCredential({
        ...current,
        credential: { ...credential, profile: { ...credential.profile, accountId: "different-source-account" } },
      }),
    ).rejects.toThrow();
    const namespace = JSON.stringify([owner.scope, "deployment", slackBotEvents.snapshot.key]);
    const first = await store.getSourceApplication(namespace, result.source.reference.applicationId);
    expect(first).not.toBeNull();
    const writes = await Promise.all([
      store.saveSourceApplication(namespace, result.source.reference.applicationId, 1, first!.application),
      store.saveSourceApplication(namespace, result.source.reference.applicationId, 1, first!.application),
    ]);
    expect(writes.filter(Boolean)).toHaveLength(1);
    expect(
      await store.saveSourceApplication(namespace, result.source.reference.applicationId, 1, first!.application),
    ).toBe(false);
    const foreign = new PostgresTriggerStore(db.pool, { ...scope, workspaceId: randomUUID() }, db.codec);
    await expect(foreign.getSourceApplication(namespace, result.source.reference.applicationId)).rejects.toThrow();
    const sql = await withScopedClient(
      db.pool,
      scope,
      async (client) =>
        (
          await client.query(
            "SELECT to_jsonb(t)::text AS value FROM integration_runtime.trigger_source_applications t WHERE id=$1",
            [result.source.reference.applicationId],
          )
        ).rows[0],
    );
    expect(sql.value).not.toContain("private-signing-secret");
  });

  it("retains private cleanup markers after a failed envelope delete and purges only after real remote cleanup", async () => {
    const { runtime, scope, store, record } = await fixture();
    await store.insertFlowTrigger(record);
    const lifecycle = new PostgresTriggerStore(
      db.pool,
      { ...scope, purpose: "lifecycle:delete", permissions: ["lifecycle:delete"] },
      db.codec,
    );
    await expect(lifecycle.purgeExactOwnedForLifecycle()).rejects.toThrow();
    await expect(
      lifecycle.cleanupExactOwnedForLifecycle(async () => {
        throw new Error("Provider unavailable");
      }),
    ).rejects.toThrow("Provider unavailable");
    expect((await lifecycle.countExactOwnedForLifecycle()).subscriptions.total).toBe(1);
    await lifecycle.cleanupExactOwnedForLifecycle(async (value, save) => {
      value.status = "deleted";
      await save();
    });
    const purger = new PostgresTriggerStore(
      db.pool,
      { ...scope, purpose: "lifecycle:delete", permissions: ["lifecycle:delete"] },
      {
        encrypted: true,
        encode: (payload, beforeWrite) => db.codec.encode(payload, beforeWrite),
        decode: (ref) => db.codec.decode(ref),
        async delete(ref) {
          // The external effect must see the committed no-read fence, even when deletion fails.
          expect(await store.getFlowTrigger(record.id)).toBeNull();
          expect(await lifecycle.countExactOwnedForLifecycle()).toMatchObject({ secrets: 1, pendingSecrets: 1 });
          return db.codec.delete(ref);
        },
      },
    );
    db.codec.failDelete = true;
    try {
      await expect(purger.purgeExactOwnedForLifecycle()).rejects.toThrow();
    } finally {
      db.codec.failDelete = false;
    }
    expect((await lifecycle.listExactOwnedForLifecycle(undefined, 100)).subscriptions).toEqual([]);
    expect(await store.getFlowTrigger(record.id)).toBeNull();
    expect(await lifecycle.countExactOwnedForLifecycle()).toMatchObject({ secrets: 1, pendingSecrets: 1 });
    await expect(purger.purgeExactOwnedForLifecycle()).resolves.toMatchObject({
      deletedSubscriptions: 0,
      deletedTriggerSecrets: 1,
    });
    await expect(runtime.connectionStore.delete("slackbot", "trigger")).resolves.toBeUndefined();
  });
  it("runs the native provider Source through private authority and real stores, and revocation denies persisted request-key replay", async () => {
    const { runtime, scope, record } = await fixture();
    const catalog = createCatalogStore([
      {
        service: "slackbot",
        displayName: "Slack",
        categories: [],
        authTypes: ["oauth2"],
        auth: [
          {
            type: "oauth2",
            authorizationUrl: "https://slack.com/oauth/v2/authorize",
            tokenUrl: "https://slack.com/api/oauth.v2.access",
            scopes: [],
            tokenEndpointAuthMethod: "client_secret_post",
          },
        ],
        actions: [],
        triggers: [slackBotEvents.snapshot],
      },
    ]);
    const providerLoader = new ProviderLoader({
      slackbot: async () => ({
        executors: {},
        triggers: [slackBotEvents],
        proxy: async () => {
          throw new Error("Unexpected network");
        },
      }),
    });
    const connections = new ConnectionService({
      catalog,
      providerLoader,
      store: runtime.connectionStore,
      oauthCredentials: {
        async refresh(_provider, value) {
          return value;
        },
      },
    });
    const capability = `trigger:${slackBotEvents.snapshot.key}`;
    const input = {
      operation: "sourceReference",
      request: {
        action: "create",
        deploymentId: "deployment",
        requestKey: "native-source",
        input: {
          appId: "A0APP",
          workspaceId: "T0TEAM",
          signingSecret: "private-native-signing",
          eventTypes: ["app_mention"],
        },
      },
    };
    const authorized = {
      ...scope,
      purpose: "action:execute:v2" as const,
      permissions: ["action:execute:v2"],
      actionId: capability,
      requestHash: canonicalActionRequestHash(capability, record.connectionId, input),
      maxOutputBytes: 65536,
    };
    const policy = new PostgresActionPolicyStore(db.pool, catalog);
    const principal = {
      subjectKind: "policy_control" as const,
      subject: "real-operator",
      purpose: "action-policy:write" as const,
      permissions: ["action-policy:write"],
      target: {
        kind: "user" as const,
        tenantId: scope.tenantId,
        workspaceId: scope.workspaceId,
        userId: scope.actorUserId,
      },
      requestId: randomUUID(),
      requestHash: "a".repeat(43),
    };
    await policy.applyForControl(principal, {
      actionIds: [capability],
      enabled: true,
      reason: "Reviewed test trigger",
    });
    const store = new PostgresTriggerStore(db.pool, authorized, db.codec);
    const runner = new SaasTriggerRunner({
      scope: authorized,
      catalog,
      actionPolicy: policy,
      connectionStore: runtime.connectionStore,
      store,
      runner: new TriggerRunner({ catalog, providerLoader, connections, store }),
    });
    const request = {
      service: "slackbot",
      triggerId: slackBotEvents.snapshot.key,
      connectorConnectionId: record.connectionId,
      input,
    };
    const first = await runner.run(request);
    expect(first).toMatchObject({ source: { revision: 1 } });
    expect(JSON.stringify(first)).not.toContain("private-native-signing");
    expect(await runner.run(request)).toEqual(first);
    await policy.applyForControl(principal, {
      actionIds: [capability],
      enabled: false,
      reason: "Revoked before replay",
    });
    await expect(runner.run(request)).rejects.toMatchObject({ code: "action_not_granted" });
    const lifecycle = new PostgresTriggerStore(
      db.pool,
      { ...scope, purpose: "lifecycle:read", permissions: ["lifecycle:read"] },
      db.codec,
    );
    expect((await lifecycle.listExactOwnedForLifecycle(undefined, 100)).sourceApplications).toMatchObject([
      { revision: 1 },
    ]);
  });

  it.each([false, true, "unavailable"] as const)(
    "rechecks current actor policy at durable admission after paused metadata (common allow: %s)",
    async (common) => {
      const { runtime, scope, record } = await fixture();
      await runtime.connectionStore.updateVisibilityById(record.connectionId, "workspace");
      const catalog = createCatalogStore([
        {
          service: "slackbot",
          displayName: "Slack",
          categories: [],
          authTypes: ["oauth2"],
          auth: [],
          actions: [],
          triggers: [slackBotEvents.snapshot],
        },
      ]);
      const capability = `trigger:${record.triggerId}`,
        bob = randomUUID();
      const input = {
        operation: "sourceReference",
        request: {
          action: "create",
          deploymentId: "deployment",
          requestKey: "paused-source",
          input: {
            appId: "A0APP",
            workspaceId: "T0TEAM",
            signingSecret: "private-paused-source",
            eventTypes: ["app_mention"],
          },
        },
      };
      const authorized = {
        ...scope,
        actorUserId: bob,
        workspaceRole: "member" as const,
        purpose: "action:execute:v2" as const,
        permissions: ["action:execute:v2"],
        actionId: capability,
        requestHash: canonicalActionRequestHash(capability, record.connectionId, input),
        maxOutputBytes: 65536,
      };
      let unavailable = false,
        nativeCalls = 0;
      const policy = new PostgresActionPolicyStore(
        {
          connect: () => {
            if (unavailable) throw new Error("Policy database unavailable");
            return db.pool.connect();
          },
        } as typeof db.pool,
        catalog,
      );
      const principal = {
        subjectKind: "policy_control" as const,
        subject: "real-operator",
        purpose: "action-policy:write" as const,
        permissions: ["action-policy:write"],
        target: { kind: "user" as const, tenantId: scope.tenantId, workspaceId: scope.workspaceId, userId: bob },
        requestId: randomUUID(),
        requestHash: "a".repeat(43),
      };
      await policy.applyForControl(
        { ...principal, target: { kind: "platform" } },
        { actionIds: [capability], enabled: common === true, reason: "Reviewed common trigger rule" },
      );
      if (common !== true)
        await policy.applyForControl(principal, {
          actionIds: [capability],
          enabled: true,
          reason: "Reviewed individual trigger rule",
        });
      const store = new PostgresTriggerStore(db.pool, authorized, db.codec);
      const providerLoader = new ProviderLoader({
        slackbot: async () => ({
          executors: {},
          triggers: [slackBotEvents],
          proxy: async () => {
            throw new Error("Unexpected provider network");
          },
        }),
      });
      const connections = new ConnectionService({
        catalog,
        providerLoader,
        store: runtime.connectionStore,
        oauthCredentials: {
          async refresh(_provider, value) {
            return value;
          },
        },
      });
      const native = new TriggerRunner({ catalog, providerLoader, connections, store });
      const { promise: paused, resolve: pause } = Promise.withResolvers<void>(),
        { promise: resumed, resolve: resume } = Promise.withResolvers<void>();
      const runner = new SaasTriggerRunner({
        scope: authorized,
        catalog,
        actionPolicy: policy,
        store,
        connectionStore: {
          async getSafeConnection(id) {
            const current = await runtime.connectionStore.getSafeConnection(id);
            pause();
            await resumed;
            return current;
          },
        },
        runner: {
          async run(request) {
            nativeCalls++;
            return native.run(request);
          },
        },
      });
      const operation = runner
        .run({ service: "slackbot", triggerId: record.triggerId, connectorConnectionId: record.connectionId, input })
        .then(
          (value) => ({ value, error: undefined }),
          (error) => ({ value: undefined, error }),
        );
      await paused;
      const lifecycle = new PostgresTriggerStore(
        db.pool,
        { ...authorized, subjectUserId: bob, purpose: "lifecycle:delete", permissions: ["lifecycle:delete"] },
        db.codec,
      );
      try {
        if (common === "unavailable") unavailable = true;
        else {
          await policy.applyForControl(principal, {
            actionIds: [capability],
            enabled: false,
            reason: "Explicit actor revoke before admission",
          });
          await lifecycle.cleanupExactOwnedForLifecycle(async () => {
            throw new Error("No native state should exist before admission");
          });
          await lifecycle.purgeExactOwnedForLifecycle();
        }
      } finally {
        resume();
      }
      const result = await operation;
      expect(result.error).toMatchObject({
        code: common === "unavailable" ? "action_policy_unavailable" : "action_not_granted",
      });
      expect(nativeCalls).toBe(0);
      const counts = await lifecycle.countExactOwnedForLifecycle();
      expect(counts.sourceApplications).toBe(0);
      expect(counts.executionLeases).toBe(0);
      expect((await runtime.connectionStore.getSafeConnection(record.connectionId))?.visibility).toBe("workspace");
      const row = await withScopedClient(
        db.pool,
        scope,
        async (client) =>
          (
            await client.query("SELECT trigger_cleanup_fenced FROM integration_runtime.connections WHERE id=$1", [
              record.connectionId,
            ])
          ).rows[0],
      );
      expect(row.trigger_cleanup_fenced).toBe(false);
    },
  );

  it("guards a real managed account tuple while allowing fresh consent for that same verified account", async () => {
    const runtime = db.forScope();
    const project = {
      id: randomUUID(),
      projectId: "remote-project",
      baseUrl: "https://source.example",
      apiKey: "private-project-key",
    };
    await runtime.saasProjects.saveProject(project, null);
    const pending = {
      connectionRequestId: randomUUID(),
      connectionId: randomUUID(),
      owner: runtime.scope.subjectUserId,
      service: "slackbot",
      connectionName: "managed",
      managedProjectId: project.id,
      providerConfigId: "config",
      externalUserId: runtime.saasProjects.externalUserId(),
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600000).toISOString(),
    };
    const lease = await runtime.connectionRequests.createSaas(pending);
    await runtime.connectionRequests.saveSaasRequest(lease, "remote-request");
    await runtime.connectionRequests.saveSaasCandidate(lease, {
      connectedAccountId: "remote-account",
      profile: credential.profile,
      status: "active",
      comment: null,
    });
    expect(await runtime.connectionRequests.completeSaas(lease)).toBe("connected");
    const store = new PostgresTriggerStore(db.pool, runtime.scope, db.codec);
    await store.insertFlowTrigger({
      id: randomUUID(),
      ownerId: scopedTriggerOwner(runtime.scope),
      mode: "webhook",
      service: "slackbot",
      connectionId: pending.connectionId,
      connectionRevision: "native",
      providerAccountId: "remote-account",
      triggerId: slackBotEvents.snapshot.key,
      requestKey: "managed",
      config: {},
      endpointUrl: "https://host.example/callback",
      callbackNonce: "nonce",
      callbackSecret: "private",
      checkpoint: null,
      subscription: {},
      reconcileAt: 0,
      status: "active",
    });
    await withScopedClient(db.pool, runtime.scope, (client) =>
      client.query(
        `UPDATE integration_runtime.connections SET source_reference=jsonb_set(source_reference,'{localRequestId}',to_jsonb($2::text)) WHERE id=$1`,
        [pending.connectionId, randomUUID()],
      ),
    );
    await expect(
      withScopedClient(db.pool, runtime.scope, (client) =>
        client.query(
          `UPDATE integration_runtime.connections SET source_reference=jsonb_set(source_reference,'{connectedAccountId}','"replacement"') WHERE id=$1`,
          [pending.connectionId],
        ),
      ),
    ).rejects.toThrow();
  });
  it("keeps a physical provider resource until both authorized actors release their own private consumers", async () => {
    const { runtime, scope, record } = await fixture();
    await runtime.connectionStore.updateVisibilityById(record.connectionId, "workspace");
    const other = { ...scope, actorUserId: randomUUID() };
    const storeA = new PostgresTriggerStore(db.pool, scope, db.codec),
      storeB = new PostgresTriggerStore(db.pool, other, db.codec);
    const owner = {
      ownerId: scopedTriggerOwner(scope),
      service: record.service,
      triggerId: record.triggerId,
      connectionId: record.connectionId,
      connectionRevision: record.connectionRevision,
      providerAccountId: record.providerAccountId,
    };
    let physical = false,
      unsubscribes = 0;
    const proxy: ConnectorProxy = {
      providerAccountId: "U0BOT",
      async execute(request) {
        if (request.method === "POST") physical = true;
        else {
          physical = false;
          unsubscribes++;
        }
        return { status: 200, data: {} };
      },
    };
    const definition: ResourceDefinition = {
      subscriptions: () => [
        {
          key: "one-physical-resource",
          subscribe: { method: "POST", endpoint: "/subscription" },
          unsubscribe: { method: "DELETE", endpoint: "/subscription" },
        },
      ],
      response: () => ({}),
    };
    const request = { operation: "resource" as const, config: {}, requestKey: "consumer", active: true },
      signal = new AbortController().signal;
    await executeResourceSubscription(storeA, definition, owner, request, proxy, signal);
    await executeResourceSubscription(
      storeB,
      definition,
      { ...owner, ownerId: scopedTriggerOwner(other) },
      request,
      proxy,
      signal,
    );
    expect(physical).toBe(true);
    await executeResourceSubscription(storeA, definition, owner, { ...request, active: false }, proxy, signal);
    expect(physical).toBe(true);
    expect(unsubscribes).toBe(0);
    await executeResourceSubscription(
      storeB,
      definition,
      { ...owner, ownerId: scopedTriggerOwner(other) },
      { ...request, active: false },
      proxy,
      signal,
    );
    expect(physical).toBe(false);
    expect(unsubscribes).toBe(1);
  });
  it("admits more native callbacks than pool clients without starving their independently durable saves", async () => {
    const { scope, record } = await fixture();
    const policy = new PostgresActionPolicyStore(db.pool, triggerCatalog);
    await policy.applyForControl(
      {
        subjectKind: "policy_control",
        subject: "real-operator",
        purpose: "action-policy:write",
        permissions: ["action-policy:write"],
        target: { kind: "user", tenantId: scope.tenantId, workspaceId: scope.workspaceId, userId: scope.actorUserId },
        requestId: randomUUID(),
        requestHash: "a".repeat(43),
      },
      { actionIds: [`trigger:${record.triggerId}`], enabled: true, reason: "Reviewed concurrent native admission" },
    );
    const executing = {
      ...scope,
      purpose: "action:execute:v2" as const,
      permissions: ["action:execute:v2"],
      actionId: `trigger:${record.triggerId}`,
    };
    const store = new PostgresTriggerStore(db.pool, executing, db.codec);
    let started = 0;
    const { promise: barrier, resolve: release } = Promise.withResolvers<void>();
    const operations = [0, 1, 2].map((index) =>
      store.withConnectionForExecution(record.service, record.connectionId, policy, async () => {
        if (++started === 3) release();
        await barrier;
        await store.insertFlowTrigger({ ...record, id: randomUUID(), requestKey: `parallel-${index}` });
        return index;
      }),
    );
    await expect(Promise.all(operations)).resolves.toEqual([0, 1, 2]);
    const lifecycle = new PostgresTriggerStore(
      db.pool,
      { ...scope, purpose: "lifecycle:delete", permissions: ["lifecycle:delete"] },
      db.codec,
    );
    const counts = await lifecycle.countExactOwnedForLifecycle();
    expect(counts.subscriptions.total).toBe(3);
    expect(counts.executionLeases).toBe(0);
  });

  it("allows an exclusive lifecycle observation during native work while durable admission still protects the actual account", async () => {
    const { runtime, scope, record } = await fixture();
    const policy = new PostgresActionPolicyStore(db.pool, triggerCatalog);
    await policy.applyForControl(
      {
        subjectKind: "policy_control",
        subject: "real-operator",
        purpose: "action-policy:write",
        permissions: ["action-policy:write"],
        target: { kind: "user", tenantId: scope.tenantId, workspaceId: scope.workspaceId, userId: scope.actorUserId },
        requestId: randomUUID(),
        requestHash: "a".repeat(43),
      },
      { actionIds: [`trigger:${record.triggerId}`], enabled: true, reason: "Reviewed durable native admission" },
    );
    const executing = {
      ...scope,
      purpose: "action:execute:v2" as const,
      permissions: ["action:execute:v2"],
      actionId: `trigger:${record.triggerId}`,
    };
    const store = new PostgresTriggerStore(db.pool, executing, db.codec);
    const { promise: admitted, resolve: started } = Promise.withResolvers<void>();
    const { promise: continueWork, resolve: release } = Promise.withResolvers<void>();
    const operation = store.withConnectionForExecution(record.service, record.connectionId, policy, async () => {
      started();
      await continueWork;
      await store.insertFlowTrigger(record);
    });
    await admitted;
    const lifecycle = new PostgresTriggerStore(
      db.pool,
      { ...scope, purpose: "lifecycle:delete", permissions: ["lifecycle:delete"] },
      db.codec,
    );
    try {
      expect((await lifecycle.countExactOwnedForLifecycle()).pendingExecutions).toBe(1);
      const current = await runtime.connectionStore.getById(record.connectionId);
      if (!current || current.source === "saas") throw new Error("Missing native connection");
      await expect(
        runtime.connectionStore.updateCredential({
          ...current,
          credential: { ...credential, profile: { ...credential.profile, accountId: "replacement" } },
        }),
      ).rejects.toThrow();
      await expect(runtime.connectionStore.delete("slackbot", "trigger")).rejects.toThrow();
    } finally {
      release();
    }
    await operation;
    expect((await lifecycle.countExactOwnedForLifecycle()).executionLeases).toBe(0);
  });

  it("does not retain native admission beyond the request's remaining hard processing budget", async () => {
    const { scope, record } = await fixture();
    const policy = new PostgresActionPolicyStore(db.pool, triggerCatalog);
    await policy.applyForControl(
      {
        subjectKind: "policy_control",
        subject: "real-operator",
        purpose: "action-policy:write",
        permissions: ["action-policy:write"],
        target: { kind: "user", tenantId: scope.tenantId, workspaceId: scope.workspaceId, userId: scope.actorUserId },
        requestId: randomUUID(),
        requestHash: "a".repeat(43),
      },
      { actionIds: [`trigger:${record.triggerId}`], enabled: true, reason: "Reviewed bounded native admission" },
    );
    const executing = {
      ...scope,
      purpose: "action:execute:v2" as const,
      permissions: ["action:execute:v2"],
      actionId: `trigger:${record.triggerId}`,
      processingDeadlineMs: Date.now() + 5000,
    };
    const store = new PostgresTriggerStore(db.pool, executing, db.codec);
    await store.withConnectionForExecution(record.service, record.connectionId, policy, async () => {
      const lease = await withScopedClient(
        db.pool,
        executing,
        async (client) =>
          (
            await client.query<{ budget_ms: number }>(
              "SELECT extract(epoch FROM (lease_until-created_at))*1000 AS budget_ms FROM integration_runtime.trigger_execution_leases WHERE connection_id=$1",
              [record.connectionId],
            )
          ).rows[0]!,
      );
      expect(Number(lease.budget_ms)).toBeGreaterThan(0);
      expect(Number(lease.budget_ms)).toBeLessThanOrEqual(5000);
    });
  });

  it("commits actor authorization and the lease before a queued lifecycle writer without starving the native save", async () => {
    const { scope, record } = await fixture();
    const policy = new PostgresActionPolicyStore(db.pool, triggerCatalog);
    await policy.applyForControl(
      {
        subjectKind: "policy_control",
        subject: "real-operator",
        purpose: "action-policy:write",
        permissions: ["action-policy:write"],
        target: { kind: "user", tenantId: scope.tenantId, workspaceId: scope.workspaceId, userId: scope.actorUserId },
        requestId: randomUUID(),
        requestHash: "a".repeat(43),
      },
      {
        actionIds: [`trigger:${record.triggerId}`],
        enabled: true,
        reason: "Reviewed admission before lifecycle boundary",
      },
    );
    const executing = {
      ...scope,
      purpose: "action:execute:v2" as const,
      permissions: ["action:execute:v2"],
      actionId: `trigger:${record.triggerId}`,
    };
    const store = new PostgresTriggerStore(db.pool, executing, db.codec);
    const { promise: held, resolve: hold } = Promise.withResolvers<PoolClient>(),
      { promise: released, resolve: release } = Promise.withResolvers<void>();
    const admissionPolicy: Pick<PostgresActionPolicyStore, "withEffectiveForActor"> = {
      async withEffectiveForActor(requestScope, ids, admit) {
        return policy.withEffectiveForActor(requestScope, ids, async (decisions, client) => {
          hold(client);
          await released;
          return admit(decisions, client);
        });
      },
    };
    const operation = store.withConnectionForExecution(
      record.service,
      record.connectionId,
      admissionPolicy,
      async () => {
        await store.insertFlowTrigger(record);
      },
    );
    const client = await held;
    const lifecycleScope = { ...scope, purpose: "lifecycle:delete" as const, permissions: ["lifecycle:delete"] };
    const writer = withScopedClient(
      db.pool,
      lifecycleScope,
      async (writerClient) =>
        (
          await writerClient.query(
            `SELECT count(*)::int AS count FROM integration_runtime.trigger_execution_leases WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3`,
            [scope.tenantId, scope.workspaceId, scope.actorUserId],
          )
        ).rows[0].count,
    );
    try {
      let queued = false;
      while (!queued)
        queued = (
          await client.query(
            `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())) AS queued`,
          )
        ).rows[0].queued;
    } finally {
      release();
    }
    expect(await writer).toBe(1);
    await operation;
    const lifecycle = new PostgresTriggerStore(db.pool, lifecycleScope, db.codec);
    const counts = await lifecycle.countExactOwnedForLifecycle();
    expect(counts.subscriptions.total).toBe(1);
    expect(counts.executionLeases).toBe(0);
  });
});
