import type { ResourceDefinition } from "../../triggers/common/integration.ts";
import type { ConnectorProxy } from "../../triggers/common/proxy.ts";
import type { SaasRequestScope } from "../contracts.ts";

import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { describe, expect, it } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import { ConnectionService } from "../../connection-service.ts";
import { ProviderLoader } from "../../providers/provider-loader.ts";
import { slackBotEvents } from "../../providers/slackbot/trigger-on-event.ts";
import { TriggerMaintenance } from "../../triggers/maintenance.ts";
import { executeResourceSubscription } from "../../triggers/resources.ts";
import { executePersistentSource } from "../../triggers/sources/persistent.ts";
import { subscriptionId, withSubscription } from "../../triggers/subscriptions.ts";
import { TriggerRunner } from "../../triggers/trigger-runner.ts";
import { PostgresActionPolicyStore } from "../storage/postgres-action-policy-store.ts";
import { PostgresConnectionStore } from "../storage/postgres-connection-store.ts";
import { withScopedClient } from "../storage/scoped-query.ts";
import { createNativePostgresHarness, MemoryConnectionSecrets } from "../testing/native-store-fixtures.ts";
import { PostgresTriggerStore, scopedTriggerOwner } from "./postgres-trigger-store.ts";
import { triggerCapability } from "./trigger-capability.ts";

const db = createNativePostgresHarness();
const credential = {
  authType: "oauth2" as const,
  accessToken: "actual-alice-secret",
  tokenType: "Bearer",
  profile: { accountId: "U0BOT", displayName: "Bot", grantedScopes: [] },
  metadata: { providerAccountVerified: true },
};
async function fixture() {
  const alice = db.forScope().scope,
    bob = randomUUID(),
    carol = randomUUID();
  const readSubjects: string[] = [];
  class TrackingSecrets extends MemoryConnectionSecrets {
    override async read(scope: Readonly<SaasRequestScope>, id: string, revision: number) {
      readSubjects.push(scope.subjectUserId);
      return super.read(scope, id, revision);
    }
  }
  const secrets = new TrackingSecrets(),
    connections = new PostgresConnectionStore(db.pool, alice, secrets);
  const connection = await connections.set("slackbot", "shared", credential);
  await connections.updateVisibilityById(connection.id, "workspace");
  let physical = false,
    unsubscribes = 0,
    subscribes = 0,
    failRemove = false;
  const resources: ResourceDefinition = {
    subscriptions: () => [
      {
        key: "physical",
        subscribe: { method: "POST", endpoint: "/subscription" },
        unsubscribe: { method: "DELETE", endpoint: "/subscription" },
      },
    ],
    response: () => ({}),
  };
  const proxy: ConnectorProxy = {
    providerAccountId: "U0BOT",
    async execute(request) {
      if (request.method === "POST") {
        physical = true;
        subscribes++;
      } else {
        if (failRemove) throw new Error("Actual provider cleanup unavailable");
        physical = false;
        unsubscribes++;
      }
      return { status: 200, data: {} };
    },
  };
  const definition = { ...slackBotEvents, resources };
  const catalog = createCatalogStore([
    {
      service: "slackbot",
      displayName: "Slack",
      categories: [],
      authTypes: ["oauth2"],
      auth: [],
      actions: [],
      triggers: [definition.snapshot],
    },
  ]);
  const providerLoader = new ProviderLoader({
    slackbot: async () => ({
      executors: {},
      triggers: [definition],
      proxy: async (request, context) => {
        const actual = await context.getCredential("slackbot");
        if (actual?.authType !== "oauth2" || actual.accessToken !== "actual-alice-secret")
          throw new Error("Wrong actual cleanup credential");
        const response = await proxy.execute({ method: request.method as "DELETE", endpoint: request.endpoint });
        return { ok: true, response: { ...response, headers: {} } };
      },
    }),
  });
  const actor = async (user: string) => {
    const scope = { ...alice, actorUserId: user, connectorConnectionId: connection.id };
    const store = new PostgresTriggerStore(db.pool, scope, db.codec);
    const owner = {
      ownerId: scopedTriggerOwner(scope),
      service: "slackbot",
      triggerId: definition.snapshot.key,
      connectionId: connection.id,
      connectionRevision: connection.revision,
      providerAccountId: "U0BOT",
    };
    const request = { operation: "resource" as const, config: {}, requestKey: "consumer", active: true };
    await executeResourceSubscription(store, resources, owner, request, proxy, new AbortController().signal);
    const source = await executePersistentSource(
      store,
      slackBotEvents,
      { scope: owner.ownerId, connectionId: connection.id },
      {
        action: "create",
        deploymentId: "deployment",
        requestKey: "private-source",
        input: {
          appId: "A0APP",
          workspaceId: "T0TEAM",
          signingSecret: `private-source-${user}`,
          eventTypes: ["app_mention"],
        },
      },
      proxy,
      new AbortController().signal,
    );
    return { scope, store, id: await subscriptionId(owner, request.requestKey), source };
  };
  const bobState = await actor(bob),
    carolState = await actor(carol);
  const lifecycle = (user: string, maintenance = false) => {
    const scope: SaasRequestScope = {
      tenantId: alice.tenantId,
      workspaceId: alice.workspaceId,
      actorUserId: user,
      subjectUserId: user,
      workspaceRole: "member",
      purpose: maintenance ? ("maintenance:run" as SaasRequestScope["purpose"]) : "lifecycle:delete",
      permissions: [maintenance ? "maintenance:run" : "lifecycle:delete"],
    };
    const store = new PostgresTriggerStore(db.pool, scope, db.codec),
      ownConnections = new PostgresConnectionStore(db.pool, scope, secrets);
    const native = new TriggerRunner({
      catalog,
      providerLoader,
      store,
      connections: new ConnectionService({
        catalog,
        providerLoader,
        store: ownConnections,
        oauthCredentials: {
          async refresh(_provider, value) {
            return value;
          },
        },
      }),
      cleanupConnection: (record) => store.getCleanupConnection(record, secrets),
    });
    return {
      scope,
      store,
      ownConnections,
      native,
      cleanup: () =>
        store.cleanupExactOwnedForLifecycle((record, save, signal) => native.cleanup(record, save, signal)),
    };
  };
  return {
    alice,
    bob,
    carol,
    bobState,
    carolState,
    connections,
    connection,
    lifecycle,
    catalog,
    policy: new PostgresActionPolicyStore(db.pool, catalog),
    readSubjects,
    physical: () => physical,
    unsubscribes: () => unsubscribes,
    subscribes: () => subscribes,
    failRemove(value: boolean) {
      failRemove = value;
    },
  };
}

describe.skipIf(!db.enabled)("actual actor data ownership on another customer credential", () => {
  it("cleanup never recreates an uncertain shared physical resource for another remaining consumer", async () => {
    const f = await fixture();
    const group = await withScopedClient(
      db.pool,
      f.alice,
      async (client) =>
        (await client.query("SELECT id FROM integration_runtime.trigger_subscriptions WHERE mode='resource-set'"))
          .rows[0].id as string,
    );
    await withSubscription(f.bobState.store, group, new AbortController().signal, async (record, save) => {
      record.subscription = { ...record.subscription, ready: false, attempted: true };
      await save();
    });
    const before = f.subscribes();
    const bob = f.lifecycle(f.bob);
    await new TriggerMaintenance({ store: bob.store, runner: bob.native, mayContinue: async () => false }).cancel(
      f.bobState.id,
      new AbortController().signal,
    );
    expect(f.subscribes()).toBe(before);
    expect(await f.carolState.store.getFlowTrigger(f.carolState.id)).toMatchObject({ status: "active" });
  });
  it("fresh maintenance removes a revoked actor reference without impersonating the shared credential owner", async () => {
    const f = await fixture();
    const capability = triggerCapability(f.catalog, "slackbot", slackBotEvents.snapshot.key);
    const target = (userId: string) => ({
      kind: "user" as const,
      tenantId: f.alice.tenantId,
      workspaceId: f.alice.workspaceId,
      userId,
    });
    const control = {
      subjectKind: "policy_control" as const,
      subject: "operator:maintenance-test",
      purpose: "action-policy:write" as const,
      permissions: ["action-policy:write"] as ["action-policy:write"],
      requestId: randomUUID(),
      requestHash: "a".repeat(43),
    };
    for (const user of [f.bob, f.carol])
      await f.policy.applyForControl(
        { ...control, target: target(user) },
        { actionIds: [capability], enabled: true, reason: "Explicit trigger permission" },
      );
    const run = async (user: string) => {
      const owner = f.lifecycle(user, true);
      await new TriggerMaintenance({
        store: owner.store,
        runner: owner.native,
        mayContinue: async (record) => {
          const [decision] = await f.policy.getEffectiveForActor(owner.scope, [capability]);
          return decision?.enabled === true && (await owner.store.hasCurrentConnection(record));
        },
      }).run(new AbortController().signal);
      return owner;
    };
    const carol = await run(f.carol);
    expect(await f.carolState.store.getFlowTrigger(f.carolState.id)).toMatchObject({ status: "active" });
    await f.policy.applyForControl(
      { ...control, target: target(f.bob) },
      { actionIds: [capability], enabled: false, reason: "Revoke only Bob" },
    );
    f.readSubjects.length = 0;
    await run(f.bob);
    expect(await f.bobState.store.getFlowTrigger(f.bobState.id)).toMatchObject({ status: "deleted" });
    expect(await f.carolState.store.getFlowTrigger(f.carolState.id)).toMatchObject({ status: "active" });
    expect(f.physical()).toBe(true);
    expect(f.unsubscribes()).toBe(0);
    expect(new Set(f.readSubjects)).toEqual(new Set([f.bob]));
    const record = (await carol.store.listFlowTriggersForMaintenance(Date.now() + 120_000, 10))[0]!;
    expect(await carol.store.hasCurrentConnection(record)).toBe(true);
    await withScopedClient(db.pool, f.alice, async (client) => {
      await client.query("UPDATE integration_runtime.connections SET trigger_cleanup_fenced=true WHERE id=$1", [
        f.connection.id,
      ]);
    });
    expect(await carol.store.hasCurrentConnection(record)).toBe(false);
    await run(f.carol);
    expect(f.physical()).toBe(false);
    expect(f.unsubscribes()).toBe(1);
    expect(await f.connections.getById(f.connection.id)).toBeDefined();
  });
  it("rechecks common revocation with native actor maintenance but never grants execution admission", async () => {
    const f = await fixture();
    const capability = triggerCapability(f.catalog, "slackbot", slackBotEvents.snapshot.key);
    const control = {
      subjectKind: "policy_control" as const,
      subject: "operator:maintenance-common",
      purpose: "action-policy:write" as const,
      permissions: ["action-policy:write"] as ["action-policy:write"],
      target: { kind: "platform" as const },
      requestId: randomUUID(),
      requestHash: "a".repeat(43),
    };
    await f.policy.applyForControl(control, {
      actionIds: [capability],
      enabled: true,
      reason: "Common trigger permission",
    });
    const bob = f.lifecycle(f.bob, true);
    expect(await f.policy.getEffectiveForActor(bob.scope, [capability])).toMatchObject([{ enabled: true }]);
    await expect(
      f.policy.withEffectiveForActor(bob.scope, [capability], async () => {
        throw new Error("Maintenance reached execution admission");
      }),
    ).rejects.toMatchObject({ status: 403 });
    await f.policy.applyForControl(control, {
      actionIds: [capability],
      enabled: false,
      reason: "Common trigger permission revoked",
    });
    for (const user of [f.bob, f.carol]) {
      const owner = f.lifecycle(user, true);
      await new TriggerMaintenance({
        store: owner.store,
        runner: owner.native,
        mayContinue: async (record) => {
          const [decision] = await f.policy.getEffectiveForActor(owner.scope, [capability]);
          return decision?.enabled === true && (await owner.store.hasCurrentConnection(record));
        },
      }).run(new AbortController().signal);
    }
    expect(f.physical()).toBe(false);
    expect(f.unsubscribes()).toBe(1);
  });
  it("deletes Bob data and decrements Alice physical resource without stopping Carol or borrowing a signed subject", async () => {
    const f = await fixture(),
      bob = f.lifecycle(f.bob);
    expect(await bob.ownConnections.getById(f.connection.id)).toBeUndefined();
    expect((await bob.store.listExactOwnedForLifecycle(undefined, 100)).subscriptions.map((row) => row.id)).toEqual([
      f.bobState.id,
    ]);
    f.readSubjects.length = 0;
    await bob.cleanup();
    expect(f.physical()).toBe(true);
    expect(f.unsubscribes()).toBe(0);
    expect(f.readSubjects.length).toBeGreaterThan(0);
    expect(new Set(f.readSubjects)).toEqual(new Set([f.bob]));
    await expect(bob.store.purgeExactOwnedForLifecycle()).resolves.toMatchObject({
      deletedSubscriptions: 1,
      deletedSourceApplications: 1,
    });
    expect(await f.carolState.store.getFlowTrigger(f.carolState.id)).toMatchObject({ status: "active" });
    expect(await f.connections.getById(f.connection.id)).toBeDefined();
    const fenced = await withScopedClient(
      db.pool,
      f.alice,
      async (client) =>
        (
          await client.query("SELECT trigger_cleanup_fenced FROM integration_runtime.connections WHERE id=$1", [
            f.connection.id,
          ])
        ).rows[0],
    );
    expect(fenced.trigger_cleanup_fenced).toBe(false);
  });
  it("owner deletion tears down all attached actors while their private Source payloads remain actor-owned and stale use is fenced", async () => {
    const f = await fixture(),
      alice = f.lifecycle(f.alice.subjectUserId);
    const before = await alice.store.listExactOwnedForLifecycle(undefined, 100);
    expect(before.sourceApplications).toEqual([]);
    expect(JSON.stringify(before)).not.toContain("private-source");
    expect((await alice.store.countExactOwnedForLifecycle()).requiresCleanup).toBe(true);
    await alice.cleanup();
    expect(f.physical()).toBe(false);
    expect(f.unsubscribes()).toBe(1);
    expect(await f.carolState.store.getFlowTrigger(f.carolState.id)).toBeNull();
    await alice.store.purgeExactOwnedForLifecycle();
    await f.connections.delete("slackbot", "shared");
    const bob = f.lifecycle(f.bob),
      carol = f.lifecycle(f.carol);
    const bobPage = await bob.store.listExactOwnedForLifecycle(undefined, 100);
    expect(bobPage.subscriptions).toEqual([
      { id: f.bobState.id, service: "slackbot", triggerId: slackBotEvents.snapshot.key, status: "deleted" },
    ]);
    expect(bobPage.sourceApplications).toHaveLength(1);
    expect(JSON.stringify(bobPage)).not.toContain(`private-source-${f.carol}`);
    await expect(bob.store.purgeExactOwnedForLifecycle()).resolves.toMatchObject({
      deletedSubscriptions: 1,
      deletedSourceApplications: 1,
    });
    await expect(carol.store.purgeExactOwnedForLifecycle()).resolves.toMatchObject({
      deletedSubscriptions: 1,
      deletedSourceApplications: 1,
    });
  });
  it("reports native maintenance provider failure and retains the same resource for a genuine successful retry", async () => {
    const f = await fixture(),
      bob = f.lifecycle(f.bob),
      carol = f.lifecycle(f.carol),
      signal = new AbortController().signal;
    const bobMaintenance = new TriggerMaintenance({
      store: bob.store,
      runner: bob.native,
      mayContinue: async () => false,
    });
    await bobMaintenance.cancel(f.bobState.id, signal);
    const maintenance = new TriggerMaintenance({
      store: carol.store,
      runner: carol.native,
      mayContinue: async () => false,
    });
    f.failRemove(true);
    await expect(maintenance.run(signal)).rejects.toThrow();
    expect(f.physical()).toBe(true);
    expect((await carol.store.listExactOwnedForLifecycle(undefined, 100)).subscriptions).toMatchObject([
      { status: "deleting" },
    ]);
    f.failRemove(false);
    await maintenance.run(signal);
    expect(f.physical()).toBe(false);
    expect(f.unsubscribes()).toBe(1);
    expect((await carol.store.listExactOwnedForLifecycle(undefined, 100)).subscriptions).toMatchObject([
      { status: "deleted" },
    ]);
  });
  it("purges expired shared credential-owner leases without erasing active or neighboring execution authority", async () => {
    const alice = db.forScope({ purpose: "connection:write", permissions: ["connection:write"] }).scope;
    const secrets = new MemoryConnectionSecrets();
    const bind = async (scope: SaasRequestScope) => {
      const store = new PostgresConnectionStore(db.pool, scope, secrets);
      const connection = await store.set("slackbot", `lease-${scope.subjectUserId}`, credential);
      await store.updateVisibilityById(connection.id, "workspace");
      const executionScope: SaasRequestScope = {
        ...scope,
        connectorConnectionId: connection.id,
        purpose: "action:execute:v2",
        permissions: ["action:execute:v2"],
      };
      return { connection, scope: executionScope };
    };
    const owned = await bind(alice);
    const bobScope = { ...owned.scope, actorUserId: randomUUID() };
    const carol = randomUUID();
    const otherOwner = await bind({
      ...alice,
      actorUserId: carol,
      subjectUserId: carol,
      localConnectionId: randomUUID(),
    });
    const otherWorkspace = await bind({ ...alice, workspaceId: randomUUID(), localConnectionId: randomUUID() });
    const otherTenant = await bind({ ...alice, tenantId: randomUUID(), localConnectionId: randomUUID() });
    const lifecycle: SaasRequestScope = { ...alice, purpose: "lifecycle:delete", permissions: ["lifecycle:delete"] };
    const store = new PostgresTriggerStore(db.pool, lifecycle, db.codec);
    const insertLease = async (scope: SaasRequestScope, connectionId: string, durationMs: number) => {
      const id = randomUUID();
      await withScopedClient(db.pool, scope, (sql) =>
        sql.query(
          `WITH budget AS (SELECT clock_timestamp() AS started)
         INSERT INTO integration_runtime.trigger_execution_leases
          (id,tenant_id,workspace_id,subject_user_id,credential_owner_id,connection_id,local_connection_id,service,capability_id,account_binding,created_at,lease_until)
         SELECT $1,$2,$3,$4,$5,$6,$7,'slackbot','trigger:slackbot.on-event',
          '{"source":"local","providerAccountId":"U0BOT"}',started,started+$8::integer*interval '1 millisecond' FROM budget`,
          [
            id,
            scope.tenantId,
            scope.workspaceId,
            scope.actorUserId,
            scope.subjectUserId,
            connectionId,
            scope.localConnectionId,
            durationMs,
          ],
        ),
      );
      return id;
    };
    const leaseIds = (scope: SaasRequestScope) =>
      withScopedClient(db.pool, scope, async (sql) =>
        (
          await sql.query<{ id: string }>("SELECT id FROM integration_runtime.trigger_execution_leases ORDER BY id")
        ).rows.map((row) => row.id),
      );
    const active = await insertLease(bobScope, owned.connection.id, 60_000);
    await expect(store.purgeExactOwnedForLifecycle()).rejects.toThrow(/execution must drain/);
    expect(await leaseIds(bobScope)).toEqual([active]);
    await withScopedClient(db.pool, bobScope, (sql) =>
      sql.query("DELETE FROM integration_runtime.trigger_execution_leases WHERE id=$1", [active]),
    );
    const expiredShared = await insertLease(bobScope, owned.connection.id, 1_000);
    const expiredOwn = await insertLease(owned.scope, owned.connection.id, 1_000);
    const neighbor = await insertLease(otherOwner.scope, otherOwner.connection.id, 60_000);
    const workspaceNeighbor = await insertLease(otherWorkspace.scope, otherWorkspace.connection.id, 60_000);
    const tenantNeighbor = await insertLease(otherTenant.scope, otherTenant.connection.id, 60_000);
    await delay(1_100);
    expect(await leaseIds(lifecycle)).toEqual([expiredShared, expiredOwn].sort());
    await expect(store.purgeExactOwnedForLifecycle()).resolves.toMatchObject({ deletedExecutionLeases: 2 });
    expect(await leaseIds(lifecycle)).toEqual([]);
    expect(await leaseIds(bobScope)).toEqual([]);
    expect(await leaseIds(otherOwner.scope)).toEqual([neighbor]);
    expect(await leaseIds(otherWorkspace.scope)).toEqual([workspaceNeighbor]);
    expect(await leaseIds(otherTenant.scope)).toEqual([tenantNeighbor]);
    expect(await new PostgresConnectionStore(db.pool, alice, secrets).getById(owned.connection.id)).toBeDefined();
  });
});
