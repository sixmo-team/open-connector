import type {
  ActionPolicyControlPrincipal,
  ActionPolicyUserTarget,
  NativeLifecycleServicePrincipal,
} from "../contracts.ts";
import type { PostgresConnectionStore } from "../storage/postgres-connection-store.ts";

import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { withActionPolicyClient, withScopedClient } from "../storage/scoped-query.ts";
import { createNativePostgresHarness } from "../testing/native-store-fixtures.ts";

const harness = createNativePostgresHarness();
async function seedPolicy(target: ActionPolicyUserTarget): Promise<void> {
  const principal: ActionPolicyControlPrincipal = {
    subjectKind: "policy_control",
    subject: "operator:actual",
    purpose: "action-policy:write",
    permissions: ["action-policy:write"],
    target,
    requestId: randomUUID(),
    requestHash: "a".repeat(43),
  };
  await withActionPolicyClient(harness.pool, principal, async (client) => {
    await client.query(
      `INSERT INTO integration_runtime.action_grants (id,tenant_id,workspace_id,user_id,action_id,enabled,created_by_subject,updated_by_subject) VALUES ($1,$2,$3,$4,'example.read',false,'operator:actual','operator:actual')`,
      [randomUUID(), target.tenantId, target.workspaceId, target.userId],
    );
  });
}

describe.skipIf(!harness.enabled)("actual owned policy lifecycle", () => {
  it("exports personal permission data when that user has no connections or runs", async () => {
    const runtime = harness.forScope({ purpose: "lifecycle:read", permissions: ["lifecycle:read"] });
    const target: ActionPolicyUserTarget = {
      kind: "user",
      tenantId: runtime.scope.tenantId,
      workspaceId: runtime.scope.workspaceId,
      userId: runtime.scope.subjectUserId,
    };
    await seedPolicy(target);
    const page = await harness.factory.lifecycleForScope(runtime.scope).exportPage({ limit: 1 });
    expect(page.actionGrants).toEqual([
      expect.objectContaining({
        actionId: "example.read",
        enabled: false,
        tenantId: target.tenantId,
        workspaceId: target.workspaceId,
        userId: target.userId,
      }),
    ]);
    expect(page.counts.actionGrants).toBe(1);
    expect(page.connections).toEqual([]);
    expect(page.runs).toEqual([]);
  });

  it("refuses full resource deletion until the dedicated permission owner purge is complete", async () => {
    const runtime = harness.forScope({ purpose: "connection:write", permissions: ["connection:write"] });
    const connection = await runtime.connectionStore.set("public_data", "owned-public", { authType: "no_auth" });
    const target: ActionPolicyUserTarget = {
      kind: "user",
      tenantId: runtime.scope.tenantId,
      workspaceId: runtime.scope.workspaceId,
      userId: runtime.scope.subjectUserId,
    };
    await seedPolicy(target);
    const deletionScope = { ...runtime.scope, purpose: "lifecycle:delete" as const, permissions: ["lifecycle:delete"] };
    await expect(
      harness.factory
        .lifecycleForScope(deletionScope)
        .purge({ correlationId: randomUUID() }, new AbortController().signal),
    ).rejects.toMatchObject({ code: "LIFECYCLE_RECONCILIATION_REQUIRED" });
    expect(await runtime.connectionStore.getSafeConnection(connection.id)).toMatchObject({
      id: connection.id,
      status: "active",
      subjectUserId: target.userId,
    });
  });

  it("prepares managed and local credential ownership for exact scoped purge", async () => {
    const runtime = harness.forScope({ purpose: "connection:write", permissions: ["connection:write"] });
    const local = await runtime.connectionStore.set("public_data", "local-owned", { authType: "no_auth" });
    const projectId = randomUUID();
    await runtime.saasProjects.saveProject({
      id: projectId,
      projectId: randomUUID(),
      baseUrl: "https://saas.example",
      apiKey: "private-test-key",
    });
    const managedId = randomUUID();
    await withScopedClient(harness.pool, runtime.scope, (client) =>
      client.query(
        `INSERT INTO integration_runtime.connections
          (id,tenant_id,workspace_id,subject_user_id,local_connection_id,service,connection_name,auth_type,revision,
           secret_ref,secret_revision,status,credential_profile,source,source_reference,source_status)
         VALUES ($1,$2,$3,$4,$5,'example','managed-owned','oauth2',$6,'managed-source',0,'active',$7,'saas',$8,'active')`,
        [
          managedId,
          runtime.scope.tenantId,
          runtime.scope.workspaceId,
          runtime.scope.subjectUserId,
          randomUUID(),
          randomUUID(),
          { authType: "oauth2", scopes: ["read"] },
          {
            managedProjectId: projectId,
            providerConfigId: "config",
            externalUserId: runtime.saasProjects.externalUserId(),
            connectedAccountId: "account",
          },
        ],
      ),
    );
    const deletion = harness.forScope({
      ...runtime.scope,
      purpose: "lifecycle:delete",
      permissions: ["lifecycle:delete"],
    });
    const connections = await (deletion.connectionStore as PostgresConnectionStore).prepareExactOwnedForLifecyclePurge(
      randomUUID(),
    );
    expect(connections.find(({ id }) => id === managedId)).toMatchObject({ id: managedId, service: "example" });
    expect(connections.find(({ id }) => id === managedId)?.credential).toBeUndefined();
    expect(connections.find(({ id }) => id === local.id)?.credential).toEqual({ authType: "no_auth" });
  });

  it("discovers retirement-only owners without another tenant and binds inventory cursors to its target", async () => {
    const first = harness.forScope();
    const secondUserId = randomUUID();
    const second = harness.forScope({
      tenantId: first.scope.tenantId,
      workspaceId: first.scope.workspaceId,
      actorUserId: secondUserId,
      subjectUserId: secondUserId,
    });
    const other = harness.forScope();
    await first.connectionStore.getRetirementGeneration("example", "first-retired");
    await second.connectionStore.getRetirementGeneration("example", "second-retired");
    await other.connectionStore.getRetirementGeneration("example", "other-retired");
    const principal: NativeLifecycleServicePrincipal = {
      subjectKind: "service",
      subject: "native-lifecycle-test",
      purpose: "lifecycle:subjects",
      permissions: ["lifecycle:subjects"],
      requestId: randomUUID(),
      target: { kind: "workspace", tenantId: first.scope.tenantId, workspaceId: first.scope.workspaceId },
    };
    const page = await harness.factory.nativeLifecycleInventory.listSubjects(principal, { limit: 1 });
    expect(page.items).toHaveLength(1);
    expect(page.nextCursor).not.toBeNull();
    const last = await harness.factory.nativeLifecycleInventory.listSubjects(principal, {
      cursor: page.nextCursor!,
      limit: 1,
    });
    expect([...page.items, ...last.items].map((target) => target.userId).sort()).toEqual(
      [first.scope.subjectUserId, secondUserId].sort(),
    );
    expect(last.nextCursor).toBeNull();
    await expect(
      harness.factory.nativeLifecycleInventory.listSubjects(
        {
          ...principal,
          target: { kind: "workspace", tenantId: other.scope.tenantId, workspaceId: other.scope.workspaceId },
        },
        { cursor: page.nextCursor!, limit: 1 },
      ),
    ).rejects.toThrow("Invalid scoped cursor");
  });
});
