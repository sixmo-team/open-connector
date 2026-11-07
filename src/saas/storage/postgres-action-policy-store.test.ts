import type { ActionPolicyControlPrincipal, SaasRequestScope } from "../contracts.ts";
import type { Pool } from "pg";

import { describe, expect, it, vi } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import { snapshot } from "../../providers/gmail/trigger-on-message-received.definition.ts";
import { createNativePostgresHarness } from "../testing/native-store-fixtures.ts";
import { PostgresActionPolicyStore } from "./postgres-action-policy-store.ts";

const target = {
  kind: "user",
  tenantId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  workspaceId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  userId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
} as const;
const catalog = createCatalogStore([
  {
    service: "example",
    displayName: "Example",
    categories: [],
    authTypes: ["no_auth"],
    auth: [{ type: "no_auth" }],
    actions: [
      {
        id: "example.echo",
        service: "example",
        name: "Echo",
        description: "Echo",
        operationType: "read",
        requiredScopes: [],
        providerPermissions: [],
        inputSchema: {},
        outputSchema: {},
      },
    ],
  },
]);
const principal: ActionPolicyControlPrincipal = {
  subjectKind: "policy_control",
  subject: "real-operator",
  requestId: "request-1",
  purpose: "action-policy:write",
  permissions: ["action-policy:write"],
  target,
  requestHash: "a".repeat(43),
};
const actor: SaasRequestScope = {
  tenantId: target.tenantId,
  workspaceId: target.workspaceId,
  actorUserId: target.userId,
  subjectUserId: target.userId,
  workspaceRole: "owner",
  purpose: "action:search",
  permissions: ["action:search"],
};

describe("PostgresActionPolicyStore trust boundaries", () => {
  it("rejects an invalid entire batch before opening any transaction", async () => {
    const connect = vi.fn();
    const store = new PostgresActionPolicyStore({ connect } as unknown as Pool, catalog);
    for (const actionIds of [["example.echo", "example.unknown"], ["example.*"], ["example.echo", "example.echo"]]) {
      await expect(
        store.applyForControl(principal, { actionIds, enabled: true, reason: "reviewed" }),
      ).rejects.toThrow();
    }
    await expect(
      store.applyForControl(
        { ...principal, target: { kind: "platform" } },
        { actionIds: ["example.echo"], enabled: null, reason: "inherit" },
      ),
    ).rejects.toThrow();
    expect(connect).not.toHaveBeenCalled();
  });
  it("rejects owner execution contexts as policy writers and mismatched search actors", async () => {
    const connect = vi.fn();
    const store = new PostgresActionPolicyStore({ connect } as unknown as Pool, catalog);
    await expect(
      store.applyForControl(actor as unknown as ActionPolicyControlPrincipal, {
        actionIds: ["example.echo"],
        enabled: true,
        reason: "forged",
      }),
    ).rejects.toThrow("forbidden");
    await expect(
      store.getEffectiveForActor({ ...actor, subjectUserId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }, ["example.echo"]),
    ).rejects.toThrow("forbidden");
    expect(connect).not.toHaveBeenCalled();
  });
  it("propagates database unavailability rather than fabricating denial or permission", async () => {
    const store = new PostgresActionPolicyStore(
      {
        connect: async () => {
          throw new Error("database unavailable");
        },
      } as unknown as Pool,
      catalog,
    );
    await expect(store.getEffectiveForActor(actor, ["example.echo"])).rejects.toThrow("database unavailable");
  });
  it("rolls a changed rule back if its audit insert fails", async () => {
    const events: string[] = [];
    const release = vi.fn();
    const store = new PostgresActionPolicyStore(
      {
        connect: async () => ({
          async query(sql: string) {
            events.push(sql);
            if (sql.includes("INSERT INTO integration_runtime.action_policy_audit"))
              throw new Error("audit unavailable");
            return { rows: [], rowCount: sql.includes("INSERT INTO integration_runtime.action_grants") ? 1 : 0 };
          },
          release,
        }),
      } as unknown as Pool,
      catalog,
    );
    await expect(
      store.applyForControl(principal, { actionIds: ["example.echo"], enabled: true, reason: "reviewed" }),
    ).rejects.toThrow("audit unavailable");
    expect(events).toContain("ROLLBACK");
    expect(events).not.toContain("COMMIT");
    expect(release).toHaveBeenCalledOnce();
  });
});

describe("explicit native trigger capabilities", () => {
  const db = createNativePostgresHarness();
  it.skipIf(!db.enabled)(
    "persists and resolves a separately granted declared trigger without granting its ordinary actions",
    async () => {
      const declared = createCatalogStore([
        {
          service: "gmail",
          displayName: "Gmail",
          categories: [],
          authTypes: ["oauth2"],
          auth: [],
          actions: [
            {
              id: "gmail.list_messages",
              service: "gmail",
              name: "List messages",
              description: "",
              operationType: "read",
              requiredScopes: [],
              providerPermissions: [],
              inputSchema: {},
              outputSchema: {},
            },
          ],
          triggers: [snapshot],
        },
      ]);
      const store = new PostgresActionPolicyStore(db.pool, declared);
      const capability = `trigger:${snapshot.key}`;
      await expect(
        store.applyForControl(
          { ...principal, target: { kind: "platform" } },
          {
            actionIds: [capability],
            enabled: true,
            reason: "Explicit reviewed trigger admission",
          },
        ),
      ).resolves.toMatchObject({ updatedCount: 1 });
      const decisions = await store.getEffectiveForActor(actor, [capability, "gmail.list_messages"]);
      expect(decisions.map(({ actionId, enabled }) => ({ actionId, enabled }))).toEqual([
        { actionId: capability, enabled: true },
        { actionId: "gmail.list_messages", enabled: false },
      ]);
      await store.applyForControl(principal, {
        actionIds: [capability],
        enabled: false,
        reason: "Revoke actor trigger",
      });
      await expect(store.getEffectiveForActor(actor, [capability])).resolves.toMatchObject([
        { enabled: false, source: "individual" },
      ]);
      await expect(
        store.applyForControl(principal, {
          actionIds: ["trigger:trigger:gmail.on_message_received"],
          enabled: true,
          reason: "Invalid",
        }),
      ).rejects.toThrow();
      const shared = {
        ...actor,
        subjectUserId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        purpose: "action:execute:v2" as const,
        permissions: ["action:execute:v2"],
      };
      await store.withEffectiveForActor(shared, [capability], async (decisions, client) => {
        expect(decisions).toMatchObject([
          { enabled: false, source: "individual", individualEnabled: false, defaultEnabled: true },
        ]);
        const context = (
          await client.query(`SELECT current_setting('integration.tenant_id') AS tenant,
        current_setting('integration.workspace_id') AS workspace,current_setting('integration.actor_user_id') AS actor,
        current_setting('integration.subject_user_id') AS owner,current_setting('integration.workspace_role') AS role,
        current_setting('integration.purpose') AS purpose,current_setting('integration.principal_kind') AS kind`)
        ).rows[0];
        expect(context).toEqual({
          tenant: target.tenantId,
          workspace: target.workspaceId,
          actor: target.userId,
          owner: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
          role: "owner",
          purpose: "action:execute:v2",
          kind: "user",
        });
      });
    },
  );
});
