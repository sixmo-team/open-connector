import type { SaasRequestScope, ActionPermissionDecision } from "../contracts.ts";
import type { SaasTriggerRunnerOptions } from "./saas-trigger-runner.ts";

import { describe, expect, it } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import { snapshot } from "../../providers/gmail/trigger-on-message-received.definition.ts";
import { canonicalActionRequestHash } from "../actions/canonical-request.ts";
import { SaasTriggerRunner } from "./saas-trigger-runner.ts";

const owner = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const connectionId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const localConnectionId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const capability = "trigger:gmail.on_message_received";
const input = { operation: "read", config: {}, checkpoint: null };
const scope: SaasRequestScope = {
  tenantId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  workspaceId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  actorUserId: owner,
  subjectUserId: owner,
  workspaceRole: "member",
  purpose: "action:execute:v2",
  permissions: ["action:execute:v2"],
  actionId: capability,
  connectorConnectionId: connectionId,
  localConnectionId,
  requestHash: canonicalActionRequestHash(capability, connectionId, input),
  maxOutputBytes: 4096,
};
const catalog = createCatalogStore([
  {
    service: "gmail",
    displayName: "Gmail",
    categories: [],
    authTypes: ["oauth2"],
    auth: [],
    actions: [],
    triggers: [snapshot],
  },
]);
function setup(
  overrides: Partial<SaasRequestScope> = {},
  requestInput: unknown = input,
  nativeOutput: unknown = { checkpoint: "next", events: [{ dedupeKey: "1", payload: { subject: "Hello" } }] },
) {
  let providerReads = 0,
    stateReads = 0,
    enabled = false,
    unavailable = false;
  const safe = {
    id: connectionId,
    localConnectionId,
    subjectUserId: owner,
    visibility: "workspace" as "user" | "workspace",
    status: "active",
    service: "gmail",
    connectionName: "mail",
  };
  const options = {
    scope: { ...scope, ...overrides },
    catalog,
    actionPolicy: {
      async getEffectiveForActor(_scope: SaasRequestScope, ids: string[]): Promise<ActionPermissionDecision[]> {
        if (unavailable) throw new Error("Policy down");
        return ids.map((actionId) => ({
          actionId,
          enabled,
          source: "individual",
          individualEnabled: enabled,
          defaultEnabled: null,
        }));
      },
    },
    connectionStore: {
      async getSafeConnection() {
        stateReads++;
        return safe;
      },
    },
    store: {
      async withConnectionForExecution<T>(_service: string, _id: string, _policy: unknown, work: () => Promise<T>) {
        return work();
      },
    },
    runner: {
      async run() {
        providerReads++;
        return nativeOutput;
      },
    },
  } as unknown as SaasTriggerRunnerOptions;
  const runner = new SaasTriggerRunner(options);
  const request = {
    service: "gmail",
    triggerId: snapshot.key,
    connectorConnectionId: connectionId,
    input: requestInput,
  };
  return {
    runner,
    request,
    safe,
    grant() {
      enabled = true;
    },
    revoke() {
      enabled = false;
    },
    failPolicy() {
      unavailable = true;
    },
    counts() {
      return { providerReads, stateReads };
    },
  };
}

describe("scoped private native trigger authority", () => {
  it("denies absent/revoked and unavailable permission before any provider or persisted replay access", async () => {
    const run = setup();
    await expect(run.runner.run(run.request)).rejects.toMatchObject({ code: "action_not_granted" });
    expect(run.counts()).toEqual({ providerReads: 0, stateReads: 0 });
    run.grant();
    await expect(run.runner.run(run.request)).resolves.toMatchObject({ events: [{ payload: { subject: "Hello" } }] });
    run.revoke();
    await expect(run.runner.run(run.request)).rejects.toMatchObject({ code: "action_not_granted" });
    expect(run.counts().providerReads).toBe(1);
    run.failPolicy();
    await expect(run.runner.run(run.request)).rejects.toMatchObject({ code: "action_policy_unavailable" });
    expect(run.counts().providerReads).toBe(1);
  });
  it("binds full native input, capability namespace, exact local and owner IDs, current visibility and output ceiling", async () => {
    for (const overrides of [
      { actionId: snapshot.key },
      { requestHash: "a".repeat(43) },
      { localConnectionId: "ffffffff-ffff-4fff-8fff-ffffffffffff" },
      { subjectUserId: "ffffffff-ffff-4fff-8fff-ffffffffffff" },
    ]) {
      const run = setup(overrides);
      run.grant();
      await expect(run.runner.run(run.request)).rejects.toThrow();
      expect(run.counts().providerReads).toBe(0);
    }
    const shared = setup({ actorUserId: "ffffffff-ffff-4fff-8fff-ffffffffffff" });
    shared.grant();
    shared.safe.visibility = "user";
    await expect(shared.runner.run(shared.request)).rejects.toThrow();
    expect(shared.counts().providerReads).toBe(0);
    const bounded = setup({ maxOutputBytes: 5 });
    bounded.grant();
    await expect(bounded.runner.run(bounded.request)).rejects.toMatchObject({ code: "action_output_too_large" });
  });
  it("never returns native private subscription or callback checkpoint envelopes", async () => {
    const receive = {
      operation: "receive",
      subscriptionId: "owned-subscription",
      method: "POST",
      headers: { "content-type": "application/json" },
      query: { connector_subscription: "nonce" },
      rawBody: Buffer.from("{}").toString("base64"),
      admit: true,
      current: true,
    };
    const output = {
      checkpoint: { private: "state" },
      subscription: { callbackSecret: "private-secret" },
      result: { outcome: "event", checkpoint: { private: "callback-state" }, outputs: { message: "Received" } },
    };
    const run = setup({ requestHash: canonicalActionRequestHash(capability, connectionId, receive) }, receive, output);
    run.grant();
    await expect(run.runner.run(run.request)).resolves.toEqual({
      result: { outcome: "event", outputs: { message: "Received" } },
      subscription: { id: "owned-subscription" },
    });
  });
});
