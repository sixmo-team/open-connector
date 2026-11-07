import type { SaasHonoEnvironment } from "../auth/scoped-request.ts";
import type { SaasRequestScope } from "../contracts.ts";

import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import { snapshot } from "../../providers/gmail/trigger-on-message-received.definition.ts";
import { canonicalActionRequestHash } from "../actions/canonical-request.ts";
import { SaasAuthorizationError } from "../auth/saas-jwt-verifier.ts";
import { SaasTriggerRunner } from "./saas-trigger-runner.ts";
import { registerScopedTriggerRoutes } from "./scoped-trigger-routes.ts";

const user = "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
  connectionId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
  localId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const input = { operation: "read", config: {}, checkpoint: null };
const scope: SaasRequestScope = {
  tenantId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  workspaceId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  subjectUserId: user,
  actorUserId: user,
  workspaceRole: "member",
  purpose: "action:execute:v2",
  permissions: ["action:execute:v2"],
  actionId: "trigger:gmail.on_message_received",
  connectorConnectionId: connectionId,
  localConnectionId: localId,
  requestHash: canonicalActionRequestHash("trigger:gmail.on_message_received", connectionId, input),
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
const path = "/internal/saas/triggers/gmail/gmail.on_message_received";
function appFor(verified: Readonly<SaasRequestScope> = scope) {
  const app = new Hono<SaasHonoEnvironment>();
  let providerCalls = 0;
  registerScopedTriggerRoutes(app, {
    verifyJwt: async (authorization) => {
      if (authorization !== "Bearer verified") throw new SaasAuthorizationError(401);
      return verified;
    },
    createRunner: (requestScope) =>
      new SaasTriggerRunner({
        scope: requestScope,
        catalog,
        actionPolicy: {
          async getEffectiveForActor() {
            return [
              {
                actionId: "trigger:gmail.on_message_received",
                enabled: true,
                source: "individual",
                individualEnabled: true,
                defaultEnabled: null,
              },
            ];
          },
          async withEffectiveForActor() {
            throw new Error("Unexpected SQL admission in HTTP unit test");
          },
        },
        connectionStore: {
          async getSafeConnection() {
            return {
              id: connectionId,
              localConnectionId: localId,
              subjectUserId: user,
              service: "gmail",
              connectionName: "mail",
              visibility: "user",
              status: "active",
              createdAt: "2026-11-06T00:00:00.000Z",
              updatedAt: "2026-11-06T00:00:00.000Z",
            };
          },
        },
        store: {
          async withConnectionForExecution(_service, _id, _policy, work) {
            return work();
          },
        },
        runner: {
          async run() {
            providerCalls++;
            return { events: [{ dedupeKey: "event", payload: { subject: "Received" } }], checkpoint: "next" };
          },
        },
      }),
  });
  return { app, calls: () => providerCalls };
}
function request(app: Hono<SaasHonoEnvironment>, body: unknown, authorization = "Bearer verified", suffix = "") {
  return app.request(path + suffix, {
    method: "POST",
    headers: { authorization, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("private scoped trigger HTTP adapter", () => {
  it("requires exact singleton authority and denies every unsigned or changed native request before provider execution", async () => {
    const { app, calls } = appFor();
    expect((await request(app, { connectorConnectionId: connectionId, input }, "Bearer wrong")).status).toBe(401);
    expect(
      (await request(app, { connectorConnectionId: connectionId, input: { ...input, checkpoint: "tampered" } })).status,
    ).toBe(403);
    expect((await request(app, { connectorConnectionId: connectionId, input, subjectUserId: user })).status).toBe(400);
    expect(
      (await request(app, { connectorConnectionId: connectionId, input }, "Bearer verified", "?callback=public"))
        .status,
    ).toBe(400);
    expect(calls()).toBe(0);
    const wrong = appFor({ ...scope, permissions: ["action:execute:v2", "catalog:read"] });
    expect((await request(wrong.app, { connectorConnectionId: connectionId, input })).status).toBe(403);
    expect(wrong.calls()).toBe(0);
    const result = await request(app, { connectorConnectionId: connectionId, input });
    expect(result.status).toBe(200);
    expect(await result.json()).toEqual({
      ok: true,
      output: { events: [{ dedupeKey: "event", payload: { subject: "Received" } }], checkpoint: "next" },
    });
  });
  it("bounds streamed JSON without trusting content length and exposes no anonymous provider callback", async () => {
    const { app, calls } = appFor();
    const oversized = new ReadableStream({
      start(controller) {
        controller.enqueue(
          new TextEncoder().encode(
            JSON.stringify({
              connectorConnectionId: connectionId,
              input: { ...input, config: { large: "x".repeat(262144) } },
            }),
          ),
        );
        controller.close();
      },
    });
    const response = await app.request(path, {
      method: "POST",
      headers: { authorization: "Bearer verified", "content-type": "application/json" },
      body: oversized,
      duplex: "half",
    } as RequestInit);
    expect(response.status).toBe(413);
    expect((await app.request(path, { method: "GET" })).status).toBe(404);
    expect(calls()).toBe(0);
  });
});
