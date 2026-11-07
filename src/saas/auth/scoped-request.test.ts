import type { ActionPolicyControlPrincipal, ActionPolicyServicePrincipal, SaasRequestScope } from "../contracts.ts";
import type { SaasHonoEnvironment } from "./scoped-request.ts";

import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { requireScopedControlPurpose, requireCatalogPurpose, requireSaasPurpose } from "./scoped-request.ts";

const user: SaasRequestScope = {
  tenantId: "t",
  workspaceId: "w",
  actorUserId: "u",
  subjectUserId: "u",
  workspaceRole: "owner",
  purpose: "catalog:read",
  permissions: ["catalog:read"],
};
const service: ActionPolicyServicePrincipal = {
  subjectKind: "service",
  subject: "cleanup-service",
  purpose: "action-policy:subjects",
  permissions: ["action-policy:subjects"],
  requestId: "request",
  target: { kind: "tenant", tenantId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
};
const control: ActionPolicyControlPrincipal = {
  subjectKind: "policy_control",
  subject: "operator",
  purpose: "action-policy:write",
  permissions: ["action-policy:write"],
  requestId: "request",
  requestHash: "a".repeat(43),
  target: { kind: "platform" },
};

describe("separate verified route contexts", () => {
  it("does not let policy service identities enter generic catalog or tenant middleware", async () => {
    const app = new Hono<SaasHonoEnvironment>();
    app.get(
      "/catalog",
      requireCatalogPurpose(async () => service),
      (c) => c.json({ leaked: true }),
    );
    app.get(
      "/tenant",
      requireSaasPurpose(async () => service, "catalog:read"),
      (c) => c.json({ leaked: true }),
    );
    expect((await app.request("/catalog")).status).toBe(403);
    expect((await app.request("/tenant")).status).toBe(403);
  });
  it("only admits the exact control principal and purpose for policy writes", async () => {
    const allowed = new Hono<SaasHonoEnvironment>();
    allowed.put(
      "/policy",
      requireScopedControlPurpose(async () => control, "action-policy:write"),
      (c) => c.json(c.get("controlPrincipal")),
    );
    expect((await allowed.request("/policy", { method: "PUT" })).status).toBe(200);
    for (const principal of [
      user,
      service,
      { ...control, purpose: "action-policy:read" as const, permissions: ["action-policy:read"] },
    ]) {
      const app = new Hono<SaasHonoEnvironment>();
      app.put(
        "/policy",
        requireScopedControlPurpose(async () => principal, "action-policy:write"),
        (c) => c.json({ leaked: true }),
      );
      expect((await app.request("/policy", { method: "PUT" })).status).toBe(403);
    }
  });
});
