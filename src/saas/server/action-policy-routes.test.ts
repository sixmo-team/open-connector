import type { ProviderDefinition } from "../../core/types.ts";
import type {
  ActionPolicyControlPrincipal,
  ActionPolicyTarget,
  NativeLifecycleServicePrincipal,
  SaasPrincipal,
  SaasRequestScope,
} from "../contracts.ts";
import type { SaasConnectServerOptions } from "./saas-connect-server.ts";

import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import { ProviderLoader } from "../../providers/provider-loader.ts";
import { resolveActionPermission } from "../actions/action-permission-policy.ts";
import { canonicalActionPolicyRequestHash } from "../actions/canonical-request.ts";
import { SaasAuthorizationError } from "../auth/saas-jwt-verifier.ts";
import { SaasConnectServer } from "./saas-connect-server.ts";

const actionId = "example.read";
const tenantId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const workspaceId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const userA = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const userB = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const platform: ActionPolicyTarget = { kind: "platform" };
const provider: ProviderDefinition = {
  service: "example",
  displayName: "Example",
  categories: ["Developer Tools"],
  authTypes: ["no_auth"],
  auth: [{ type: "no_auth" }],
  actions: [
    {
      id: actionId,
      service: "example",
      name: "read",
      description: "Read public data.",
      operationType: "read",
      requiredScopes: [],
      providerPermissions: [],
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
    },
  ],
};

function fixture() {
  let defaultEnabled: boolean | null = null;
  const grants = new Map<string, boolean>();
  const controls = new Map<string, ActionPolicyControlPrincipal>();
  const executions = new Map<string, SaasPrincipal>();
  const token = (kid: string) =>
    `${Buffer.from(JSON.stringify({ alg: "EdDSA", kid })).toString("base64url")}.e30.${randomUUID()}`;
  const control = (
    purpose: ActionPolicyControlPrincipal["purpose"],
    target: ActionPolicyTarget,
    path?: string,
    body?: object,
  ) => {
    const value = token("policy-control");
    controls.set(`Bearer ${value}`, {
      subjectKind: "policy_control",
      subject: "operator:test",
      purpose,
      permissions: [purpose],
      target,
      requestId: randomUUID(),
      ...(path ? { requestHash: canonicalActionPolicyRequestHash("PUT", path, target, body) } : {}),
    });
    return { authorization: `Bearer ${value}`, "content-type": "application/json" };
  };
  const user = (userId: string) => {
    const value = token("execution");
    const scope: SaasRequestScope = {
      tenantId,
      workspaceId,
      actorUserId: userId,
      subjectUserId: userId,
      workspaceRole: "member",
      purpose: "action:search",
      permissions: ["action:search"],
    };
    executions.set(`Bearer ${value}`, scope);
    return { authorization: `Bearer ${value}`, "content-type": "application/json" };
  };
  const native = (
    purpose: NativeLifecycleServicePrincipal["purpose"],
    target: NativeLifecycleServicePrincipal["target"],
    path?: string,
    body?: object,
  ) => {
    const value = token("execution");
    executions.set(`Bearer ${value}`, {
      subjectKind: "service",
      subject: "native-lifecycle-job",
      purpose,
      permissions: [purpose],
      target,
      requestId: randomUUID(),
      ...(path ? { requestHash: canonicalActionPolicyRequestHash("POST", path, target, body) } : {}),
    });
    return { authorization: `Bearer ${value}`, "content-type": "application/json" };
  };
  const policy = {
    async getEffectiveForActor(scope: SaasRequestScope, ids: string[]) {
      return ids.map((id) => resolveActionPermission(id, grants.get(scope.actorUserId) ?? null, defaultEnabled));
    },
    async getEffectiveForControl(principal: ActionPolicyControlPrincipal, ids: string[]) {
      const individual = principal.target.kind === "user" ? (grants.get(principal.target.userId) ?? null) : null;
      return ids.map((id) => resolveActionPermission(id, individual, defaultEnabled));
    },
    async readForControl(principal: ActionPolicyControlPrincipal) {
      const enabled =
        principal.target.kind === "platform"
          ? defaultEnabled
          : principal.target.kind === "user"
            ? grants.get(principal.target.userId)
            : undefined;
      return {
        items:
          enabled === null || enabled === undefined
            ? []
            : [
                {
                  actionId,
                  enabled,
                  createdBySubject: "operator:test",
                  updatedBySubject: "operator:test",
                  createdAt: "2026-11-06T00:00:00.000Z",
                  updatedAt: "2026-11-06T00:00:00.000Z",
                  ...(principal.target.kind === "user" ? principal.target : {}),
                },
              ],
        nextCursor: null,
      };
    },
    async applyForControl(
      principal: ActionPolicyControlPrincipal,
      input: { actionIds: string[]; enabled: boolean | null },
    ) {
      let removedCount = 0;
      if (principal.target.kind === "platform") defaultEnabled = input.enabled;
      else if (principal.target.kind === "user") {
        if (input.enabled === null) removedCount = grants.delete(principal.target.userId) ? 1 : 0;
        else grants.set(principal.target.userId, input.enabled);
      }
      return { updatedCount: input.enabled === null ? 0 : input.actionIds.length, removedCount, auditId: randomUUID() };
    },
  };
  const app = new SaasConnectServer({
    catalog: createCatalogStore([provider]),
    providerLoader: new ProviderLoader({}),
    verifyJwt: async (header: string | undefined) => {
      const principal = executions.get(header ?? "");
      if (!principal) throw new SaasAuthorizationError(401);
      return principal;
    },
    verifyActionPolicyJwt: async (header: string | undefined) => {
      const principal = controls.get(header ?? "");
      if (!principal) throw new SaasAuthorizationError(401);
      return principal;
    },
    policyControlActiveKid: "policy-control",
    readiness: async () => ({
      postgres: true,
      openBao: true,
      jwks: true,
      seaweedFs: true,
      providerRegistry: true,
      catalogFingerprint: true,
    }),
    runtimeDatabaseFactory: {
      actionPolicy: policy,
      forScope() {
        throw new Error("Policy routes must not invent a customer database scope");
      },
    },
  } as unknown as SaasConnectServerOptions).createApp();
  const access = async (userId: string) => {
    const response = await app.request("/internal/saas/action-access", {
      method: "POST",
      headers: user(userId),
      body: JSON.stringify({ actionIds: [actionId] }),
    });
    expect(response.status).toBe(200);
    return (await response.json()).decisions[0];
  };
  return { app, control, user, native, access };
}

describe("owner policy HTTP boundary", () => {
  it("applies a common rule to a new actor without copying personal rows and preserves explicit exceptions", async () => {
    const f = fixture();
    const defaultsPath = "/internal/saas/action-policy/defaults";
    const defaults = { actionIds: [actionId], enabled: true, reason: "  reviewed  " };
    expect(
      (
        await f.app.request(defaultsPath, {
          method: "PUT",
          headers: f.control("action-policy:write", platform, defaultsPath, defaults),
          body: JSON.stringify(defaults),
        })
      ).status,
    ).toBe(200);
    expect(await f.access(userB)).toMatchObject({ enabled: true, source: "platform", individualEnabled: null });
    const target: ActionPolicyTarget = { kind: "user", tenantId, workspaceId, userId: userB };
    const personal = await f.app.request("/internal/saas/action-policy/grants", {
      headers: f.control("action-policy:read", target),
    });
    expect((await personal.json()).items).toEqual([]);
    const grantsPath = "/internal/saas/action-policy/grants";
    const deny = { actionIds: [actionId], enabled: false, reason: "personal exception" };
    expect(
      (
        await f.app.request(grantsPath, {
          method: "PUT",
          headers: f.control("action-policy:write", target, grantsPath, deny),
          body: JSON.stringify(deny),
        })
      ).status,
    ).toBe(200);
    expect(await f.access(userB)).toMatchObject({ enabled: false, source: "individual", defaultEnabled: true });
    expect(await f.access(userA)).toMatchObject({ enabled: true, source: "platform" });
    const reset = { ...deny, enabled: null };
    expect(
      (
        await f.app.request(grantsPath, {
          method: "PUT",
          headers: f.control("action-policy:write", target, grantsPath, reset),
          body: JSON.stringify(reset),
        })
      ).status,
    ).toBe(200);
    expect(await f.access(userB)).toMatchObject({ enabled: true, source: "platform", individualEnabled: null });
  });

  it("rejects altered write content, route, authority and user substitution before changing policy", async () => {
    const f = fixture();
    const path = "/internal/saas/action-policy/defaults";
    const body = { actionIds: [actionId], enabled: true, reason: "reviewed" };
    const headers = f.control("action-policy:write", platform, path, body);
    expect(
      (await f.app.request(path, { method: "PUT", headers, body: JSON.stringify({ ...body, enabled: false }) })).status,
    ).toBe(403);
    expect(
      (
        await f.app.request(`${path}/${actionId}`, {
          method: "PUT",
          headers,
          body: JSON.stringify({ enabled: true, reason: "reviewed" }),
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await f.app.request("/internal/saas/action-policy/grants", {
          method: "PUT",
          headers,
          body: JSON.stringify(body),
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await f.app.request(path, {
          method: "PUT",
          headers: f.control("action-policy:read", platform),
          body: JSON.stringify(body),
        })
      ).status,
    ).toBe(403);
    const own = await f.app.request("/internal/saas/action-access", {
      method: "POST",
      headers: f.user(userA),
      body: JSON.stringify({ actionIds: [actionId], userId: userB }),
    });
    expect(own.status).toBe(400);
    expect(await f.access(userB)).toMatchObject({ enabled: false, source: "none" });
  });

  it("requires exact service authority and signed purge content for native lifecycle operations", async () => {
    const f = fixture();
    const target: NativeLifecycleServicePrincipal["target"] = { kind: "workspace", tenantId, workspaceId };
    expect((await f.app.request("/internal/saas/lifecycle/subjects", { headers: f.user(userA) })).status).toBe(403);
    expect(
      (
        await f.app.request("/internal/saas/lifecycle/configuration", {
          headers: f.native("lifecycle:subjects", target),
        })
      ).status,
    ).toBe(403);
    const path = "/internal/saas/lifecycle/configuration/purge";
    const body = { correlationId: randomUUID() };
    const headers = f.native("lifecycle:configuration:purge", target, path, body);
    expect(
      (await f.app.request(path, { method: "POST", headers, body: JSON.stringify({ correlationId: randomUUID() }) }))
        .status,
    ).toBe(403);
    expect(
      (
        await f.app.request("/internal/saas/lifecycle/subjects?userId=another-user", {
          headers: f.native("lifecycle:subjects", target),
        })
      ).status,
    ).toBe(400);
  });
});
