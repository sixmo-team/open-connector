import { describe, expect, it } from "vitest";
import {
  actionAccessInputSchema,
  actionPolicyMutationInputSchema,
  actionPolicyTargetSchema,
  parseActionPolicyControlClaims,
  parseConnectorIdentityClaims,
} from "./contracts.ts";

const time = {
  iss: "control-issuer",
  aud: "control-audience",
  sub: "operator:real",
  jti: "request-1",
  iat: 1000,
  nbf: 1000,
  exp: 1060,
};
const user = {
  kind: "user",
  tenantId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  workspaceId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  userId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
};

describe("strict action policy wire contracts", () => {
  it("admits a real operator platform target without inventing customer scope", () => {
    expect(
      parseActionPolicyControlClaims({
        ...time,
        subject_kind: "policy_control",
        purpose: "action-policy:write",
        permissions: ["action-policy:write"],
        policy_target: { kind: "platform" },
        request_hash: "a".repeat(43),
      }),
    ).toMatchObject({ sub: "operator:real", target: { kind: "platform" } });
  });
  it("never accepts control principals in the execution parser", () => {
    expect(() =>
      parseConnectorIdentityClaims({
        ...time,
        subject_kind: "policy_control",
        purpose: "action-policy:read",
        permissions: ["action-policy:read"],
        policy_target: user,
      }),
    ).toThrow();
  });
  it("separates service inventory and purge targets without fake workspace roles", () => {
    expect(
      parseConnectorIdentityClaims({
        ...time,
        aud: "open-connector-saas",
        subject_kind: "service",
        purpose: "action-policy:subjects",
        permissions: ["action-policy:subjects"],
        policy_target: { kind: "tenant", tenantId: user.tenantId },
      }),
    ).toMatchObject({ purpose: "action-policy:subjects" });
    for (const purpose of ["action-policy:subjects", "action-policy:purge"]) {
      expect(() =>
        parseConnectorIdentityClaims({
          ...time,
          aud: "open-connector-saas",
          subject_kind: "service",
          purpose,
          permissions: [purpose],
          policy_target: { kind: "platform" },
          ...(purpose.endsWith("purge") ? { request_hash: "a".repeat(43) } : {}),
        }),
      ).toThrow();
    }
  });
  it.each(["lifecycle:subjects", "lifecycle:configuration:read", "lifecycle:configuration:purge"])(
    "limits native %s maintenance to a real tenant/workspace target",
    (purpose) => {
      const claims = {
        ...time,
        aud: "open-connector-saas",
        subject_kind: "service",
        purpose,
        permissions: [purpose],
        policy_target: { kind: "workspace", tenantId: user.tenantId, workspaceId: user.workspaceId },
        ...(purpose.endsWith(":purge") ? { request_hash: "a".repeat(43) } : {}),
      };
      expect(parseConnectorIdentityClaims(claims)).toMatchObject({
        subjectKind: "service",
        purpose,
        target: claims.policy_target,
      });
      for (const invalid of [
        { ...claims, policy_target: user },
        { ...claims, policy_target: { kind: "platform" } },
        { ...claims, exp: claims.iat + 61 },
        { ...claims, workspace_role: "owner" },
        { ...claims, permissions: [purpose, "action:execute:v2"] },
        { ...claims, processingDeadlineMs: 9999999999999 },
        { ...claims, request_hash: purpose.endsWith(":purge") ? undefined : "a".repeat(43) },
      ])
        expect(() => parseConnectorIdentityClaims(invalid)).toThrow();
    },
  );
  it("binds ordinary search to the requesting actor, not a shared connection owner", () => {
    const claims = {
      ...time,
      aud: "open-connector-saas",
      sub: user.userId,
      tenant_id: user.tenantId,
      workspace_id: user.workspaceId,
      actor_user_id: user.userId,
      subject_user_id: user.userId,
      workspace_role: "owner",
      purpose: "action:search",
      permissions: ["action:search"],
    };
    expect(parseConnectorIdentityClaims(claims)).toMatchObject({
      actorUserId: user.userId,
      subjectUserId: user.userId,
    });
    expect(() =>
      parseConnectorIdentityClaims({ ...claims, actor_user_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }),
    ).toThrow("action:search actor must equal subject");
  });
  it("rejects broad/malformed targets, duplicate/wildcard actions and actor substitution", () => {
    expect(() => actionPolicyTargetSchema.parse({ ...user, role: "owner" })).toThrow();
    expect(() => actionPolicyTargetSchema.parse({ ...user, tenantId: "fake-tenant" })).toThrow();
    for (const body of [
      { actionIds: ["gmail.messages_list", "gmail.messages_list"] },
      { actionIds: ["gmail.*"] },
      { actionIds: ["gmail.messages_list"], userId: user.userId },
    ])
      expect(() => actionAccessInputSchema.parse(body)).toThrow();
    expect(() =>
      actionAccessInputSchema.parse({ actionIds: Array.from({ length: 5001 }, (_, i) => `gmail.action_${i}`) }),
    ).toThrow();
  });
  it("retains actual wire reason until after request hashing and forbids extra write fields", () => {
    expect(
      actionPolicyMutationInputSchema.parse({
        actionIds: ["gmail.messages_list"],
        enabled: null,
        reason: "  inherit  ",
      }).reason,
    ).toBe("  inherit  ");
    for (const reason of ["  ", "x".repeat(501)])
      expect(() =>
        actionPolicyMutationInputSchema.parse({ actionIds: ["gmail.messages_list"], enabled: true, reason }),
      ).toThrow();
    expect(() =>
      actionPolicyMutationInputSchema.parse({
        actionIds: ["gmail.messages_list"],
        enabled: true,
        reason: "why",
        operatorSubject: "forged",
      }),
    ).toThrow();
  });
});
