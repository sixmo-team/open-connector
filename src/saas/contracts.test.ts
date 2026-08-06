import { describe, expect, it } from "vitest";
import { canonicalActionRequestHash, canonicalRequestHash } from "./actions/canonical-request.ts";
import {
  connectionVisibilityInputSchema,
  lifecyclePurgeInputSchema,
  maximumActionOutputBytes,
  parseConnectorIdentityClaims,
} from "./contracts.ts";

const validClaims = {
  iss: "https://backend.internal",
  aud: "open-connector-saas",
  sub: "subject-1",
  jti: "token-1",
  iat: 1_000,
  nbf: 1_000,
  exp: 1_060,
  tenant_id: "tenant-1",
  workspace_id: "workspace-1",
  actor_user_id: "actor-1",
  subject_user_id: "subject-1",
  workspace_role: "member",
  purpose: "catalog:read",
  permissions: ["catalog:read"],
} as const;

const validCatalogServiceClaims = {
  iss: "https://backend.internal",
  aud: "open-connector-saas",
  sub: "open-connector-catalog",
  jti: "catalog-token-1",
  iat: 1_000,
  nbf: 1_000,
  exp: 1_060,
  subject_kind: "service",
  purpose: "catalog:read",
  permissions: ["catalog:read"],
} as const;

describe("parseConnectorIdentityClaims", () => {
  it("strictly rejects unknown wire claims", () => {
    expect(() => parseConnectorIdentityClaims({ ...validClaims, tenantId: "tenant-override" })).toThrow(
      /unrecognized key/i,
    );
  });

  it("parses wire identity into stable camelCase fields", () => {
    expect(parseConnectorIdentityClaims(validClaims)).toMatchObject({
      tenantId: "tenant-1",
      workspaceId: "workspace-1",
      actorUserId: "actor-1",
      subjectUserId: "subject-1",
      workspaceRole: "member",
      purpose: "catalog:read",
      permissions: ["catalog:read"],
    });
  });

  it("parses a distinct tenant-free catalog service identity", () => {
    expect(parseConnectorIdentityClaims(validCatalogServiceClaims)).toEqual({
      iss: "https://backend.internal",
      aud: "open-connector-saas",
      sub: "open-connector-catalog",
      jti: "catalog-token-1",
      iat: 1_000,
      nbf: 1_000,
      exp: 1_060,
      subjectKind: "service",
      purpose: "catalog:read",
      permissions: ["catalog:read"],
    });
  });

  it("rejects mixed, unknown, wildcard, and overlong catalog service claims", () => {
    expect(() => parseConnectorIdentityClaims({ ...validCatalogServiceClaims, tenant_id: "tenant-1" })).toThrow();
    expect(() => parseConnectorIdentityClaims({ ...validCatalogServiceClaims, subject_kind: "worker" })).toThrow();
    expect(() => parseConnectorIdentityClaims({ ...validCatalogServiceClaims, permissions: ["*"] })).toThrow();
    expect(() =>
      parseConnectorIdentityClaims({
        ...validCatalogServiceClaims,
        permissions: ["catalog:read", "connection:read"],
      }),
    ).toThrow();
    expect(() => parseConnectorIdentityClaims({ ...validCatalogServiceClaims, exp: 1_061 })).toThrow(
      "catalog:read service claims have an invalid expiry",
    );
  });

  it("requires one permission exactly matching the purpose", () => {
    expect(() => parseConnectorIdentityClaims({ ...validClaims, sub: "other-user" })).toThrow(
      "JWT subject does not match scoped subject",
    );
    expect(() => parseConnectorIdentityClaims({ ...validClaims, permissions: ["connection:read"] })).toThrow(
      "permissions must exactly match purpose",
    );
    expect(() =>
      parseConnectorIdentityClaims({
        ...validClaims,
        permissions: ["catalog:read", "connection:read"],
      }),
    ).toThrow("permissions must exactly match purpose");
  });

  it("requires every action execution binding", () => {
    expect(() => parseConnectorIdentityClaims({ ...validClaims, purpose: "action:execute" })).toThrow(
      "action:execute claims are incomplete",
    );

    const requestHash = canonicalActionRequestHash("gmail.messages_list", "connector-1", { maxResults: 10 });
    expect(
      parseConnectorIdentityClaims({
        ...validClaims,
        purpose: "action:execute",
        permissions: ["action:execute"],
        local_connection_id: "local-1",
        connector_connection_id: "connector-1",
        action_id: "gmail.messages_list",
        max_output_bytes: maximumActionOutputBytes,
        request_hash: requestHash,
      }),
    ).toMatchObject({
      localConnectionId: "local-1",
      connectorConnectionId: "connector-1",
      actionId: "gmail.messages_list",
      maxOutputBytes: maximumActionOutputBytes,
      requestHash,
    });
    expect(() =>
      parseConnectorIdentityClaims({
        ...validClaims,
        purpose: "action:execute",
        permissions: ["action:execute"],
        local_connection_id: "local-1",
        connector_connection_id: "connector-1",
        action_id: "gmail.messages_list",
        request_hash: requestHash,
        max_output_bytes: maximumActionOutputBytes + 1,
      }),
    ).toThrow();
    expect(() =>
      parseConnectorIdentityClaims({
        ...validClaims,
        purpose: "action:execute",
        permissions: ["action:execute"],
        local_connection_id: "local-1",
        connector_connection_id: "connector-1",
        action_id: "gmail.messages_list",
        request_hash: requestHash,
        max_output_bytes: 0,
      }),
    ).toThrow();
    expect(() => parseConnectorIdentityClaims({ ...validClaims, max_output_bytes: 1 })).toThrow(
      "max_output_bytes is only valid for action:execute claims",
    );
  });

  it("requires an exact file binding for transit downloads", () => {
    const fileId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    expect(() =>
      parseConnectorIdentityClaims({
        ...validClaims,
        purpose: "file:read",
        permissions: ["file:read"],
      }),
    ).toThrow("file:read claims are incomplete");
    expect(
      parseConnectorIdentityClaims({
        ...validClaims,
        purpose: "file:read",
        permissions: ["file:read"],
        file_id: fileId,
      }),
    ).toMatchObject({ purpose: "file:read", fileId });
    expect(() => parseConnectorIdentityClaims({ ...validClaims, file_id: fileId })).toThrow(
      "file_id is only valid for file:read claims",
    );
  });

  it("rejects a malformed execute request hash", () => {
    expect(() =>
      parseConnectorIdentityClaims({
        ...validClaims,
        purpose: "action:execute",
        permissions: ["action:execute"],
        local_connection_id: "local-1",
        connector_connection_id: "connector-1",
        action_id: "gmail.messages_list",
        max_output_bytes: maximumActionOutputBytes,
        request_hash: "not-a-sha256-digest",
      }),
    ).toThrow("request_hash must be a SHA-256 base64url digest");
  });

  it("requires exact local and connector bindings for hashed connection writes", () => {
    expect(() =>
      parseConnectorIdentityClaims({
        ...validClaims,
        purpose: "connection:write",
        permissions: ["connection:write"],
      }),
    ).toThrow("connection:write claims are incomplete");
    expect(
      parseConnectorIdentityClaims({
        ...validClaims,
        purpose: "connection:write",
        permissions: ["connection:write"],
        local_connection_id: "00000000-0000-4000-8000-000000000001",
      }),
    ).toMatchObject({ localConnectionId: "00000000-0000-4000-8000-000000000001" });

    const visibility = { visibility: "workspace" } as const;
    const requestHash = canonicalActionRequestHash("connection.visibility", "connector-1", visibility);
    expect(() =>
      parseConnectorIdentityClaims({
        ...validClaims,
        purpose: "connection:write",
        permissions: ["connection:write"],
        local_connection_id: "00000000-0000-4000-8000-000000000001",
        request_hash: requestHash,
      }),
    ).toThrow("connection:write claims are incomplete");
    expect(
      parseConnectorIdentityClaims({
        ...validClaims,
        purpose: "connection:write",
        permissions: ["connection:write"],
        local_connection_id: "00000000-0000-4000-8000-000000000001",
        connector_connection_id: "connector-1",
        request_hash: requestHash,
      }),
    ).toMatchObject({
      localConnectionId: "00000000-0000-4000-8000-000000000001",
      connectorConnectionId: "connector-1",
      requestHash,
    });
    expect(connectionVisibilityInputSchema.parse(visibility)).toEqual(visibility);
    expect(() => connectionVisibilityInputSchema.parse({ ...visibility, subjectUserId: "caller-controlled" })).toThrow(
      /unrecognized key/i,
    );
  });

  it.each(["oauth:start", "oauth:complete"] as const)("requires the %s session and local connection", (purpose) => {
    expect(() => parseConnectorIdentityClaims({ ...validClaims, purpose })).toThrow(`${purpose} claims are incomplete`);
    expect(
      parseConnectorIdentityClaims({
        ...validClaims,
        purpose,
        permissions: [purpose],
        oauth_session_id: "oauth-1",
        local_connection_id: "local-1",
        exp: 1_060,
      }),
    ).toMatchObject({ purpose, oauthSessionId: "oauth-1", localConnectionId: "local-1" });
  });

  it("enforces the 60-second maximum lifetime for every purpose", () => {
    expect(() => parseConnectorIdentityClaims({ ...validClaims, exp: 1_061 })).toThrow(
      "catalog:read claims have an invalid expiry",
    );
    expect(() =>
      parseConnectorIdentityClaims({
        ...validClaims,
        purpose: "oauth:complete",
        permissions: ["oauth:complete"],
        oauth_session_id: "oauth-1",
        local_connection_id: "local-1",
        exp: 1_061,
      }),
    ).toThrow("oauth:complete claims have an invalid expiry");
    expect(() => parseConnectorIdentityClaims({ ...validClaims, exp: 1_000 })).toThrow("invalid expiry");
  });

  it.each(["tenant_id", "workspace_id", "actor_user_id", "subject_user_id"] as const)(
    "rejects lifecycle claims missing %s",
    (claim) => {
      const claims: Record<string, unknown> = {
        ...validClaims,
        purpose: "lifecycle:read",
        permissions: ["lifecycle:read"],
      };
      delete claims[claim];
      expect(() => parseConnectorIdentityClaims(claims)).toThrow();
    },
  );

  it("accepts exact lifecycle claims and requires the purge request hash", () => {
    expect(
      parseConnectorIdentityClaims({
        ...validClaims,
        purpose: "lifecycle:read",
        permissions: ["lifecycle:read"],
      }),
    ).toMatchObject({ purpose: "lifecycle:read", subjectUserId: "subject-1" });
    expect(() =>
      parseConnectorIdentityClaims({
        ...validClaims,
        purpose: "lifecycle:read",
        permissions: ["lifecycle:read"],
        local_connection_id: "unexpected",
      }),
    ).toThrow("lifecycle:read claims must be unbound");
    expect(() =>
      parseConnectorIdentityClaims({
        ...validClaims,
        purpose: "lifecycle:delete",
        permissions: ["lifecycle:delete"],
      }),
    ).toThrow("lifecycle:delete claims are incomplete");

    const purgeInput = {
      correlationId: "00000000-0000-4000-8000-000000000001",
    };
    expect(lifecyclePurgeInputSchema.parse(purgeInput)).toEqual(purgeInput);
    expect(() => lifecyclePurgeInputSchema.parse({})).toThrow();
    expect(() => lifecyclePurgeInputSchema.parse({ ...purgeInput, subjectUserId: "caller-controlled" })).toThrow(
      /unrecognized key/i,
    );
    const requestHash = canonicalRequestHash("lifecycle.purge", purgeInput);
    expect(
      parseConnectorIdentityClaims({
        ...validClaims,
        purpose: "lifecycle:delete",
        permissions: ["lifecycle:delete"],
        request_hash: requestHash,
      }),
    ).toMatchObject({ purpose: "lifecycle:delete", requestHash });
    expect(() =>
      parseConnectorIdentityClaims({
        ...validClaims,
        purpose: "lifecycle:delete",
        permissions: ["lifecycle:delete"],
        request_hash: requestHash,
        connector_connection_id: "unexpected",
      }),
    ).toThrow("lifecycle:delete claims are incomplete");
  });

  it("rejects wildcard permissions", () => {
    expect(() => parseConnectorIdentityClaims({ ...validClaims, permissions: ["*"] })).toThrow(
      "wildcard permissions are forbidden",
    );
    expect(() => parseConnectorIdentityClaims({ ...validClaims, permissions: ["action:*"] })).toThrow(
      "wildcard permissions are forbidden",
    );
  });
});
