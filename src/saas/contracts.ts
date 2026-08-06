import * as z from "zod/v4";

export const saasPurposes = [
  "catalog:read",
  "connection:read",
  "connection:write",
  "oauth:start",
  "oauth:complete",
  "file:read",
  "action:search",
  "action:execute",
  "admin:read",
  "lifecycle:read",
  "lifecycle:delete",
] as const;

export type SaasPurpose = (typeof saasPurposes)[number];
export type WorkspaceRole = "owner" | "admin" | "member" | "viewer";

/** Absolute connector-side ceiling for signed, reviewed action output limits. */
export const maximumActionOutputBytes = 8_388_608;

export type SafeConnectionStatus = "pending" | "active" | "reconnect_required" | "failed" | "expired" | "revoked";

export interface SafeCredentialField {
  name: string;
  label: string;
  description?: string;
  inputType: "text" | "password";
  required: boolean;
}
export type SafeConnectionMethodReason =
  | "oauth_client_config_missing"
  | "oauth_client_config_invalid"
  | "oauth_client_config_access_denied";
export type OAuthClientConfigReadiness =
  | { status: "operational" }
  | { status: "unavailable"; reasonCode: SafeConnectionMethodReason };

export interface SafeConnectionMethod {
  type: "no_auth" | "oauth2" | "api_key" | "custom_credential";
  fields: SafeCredentialField[];
  status: "operational" | "unavailable";
  reasonCode?: SafeConnectionMethodReason;
}

export interface SafeProviderCatalog {
  service: string;
  displayName: string;
  description?: string;
  categories: string[];
  authTypes: Array<"no_auth" | "api_key" | "custom_credential" | "oauth2">;
  homepageUrl?: string;
  iconUrl?: string;
  connectionMethods: SafeConnectionMethod[];
}

export interface SafeActionSummary {
  id: string;
  service: string;
  name: string;
  description: string;
  requiredScopes: string[];
  providerPermissions: string[];
  followUpActions?: string[];
  asyncLifecycle?: {
    startActionId: string;
    statusActionId: string;
    cancelActionId?: string;
  };
}

export interface SafeActionCatalog extends SafeActionSummary {
  inputSchema: Record<string, unknown>;
  outputSchema: Record<string, unknown>;
}

export interface SafeActionCatalogPage {
  items: SafeActionCatalog[];
  nextCursor: string | null;
  catalogFingerprint: string;
}

export interface SafeConnectionSummary {
  id: string;
  localConnectionId: string;
  service: string;
  connectionName: string;
  visibility: "user" | "workspace";
  status: SafeConnectionStatus;
  profile?: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface ConnectorCredentialInput {
  localConnectionId: string;
  service: string;
  connectionName: string;
  authType: "api_key" | "custom_credential";
  credentials: Record<string, string>;
}
export interface ConnectorCredentialReplacementInput extends ConnectorCredentialInput {
  connectorConnectionId: string;
}

export interface ConnectionTransferInput {
  targetSubjectUserId: string;
}

export interface ConnectionVisibilityInput {
  visibility: "user" | "workspace";
}

export interface LifecyclePurgeInput {
  correlationId: string;
}

const connectorCredentialInputObjectSchema = z
  .object({
    localConnectionId: z.uuid(),
    service: z.string().trim().min(1).max(128),
    connectionName: z.string().trim().min(1).max(255),
    authType: z.enum(["api_key", "custom_credential"]),
    credentials: z
      .record(z.string().min(1).max(255), z.string().max(65_536))
      .refine((values) => Object.keys(values).length <= 64, "too many credential fields"),
  })
  .strict();
export const connectorCredentialInputSchema: z.ZodType<ConnectorCredentialInput> = connectorCredentialInputObjectSchema;
export const connectorCredentialReplacementInputSchema: z.ZodType<ConnectorCredentialReplacementInput> =
  connectorCredentialInputObjectSchema
    .extend({
      connectorConnectionId: z.string().trim().min(1).max(255),
    })
    .strict();

export const connectionTransferInputSchema: z.ZodType<ConnectionTransferInput> = z
  .object({
    targetSubjectUserId: z.uuid(),
  })
  .strict();

export const connectionVisibilityInputSchema: z.ZodType<ConnectionVisibilityInput> = z
  .object({
    visibility: z.enum(["user", "workspace"]),
  })
  .strict();

export const lifecyclePurgeInputSchema: z.ZodType<LifecyclePurgeInput> = z
  .object({
    correlationId: z.uuid(),
  })
  .strict();

/** Tenant and authorization context captured once for a SaaS request. */
export interface SaasRequestScope {
  tenantId: string;
  workspaceId: string;
  actorUserId: string;
  subjectUserId: string;
  workspaceRole: WorkspaceRole;
  purpose: SaasPurpose;
  permissions: string[];
  localConnectionId?: string;
  connectorConnectionId?: string;
  fileId?: string;
  oauthSessionId?: string;
  actionId?: string;
  maxOutputBytes?: number;
  requestHash?: string;
}

/** Service identity accepted only by catalog route middleware. */
export interface CatalogServicePrincipal {
  subjectKind: "service";
  subject: string;
  purpose: "catalog:read";
  permissions: ["catalog:read"];
}

/** Verified JWT claims after the snake_case wire representation is parsed. */
export interface ConnectorIdentityClaims extends SaasRequestScope {
  iss: string;
  aud: "open-connector-saas";
  sub: string;
  jti: string;
  iat: number;
  nbf: number;
  exp: number;
}

/** Verified catalog service claims after strict wire parsing. */
export interface CatalogServiceIdentityClaims {
  iss: string;
  aud: "open-connector-saas";
  sub: string;
  jti: string;
  iat: number;
  nbf: number;
  exp: number;
  subjectKind: "service";
  purpose: "catalog:read";
  permissions: ["catalog:read"];
}

export type VerifiedConnectorIdentityClaims = ConnectorIdentityClaims | CatalogServiceIdentityClaims;
export type SaasPrincipal = SaasRequestScope | CatalogServicePrincipal;

const nonEmptyWireString = z
  .string()
  .min(1)
  .refine((value) => value.trim() === value, "must not have surrounding whitespace");
const timestamp = z.number().int().nonnegative();

const catalogServiceIdentityClaimsSchema: z.ZodType<CatalogServiceIdentityClaims> = z
  .object({
    iss: nonEmptyWireString,
    aud: z.literal("open-connector-saas"),
    sub: nonEmptyWireString,
    jti: nonEmptyWireString,
    iat: timestamp,
    nbf: timestamp,
    exp: timestamp,
    subject_kind: z.literal("service"),
    purpose: z.literal("catalog:read"),
    permissions: z.tuple([z.literal("catalog:read")]),
  })
  .strict()
  .superRefine((claims, context) => {
    if (claims.exp <= claims.iat || claims.exp - claims.iat > 60 || claims.nbf > claims.exp) {
      context.addIssue({ code: "custom", message: "catalog:read service claims have an invalid expiry" });
    }
  })
  .transform(
    (claims): CatalogServiceIdentityClaims => ({
      iss: claims.iss,
      aud: claims.aud,
      sub: claims.sub,
      jti: claims.jti,
      iat: claims.iat,
      nbf: claims.nbf,
      exp: claims.exp,
      subjectKind: claims.subject_kind,
      purpose: claims.purpose,
      permissions: claims.permissions,
    }),
  );

const tenantIdentityClaimsSchema: z.ZodType<ConnectorIdentityClaims> = z
  .object({
    iss: nonEmptyWireString,
    aud: z.literal("open-connector-saas"),
    sub: nonEmptyWireString,
    jti: nonEmptyWireString,
    iat: timestamp,
    nbf: timestamp,
    exp: timestamp,
    tenant_id: nonEmptyWireString,
    workspace_id: nonEmptyWireString,
    actor_user_id: nonEmptyWireString,
    subject_user_id: nonEmptyWireString,
    workspace_role: z.enum(["owner", "admin", "member", "viewer"]),
    purpose: z.enum(saasPurposes),
    permissions: z.array(nonEmptyWireString),
    local_connection_id: nonEmptyWireString.optional(),
    connector_connection_id: nonEmptyWireString.optional(),
    oauth_session_id: nonEmptyWireString.optional(),
    action_id: nonEmptyWireString.optional(),
    file_id: z.uuid().optional(),
    max_output_bytes: z.number().int().positive().max(maximumActionOutputBytes).optional(),
    request_hash: z
      .string()
      .regex(/^[A-Za-z0-9_-]{43}$/, "request_hash must be a SHA-256 base64url digest")
      .optional(),
  })
  .strict()
  .superRefine((claims, context) => {
    if (claims.exp <= claims.iat || claims.exp - claims.iat > 60 || claims.nbf > claims.exp) {
      context.addIssue({ code: "custom", message: `${claims.purpose} claims have an invalid expiry` });
    }

    if (claims.sub !== claims.subject_user_id) {
      context.addIssue({ code: "custom", message: "JWT subject does not match scoped subject", path: ["sub"] });
    }
    if (claims.permissions.length !== 1 || claims.permissions[0] !== claims.purpose) {
      context.addIssue({
        code: "custom",
        message: "permissions must exactly match purpose",
        path: ["permissions"],
      });
    }

    if (claims.permissions.some((permission) => permission.includes("*"))) {
      context.addIssue({ code: "custom", message: "wildcard permissions are forbidden", path: ["permissions"] });
    }

    const hasConnectionBinding =
      claims.local_connection_id !== undefined || claims.connector_connection_id !== undefined;
    const hasOAuthBinding = claims.oauth_session_id !== undefined;
    const hasActionBinding = claims.action_id !== undefined;
    const hasOutputBinding = claims.max_output_bytes !== undefined;
    const hasRequestBinding = claims.request_hash !== undefined;
    const hasFileBinding = claims.file_id !== undefined;

    if (
      claims.purpose === "action:execute" &&
      (!claims.local_connection_id ||
        !claims.connector_connection_id ||
        !claims.action_id ||
        !claims.request_hash ||
        !claims.max_output_bytes ||
        hasOAuthBinding)
    ) {
      context.addIssue({ code: "custom", message: "action:execute claims are incomplete" });
    }

    if (claims.purpose !== "action:execute" && hasOutputBinding) {
      context.addIssue({ code: "custom", message: "max_output_bytes is only valid for action:execute claims" });
    }

    if (
      claims.purpose === "file:read" &&
      (!claims.file_id ||
        hasConnectionBinding ||
        hasOAuthBinding ||
        hasActionBinding ||
        hasOutputBinding ||
        hasRequestBinding)
    ) {
      context.addIssue({ code: "custom", message: "file:read claims are incomplete" });
    }

    if (claims.purpose !== "file:read" && hasFileBinding) {
      context.addIssue({ code: "custom", message: "file_id is only valid for file:read claims" });
    }

    if (
      claims.purpose === "connection:write" &&
      (!claims.local_connection_id ||
        (hasRequestBinding && !claims.connector_connection_id) ||
        hasOAuthBinding ||
        hasActionBinding)
    ) {
      context.addIssue({ code: "custom", message: "connection:write claims are incomplete" });
    }

    if (
      (claims.purpose === "oauth:start" || claims.purpose === "oauth:complete") &&
      (!claims.oauth_session_id ||
        !claims.local_connection_id ||
        claims.connector_connection_id !== undefined ||
        hasActionBinding ||
        hasRequestBinding)
    ) {
      context.addIssue({ code: "custom", message: `${claims.purpose} claims are incomplete` });
    }

    if (
      claims.purpose === "lifecycle:delete" &&
      (!claims.request_hash || hasConnectionBinding || hasOAuthBinding || hasActionBinding)
    ) {
      context.addIssue({ code: "custom", message: "lifecycle:delete claims are incomplete" });
    }

    if (
      (claims.purpose === "catalog:read" ||
        claims.purpose === "connection:read" ||
        claims.purpose === "action:search" ||
        claims.purpose === "admin:read" ||
        claims.purpose === "lifecycle:read") &&
      (hasConnectionBinding || hasOAuthBinding || hasActionBinding || hasRequestBinding)
    ) {
      context.addIssue({ code: "custom", message: `${claims.purpose} claims must be unbound` });
    }
  })
  .transform(
    (claims): ConnectorIdentityClaims => ({
      iss: claims.iss,
      aud: claims.aud,
      sub: claims.sub,
      jti: claims.jti,
      iat: claims.iat,
      nbf: claims.nbf,
      exp: claims.exp,
      tenantId: claims.tenant_id,
      workspaceId: claims.workspace_id,
      actorUserId: claims.actor_user_id,
      subjectUserId: claims.subject_user_id,
      workspaceRole: claims.workspace_role,
      purpose: claims.purpose,
      permissions: claims.permissions,
      localConnectionId: claims.local_connection_id,
      connectorConnectionId: claims.connector_connection_id,
      oauthSessionId: claims.oauth_session_id,
      actionId: claims.action_id,
      maxOutputBytes: claims.max_output_bytes,
      requestHash: claims.request_hash,
      fileId: claims.file_id,
    }),
  );

export const connectorIdentityClaimsSchema: z.ZodType<VerifiedConnectorIdentityClaims> = z.union([
  catalogServiceIdentityClaimsSchema,
  tenantIdentityClaimsSchema,
]);

/** Strictly parse backend-issued wire claims into connector-native camelCase names. */
export function parseConnectorIdentityClaims(value: unknown): VerifiedConnectorIdentityClaims {
  return typeof value === "object" && value !== null && "subject_kind" in value
    ? catalogServiceIdentityClaimsSchema.parse(value)
    : tenantIdentityClaimsSchema.parse(value);
}
