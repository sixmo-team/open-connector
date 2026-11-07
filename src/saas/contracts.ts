import type { RequestProcessingContext } from "../core/cancellation.ts";

import * as z from "zod/v4";

export const saasPurposes = [
  "catalog:read",
  "connection:read",
  "connection:write",
  "oauth:start",
  "oauth:complete",
  "file:read",
  "action:search",
  "action:execute:v2",
  "admin:read",
  "lifecycle:read",
  "lifecycle:delete",
  "maintenance:run",
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
  authType: "no_auth" | "api_key" | "custom_credential";
  credentials: Record<string, string>;
}
export interface ConnectorCredentialReplacementInput extends Omit<ConnectorCredentialInput, "authType"> {
  connectorConnectionId: string;
  authType: "api_key" | "custom_credential";
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
    authType: z.enum(["no_auth", "api_key", "custom_credential"]),
    credentials: z
      .record(z.string().min(1).max(255), z.string().max(65_536))
      .refine((values) => Object.keys(values).length <= 64, "too many credential fields"),
  })
  .strict();
export const connectorCredentialInputSchema: z.ZodType<ConnectorCredentialInput> =
  connectorCredentialInputObjectSchema.refine(
    (input) => input.authType !== "no_auth" || Object.keys(input.credentials).length === 0,
    "public connections cannot contain credentials",
  );
export const connectorCredentialReplacementInputSchema: z.ZodType<ConnectorCredentialReplacementInput> =
  connectorCredentialInputObjectSchema
    .extend({
      authType: z.enum(["api_key", "custom_credential"]),
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
export interface SaasRequestScope extends RequestProcessingContext {
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

export type VerifiedConnectorIdentityClaims =
  | ConnectorIdentityClaims
  | CatalogServiceIdentityClaims
  | ActionPolicyServiceIdentityClaims
  | NativeLifecycleServiceIdentityClaims;
export type SaasPrincipal =
  | SaasRequestScope
  | CatalogServicePrincipal
  | ActionPolicyServicePrincipal
  | NativeLifecycleServicePrincipal;

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
  .transform((claims): CatalogServiceIdentityClaims => ({
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
  }));

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
    if (
      (claims.purpose === "action:search" || claims.purpose === "maintenance:run") &&
      claims.actor_user_id !== claims.subject_user_id
    ) {
      context.addIssue({ code: "custom", message: `${claims.purpose} actor must equal subject` });
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
      claims.purpose === "action:execute:v2" &&
      (!claims.local_connection_id ||
        !claims.connector_connection_id ||
        !claims.action_id ||
        !claims.request_hash ||
        !claims.max_output_bytes ||
        hasOAuthBinding)
    ) {
      context.addIssue({ code: "custom", message: "action:execute:v2 claims are incomplete" });
    }

    if (claims.purpose !== "action:execute:v2" && hasOutputBinding) {
      context.addIssue({ code: "custom", message: "max_output_bytes is only valid for action:execute:v2 claims" });
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

    if (claims.purpose === "connection:write" && (!claims.local_connection_id || hasOAuthBinding || hasActionBinding)) {
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
        claims.purpose === "lifecycle:read" ||
        claims.purpose === "maintenance:run") &&
      (hasConnectionBinding || hasOAuthBinding || hasActionBinding || hasRequestBinding)
    ) {
      context.addIssue({ code: "custom", message: `${claims.purpose} claims must be unbound` });
    }
  })
  .transform((claims): ConnectorIdentityClaims => ({
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
  }));

export interface ActionPermissionDecision {
  actionId: string;
  enabled: boolean;
  source: "individual" | "platform" | "none";
  individualEnabled: boolean | null;
  defaultEnabled: boolean | null;
}

export type ActionPolicyTarget =
  | { kind: "platform" }
  | { kind: "user"; tenantId: string; workspaceId: string; userId: string }
  | { kind: "workspace"; tenantId: string; workspaceId: string }
  | { kind: "tenant"; tenantId: string };
export type ActionPolicyUserTarget = Extract<ActionPolicyTarget, { kind: "user" }>;

export interface ActionPolicyControlPrincipal extends RequestProcessingContext {
  subjectKind: "policy_control";
  subject: string;
  purpose: "action-policy:read" | "action-policy:write";
  permissions: string[];
  target: Readonly<ActionPolicyTarget>;
  requestId: string;
  requestHash?: string;
}
export interface ActionPolicyServicePrincipal extends RequestProcessingContext {
  subjectKind: "service";
  subject: string;
  purpose: "action-policy:subjects" | "action-policy:purge";
  permissions: string[];
  target: Readonly<ActionPolicyTarget>;
  requestId: string;
  requestHash?: string;
}
export interface NativeLifecycleServicePrincipal extends RequestProcessingContext {
  subjectKind: "service";
  subject: string;
  purpose: "lifecycle:subjects" | "lifecycle:configuration:read" | "lifecycle:configuration:purge";
  permissions: string[];
  target: Readonly<Extract<ActionPolicyTarget, { kind: "tenant" | "workspace" }>>;
  requestId: string;
  requestHash?: string;
}
export interface NativeConfigurationMetadata {
  kind: "managed_project" | "oauth_source";
  tenantId: string;
  workspaceId: string;
  id: string;
  service?: string;
  source?: "local" | "saas";
  managedProjectId?: string;
  createdAt: string;
  updatedAt: string;
}
export interface ActionPolicyRecord {
  actionId: string;
  enabled: boolean;
  createdBySubject: string;
  updatedBySubject: string;
  createdAt: string;
  updatedAt: string;
  tenantId?: string;
  workspaceId?: string;
  userId?: string;
}
export interface ActionPolicyAuditRecord {
  id: string;
  target: ActionPolicyTarget;
  operatorSubject: string;
  actionIds: string[];
  enabled: boolean | null;
  reason: string;
  createdAt: string;
  requestId: string;
}
export interface ActionPolicyPage {
  cursor?: string;
  limit?: number;
}
export interface ActionPolicyMutationInput {
  actionIds: string[];
  enabled: boolean | null;
  reason: string;
}
export interface ActionPolicyWriteResult {
  updatedCount: number;
  removedCount: number;
  auditId: string;
}
export interface ActionPolicyPurgeResult {
  correlationId: string;
  deletedGrants: number;
  deletedAudit: number;
}

export const actionPolicyTargetSchema: z.ZodType<ActionPolicyTarget> = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("platform") }).strict(),
  z.object({ kind: z.literal("user"), tenantId: z.uuid(), workspaceId: z.uuid(), userId: z.uuid() }).strict(),
  z.object({ kind: z.literal("workspace"), tenantId: z.uuid(), workspaceId: z.uuid() }).strict(),
  z.object({ kind: z.literal("tenant"), tenantId: z.uuid() }).strict(),
]);
const actionIdsSchema = z
  .array(
    z
      .string()
      .min(1)
      .max(255)
      .regex(/^(?:trigger:)?[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+$/),
  )
  .min(1)
  .max(5000)
  .refine((ids) => new Set(ids).size === ids.length, "duplicate action IDs");
// Keep raw wire strings intact until the signed request hash has been checked.
const actionPolicyReasonSchema = z
  .string()
  .min(1)
  .max(500)
  .refine((reason) => reason.trim().length > 0, "reason is required");
export const actionAccessInputSchema: z.ZodType<Pick<ActionPolicyMutationInput, "actionIds">> = z
  .object({ actionIds: actionIdsSchema })
  .strict();
export const actionPolicyMutationInputSchema: z.ZodType<ActionPolicyMutationInput> = z
  .object({
    actionIds: actionIdsSchema,
    enabled: z.boolean().nullable(),
    reason: actionPolicyReasonSchema,
  })
  .strict();
export const actionPolicySingleMutationInputSchema: z.ZodType<Pick<ActionPolicyMutationInput, "enabled" | "reason">> = z
  .object({
    enabled: z.boolean().nullable(),
    reason: actionPolicyReasonSchema,
  })
  .strict();
export const actionPolicyPageSchema: z.ZodType<ActionPolicyPage> = z
  .object({
    cursor: z.string().min(1).max(4096).optional(),
    limit: z.number().int().min(1).max(100).optional(),
  })
  .strict();

const policyIdentityWire = {
  iss: nonEmptyWireString,
  aud: nonEmptyWireString,
  sub: nonEmptyWireString,
  jti: nonEmptyWireString,
  iat: timestamp,
  nbf: timestamp,
  exp: timestamp,
  permissions: z.array(nonEmptyWireString),
  policy_target: actionPolicyTargetSchema,
  request_hash: z
    .string()
    .regex(/^[A-Za-z0-9_-]{43}$/)
    .optional(),
};
interface PolicyIdentityMetadata {
  iss: string;
  aud: string;
  sub: string;
  jti: string;
  iat: number;
  nbf: number;
  exp: number;
}
export type ActionPolicyControlIdentityClaims = Omit<
  ActionPolicyControlPrincipal,
  "subject" | "requestId" | keyof RequestProcessingContext
> &
  PolicyIdentityMetadata;
export type ActionPolicyServiceIdentityClaims = Omit<
  ActionPolicyServicePrincipal,
  "subject" | "requestId" | keyof RequestProcessingContext
> &
  PolicyIdentityMetadata;
export type NativeLifecycleServiceIdentityClaims = Omit<
  NativeLifecycleServicePrincipal,
  "subject" | "requestId" | keyof RequestProcessingContext
> &
  PolicyIdentityMetadata;

export const actionPolicyControlClaimsSchema: z.ZodType<ActionPolicyControlIdentityClaims> = z
  .object({
    ...policyIdentityWire,
    subject_kind: z.literal("policy_control"),
    purpose: z.enum(["action-policy:read", "action-policy:write"]),
  })
  .strict()
  .superRefine((claims, context) => {
    validatePolicyClaims(claims, context);
    if (claims.policy_target.kind !== "platform" && claims.policy_target.kind !== "user") {
      context.addIssue({ code: "custom", message: "control policy target must be platform or user" });
    }
  })
  .transform((claims): ActionPolicyControlIdentityClaims => ({
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
    target: claims.policy_target,
    requestHash: claims.request_hash,
  }));
const actionPolicyServiceIdentityClaimsSchema = z
  .object({
    ...policyIdentityWire,
    aud: z.literal("open-connector-saas"),
    subject_kind: z.literal("service"),
    purpose: z.enum(["action-policy:subjects", "action-policy:purge"]),
  })
  .strict()
  .superRefine((claims, context) => {
    validatePolicyClaims(claims, context);
    if (
      claims.policy_target.kind === "platform" ||
      (claims.purpose === "action-policy:subjects" && claims.policy_target.kind === "user")
    ) {
      context.addIssue({ code: "custom", message: "invalid service policy target" });
    }
  })
  .transform((claims): ActionPolicyServiceIdentityClaims => ({
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
    target: claims.policy_target,
    requestHash: claims.request_hash,
  }));
const nativeLifecycleServiceIdentityClaimsSchema = z
  .object({
    ...policyIdentityWire,
    aud: z.literal("open-connector-saas"),
    subject_kind: z.literal("service"),
    purpose: z.enum(["lifecycle:subjects", "lifecycle:configuration:read", "lifecycle:configuration:purge"]),
  })
  .strict()
  .superRefine((claims, context) => {
    validatePolicyClaims(claims, context);
    if (claims.policy_target.kind !== "tenant" && claims.policy_target.kind !== "workspace") {
      context.addIssue({ code: "custom", message: "native maintenance requires a tenant/workspace target" });
    }
  })
  .transform((claims): NativeLifecycleServiceIdentityClaims => ({
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
    target: claims.policy_target as NativeLifecycleServicePrincipal["target"],
    requestHash: claims.request_hash,
  }));

function validatePolicyClaims(
  claims: { iat: number; nbf: number; exp: number; purpose: string; permissions: string[]; request_hash?: string },
  context: z.RefinementCtx,
): void {
  if (claims.exp <= claims.iat || claims.exp - claims.iat > 60 || claims.nbf > claims.exp) {
    context.addIssue({ code: "custom", message: "invalid policy token expiry" });
  }
  if (claims.permissions.length !== 1 || claims.permissions[0] !== claims.purpose) {
    context.addIssue({ code: "custom", message: "permissions must exactly match purpose" });
  }
  const write =
    claims.purpose === "action-policy:write" ||
    claims.purpose === "action-policy:purge" ||
    claims.purpose === "lifecycle:configuration:purge";
  if (write !== (claims.request_hash !== undefined)) {
    context.addIssue({ code: "custom", message: "only policy mutations require request_hash" });
  }
}

export function parseActionPolicyControlClaims(value: unknown): ActionPolicyControlIdentityClaims {
  return actionPolicyControlClaimsSchema.parse(value);
}

export const connectorIdentityClaimsSchema: z.ZodType<VerifiedConnectorIdentityClaims> = z.union([
  catalogServiceIdentityClaimsSchema,
  tenantIdentityClaimsSchema,
  actionPolicyServiceIdentityClaimsSchema,
  nativeLifecycleServiceIdentityClaimsSchema,
]);

/** Strictly parse backend-issued wire claims into connector-native camelCase names. */
export function parseConnectorIdentityClaims(value: unknown): VerifiedConnectorIdentityClaims {
  if (typeof value === "object" && value !== null && "subject_kind" in value) {
    if ("purpose" in value && value.purpose === "catalog:read") return catalogServiceIdentityClaimsSchema.parse(value);
    if ("purpose" in value && typeof value.purpose === "string" && value.purpose.startsWith("lifecycle:"))
      return nativeLifecycleServiceIdentityClaimsSchema.parse(value);
    return actionPolicyServiceIdentityClaimsSchema.parse(value);
  }
  return tenantIdentityClaimsSchema.parse(value);
}
