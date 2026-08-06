import type { GuardedFetchDnsLookup } from "../../core/guarded-fetch.ts";
import type { ResolvedCredential } from "../../core/types.ts";

import { createGuardedFetch } from "../../core/guarded-fetch.ts";
import { readBoundedResponseBytes } from "../../core/request.ts";

export type ProviderCredentialRevocationOutcome = "revoked" | "unsupported" | "failed";

export interface SaasProviderCredentialRevocationInput {
  service: string;
  credential: ResolvedCredential;
  signal: AbortSignal;
}

export interface SaasProviderCredentialRevoker {
  revoke(input: SaasProviderCredentialRevocationInput): Promise<ProviderCredentialRevocationOutcome>;
}

type OAuthRevocationResponse =
  | {
      successStatus: number;
      body: "empty";
      alreadyRevoked?: { status: number; field: string; values: readonly string[] };
    }
  | { successStatus: number; body: "json_null" }
  | {
      successStatus: number;
      body: "json_field";
      successField: string;
      successValue: string | boolean;
      alreadyRevoked?: { field: string; values: readonly string[] };
    };

/** Internal-only, reviewed provider metadata. It must never be copied into catalog DTOs. */
export interface ProviderCredentialRevocationDefinition {
  readonly service: string;
  readonly endpoint: string;
  readonly method: "POST";
  readonly contentType: "application/x-www-form-urlencoded" | "application/json";
  readonly tokenKind: "access_token" | "refresh_or_access";
  readonly auth:
    | { readonly type: "body"; readonly field: string }
    | { readonly type: "bearer"; readonly body: "json_null" };
  readonly response: OAuthRevocationResponse;
}

export interface ProviderCredentialRevokerOptions {
  definitions?: readonly ProviderCredentialRevocationDefinition[];
  fetchFn?: typeof fetch;
  lookup?: GuardedFetchDnsLookup | null;
  maxRequestBytes?: number;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

const googleServices = [
  "gmail",
  "googlecalendar",
  "googledrive",
  "googledocs",
  "googlesheets",
  "googleslides",
  "googleforms",
  "googletasks",
  "googlephotos",
  "googleads",
  "google_analytics",
  "google_search_console",
  "google_bigquery",
  "google_routes",
  "google_address_validation",
  "youtube",
] as const;

const googleRevocation = {
  endpoint: "https://oauth2.googleapis.com/revoke",
  method: "POST",
  contentType: "application/x-www-form-urlencoded",
  tokenKind: "refresh_or_access",
  auth: { type: "body", field: "token" },
  response: {
    successStatus: 200,
    body: "empty",
    alreadyRevoked: { status: 400, field: "error", values: ["invalid_token"] },
  },
} as const satisfies Omit<ProviderCredentialRevocationDefinition, "service">;

/** Reviewed, non-secret revocation capabilities kept outside every public provider DTO. */
const providerCredentialRevocationDefinitions: readonly ProviderCredentialRevocationDefinition[] = Object.freeze([
  ...googleServices.map((service) => ({ service, ...googleRevocation })),
  {
    service: "slack",
    endpoint: "https://slack.com/api/auth.revoke",
    method: "POST",
    contentType: "application/x-www-form-urlencoded",
    tokenKind: "access_token",
    auth: { type: "body", field: "token" },
    response: {
      successStatus: 200,
      body: "json_field",
      successField: "ok",
      successValue: true,
      alreadyRevoked: { field: "error", values: ["token_revoked"] },
    },
  },
  {
    service: "dropbox",
    endpoint: "https://api.dropboxapi.com/2/auth/token/revoke",
    method: "POST",
    contentType: "application/json",
    tokenKind: "access_token",
    auth: { type: "bearer", body: "json_null" },
    response: { successStatus: 200, body: "json_null" },
  },
]);

/** Revokes only capabilities present in the reviewed internal definition registry. */
export class ProviderSaasCredentialRevoker implements SaasProviderCredentialRevoker {
  private readonly definitions: readonly ProviderCredentialRevocationDefinition[];
  private readonly maxRequestBytes: number;
  private readonly fetchFn: typeof fetch;
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;

  constructor(options: ProviderCredentialRevokerOptions = {}) {
    this.definitions = options.definitions ?? providerCredentialRevocationDefinitions;
    this.fetchFn = createGuardedFetch({
      fetch: options.fetchFn,
      ...(options.lookup === undefined ? {} : { lookup: options.lookup }),
    });
    this.maxRequestBytes = positiveInteger(options.maxRequestBytes ?? 16_384, "Provider revocation request limit");
    this.timeoutMs = positiveInteger(options.timeoutMs ?? 5_000, "Provider revocation timeout");
    this.maxResponseBytes = positiveInteger(options.maxResponseBytes ?? 4_096, "Provider revocation response limit");
  }

  async revoke(input: SaasProviderCredentialRevocationInput): Promise<ProviderCredentialRevocationOutcome> {
    const definition = this.definitions.find((item) => item.service === input.service);
    if (!definition || input.credential.authType !== "oauth2") return "unsupported";
    const selectedToken = (
      definition.tokenKind === "access_token"
        ? input.credential.accessToken
        : input.credential.refreshToken || input.credential.accessToken
    ).trim();
    const tokens = new Set(selectedToken ? [selectedToken] : []);
    let outcome: ProviderCredentialRevocationOutcome = "revoked";
    if (input.service === "slack" && input.credential.providerSecret?.userGrant !== undefined) {
      const userGrant = input.credential.providerSecret.userGrant;
      const userToken =
        typeof userGrant === "object" &&
        userGrant !== null &&
        !Array.isArray(userGrant) &&
        "accessToken" in userGrant &&
        typeof userGrant.accessToken === "string"
          ? userGrant.accessToken.trim()
          : "";
      if (userToken) tokens.add(userToken);
      else outcome = "failed";
    }
    if (tokens.size === 0) return outcome === "failed" ? "failed" : "unsupported";
    let endpoint: URL;
    try {
      endpoint = new URL(definition.endpoint);
    } catch {
      return "failed";
    }
    if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password) return "failed";
    const signal = AbortSignal.any([input.signal, AbortSignal.timeout(this.timeoutMs)]);

    for (const token of tokens) {
      if (new TextEncoder().encode(token).byteLength > this.maxRequestBytes) {
        outcome = "failed";
        continue;
      }
      try {
        const headers = new Headers({ "content-type": definition.contentType });
        let body: string;
        if (definition.auth.type === "body") {
          body = new URLSearchParams({ [definition.auth.field]: token }).toString();
        } else {
          headers.set("authorization", `Bearer ${token}`);
          body = "null";
        }
        const response = await this.fetchFn(endpoint.toString(), {
          method: definition.method,
          headers,
          body,
          redirect: "error",
          signal,
        });
        const bytes = await readBoundedResponseBytes(response, {
          maxBytes: this.maxResponseBytes,
          fieldName: "Provider revocation response",
          createError: (message) => new Error(message),
        });
        if (!responseMatches(definition.response, response.status, new TextDecoder().decode(bytes))) outcome = "failed";
      } catch {
        outcome = "failed";
      }
    }
    return outcome;
  }
}

function responseMatches(response: OAuthRevocationResponse, status: number, body: string): boolean {
  if (response.body === "empty") {
    if (status === response.successStatus && body.trim() === "") return true;
    if (!response.alreadyRevoked || status !== response.alreadyRevoked.status) return false;
    const parsed = parseJsonRecord(body);
    return parsed ? response.alreadyRevoked.values.includes(String(parsed[response.alreadyRevoked.field])) : false;
  }
  if (response.body === "json_null") {
    if (status !== response.successStatus) return false;
    try {
      return JSON.parse(body) === null;
    } catch {
      return false;
    }
  }
  if (status !== response.successStatus) return false;
  const parsed = parseJsonRecord(body);
  if (!parsed) return false;
  if (parsed[response.successField] === response.successValue) return true;
  return response.alreadyRevoked
    ? response.alreadyRevoked.values.includes(String(parsed[response.alreadyRevoked.field]))
    : false;
}

function parseJsonRecord(body: string): Record<string, unknown> | undefined {
  try {
    const value: unknown = JSON.parse(body);
    return typeof value === "object" && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}
