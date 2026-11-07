import type { ResolvedCredential } from "../../core/types.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { OpenBaoReadResult } from "./openbao-client.ts";

import { assertProcessingActive } from "../../core/cancellation.ts";
import { OpenBaoClient, OpenBaoError } from "./openbao-client.ts";

interface ConnectionSecretBase {
  provider: string;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
  revision: number;
}

export type OpenBaoConnectionSecret = ConnectionSecretBase &
  (
    | { authType: "no_auth"; value: Record<string, never> }
    | { authType: "api_key"; value: { apiKey: string; values: Record<string, string> } }
    | { authType: "custom_credential"; value: { values: Record<string, string> } }
    | {
        authType: "oauth2";
        value: {
          accessToken: string;
          tokenType: string;
          expiresAt?: string;
          refreshToken?: string;
          providerSecret?: Record<string, unknown>;
        };
      }
  );

export interface OpenBaoSecretReference {
  secretRef: string;
  secretRevision: number;
}

/** Stores the complete credential payload; PostgreSQL owns only safe profile metadata. */
export class OpenBaoConnectionSecretStore {
  private readonly client: OpenBaoClient;

  constructor(client: OpenBaoClient) {
    this.client = client;
  }

  async create(
    scope: Readonly<SaasRequestScope>,
    connectionId: string,
    provider: string,
    credential: ResolvedCredential,
  ): Promise<OpenBaoSecretReference> {
    const path = connectionSecretPath(scope, connectionId);
    const now = new Date().toISOString();
    const record = toRecord(provider, credential, now, now, 1);
    assertProcessingActive(scope);
    const secretRevision = await this.client.write(path, { ...record }, 0, scope.requestSignal);
    assertExpectedRevision(secretRevision, 1, path);
    return { secretRef: path, secretRevision };
  }

  async read(
    scope: Readonly<SaasRequestScope>,
    connectionId: string,
    revision: number,
  ): Promise<OpenBaoConnectionSecret | undefined> {
    const path = connectionSecretPath(scope, connectionId);
    try {
      assertProcessingActive(scope);
      const result = await this.client.read<Record<string, unknown>>(path, revision, scope.requestSignal);
      assertExpectedRevision(result.revision, revision, path);
      return parseRecord(result.data, result.revision, path);
    } catch (error) {
      if (error instanceof OpenBaoError && error.code === "OPENBAO_NOT_FOUND") return undefined;
      throw error;
    }
  }

  async update(
    scope: Readonly<SaasRequestScope>,
    connectionId: string,
    provider: string,
    expectedRevision: number,
    credential: ResolvedCredential,
  ): Promise<number | false> {
    const path = connectionSecretPath(scope, connectionId);
    let result: OpenBaoReadResult<Record<string, unknown>>;
    try {
      assertProcessingActive(scope);
      result = await this.client.read<Record<string, unknown>>(path, undefined, scope.requestSignal);
    } catch (error) {
      if (error instanceof OpenBaoError && error.code === "OPENBAO_NOT_FOUND") return false;
      throw error;
    }
    if (result.revision !== expectedRevision) return false;
    const current = parseRecord(result.data, result.revision, path);
    const revision = expectedRevision + 1;
    const record = toRecord(provider, credential, current.createdAt, new Date().toISOString(), revision);
    try {
      assertProcessingActive(scope);
      const writtenRevision = await this.client.write(path, { ...record }, expectedRevision, scope.requestSignal);
      assertExpectedRevision(writtenRevision, revision, path);
      return writtenRevision;
    } catch (error) {
      if (error instanceof OpenBaoError && error.code === "OPENBAO_CONFLICT") return false;
      throw error;
    }
  }

  async delete(scope: Readonly<SaasRequestScope>, connectionId: string): Promise<void> {
    assertProcessingActive(scope);
    try {
      await this.client.delete(connectionSecretPath(scope, connectionId));
    } catch (error) {
      if (!(error instanceof OpenBaoError) || error.code !== "OPENBAO_NOT_FOUND") throw error;
    }
  }
}

function connectionSecretPath(scope: Readonly<SaasRequestScope>, connectionId: string): string {
  return `client-secrets/data/tenants/${segment(scope.tenantId, "tenantId")}/workspaces/${segment(scope.workspaceId, "workspaceId")}/integrations/connections/${segment(connectionId, "connectionId")}`;
}

function toRecord(
  provider: string,
  credential: ResolvedCredential,
  createdAt: string,
  updatedAt: string,
  revision: number,
): OpenBaoConnectionSecret {
  const base = {
    provider: requiredString(provider, "provider"),
    metadata: "metadata" in credential ? credential.metadata : {},
    createdAt,
    updatedAt,
    revision,
  };
  switch (credential.authType) {
    case "no_auth":
      return { ...base, authType: "no_auth", value: {} };
    case "api_key":
      return {
        ...base,
        authType: "api_key",
        value: { apiKey: credential.apiKey, values: credential.values },
      };
    case "custom_credential":
      return { ...base, authType: "custom_credential", value: { values: credential.values } };
    case "oauth2":
      return {
        ...base,
        authType: "oauth2",
        value: {
          accessToken: credential.accessToken,
          tokenType: credential.tokenType,
          ...(credential.expiresAt === undefined ? {} : { expiresAt: credential.expiresAt }),
          ...(credential.refreshToken === undefined ? {} : { refreshToken: credential.refreshToken }),
          ...(credential.providerSecret === undefined ? {} : { providerSecret: credential.providerSecret }),
        },
      };
  }
}

function parseRecord(data: Record<string, unknown>, revision: number, path: string): OpenBaoConnectionSecret {
  const provider = requiredStoredString(data.provider, path);
  const createdAt = requiredTimestamp(data.createdAt, path);
  const updatedAt = requiredTimestamp(data.updatedAt, path);
  assertExpectedRevision(data.revision, revision, path);
  const value = storedObject(data.value, path);
  const metadata = storedObject(data.metadata, path);

  switch (data.authType) {
    case "no_auth":
      return { provider, metadata, authType: "no_auth", value: {}, createdAt, updatedAt, revision };
    case "api_key":
      return {
        provider,
        metadata,
        authType: "api_key",
        value: {
          apiKey: requiredStoredString(value.apiKey, path),
          values: storedStringRecord(value.values, path),
        },
        createdAt,
        updatedAt,
        revision,
      };
    case "custom_credential":
      return {
        provider,
        metadata,
        authType: "custom_credential",
        value: { values: storedStringRecord(value.values, path) },
        createdAt,
        updatedAt,
        revision,
      };
    case "oauth2":
      return {
        provider,
        metadata,
        authType: "oauth2",
        value: {
          accessToken: requiredStoredString(value.accessToken, path),
          tokenType: requiredStoredString(value.tokenType, path),
          ...optionalStoredString(value.expiresAt, "expiresAt", path),
          ...optionalStoredString(value.refreshToken, "refreshToken", path),
          ...(value.providerSecret === undefined ? {} : { providerSecret: storedObject(value.providerSecret, path) }),
        },
        createdAt,
        updatedAt,
        revision,
      };
    default:
      throw invalid(path);
  }
}

function segment(value: string, name: string): string {
  if (!/^[A-Za-z0-9_-]{1,255}$/.test(value)) {
    throw new TypeError(`${name} contains invalid path characters`);
  }
  return value;
}

function requiredString(value: string, name: string): string {
  const normalized = value.trim();
  if (!normalized) throw new TypeError(`${name} must not be empty`);
  return normalized;
}

function requiredStoredString(value: unknown, path: string): string {
  if (typeof value !== "string" || !value) throw invalid(path);
  return value;
}

function requiredTimestamp(value: unknown, path: string): string {
  const timestamp = requiredStoredString(value, path);
  if (!Number.isFinite(Date.parse(timestamp))) throw invalid(path);
  return timestamp;
}

function storedObject(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw invalid(path);
  return value as Record<string, unknown>;
}

function storedStringRecord(value: unknown, path: string): Record<string, string> {
  const record = storedObject(value, path);
  if (Object.values(record).some((item) => typeof item !== "string")) throw invalid(path);
  return record as Record<string, string>;
}

function optionalStoredString(
  value: unknown,
  key: "expiresAt" | "refreshToken",
  path: string,
): { expiresAt?: string; refreshToken?: string } {
  if (value === undefined) return {};
  return { [key]: requiredStoredString(value, path) };
}

function assertExpectedRevision(actual: unknown, expected: number, path: string): void {
  if (!Number.isSafeInteger(expected) || expected <= 0 || actual !== expected) throw invalid(path);
}

function invalid(path: string): OpenBaoError {
  return new OpenBaoError("OPENBAO_INVALID_RESPONSE", path);
}
