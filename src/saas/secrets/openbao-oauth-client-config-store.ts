import type { OAuth2AuthDefinition } from "../../core/types.ts";
import type { IOAuthClientConfigStore, OAuthClientConfig } from "../../oauth/oauth-client-config-service.ts";
import type { OAuthClientConfigReadiness } from "../contracts.ts";

import { OpenBaoClient, OpenBaoError } from "./openbao-client.ts";

interface StoredOAuthClientConfig extends OAuthClientConfig {
  revision: number;
  createdAt: string;
  updatedAt: string;
}
export interface OAuthClientConfigProbeTarget {
  service: string;
  auth: OAuth2AuthDefinition;
}

const APPLICATIONS_DATA_PATH = "service-secrets/data/integration-provider-applications";
const APPLICATIONS_METADATA_PATH = "service-secrets/metadata/integration-provider-applications";
const OAUTH_PROBE_CONCURRENCY = 8;

/** Global platform OAuth applications. Tenant-specific overrides are intentionally impossible. */
export class OpenBaoOAuthClientConfigStore implements IOAuthClientConfigStore {
  private readonly client: OpenBaoClient;

  constructor(client: OpenBaoClient) {
    this.client = client;
  }

  async get(service: string): Promise<OAuthClientConfig | undefined> {
    const path = applicationPath(service);
    try {
      const result = await this.client.read<Record<string, unknown>>(path);
      const record = parseRecord(result.data, result.revision, path);
      if (record.service !== service) throw invalid(path);
      return {
        service: record.service,
        clientId: record.clientId,
        clientSecret: record.clientSecret,
        extra: record.extra,
        secretExtra: record.secretExtra,
        redirectUri: record.redirectUri,
        requestedScopes: record.requestedScopes,
      };
    } catch (error) {
      if (error instanceof OpenBaoError && error.code === "OPENBAO_NOT_FOUND") return undefined;
      throw error;
    }
  }
  async probe(service: string, auth: OAuth2AuthDefinition): Promise<OAuthClientConfigReadiness> {
    try {
      const config = await this.get(service);
      if (!config) return { status: "unavailable", reasonCode: "oauth_client_config_missing" };
      validateConfig(config, auth, applicationPath(service));
      return { status: "operational" };
    } catch (error) {
      if (error instanceof OpenBaoError && error.code === "OPENBAO_INVALID_RESPONSE") {
        return { status: "unavailable", reasonCode: "oauth_client_config_invalid" };
      }
      if (error instanceof OpenBaoError && error.code === "OPENBAO_FORBIDDEN") {
        return { status: "unavailable", reasonCode: "oauth_client_config_access_denied" };
      }
      throw error;
    }
  }
  async probeAll(
    targets: readonly OAuthClientConfigProbeTarget[],
  ): Promise<ReadonlyMap<string, OAuthClientConfigReadiness>> {
    const entries = new Array<readonly [string, OAuthClientConfigReadiness]>(targets.length);
    let nextIndex = 0;
    await Promise.all(
      Array.from({ length: Math.min(OAUTH_PROBE_CONCURRENCY, targets.length) }, async () => {
        while (nextIndex < targets.length) {
          const index = nextIndex;
          nextIndex += 1;
          const target = targets[index]!;
          entries[index] = [target.service, await this.probe(target.service, target.auth)];
        }
      }),
    );
    return new Map(entries);
  }

  async set(config: OAuthClientConfig): Promise<void> {
    const path = applicationPath(config.service);
    const current = await this.readStored(path);
    if (current && current.service !== config.service) throw invalid(path);
    const expectedRevision = current?.revision ?? 0;
    const revision = expectedRevision + 1;
    const now = new Date().toISOString();
    const record: StoredOAuthClientConfig = {
      service: required(config.service, "service"),
      clientId: required(config.clientId, "clientId"),
      clientSecret: config.clientSecret,
      extra: stringRecord(config.extra, path),
      secretExtra: stringRecord(config.secretExtra, path),
      redirectUri: config.redirectUri,
      requestedScopes: config.requestedScopes,
      revision,
      createdAt: current?.createdAt ?? now,
      updatedAt: now,
    };
    const written = await this.client.write(path, { ...record }, expectedRevision);
    if (written !== revision) throw invalid(path);
  }

  async delete(service: string): Promise<void> {
    await this.client.delete(applicationPath(service));
  }

  async list(): Promise<OAuthClientConfig[]> {
    let services: string[];
    try {
      services = await this.client.list(APPLICATIONS_METADATA_PATH);
    } catch (error) {
      if (error instanceof OpenBaoError && error.code === "OPENBAO_NOT_FOUND") return [];
      throw error;
    }
    const configs = await Promise.all(
      services.filter((service) => !service.endsWith("/")).map((service) => this.get(service)),
    );
    return configs.filter((config): config is OAuthClientConfig => config !== undefined);
  }

  private async readStored(path: string): Promise<StoredOAuthClientConfig | undefined> {
    try {
      const result = await this.client.read<Record<string, unknown>>(path);
      return parseRecord(result.data, result.revision, path);
    } catch (error) {
      if (error instanceof OpenBaoError && error.code === "OPENBAO_NOT_FOUND") return undefined;
      throw error;
    }
  }
}

function applicationPath(service: string): string {
  if (!/^[A-Za-z0-9_-]{1,255}$/.test(service)) {
    throw new TypeError("service contains invalid path characters");
  }
  return `${APPLICATIONS_DATA_PATH}/${service}`;
}

function parseRecord(data: Record<string, unknown>, revision: number, path: string): StoredOAuthClientConfig {
  if (data.revision !== revision) throw invalid(path);
  return {
    service: storedString(data.service, path),
    clientId: storedString(data.clientId, path),
    clientSecret: typeof data.clientSecret === "string" ? data.clientSecret : invalidValue(path),
    extra: stringRecord(data.extra, path),
    secretExtra: stringRecord(data.secretExtra, path),
    redirectUri: data.redirectUri === undefined ? undefined : storedString(data.redirectUri, path),
    requestedScopes: data.requestedScopes === undefined ? undefined : stringArray(data.requestedScopes, path),
    revision,
    createdAt: timestamp(data.createdAt, path),
    updatedAt: timestamp(data.updatedAt, path),
  };
}
function validateConfig(config: OAuthClientConfig, auth: OAuth2AuthDefinition, path: string): void {
  if (
    !config.clientId ||
    config.clientId.trim() !== config.clientId ||
    config.clientSecret.trim() !== config.clientSecret
  ) {
    throw invalid(path);
  }
  if (auth.tokenEndpointAuthMethod !== "none" && !config.clientSecret) throw invalid(path);

  const fields = auth.clientConfigFields ?? [];
  const expectedExtra = new Set(
    fields.filter((field) => (field.location ?? "extra") === "extra").map((field) => field.key),
  );
  const expectedSecretExtra = new Set(
    fields.filter((field) => field.location === "secretExtra").map((field) => field.key),
  );
  if (
    Object.keys(config.extra).some((key) => !expectedExtra.has(key)) ||
    Object.keys(config.secretExtra).some((key) => !expectedSecretExtra.has(key))
  ) {
    throw invalid(path);
  }
  for (const field of fields) {
    const values = field.location === "secretExtra" ? config.secretExtra : config.extra;
    const value = values[field.key];
    if (value !== undefined && value.trim() !== value) throw invalid(path);
    if ((field.required || field.defaultValue !== undefined) && !value) throw invalid(path);
  }
}

function required(value: string, name: string): string {
  const normalized = value.trim();
  if (!normalized) throw new TypeError(`${name} must not be empty`);
  return normalized;
}

function storedString(value: unknown, path: string): string {
  if (typeof value !== "string" || !value) return invalidValue(path);
  return value;
}

function timestamp(value: unknown, path: string): string {
  const result = storedString(value, path);
  if (!Number.isFinite(Date.parse(result))) throw invalid(path);
  return result;
}

function stringArray(value: unknown, path: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !item)) throw invalid(path);
  return value;
}

function stringRecord(value: unknown, path: string): Record<string, string> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw invalid(path);
  const record = value as Record<string, unknown>;
  if (Object.values(record).some((item) => typeof item !== "string")) throw invalid(path);
  return record as Record<string, string>;
}

function invalidValue(path: string): never {
  throw invalid(path);
}

function invalid(path: string): OpenBaoError {
  return new OpenBaoError("OPENBAO_INVALID_RESPONSE", path);
}
