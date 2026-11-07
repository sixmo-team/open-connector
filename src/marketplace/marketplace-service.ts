import type { CatalogStore } from "../catalog-store.ts";
import type { ConnectionSummary } from "../connection-service.ts";
import type { IConnectionStore, StoredConnection, StoredLocalConnection } from "../connection-store.ts";
import type { ExecutionResult } from "../core/types.ts";
import type { SaasRequestScope } from "../saas/contracts.ts";

import { normalizeConnectionName } from "../connection-service.ts";
import { assertProcessingActive, captureRequestProcessing, remainingProcessingMs } from "../core/cancellation.ts";
import {
  isFailureEnvelope,
  isSuccessEnvelope,
  readRemoteJson,
  RemoteHttpError,
  requestRemote,
} from "../core/remote-http.ts";
import { isAbortLikeError } from "../providers/provider-runtime.ts";
import { maximumActionOutputBytes } from "../saas/contracts.ts";
import { defaultMarketplaceDiscoveryUrl } from "./default-marketplace.ts";

export type MarketplacePricing = "free" | "metered";
export interface MarketplaceDiscovery {
  version: 1;
  id: string;
  name: string;
  pricing: MarketplacePricing;
  validate: string;
  endpoint: string;
  actions: string[];
}
export interface MarketplaceDiscoverySummary {
  version: 1;
  name: string;
  actions: string[];
}
export interface MarketplaceConnectInput {
  discoveryUrl?: string;
  apiKey: string;
  connectionName: string;
  /** Explicit opt-in, never all discovered actions or a wildcard. This does not grant OO permission. */
  actionIds: string[];
}
export interface MarketplaceServiceOptions {
  scope: Readonly<SaasRequestScope>;
  catalog: CatalogStore;
  store: IConnectionStore;
  fetcher?: typeof fetch;
}
interface MarketplaceBinding {
  version: 1;
  tenantId: string;
  workspaceId: string;
  localConnectionId: string;
  discoveryUrl: string;
  marketplaceId: string;
  actionIds: string[];
}
interface MarketplaceSelection {
  connection: StoredLocalConnection;
  binding: MarketplaceBinding;
  definition: MarketplaceDiscovery;
}
export class MarketplaceError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, message: string, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}
/** Reserved routing metadata is created only by connect(), not provider credential validators. */
export function hasMarketplaceBinding(connection: StoredConnection): boolean {
  return (
    connection.source !== "saas" &&
    connection.credential.authType !== "no_auth" &&
    Object.hasOwn(connection.credential.metadata, "nativeMarketplace")
  );
}

/** One verified request and one real persisted credential lineage; no global configuration or virtual accounts. */
export class MarketplaceService {
  private readonly scope: Readonly<SaasRequestScope>;
  private selection?: MarketplaceSelection;
  private readonly options: MarketplaceServiceOptions;
  constructor(options: MarketplaceServiceOptions) {
    this.options = options;
    this.scope = captureRequestProcessing(
      Object.freeze({ ...options.scope, permissions: [...options.scope.permissions] }),
    );
  }
  async getDefaultDiscovery(signal?: AbortSignal): Promise<MarketplaceDiscoverySummary> {
    const definition = await this.discover(defaultMarketplaceDiscoveryUrl, this.signal(signal));
    return { version: 1, name: definition.name, actions: definition.actions };
  }
  async connect(service: string, input: MarketplaceConnectInput): Promise<ConnectionSummary> {
    const signal = this.signal();
    if (
      this.scope.purpose !== "connection:write" ||
      this.scope.actorUserId !== this.scope.subjectUserId ||
      !this.scope.localConnectionId
    )
      throw new MarketplaceError(
        "forbidden",
        "Marketplace connect requires the exact interactive credential owner.",
        403,
      );
    if (!this.options.catalog.providers.some((provider) => provider.service === service))
      throw new MarketplaceError("unknown_service", "Unknown Marketplace provider.", 404);
    if (typeof input.apiKey !== "string" || !input.apiKey.trim() || /[\r\n]/.test(input.apiKey))
      throw new MarketplaceError("invalid_input", "A Marketplace API key is required.");
    const connectionName = normalizeConnectionName(input.connectionName);
    const existing = await this.options.store.get(service, connectionName);
    if (existing)
      throw new MarketplaceError(
        "connection_changed",
        "Disconnect the existing connection before selecting Marketplace.",
        409,
      );
    const generation = await this.options.store.getRetirementGeneration(service, connectionName);
    const discoveryUrl = input.discoveryUrl ?? defaultMarketplaceDiscoveryUrl;
    const definition = await this.discover(discoveryUrl, signal);
    const actionIds = this.validateActions(service, input.actionIds, definition);
    // Native validation proves authorization only. The vendor protocol supplies no verified account identity.
    await this.validateApiKey(discoveryUrl, definition.validate, input.apiKey.trim(), signal);
    assertProcessingActive(this.scope);
    signal?.throwIfAborted();
    const binding: MarketplaceBinding = {
      version: 1,
      tenantId: this.scope.tenantId,
      workspaceId: this.scope.workspaceId,
      localConnectionId: this.scope.localConnectionId,
      discoveryUrl,
      marketplaceId: definition.id,
      actionIds,
    };
    const stored = await this.options.store.setIfCurrentGeneration(
      service,
      connectionName,
      {
        authType: "api_key",
        apiKey: input.apiKey.trim(),
        values: {},
        profile: { accountId: this.scope.localConnectionId, displayName: definition.name, grantedScopes: [] },
        metadata: { nativeMarketplace: binding, providerAccountVerified: false },
      },
      generation,
    );
    if (!stored)
      throw new MarketplaceError("connection_changed", "The connection was retired during Marketplace setup.", 409);
    this.selection = { connection: stored, binding, definition };
    return this.summary(this.selection);
  }
  async getConnectionSummary(connection: StoredLocalConnection): Promise<ConnectionSummary> {
    return this.summary(await this.select(connection));
  }
  supportsAction(actionId: string): boolean {
    return (
      this.selection?.binding.actionIds.includes(actionId) === true &&
      this.selection.definition.actions.includes(actionId)
    );
  }
  async execute(actionId: string, input: unknown, signal?: AbortSignal): Promise<ExecutionResult> {
    signal = this.signal(signal);
    if (
      this.scope.purpose !== "action:execute:v2" ||
      this.scope.actionId !== actionId ||
      !this.scope.connectorConnectionId
    )
      throw new MarketplaceError(
        "forbidden",
        "Marketplace execution requires an exact signed action and connection.",
        403,
      );
    const stored = await this.options.store.getById(this.scope.connectorConnectionId);
    if (!stored || stored.source === "saas" || !hasMarketplaceBinding(stored))
      throw new MarketplaceError("connection_not_found", "Marketplace connection is unavailable.", 404);
    const selected = await this.select(stored, signal);
    if (!this.supportsAction(actionId))
      throw new MarketplaceError("connection_not_found", "This Marketplace action was not explicitly selected.", 404);
    assertProcessingActive(this.scope);
    signal?.throwIfAborted();
    let payload: unknown;
    try {
      payload = await requestRemote(
        {
          url: new URL(
            `${selected.definition.endpoint}/${encodeURIComponent(actionId)}`,
            selected.binding.discoveryUrl,
          ),
          label: "Marketplace action",
          fetcher: this.options.fetcher,
          requireHttps: false,
          allowTrustedHosts: true,
          init: {
            method: "POST",
            headers: {
              authorization: `Bearer ${stored.credential.authType === "api_key" ? stored.credential.apiKey : ""}`,
              "content-type": "application/json",
            },
            body: JSON.stringify({ input }),
            signal,
          },
        },
        (response, signal) =>
          readRemoteJson(response, {
            label: "Marketplace action response",
            maxBytes: maximumActionOutputBytes,
            signal,
          }),
      );
    } catch (error) {
      signal?.throwIfAborted();
      return {
        ok: false,
        error: {
          code: "marketplace_unavailable",
          message: error instanceof RemoteHttpError ? error.message : "Marketplace request failed.",
        },
      };
    }
    if (isSuccessEnvelope(payload)) return { ok: true, output: payload.data };
    if (isFailureEnvelope(payload))
      return { ok: false, error: { code: payload.errorCode, message: payload.message, details: payload.data } };
    return {
      ok: false,
      error: { code: "provider_error", message: "Marketplace returned an invalid action response." },
    };
  }
  private async select(connection: StoredLocalConnection, signal = this.signal()): Promise<MarketplaceSelection> {
    assertProcessingActive(this.scope);
    const current = await this.options.store.getById(connection.id);
    if (
      !current ||
      current.source === "saas" ||
      current.revision !== connection.revision ||
      (this.scope.connectorConnectionId && current.id !== this.scope.connectorConnectionId) ||
      current.credential.authType !== "api_key" ||
      !hasMarketplaceBinding(current)
    )
      throw new MarketplaceError("connection_changed", "Marketplace credential no longer matches this request.", 409);
    const value = current.credential.metadata.nativeMarketplace;
    if (!value || typeof value !== "object")
      throw new MarketplaceError("connection_not_found", "Marketplace configuration is invalid.", 404);
    const binding = value as MarketplaceBinding;
    if (
      binding.version !== 1 ||
      binding.tenantId !== this.scope.tenantId ||
      binding.workspaceId !== this.scope.workspaceId ||
      binding.localConnectionId !== this.scope.localConnectionId ||
      typeof binding.discoveryUrl !== "string" ||
      typeof binding.marketplaceId !== "string"
    )
      throw new MarketplaceError(
        "connection_not_found",
        "Marketplace configuration does not match the verified lineage.",
        404,
      );
    const cached = this.selection;
    const definition =
      cached?.connection.id === current.id && cached.connection.revision === current.revision
        ? cached.definition
        : await this.discover(binding.discoveryUrl, signal);
    if (definition.id !== binding.marketplaceId)
      throw new MarketplaceError("connection_changed", "Marketplace identity changed.", 409);
    this.validateActions(current.service, binding.actionIds, definition);
    signal?.throwIfAborted();
    return (this.selection = { connection: current, binding, definition });
  }
  private summary({ connection, definition }: MarketplaceSelection): ConnectionSummary {
    if (connection.credential.authType !== "api_key")
      throw new MarketplaceError("connection_not_found", "Marketplace credential is unavailable.", 404);
    return {
      id: connection.id,
      service: connection.service,
      connectionName: connection.connectionName,
      authType: "marketplace",
      configured: true,
      status: "active",
      virtual: false,
      default: connection.connectionName === "default",
      profile: connection.credential.profile,
      marketplace: { id: definition.id, pricing: definition.pricing },
    };
  }
  private validateActions(service: string, actionIds: string[], definition: MarketplaceDiscovery): string[] {
    if (
      !Array.isArray(actionIds) ||
      !actionIds.length ||
      actionIds.length > 5000 ||
      new Set(actionIds).size !== actionIds.length ||
      actionIds.some(
        (id) =>
          typeof id !== "string" ||
          this.options.catalog.actionsById.get(id)?.service !== service ||
          !definition.actions.includes(id),
      )
    )
      throw new MarketplaceError(
        "invalid_input",
        "Select distinct current Marketplace action IDs for this provider explicitly.",
      );
    return [...actionIds];
  }
  private signal(signal?: AbortSignal): AbortSignal | undefined {
    const remaining = remainingProcessingMs(this.scope);
    const signals = [
      this.scope.requestSignal,
      signal,
      remaining === undefined ? undefined : AbortSignal.timeout(remaining),
    ].filter((value): value is AbortSignal => value !== undefined);
    const bounded = signals.length ? AbortSignal.any(signals) : undefined;
    bounded?.throwIfAborted();
    return bounded;
  }
  private async discover(discoveryUrl: string, signal?: AbortSignal): Promise<MarketplaceDiscovery> {
    try {
      return await requestRemote(
        {
          url: discoveryUrl,
          label: "Marketplace discovery",
          fetcher: this.options.fetcher,
          requireHttps: false,
          allowTrustedHosts: true,
          timeoutMs: 15_000,
          init: { headers: { accept: "application/json" }, signal },
        },
        async (response, signal) => {
          if (!response.ok)
            throw new MarketplaceError(
              "marketplace_unavailable",
              `Marketplace discovery failed with HTTP ${response.status}.`,
              502,
            );
          return parseDiscovery(
            await readRemoteJson(response, { label: "Marketplace discovery", maxBytes: 4 * 1024 * 1024, signal }),
            new URL(discoveryUrl),
          );
        },
      );
    } catch (error) {
      signal?.throwIfAborted();
      if (error instanceof MarketplaceError) throw error;
      if (isAbortLikeError(error))
        throw new MarketplaceError("marketplace_unavailable", "Marketplace request timed out.", 504);
      if (
        error instanceof RemoteHttpError &&
        ["too_large", "invalid_url", "redirect", "invalid_json"].includes(error.kind)
      )
        throw new MarketplaceError("invalid_marketplace_discovery", error.message);
      throw new MarketplaceError(
        "marketplace_unavailable",
        error instanceof RemoteHttpError ? error.message : "Marketplace discovery failed.",
        502,
      );
    }
  }
  private async validateApiKey(
    discoveryUrl: string,
    path: string,
    apiKey: string,
    signal?: AbortSignal,
  ): Promise<void> {
    try {
      await requestRemote(
        {
          url: new URL(path, discoveryUrl),
          label: "Marketplace validation",
          fetcher: this.options.fetcher,
          requireHttps: false,
          allowTrustedHosts: true,
          timeoutMs: 15_000,
          init: { method: "POST", headers: { authorization: `Bearer ${apiKey}` }, signal },
        },
        async (response) => {
          if (response.status === 204) return;
          if (response.status === 401 || response.status === 403)
            throw new MarketplaceError(
              "marketplace_auth_error",
              "The Marketplace API key is invalid or not permitted.",
              response.status,
            );
          throw new MarketplaceError(
            "marketplace_unavailable",
            `Marketplace validation failed with HTTP ${response.status}.`,
            502,
          );
        },
      );
    } catch (error) {
      signal?.throwIfAborted();
      if (error instanceof MarketplaceError) throw error;
      if (isAbortLikeError(error))
        throw new MarketplaceError("marketplace_unavailable", "Marketplace request timed out.", 504);
      throw new MarketplaceError(
        "marketplace_unavailable",
        error instanceof RemoteHttpError ? error.message : "Marketplace validation request failed.",
        502,
      );
    }
  }
}
function parseDiscovery(value: unknown, discoveryUrl: URL): MarketplaceDiscovery {
  if (!value || typeof value !== "object")
    throw new MarketplaceError("invalid_marketplace_discovery", "Marketplace discovery must be an object.");
  const record = value as Record<string, unknown>;
  if (
    record.version !== 1 ||
    typeof record.id !== "string" ||
    !record.id ||
    typeof record.name !== "string" ||
    !record.name ||
    (record.pricing !== "free" && record.pricing !== "metered") ||
    !isAbsolutePath(record.validate) ||
    !isAbsolutePath(record.endpoint) ||
    !Array.isArray(record.actions) ||
    !record.actions.every((item) => typeof item === "string" && item.includes("."))
  )
    throw new MarketplaceError(
      "invalid_marketplace_discovery",
      "Marketplace discovery does not match the v1 contract.",
    );
  for (const path of [record.validate, record.endpoint] as string[])
    if (new URL(path, discoveryUrl).origin !== discoveryUrl.origin)
      throw new MarketplaceError(
        "invalid_marketplace_discovery",
        "Marketplace endpoints must use the discovery origin.",
      );
  const actions = [...new Set(record.actions as string[])];
  if (actions.length !== record.actions.length)
    throw new MarketplaceError("invalid_marketplace_discovery", "Marketplace action IDs must be unique.");
  return {
    version: 1,
    id: record.id,
    name: record.name,
    pricing: record.pricing,
    validate: record.validate as string,
    endpoint: record.endpoint as string,
    actions,
  };
}
function isAbsolutePath(value: unknown): boolean {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//")) return false;
  const url = new URL(value, "https://marketplace.invalid");
  return !url.username && !url.password && !url.search && !url.hash;
}
