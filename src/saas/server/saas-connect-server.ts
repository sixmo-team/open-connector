import type {
  CatalogStore,
  RuntimeActionDefinition,
  RuntimeActionSummary,
  RuntimeProviderDefinition,
} from "../../catalog-store.ts";
import type { ActionSearchIndexProvider } from "../../core/action-search.ts";
import type { CredentialDefinition } from "../../core/types.ts";
import type { MarketplaceService } from "../../marketplace/marketplace-service.ts";
import type { IOAuthCredentialRefresher } from "../../oauth/oauth-credential-refresh-service.ts";
import type { IProviderLoader } from "../../providers/provider-loader.ts";
import type { ActionPolicyJwtVerifier, SaasJwtVerifier } from "../auth/saas-jwt-verifier.ts";
import type { SaasHonoEnvironment } from "../auth/scoped-request.ts";
import type { SaasProviderCredentialRevoker } from "../connections/provider-credential-revoker.ts";
import type { OAuthClientConfigReadiness } from "../contracts.ts";
import type {
  ConnectionTransferInput,
  ConnectionVisibilityInput,
  LifecyclePurgeInput,
  SaasRequestScope,
  ConnectorCredentialInput,
  ConnectorCredentialReplacementInput,
  SafeActionCatalog,
  SafeActionCatalogPage,
  SafeActionSummary,
  SafeCredentialField,
  SafeProviderCatalog,
} from "../contracts.ts";
import type { ScopedLifecycleService } from "../lifecycle/scoped-lifecycle-service.ts";
import type { SaasOAuthService } from "../oauth/saas-oauth-service.ts";
import type { SaasExecutionService } from "../saas-execution-service.ts";
import type { SaasRuntimeDatabase, SaasRuntimeDatabaseFactory } from "../storage/postgres-runtime-database.ts";
import type { RunLog, RunLogCaller, RunLogListInput } from "../storage/run-store.ts";
import type { TriggerLifecycleCleanup } from "../triggers/postgres-trigger-store.ts";
import type { SaasTriggerRunner } from "../triggers/saas-trigger-runner.ts";
import type { Context, Hono as HonoApp, MiddlewareHandler } from "hono";

import { Hono } from "hono";
import { createHash } from "node:crypto";
import { z } from "zod/v4";
import { ConnectionError } from "../../connection-error.ts";
import { createActionSearchIndexProvider, searchActions } from "../../core/action-search.ts";
import { assertProcessingActive, waitForSignal, withRequestProcessing } from "../../core/cancellation.ts";
import { PromiseCache } from "../../core/promise-cache.ts";
import { OAuthFlowError } from "../../oauth/oauth-flow-service.ts";
import { canonicalActionRequestHash, canonicalRequestHash } from "../actions/canonical-request.ts";
import { SaasActionRunner } from "../actions/saas-action-runner.ts";
import { SaasAuthorizationError } from "../auth/saas-jwt-verifier.ts";
import { getSaasRequestScope, requireCatalogPurpose, requireSaasPurpose } from "../auth/scoped-request.ts";
import { toSafeConnectionSummary } from "../connections/safe-connection-summary.ts";
import { createScopedConnectionService } from "../connections/scoped-connection-service.ts";
import {
  connectionTransferInputSchema,
  connectionVisibilityInputSchema,
  connectorCredentialInputSchema,
  connectorCredentialReplacementInputSchema,
  lifecyclePurgeInputSchema,
} from "../contracts.ts";
import { TransitFileError } from "../files/transit-file-store.ts";
import {
  LifecyclePurgeConflictError,
  LifecycleReconciliationRequiredError,
} from "../lifecycle/scoped-lifecycle-service.ts";
import { SaasError } from "../saas-client.ts";
import { decodeRunLogCursor } from "../storage/run-store.ts";
import { registerScopedTriggerRoutes } from "../triggers/scoped-trigger-routes.ts";
import { registerActionPolicyRoutes } from "./action-policy-routes.ts";
import { exactQuery, JsonBodyTooLargeError, readBoundedJson, runScopedHttpOperation } from "./http-input.ts";
import { registerMaintenanceRoutes } from "./maintenance-routes.ts";
import { registerMarketplaceRoutes } from "./marketplace-routes.ts";
import { registerNativeLifecycleRoutes } from "./native-lifecycle-routes.ts";

export interface SaasDependencyReadiness {
  postgres: boolean;
  openBao: boolean;
  jwks: boolean;
  seaweedFs: boolean;
  providerRegistry: boolean;
  catalogFingerprint: boolean;
}

export interface SaasConnectServerOptions {
  catalog: CatalogStore;
  providerLoader: IProviderLoader;
  verifyJwt: SaasJwtVerifier;
  verifyActionPolicyJwt?: ActionPolicyJwtVerifier;
  policyControlActiveKid?: string;
  readiness: () => Promise<Readonly<SaasDependencyReadiness>>;
  oauthCredentials?: IOAuthCredentialRefresher;
  oauthClientReadiness?: ReadonlyMap<string, OAuthClientConfigReadiness>;
  refreshOAuthClientReadiness?: () => Promise<ReadonlyMap<string, OAuthClientConfigReadiness>>;
  scopedOAuthClientReadiness?: (
    scope: Readonly<SaasRequestScope>,
    local: ReadonlyMap<string, OAuthClientConfigReadiness>,
  ) => Promise<ReadonlyMap<string, OAuthClientConfigReadiness>>;
  nativeExecutionForScope?: (
    scope: Readonly<SaasRequestScope>,
    runtime: SaasRuntimeDatabase,
  ) => {
    saasExecution: Pick<SaasExecutionService, "executeAction">;
    marketplace: MarketplaceService;
  };
  triggerRunnerForScope?: (scope: Readonly<SaasRequestScope>) => Pick<SaasTriggerRunner, "run">;
  triggerCleanupForScope?: (scope: Readonly<SaasRequestScope>) => TriggerLifecycleCleanup;
  maintenanceForScope?: (scope: Readonly<SaasRequestScope>) => Promise<void>;
  runtimeDatabaseFactory?: Pick<SaasRuntimeDatabaseFactory, "forScope" | "actionPolicy"> &
    Partial<Pick<SaasRuntimeDatabaseFactory, "nativeConfiguration" | "nativeLifecycleInventory">> & {
      lifecycleForScope?: (
        scope: Readonly<SaasRequestScope>,
        credentialRevoker?: SaasProviderCredentialRevoker,
        triggerCleanup?: TriggerLifecycleCleanup,
      ) => Pick<ScopedLifecycleService, "exportPage" | "purge">;
    };
  oauthServiceFactory?: {
    forScope(scope: Readonly<SaasRequestScope>): SaasOAuthService;
  };
  credentialRevoker?: SaasProviderCredentialRevoker;
}

/** Private listener containing only fail-closed SaaS routes. */
export class SaasConnectServer {
  private readonly options: SaasConnectServerOptions;
  private readonly safeProviders: SafeProviderCatalog[];
  private readonly catalogFingerprint = new PromiseCache<string>();
  private readonly actionSearch: ActionSearchIndexProvider;
  private providerReadinessExpiresAt = 0;
  private providerReadinessRefresh?: Promise<void>;
  private localOAuthClientReadiness: ReadonlyMap<string, OAuthClientConfigReadiness>;

  constructor(options: SaasConnectServerOptions) {
    this.options = options;
    this.localOAuthClientReadiness = options.oauthClientReadiness ?? new Map();
    this.safeProviders = options.catalog.providers.map((provider) =>
      toSafeProvider(provider, options.oauthClientReadiness?.get(provider.service)),
    );
    this.actionSearch = createActionSearchIndexProvider(options.catalog.actions);
  }

  getCatalogFingerprint(): Promise<string> {
    return this.catalogFingerprint.get("immutable-catalog", async () => {
      const providers = this.safeProviders.map((provider) => ({
        ...provider,
        connectionMethods: provider.connectionMethods.map(({ type, fields }) => ({ type, fields })),
      }));
      const hash = createHash("sha256")
        .update('{"providers":')
        .update(JSON.stringify(providers))
        .update(',"actions":[');
      let separator = "";
      // ponytail: scan schemas once without retaining them; generate this digest if startup becomes the bottleneck.
      for (const summary of this.options.catalog.actions) {
        const action = await this.options.catalog.getAction(summary.id);
        if (!action) throw new Error("Catalog action definition is unavailable");
        hash.update(separator).update(JSON.stringify(toSafeAction(action)));
        separator = ",";
      }
      return hash.update("]}").digest("base64url");
    });
  }

  private async refreshProviderReadiness(): Promise<void> {
    const refresh = this.options.refreshOAuthClientReadiness;
    if (!refresh || Date.now() < this.providerReadinessExpiresAt) return;
    this.providerReadinessRefresh ??= (async () => {
      const readiness = await refresh();
      assertProcessingActive();
      this.localOAuthClientReadiness = readiness;
      for (let index = 0; index < this.options.catalog.providers.length; index++) {
        const provider = this.options.catalog.providers[index]!;
        this.safeProviders[index] = toSafeProvider(
          provider,
          readiness.get(provider.service),
          this.safeProviders[index],
        );
      }
      // ponytail: technical configuration can lag five seconds; invalidate this cache on writes if instant refresh is needed.
      this.providerReadinessExpiresAt = Date.now() + 5000;
    })().finally(() => {
      this.providerReadinessRefresh = undefined;
    });
    await this.providerReadinessRefresh;
  }

  createApp(): HonoApp<SaasHonoEnvironment> {
    const app = new Hono<SaasHonoEnvironment>();
    app.use("/internal/*", (context, next) => {
      const processing = Object.freeze({
        processingDeadlineMs: Date.now() + 120_000,
        // Reserve five seconds for bounded secret reconciliation inside the same hard deadline.
        requestSignal: AbortSignal.any([context.req.raw.signal, AbortSignal.timeout(115_000)]),
      });
      return withRequestProcessing(processing, async () => {
        try {
          await waitForSignal(next(), processing.requestSignal);
        } catch (error) {
          if (processing.requestSignal.aborted) return context.json({ error: "request_processing_timeout" }, 503);
          throw error;
        }
      });
    });
    registerActionPolicyRoutes(app, this.options);
    registerNativeLifecycleRoutes(app, this.options);
    registerMarketplaceRoutes(app, this.options);
    registerMaintenanceRoutes(app, this.options);
    registerScopedTriggerRoutes(app, {
      verifyJwt: this.options.verifyJwt,
      createRunner: (scope) => {
        const runner = this.options.triggerRunnerForScope?.(scope);
        if (!runner) throw new Error("Scoped native Trigger runtime is unavailable");
        return runner;
      },
    });

    app.get("/health", (context) => context.json({ ok: true }));
    app.get("/ready", async (context) => {
      const readiness = await this.options.readiness();
      if (!Object.values(readiness).every(Boolean)) return context.json({ ok: false }, 503);
      try {
        await this.getCatalogFingerprint();
        return context.json({ ok: true });
      } catch {
        return context.json({ ok: false }, 503);
      }
    });

    app.get("/internal/saas/catalog/providers", requireCatalogPurpose(this.options.verifyJwt), async (context) => {
      if (!exactQuery(context, [])) return invalidInput(context);
      try {
        await this.refreshProviderReadiness();
        return context.json(this.safeProviders);
      } catch {
        return context.json({ error: "oauth_client_readiness_unavailable" }, 503);
      }
    });
    app.get(
      "/internal/saas/catalog/providers/scoped",
      requireSaasPurpose(this.options.verifyJwt, "connection:read"),
      (context) =>
        runScopedHttpOperation(context, "catalog_unavailable", async () => {
          if (!exactQuery(context, [])) throw new SyntaxError("Unexpected query");
          const scope = getSaasRequestScope(context, "connection:read");
          if (scope.actorUserId !== scope.subjectUserId) throw new SaasAuthorizationError(403);
          const resolve = this.options.scopedOAuthClientReadiness;
          if (!resolve) throw new Error("Scoped OAuth source readiness is unavailable");
          await this.refreshProviderReadiness();
          const readiness = await resolve(scope, this.localOAuthClientReadiness);
          assertProcessingActive(scope);
          return context.json(
            this.options.catalog.providers.map((provider, index) =>
              toSafeProvider(provider, readiness.get(provider.service), this.safeProviders[index]),
            ),
          );
        }),
    );
    app.get("/internal/saas/catalog/actions", requireCatalogPurpose(this.options.verifyJwt), (context) =>
      listCatalogActions(context, this.options.catalog, this.getCatalogFingerprint()),
    );
    app.get(
      "/internal/saas/catalog/actions/search",
      requireSaasPurpose(this.options.verifyJwt, "action:search"),
      (context) => searchCatalogActions(context, this.options.catalog, this.actionSearch),
    );
    app.get("/internal/saas/connections", requireSaasPurpose(this.options.verifyJwt, "connection:read"), (context) =>
      listConnections(context, this.options.runtimeDatabaseFactory),
    );
    app.post(
      "/internal/saas/connections/credentials",
      requireSaasPurpose(this.options.verifyJwt, "connection:write"),
      (context) => createCredentialConnection(context, this.options),
    );
    app.put(
      "/internal/saas/connections/:connectionId/credentials",
      requireSaasPurpose(this.options.verifyJwt, "connection:write"),
      (context) => replaceCredentialConnection(context, this.options),
    );
    app.patch(
      "/internal/saas/connections/:connectionId/visibility",
      requireSaasPurpose(this.options.verifyJwt, "connection:write"),
      (context) => updateConnectionVisibility(context, this.options.runtimeDatabaseFactory),
    );
    app.post(
      "/internal/saas/connections/:connectionId/transfer",
      requireSaasPurpose(this.options.verifyJwt, "connection:write"),
      (context) => transferConnection(context, this.options.runtimeDatabaseFactory),
    );
    app.delete(
      "/internal/saas/connections/:connectionId",
      requireSaasPurpose(this.options.verifyJwt, "connection:write"),
      (context) => deleteConnection(context, this.options),
    );
    app.post("/internal/saas/oauth/start", requireSaasPurpose(this.options.verifyJwt, "oauth:start"), (context) =>
      handleOAuth(context, "oauth:start", this.options.oauthServiceFactory),
    );
    app.post("/internal/saas/oauth/complete", requireSaasPurpose(this.options.verifyJwt, "oauth:complete"), (context) =>
      handleOAuth(context, "oauth:complete", this.options.oauthServiceFactory),
    );
    app.get(
      "/internal/saas/oauth/requests/:requestId",
      requireSaasPurpose(this.options.verifyJwt, "oauth:complete"),
      (context) => handleOAuthRequest(context, this.options.oauthServiceFactory, false),
    );
    app.post(
      "/internal/saas/oauth/requests/:requestId/cancel",
      requireSaasPurpose(this.options.verifyJwt, "oauth:complete"),
      (context) => handleOAuthRequest(context, this.options.oauthServiceFactory, true),
    );
    app.post(
      "/internal/saas/actions/:actionId",
      requireSaasPurpose(this.options.verifyJwt, "action:execute:v2"),
      (context) => executeSaasAction(context, this.options),
    );
    app.get("/internal/saas/files/:fileId", requireSaasPurpose(this.options.verifyJwt, "file:read"), (context) =>
      downloadTransitFile(context, this.options.runtimeDatabaseFactory),
    );
    app.get("/internal/saas/runs", requireSaasPurpose(this.options.verifyJwt, "admin:read"), (context) =>
      listSaasRuns(context, this.options.runtimeDatabaseFactory),
    );
    app.get("/internal/saas/runs/:executionId", requireSaasPurpose(this.options.verifyJwt, "admin:read"), (context) =>
      getSaasRun(context, this.options.runtimeDatabaseFactory),
    );
    app.get("/internal/saas/lifecycle/export", lifecyclePurpose(this.options.verifyJwt, "lifecycle:read"), (context) =>
      exportLifecycleScope(context, this.options.runtimeDatabaseFactory),
    );
    app.post(
      "/internal/saas/lifecycle/purge",
      lifecyclePurpose(this.options.verifyJwt, "lifecycle:delete"),
      (context) => purgeLifecycleScope(context, this.options),
    );

    return app;
  }
}

function runtimeUnavailable(context: Context<SaasHonoEnvironment>): Response {
  return context.json({ error: "service_unavailable" }, 503);
}
const defaultCatalogPageSize = 100;
const maximumCatalogPageSize = 500;
const defaultRunPageSize = 50;
const maximumRunPageSize = 100;
const maximumRunCursorLength = 512;
const defaultLifecyclePageSize = 50;
const maximumLifecyclePageSize = 100;
const maximumLifecycleCursorLength = 4096;

async function listCatalogActions(
  context: Context<SaasHonoEnvironment>,
  catalog: CatalogStore,
  fingerprint: Promise<string>,
): Promise<Response> {
  const query = exactQuery(context, ["cursor", "limit"]);
  if (!query) return invalidInput(context);
  const limit = parseBoundedInteger(query.get("limit"), defaultCatalogPageSize, maximumCatalogPageSize);
  if (!limit) return invalidInput(context);
  try {
    const catalogFingerprint = await fingerprint;
    const offset = decodeCatalogCursor(query.get("cursor"), catalogFingerprint, catalog.actions.length);
    if (offset === undefined) return invalidInput(context);
    const nextOffset = offset + limit;
    const items: SafeActionCatalog[] = [];
    for (const summary of catalog.actions.slice(offset, nextOffset)) {
      const action = await catalog.getAction(summary.id);
      if (!action) throw new Error("Catalog action definition is unavailable");
      items.push(toSafeAction(action));
    }
    const page: SafeActionCatalogPage = {
      items,
      nextCursor:
        nextOffset < catalog.actions.length
          ? Buffer.from(JSON.stringify([catalogFingerprint, nextOffset])).toString("base64url")
          : null,
      catalogFingerprint,
    };
    return context.json(page);
  } catch {
    return context.json({ error: "catalog_unavailable" }, 503);
  }
}

async function searchCatalogActions(
  context: Context<SaasHonoEnvironment>,
  catalog: CatalogStore,
  searchIndex: ActionSearchIndexProvider,
): Promise<Response> {
  const query = exactQuery(context, ["q", "service", "limit"]);
  if (!query) return invalidInput(context);
  const text = query.get("q");
  const service = query.get("service") ?? undefined;
  const limit = parseBoundedInteger(query.get("limit"), 10, 100);
  if (
    text === null ||
    !text.trim() ||
    text.length > 256 ||
    (service !== undefined && (!service || service.length > 128)) ||
    !limit
  ) {
    return invalidInput(context);
  }
  const matches = searchActions(await searchIndex.get(), text, { limit, service });
  return context.json(
    matches.flatMap((match): SafeActionSummary[] => {
      const action = catalog.actionsById.get(match.id);
      return action ? [toSafeActionSummary(action)] : [];
    }),
  );
}

async function listConnections(
  context: Context<SaasHonoEnvironment>,
  factory: Pick<SaasRuntimeDatabaseFactory, "forScope"> | undefined,
): Promise<Response> {
  const scope = getSaasRequestScope(context, "connection:read");
  const runtime = factory?.forScope(scope);
  if (!runtime) return runtimeUnavailable(context);
  try {
    return context.json((await runtime.connectionStore.listSafeConnections()).map(toSafeConnectionSummary));
  } catch {
    return context.json({ error: "service_unavailable" }, 503);
  }
}

async function createCredentialConnection(
  context: Context<SaasHonoEnvironment>,
  options: SaasConnectServerOptions,
): Promise<Response> {
  const scope = getSaasRequestScope(context, "connection:write");
  let input: ConnectorCredentialInput;
  try {
    input = connectorCredentialInputSchema.parse(await readBoundedJson(context));
  } catch (error) {
    return error instanceof JsonBodyTooLargeError ? payloadTooLarge(context) : invalidInput(context);
  }
  if (scope.connectorConnectionId || input.localConnectionId !== scope.localConnectionId) return forbidden(context);
  if (!options.oauthCredentials) return context.json({ error: "service_unavailable" }, 503);
  const runtime = options.runtimeDatabaseFactory?.forScope(scope);
  if (!runtime) return runtimeUnavailable(context);

  try {
    const connections = createScopedConnectionService({
      catalog: options.catalog,
      providerLoader: options.providerLoader,
      store: runtime.connectionStore,
      oauthCredentials: options.oauthCredentials,
      refreshCoordinator: runtime.refreshCoordinator,
    });
    const connected =
      input.authType === "no_auth"
        ? await connections.connectWithoutAuth(input.service, { connectionName: input.connectionName })
        : input.authType === "api_key"
          ? await connections.connectWithApiKey(input.service, {
              connectionName: input.connectionName,
              values: input.credentials,
              signal: scope.requestSignal ?? context.req.raw.signal,
            })
          : await connections.connectWithCustomCredential(input.service, {
              connectionName: input.connectionName,
              values: input.credentials,
              signal: scope.requestSignal ?? context.req.raw.signal,
            });
    const summary = await runtime.connectionStore.getSafeConnection(connected.id);
    if (!summary) throw new Error("Stored connection metadata is unavailable");
    return context.json(toSafeConnectionSummary(summary), 201);
  } catch (error) {
    if (error instanceof ConnectionError) return invalidInput(context);
    if (isPostgresConflict(error)) return context.json({ error: "connection_conflict" }, 409);
    return context.json({ error: "service_unavailable" }, 503);
  }
}
async function replaceCredentialConnection(
  context: Context<SaasHonoEnvironment>,
  options: SaasConnectServerOptions,
): Promise<Response> {
  const scope = getSaasRequestScope(context, "connection:write");
  const connectionId = context.req.param("connectionId");
  let input: ConnectorCredentialReplacementInput;
  try {
    input = connectorCredentialReplacementInputSchema.parse(await readBoundedJson(context));
  } catch (error) {
    return error instanceof JsonBodyTooLargeError ? payloadTooLarge(context) : invalidInput(context);
  }
  if (
    !scope.localConnectionId ||
    !scope.connectorConnectionId ||
    connectionId !== scope.connectorConnectionId ||
    input.connectorConnectionId !== connectionId ||
    input.localConnectionId !== scope.localConnectionId
  ) {
    return forbidden(context);
  }
  if (!options.oauthCredentials) return context.json({ error: "service_unavailable" }, 503);
  const runtime = options.runtimeDatabaseFactory?.forScope(scope);
  if (!runtime) return runtimeUnavailable(context);

  try {
    const target = await runtime.connectionStore.getCredentialReplacementTarget(connectionId);
    if (!target) return context.json({ error: "not_found" }, 404);
    if (
      target.service !== input.service ||
      target.connectionName !== input.connectionName ||
      target.source === "saas" ||
      target.credential.authType !== input.authType
    ) {
      return context.json({ error: "connection_conflict" }, 409);
    }
    const connections = createScopedConnectionService({
      catalog: options.catalog,
      providerLoader: options.providerLoader,
      store: runtime.connectionStore,
      oauthCredentials: options.oauthCredentials,
      refreshCoordinator: runtime.refreshCoordinator,
    });
    if (input.authType === "api_key") {
      await connections.connectWithApiKey(input.service, {
        connectionName: input.connectionName,
        values: input.credentials,
        expectedConnection: target,
        signal: scope.requestSignal ?? context.req.raw.signal,
      });
    } else {
      await connections.connectWithCustomCredential(input.service, {
        connectionName: input.connectionName,
        values: input.credentials,
        expectedConnection: target,
        signal: scope.requestSignal ?? context.req.raw.signal,
      });
    }
    const summary = await runtime.connectionStore.getSafeConnection(connectionId);
    if (!summary) throw new Error("Stored connection metadata is unavailable");
    return context.json(toSafeConnectionSummary(summary));
  } catch (error) {
    if (error instanceof ConnectionError) {
      return error.code === "connection_changed"
        ? context.json({ error: "connection_conflict" }, 409)
        : invalidInput(context);
    }
    return context.json({ error: "service_unavailable" }, 503);
  }
}

async function transferConnection(
  context: Context<SaasHonoEnvironment>,
  factory: Pick<SaasRuntimeDatabaseFactory, "forScope"> | undefined,
): Promise<Response> {
  const scope = getSaasRequestScope(context, "connection:write");
  const connectionId = context.req.param("connectionId");
  let input: ConnectionTransferInput;
  try {
    input = connectionTransferInputSchema.parse(await readBoundedJson(context));
  } catch (error) {
    return error instanceof JsonBodyTooLargeError ? payloadTooLarge(context) : invalidInput(context);
  }
  if (
    !scope.localConnectionId ||
    !scope.connectorConnectionId ||
    connectionId !== scope.connectorConnectionId ||
    (scope.workspaceRole !== "owner" && scope.workspaceRole !== "admin") ||
    canonicalActionRequestHash("connection.transfer", connectionId, input) !== scope.requestHash
  ) {
    return forbidden(context);
  }
  const runtime = factory?.forScope(scope);
  if (!runtime) return runtimeUnavailable(context);
  try {
    const transferred = await runtime.connectionStore.transferById(connectionId, input.targetSubjectUserId);
    return transferred ? context.json(toSafeConnectionSummary(transferred)) : context.json({ error: "not_found" }, 404);
  } catch {
    return context.json({ error: "service_unavailable" }, 503);
  }
}

async function updateConnectionVisibility(
  context: Context<SaasHonoEnvironment>,
  factory: Pick<SaasRuntimeDatabaseFactory, "forScope"> | undefined,
): Promise<Response> {
  const scope = getSaasRequestScope(context, "connection:write");
  const connectionId = context.req.param("connectionId");
  let input: ConnectionVisibilityInput;
  try {
    input = connectionVisibilityInputSchema.parse(await readBoundedJson(context));
  } catch (error) {
    return error instanceof JsonBodyTooLargeError ? payloadTooLarge(context) : invalidInput(context);
  }
  if (
    !scope.localConnectionId ||
    !scope.connectorConnectionId ||
    connectionId !== scope.connectorConnectionId ||
    (scope.workspaceRole !== "owner" && scope.workspaceRole !== "admin") ||
    canonicalActionRequestHash("connection.visibility", connectionId, input) !== scope.requestHash
  ) {
    return forbidden(context);
  }
  const runtime = factory?.forScope(scope);
  if (!runtime) return runtimeUnavailable(context);
  try {
    const updated = await runtime.connectionStore.updateVisibilityById(connectionId, input.visibility);
    return updated ? context.json(toSafeConnectionSummary(updated)) : context.json({ error: "not_found" }, 404);
  } catch {
    return context.json({ error: "service_unavailable" }, 503);
  }
}

async function deleteConnection(
  context: Context<SaasHonoEnvironment>,
  options: SaasConnectServerOptions,
): Promise<Response> {
  const scope = getSaasRequestScope(context, "connection:write");
  const connectionId = context.req.param("connectionId");
  if (!scope.connectorConnectionId || connectionId !== scope.connectorConnectionId) return forbidden(context);
  const runtime = options.runtimeDatabaseFactory?.forScope(scope);
  if (!runtime) return runtimeUnavailable(context);
  try {
    if (await runtime.connectionStore.hasRevocationReceipt(connectionId)) return context.body(null, 204);
    if (await runtime.connectionStore.resumeRevocation(connectionId)) return context.body(null, 204);
    const connection = await runtime.connectionStore.blockForRevocation(connectionId);
    if (!connection) {
      return (await runtime.connectionStore.hasRevocationReceipt(connectionId))
        ? context.body(null, 204)
        : context.json({ error: "not_found" }, 404);
    }
    const result =
      connection.source === "saas"
        ? "unsupported"
        : await options.credentialRevoker?.revoke({
            service: connection.service,
            credential: connection.credential,
            signal: scope.requestSignal ?? context.req.raw.signal,
          });
    if (!result || result === "failed") {
      return context.json({ error: "provider_revocation_failed" }, 503);
    }
    return (await runtime.connectionStore.deleteById(connectionId, result))
      ? context.body(null, 204)
      : context.json({ error: "revocation_reconciliation_required" }, 409);
  } catch {
    return context.json({ error: "provider_revocation_failed" }, 503);
  }
}

async function exportLifecycleScope(
  context: Context<SaasHonoEnvironment>,
  factory: SaasConnectServerOptions["runtimeDatabaseFactory"],
): Promise<Response> {
  const query = exactQuery(context, ["cursor", "limit"]);
  const limit = query
    ? parseBoundedInteger(query.get("limit"), defaultLifecyclePageSize, maximumLifecyclePageSize)
    : undefined;
  const cursor = query?.get("cursor") ?? null;
  if (!query || !limit || (cursor !== null && (!cursor || cursor.length > maximumLifecycleCursorLength))) {
    return lifecycleError(context, 400, "invalid_input", "Lifecycle export query is invalid.");
  }
  const scope = getSaasRequestScope(context, "lifecycle:read");
  const service = factory?.lifecycleForScope?.(scope);
  if (!service) return lifecycleError(context, 503, "service_unavailable", "Lifecycle export is unavailable.");
  try {
    const page = await service.exportPage({ limit, ...(cursor === null ? {} : { cursor }) });
    if (
      page.connections.length +
        page.runs.length +
        page.actionGrants.length +
        page.actionPolicyAudit.length +
        page.connectionRequests.length +
        page.saasCleanup.length +
        page.connectionRetirements.length +
        page.triggerSubscriptions.length +
        page.triggerSourceApplications.length >
        limit ||
      (page.nextCursor !== null && page.nextCursor.length > maximumLifecycleCursorLength)
    ) {
      throw new Error("Lifecycle service returned an out-of-bounds page");
    }
    return context.json(page);
  } catch (error) {
    return error instanceof TypeError
      ? lifecycleError(context, 400, "invalid_input", "Lifecycle export cursor is invalid.")
      : lifecycleError(context, 503, "service_unavailable", "Lifecycle export is unavailable.");
  }
}

async function purgeLifecycleScope(
  context: Context<SaasHonoEnvironment>,
  options: SaasConnectServerOptions,
): Promise<Response> {
  if (!exactQuery(context, [])) {
    return lifecycleError(context, 400, "invalid_input", "Lifecycle purge query is invalid.");
  }
  let input: LifecyclePurgeInput;
  try {
    input = lifecyclePurgeInputSchema.parse(await readBoundedJson(context));
  } catch (error) {
    return error instanceof JsonBodyTooLargeError
      ? lifecycleError(context, 413, "payload_too_large", "Lifecycle purge body is too large.")
      : lifecycleError(context, 400, "invalid_input", "Lifecycle purge body is invalid.");
  }
  const scope = getSaasRequestScope(context, "lifecycle:delete");
  if (canonicalRequestHash("lifecycle.purge", input) !== scope.requestHash) {
    return lifecycleError(context, 403, "forbidden", "Lifecycle purge authorization does not match the body.");
  }
  const service = options.runtimeDatabaseFactory?.lifecycleForScope?.(
    scope,
    options.credentialRevoker,
    options.triggerCleanupForScope?.(scope),
  );
  if (!service) return lifecycleError(context, 503, "service_unavailable", "Lifecycle purge is unavailable.");
  try {
    return context.json(await service.purge(input, scope.requestSignal ?? context.req.raw.signal));
  } catch (error) {
    if (error instanceof LifecyclePurgeConflictError) {
      return lifecycleError(
        context,
        409,
        "lifecycle_purge_conflict",
        "The lifecycle scope has another purge in progress.",
      );
    }
    if (error instanceof LifecycleReconciliationRequiredError) {
      return lifecycleError(
        context,
        503,
        "reconciliation_required",
        "Lifecycle cleanup requires reconciliation; retry with the same correlationId.",
      );
    }
    return lifecycleError(context, 503, "service_unavailable", "Lifecycle purge is unavailable.");
  }
}

function lifecycleError(
  context: Context<SaasHonoEnvironment>,
  status: 400 | 403 | 409 | 413 | 503,
  errorCode: string,
  message: string,
): Response {
  return context.json({ errorCode, message }, status);
}

function lifecyclePurpose(
  verifier: SaasJwtVerifier,
  purpose: "lifecycle:read" | "lifecycle:delete",
): MiddlewareHandler<SaasHonoEnvironment> {
  const middleware = requireSaasPurpose(verifier, purpose);
  return async (context, next) => {
    const response = await middleware(context, next);
    if (response instanceof Response && response.status === 401) {
      return context.json({ errorCode: "unauthorized", message: "Lifecycle authentication is required." }, 401);
    }
    if (response instanceof Response && response.status === 403) {
      return context.json({ errorCode: "forbidden", message: "The exact lifecycle purpose is required." }, 403);
    }
    return response;
  };
}

async function listSaasRuns(
  context: Context<SaasHonoEnvironment>,
  factory: Pick<SaasRuntimeDatabaseFactory, "forScope"> | undefined,
): Promise<Response> {
  const query = exactQuery(context, ["cursor", "limit", "service", "actionId", "caller", "ok"]);
  if (!query) return invalidInput(context);
  const limit = parseBoundedInteger(query.get("limit"), defaultRunPageSize, maximumRunPageSize);
  const cursor = query.get("cursor");
  const service = query.get("service");
  const actionId = query.get("actionId");
  const caller = query.get("caller");
  const ok = query.get("ok");
  if (
    !limit ||
    !validRunCursor(cursor) ||
    (service !== null && (!service || service.length > 128)) ||
    (actionId !== null && (!actionId || actionId.length > 255)) ||
    (caller !== null && !isRunLogCaller(caller)) ||
    (ok !== null && ok !== "true" && ok !== "false")
  ) {
    return invalidInput(context);
  }

  const input: RunLogListInput = { limit };
  if (cursor !== null) input.cursor = cursor;
  if (service !== null) input.service = service;
  if (actionId !== null) input.actionId = actionId;
  if (caller !== null) input.caller = caller;
  if (ok !== null) input.ok = ok === "true";
  try {
    const runtime = factory?.forScope(getSaasRequestScope(context, "admin:read"));
    if (!runtime) return context.json({ error: "service_unavailable" }, 503);
    const page = await runtime.runLogStore.list(input);
    if (
      page.items.length > limit ||
      (page.nextCursor !== undefined && (!page.nextCursor || page.nextCursor.length > maximumRunCursorLength))
    ) {
      throw new Error("Run store returned an out-of-bounds page");
    }
    return context.json({
      items: page.items.map(toSafeRun),
      nextCursor: page.nextCursor ?? null,
    });
  } catch {
    return context.json({ error: "service_unavailable" }, 503);
  }
}

async function getSaasRun(
  context: Context<SaasHonoEnvironment>,
  factory: Pick<SaasRuntimeDatabaseFactory, "forScope"> | undefined,
): Promise<Response> {
  if (!exactQuery(context, [])) return invalidInput(context);
  try {
    const runtime = factory?.forScope(getSaasRequestScope(context, "admin:read"));
    if (!runtime) return context.json({ error: "service_unavailable" }, 503);
    const executionId = context.req.param("executionId");
    if (!executionId) return invalidInput(context);
    const run = await runtime.runLogStore.get(executionId);
    return run ? context.json(toSafeRun(run)) : context.json({ error: "not_found" }, 404);
  } catch {
    return context.json({ error: "service_unavailable" }, 503);
  }
}

function validRunCursor(cursor: string | null): boolean {
  if (cursor === null) return true;
  if (!cursor || cursor.length > maximumRunCursorLength) return false;
  try {
    const decoded = decodeRunLogCursor(cursor);
    return (
      decoded !== undefined &&
      decoded.id.length > 0 &&
      decoded.id.length <= 255 &&
      !Number.isNaN(Date.parse(decoded.startedAt))
    );
  } catch {
    return false;
  }
}

function isRunLogCaller(value: string): value is RunLogCaller {
  return value === "http" || value === "mcp" || value === "web";
}

function toSafeRun(run: RunLog) {
  if (
    !boundedString(run.id, 255) ||
    !boundedString(run.service, 128) ||
    !boundedString(run.actionId, 255) ||
    !isRunLogCaller(run.caller) ||
    Number.isNaN(Date.parse(run.startedAt)) ||
    Number.isNaN(Date.parse(run.completedAt)) ||
    !Number.isSafeInteger(run.durationMs) ||
    run.durationMs < 0 ||
    (run.runtimeTokenId !== undefined && !boundedString(run.runtimeTokenId, 255)) ||
    (run.errorCode !== undefined && !boundedString(run.errorCode, 64)) ||
    (run.connectionProfile !== undefined &&
      (!boundedString(run.connectionProfile.accountId, 512) ||
        !boundedString(run.connectionProfile.displayName, 512) ||
        run.connectionProfile.grantedScopes.length > 256 ||
        run.connectionProfile.grantedScopes.some((scope) => !boundedString(scope, 512)))) ||
    (run.policy !== undefined &&
      (run.policy.checks.length > 16 ||
        run.policy.checks.some((check) => check.rule !== undefined && !boundedString(check.rule, 512)) ||
        (!run.policy.allowed && !boundedString(run.policy.message, 512))))
  ) {
    throw new Error("Run store returned an invalid safe run");
  }
  return {
    id: run.id,
    service: run.service,
    actionId: run.actionId,
    caller: run.caller,
    startedAt: run.startedAt,
    completedAt: run.completedAt,
    durationMs: run.durationMs,
    ok: run.ok,
    ...(run.connectionId === undefined ? {} : { connectionId: run.connectionId }),
    ...(run.connectionProfile === undefined
      ? {}
      : {
          connectionProfile: {
            accountId: run.connectionProfile.accountId,
            displayName: run.connectionProfile.displayName,
            grantedScopes: [...run.connectionProfile.grantedScopes],
          },
        }),
    ...(run.runtimeTokenId === undefined ? {} : { runtimeTokenId: run.runtimeTokenId }),
    ...(run.policy === undefined
      ? {}
      : {
          policy: {
            allowed: run.policy.allowed,
            ...(!run.policy.allowed ? { code: run.policy.code, message: run.policy.message } : {}),
            checks: run.policy.checks.map((check) => ({
              source: check.source,
              outcome: check.outcome,
              ...(check.rule === undefined ? {} : { rule: check.rule }),
            })),
          },
        }),
    ...(run.errorCode === undefined ? {} : { errorCode: run.errorCode }),
  };
}

function boundedString(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length <= maximum;
}

function parseBoundedInteger(value: string | null, fallback: number, maximum: number): number | undefined {
  if (value === null) return fallback;
  if (!/^[1-9]\d*$/.test(value)) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed <= maximum ? parsed : undefined;
}

function decodeCatalogCursor(cursor: string | null, fingerprint: string, actionCount: number): number | undefined {
  if (cursor === null) return 0;
  if (!cursor || cursor.length > 512 || !/^[A-Za-z0-9_-]+$/.test(cursor)) return undefined;
  try {
    const value = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as unknown;
    if (
      !Array.isArray(value) ||
      value.length !== 2 ||
      value[0] !== fingerprint ||
      !Number.isSafeInteger(value[1]) ||
      (value[1] as number) < 0 ||
      (value[1] as number) > actionCount
    ) {
      return undefined;
    }
    return value[1] as number;
  } catch {
    return undefined;
  }
}

function toSafeProvider(
  provider: RuntimeProviderDefinition,
  oauthReadiness: OAuthClientConfigReadiness | undefined,
  previous?: SafeProviderCatalog,
): SafeProviderCatalog {
  if (previous) {
    const current = previous.connectionMethods.find((method) => method.type === "oauth2");
    if (!current) return previous;
    const status = oauthReadiness?.status ?? "unavailable";
    const reason =
      oauthReadiness?.status === "unavailable"
        ? oauthReadiness.reasonCode
        : oauthReadiness
          ? undefined
          : "oauth_client_config_missing";
    if (current.status === status && current.reasonCode === reason) return previous;
  }
  const connectionMethods = provider.auth.flatMap((auth): SafeProviderCatalog["connectionMethods"] => {
    if (auth.type === "no_auth") return [{ type: "no_auth", fields: [], status: "operational" }];
    if (auth.type === "oauth2") {
      const readiness = oauthReadiness ?? {
        status: "unavailable" as const,
        reasonCode: "oauth_client_config_missing" as const,
      };
      return [{ type: "oauth2", fields: [], ...readiness }];
    }
    if (auth.type === "api_key") {
      const apiKey: SafeCredentialField = {
        name: "apiKey",
        label: auth.label ?? "API Key",
        inputType: "password",
        required: true,
      };
      if (auth.description) apiKey.description = auth.description;
      return [
        {
          type: "api_key",
          fields: [apiKey, ...(auth.extraFields ?? []).map(toSafeCredentialField)],
          status: "operational",
        },
      ];
    }
    return [{ type: "custom_credential", fields: auth.fields.map(toSafeCredentialField), status: "operational" }];
  });
  return {
    service: provider.service,
    displayName: provider.displayName,
    description: provider.description,
    categories: [...provider.categories],
    authTypes: [...provider.authTypes],
    homepageUrl: provider.homepageUrl,
    iconUrl: provider.iconUrl,
    connectionMethods,
  };
}

function toSafeCredentialField(field: CredentialDefinition): SafeCredentialField {
  const safe: SafeCredentialField = {
    name: field.key,
    label: field.label,
    inputType: field.secret || field.inputType === "password" ? "password" : "text",
    required: field.required,
  };
  if (field.description) safe.description = field.description;
  return safe;
}

function toSafeActionSummary(action: RuntimeActionSummary): SafeActionSummary {
  return {
    id: action.id,
    service: action.service,
    name: action.name,
    description: action.description,
    requiredScopes: [...action.requiredScopes],
    providerPermissions: [...action.providerPermissions],
    followUpActions: action.followUpActions ? [...action.followUpActions] : undefined,
    asyncLifecycle: action.asyncLifecycle ? { ...action.asyncLifecycle } : undefined,
  };
}

function toSafeAction(action: RuntimeActionDefinition): SafeActionCatalog {
  return {
    ...toSafeActionSummary(action),
    inputSchema: action.inputSchema,
    outputSchema: action.outputSchema,
  };
}

function isPostgresConflict(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "23505";
}

const oauthBindingSchema = z.object({ localConnectionId: z.guid(), oauthSessionId: z.guid() }).strict();
const oauthStartInputSchema = oauthBindingSchema.extend({
  service: z.string().min(1).max(255),
  authorizationOptionIds: z.array(z.string().min(1).max(255)).max(64).optional(),
  clientConfig: z
    .object({
      clientId: z.string().min(1).max(4096),
      clientSecret: z.string().max(8192).optional(),
      redirectUri: z.url().optional(),
      requestedScopes: z.array(z.string().min(1).max(4096)).max(256).optional(),
      extra: z.record(z.string().min(1).max(128), z.string().max(8192)).optional(),
      secretExtra: z.record(z.string().min(1).max(128), z.string().max(8192)).optional(),
    })
    .strict()
    .optional(),
});
const oauthCompleteInputSchema = oauthBindingSchema.extend({
  state: z
    .string()
    .min(1)
    .max(4096)
    .refine((value) => Boolean(value.trim())),
  code: z
    .string()
    .min(1)
    .max(4096)
    .refine((value) => Boolean(value.trim())),
  callbackQuery: z.string().max(16384).optional(),
  callbackParameters: z
    .record(z.string().min(1).max(128), z.string().max(4096))
    .refine((value) => Object.keys(value).length <= 64)
    .optional(),
});
const oauthRequestIdSchema = z.guid();

function runOAuthOperation(context: Context<SaasHonoEnvironment>, work: () => Promise<Response>): Promise<Response> {
  return runScopedHttpOperation(context, "oauth_unavailable", async () => {
    try {
      return await work();
    } catch (error) {
      if (error instanceof OAuthFlowError) return context.json({ error: error.code }, 400);
      if (error instanceof SaasError) return context.json({ error: error.code }, error.status);
      if (error instanceof ConnectionError)
        return error.code === "connection_changed"
          ? context.json({ error: "connection_conflict" }, 409)
          : invalidInput(context);
      throw error;
    }
  });
}

async function handleOAuth(
  context: Context<SaasHonoEnvironment>,
  purpose: "oauth:start" | "oauth:complete",
  oauthFactory: SaasConnectServerOptions["oauthServiceFactory"],
): Promise<Response> {
  return runOAuthOperation(context, async () => {
    const scope = getSaasRequestScope(context, purpose);
    if (!exactQuery(context, [])) return invalidInput(context);
    const raw = await readBoundedJson(context, 65536);
    const body = purpose === "oauth:start" ? oauthStartInputSchema.parse(raw) : oauthCompleteInputSchema.parse(raw);
    if (
      !scope.localConnectionId ||
      !scope.oauthSessionId ||
      body.localConnectionId !== scope.localConnectionId ||
      body.oauthSessionId !== scope.oauthSessionId
    )
      return forbidden(context);
    const service = oauthFactory?.forScope(scope);
    if (!service) return runtimeUnavailable(context);
    if ("service" in body)
      return context.json(
        await service.start(body.service, {
          authorizationOptionIds: body.authorizationOptionIds,
          clientConfig: body.clientConfig,
        }),
      );
    return context.json(
      await service.complete({
        state: body.state,
        code: body.code,
        callbackQuery: body.callbackQuery,
        callbackParameters: body.callbackParameters,
      }),
    );
  });
}

async function handleOAuthRequest(
  context: Context<SaasHonoEnvironment>,
  factory: SaasConnectServerOptions["oauthServiceFactory"],
  cancel: boolean,
): Promise<Response> {
  return runOAuthOperation(context, async () => {
    const scope = getSaasRequestScope(context, "oauth:complete");
    if (!exactQuery(context, [])) return invalidInput(context);
    const requestId = oauthRequestIdSchema.parse(context.req.param("requestId"));
    if (cancel && !isExactObject(await readBoundedJson(context, 65536), [])) return invalidInput(context);
    const service = factory?.forScope(scope);
    if (!service) return runtimeUnavailable(context);
    const result = await (cancel ? service.cancelRequest(requestId) : service.getRequest(requestId));
    return result ? context.json(result) : context.json({ error: "oauth_request_not_found" }, 404);
  });
}

function isExactObject(value: unknown, keys: string[]): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function invalidInput(context: Context<SaasHonoEnvironment>): Response {
  return context.json({ error: "invalid_input" }, 400);
}

function payloadTooLarge(context: Context<SaasHonoEnvironment>): Response {
  return context.json({ error: "payload_too_large" }, 413);
}

async function downloadTransitFile(
  context: Context<SaasHonoEnvironment>,
  factory: SaasConnectServerOptions["runtimeDatabaseFactory"],
): Promise<Response> {
  const scope = getSaasRequestScope(context, "file:read");
  const fileId = context.req.param("fileId");
  if (!fileId || fileId !== scope.fileId || !exactQuery(context, [])) return forbidden(context);
  const transitFiles = factory?.forScope(scope).transitFiles;
  if (!transitFiles?.response) return context.json({ error: "service_unavailable" }, 503);
  try {
    return await transitFiles.response(fileId);
  } catch (error) {
    if (error instanceof TransitFileError) return context.json({ error: error.code }, error.status);
    return context.json({ error: "service_unavailable" }, 503);
  }
}

async function executeSaasAction(
  context: Context<SaasHonoEnvironment>,
  options: SaasConnectServerOptions,
): Promise<Response> {
  const scope = getSaasRequestScope(context, "action:execute:v2");
  let body: unknown;
  try {
    body = await readBoundedJson(context);
  } catch (error) {
    return error instanceof JsonBodyTooLargeError ? payloadTooLarge(context) : invalidInput(context);
  }
  if (
    !isExactObject(body, ["connectorConnectionId", "input"]) ||
    typeof body.connectorConnectionId !== "string" ||
    !body.connectorConnectionId
  ) {
    return invalidInput(context);
  }
  const actionId = context.req.param("actionId");
  if (!actionId) return invalidInput(context);
  try {
    if (
      actionId !== scope.actionId ||
      body.connectorConnectionId !== scope.connectorConnectionId ||
      canonicalActionRequestHash(actionId, body.connectorConnectionId, body.input) !== scope.requestHash
    ) {
      return forbidden(context);
    }
  } catch {
    return forbidden(context);
  }
  const idempotencyKey = context.req.header("idempotency-key");
  if (!idempotencyKey || idempotencyKey.length > 255) return invalidInput(context);
  if (!options.oauthCredentials) return context.json({ error: "service_unavailable" }, 503);

  try {
    const runtime = options.runtimeDatabaseFactory?.forScope(scope);
    if (!runtime) return runtimeUnavailable(context);
    const native = options.nativeExecutionForScope?.(scope, runtime);
    const connections = createScopedConnectionService({
      catalog: options.catalog,
      providerLoader: options.providerLoader,
      store: runtime.connectionStore,
      oauthCredentials: options.oauthCredentials,
      refreshCoordinator: runtime.refreshCoordinator,
      marketplace: native?.marketplace,
    });
    const result = await new SaasActionRunner({
      scope,
      catalog: options.catalog,
      providerLoader: options.providerLoader,
      connectionStore: runtime.connectionStore,
      connections,
      idempotency: runtime.saasIdempotencyStore,
      journal: runtime.executionJournal,
      actionPolicy: runtime.actionPolicy,
      saasExecution: native?.saasExecution,
      marketplace: native?.marketplace,
      transitFiles: runtime.transitFiles,
    }).run({
      actionId,
      connectorConnectionId: body.connectorConnectionId,
      input: body.input,
      idempotencyKey,
      signal: scope.requestSignal ?? context.req.raw.signal,
    });
    if (result.ok) {
      return context.json({
        executionId: result.executionId,
        status: result.status,
        output: result.output,
      });
    }

    const status =
      result.error.code === "forbidden" ||
      result.error.code === "action_not_granted" ||
      result.error.code === "request_hash_mismatch" ||
      result.error.code === "connection_provider_mismatch"
        ? 403
        : result.error.code === "action_policy_unavailable" || result.error.code === "action_schema_unavailable"
          ? 503
          : result.error.code === "invalid_input" || result.error.code === "invalid_idempotency_key"
            ? 400
            : 409;
    return context.json(
      {
        errorCode: result.error.code,
        message: result.error.message,
        ...(result.executionId ? { executionId: result.executionId } : {}),
        ...(result.error.retryable ? { retryable: true } : {}),
      },
      status,
    );
  } catch {
    return context.json(
      {
        errorCode: "execution_reconciliation_required",
        message: "Execution requires durable reconciliation before it can be retried.",
        retryable: true,
      },
      409,
    );
  }
}

function forbidden(context: Context<SaasHonoEnvironment>): Response {
  return context.json({ error: "forbidden" }, 403);
}
