import type { CatalogStore } from "../catalog-store.ts";
import type { OAuthClientConfigReadiness, SaasRequestScope } from "./contracts.ts";
import type { SaasRuntimeDatabase } from "./storage/postgres-runtime-database.ts";

import { assertProcessingActive, captureRequestProcessing, remainingProcessingMs } from "../core/cancellation.ts";
import { MarketplaceService } from "../marketplace/marketplace-service.ts";
import { SaasClient } from "./saas-client.ts";
import { SaasExecutionService } from "./saas-execution-service.ts";
import { parseManagedCompletionUri, SaasOAuthService } from "./saas-oauth-service.ts";
import { SaasProjectService } from "./saas-project-service.ts";

export interface ScopedNativeServicesOptions {
  scope: Readonly<SaasRequestScope>;
  catalog: CatalogStore;
  /** The exact bundle returned by forScope(scope), never another owner's cloned scope. */
  runtime: Pick<SaasRuntimeDatabase, "saasProjects" | "connectionStore" | "connectionRequests" | "secretCodec">;
  configuredOrigin?: string;
  managedCompletionUri?: string;
  fetcher?: typeof fetch;
}
/** No initialization snapshot or singleton: persisted workspace selection is resolved on the actual request. */
export function createScopedNativeServices(options: ScopedNativeServicesOptions): {
  projects: SaasProjectService;
  managedOAuth: SaasOAuthService;
  saasExecution: SaasExecutionService;
  marketplace: MarketplaceService;
  getOAuthReadiness(
    localReadiness: ReadonlyMap<string, OAuthClientConfigReadiness>,
  ): Promise<ReadonlyMap<string, OAuthClientConfigReadiness>>;
} {
  const { scope, catalog, runtime, configuredOrigin, managedCompletionUri, fetcher } = options;
  const client = new SaasClient(fetcher);
  const projects = new SaasProjectService({
    catalog,
    store: runtime.saasProjects,
    secretCodec: runtime.secretCodec,
    configuredOrigin,
    client,
  });
  const capturedScope = captureRequestProcessing(scope);
  return {
    projects,
    managedOAuth: new SaasOAuthService({
      projects,
      requests: runtime.connectionRequests,
      client,
      completionUri: managedCompletionUri,
    }),
    saasExecution: new SaasExecutionService({ scope, connections: runtime.connectionStore, projects, client }),
    marketplace: new MarketplaceService({ scope, catalog, store: runtime.connectionStore, fetcher }),
    async getOAuthReadiness(
      localReadiness: ReadonlyMap<string, OAuthClientConfigReadiness>,
    ): Promise<ReadonlyMap<string, OAuthClientConfigReadiness>> {
      assertProcessingActive(capturedScope);
      if (scope.purpose !== "connection:read" || scope.actorUserId !== scope.subjectUserId)
        throw new Error("Scoped OAuth readiness requires the actual interactive metadata actor");
      const remaining = remainingProcessingMs(capturedScope);
      const signals = [
        capturedScope.requestSignal,
        remaining === undefined ? undefined : AbortSignal.timeout(remaining),
      ].filter((value): value is AbortSignal => value !== undefined);
      const signal = signals.length ? AbortSignal.any(signals) : undefined;
      const managed = await projects.probeSources(signal);
      let continuationConfigured = true;
      if (managed.size) {
        try {
          parseManagedCompletionUri(managedCompletionUri);
        } catch {
          continuationConfigured = false;
        }
      }
      const readiness = new Map<string, OAuthClientConfigReadiness>();
      for (const provider of catalog.providers) {
        if (!provider.auth.some((auth) => auth.type === "oauth2")) continue;
        const selected = managed.get(provider.service);
        if (selected)
          readiness.set(
            provider.service,
            continuationConfigured ? selected : { status: "unavailable", reasonCode: "oauth_client_config_invalid" },
          );
        else {
          const local = localReadiness.get(provider.service);
          if (!local) throw new Error("Local OAuth readiness was not probed");
          readiness.set(provider.service, local);
        }
      }
      assertProcessingActive(capturedScope);
      return readiness;
    },
  };
}
