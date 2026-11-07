import type { CatalogStore } from "../catalog-store.ts";
import type { SaasRequestScope } from "./contracts.ts";
import type { SaasRuntimeDatabase } from "./storage/postgres-runtime-database.ts";

import { HeadBucketCommand } from "@aws-sdk/client-s3";
import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { fileURLToPath } from "node:url";
import { loadCatalog } from "../catalog-store.ts";
import { assertProcessingActive, getRequestSignal } from "../core/cancellation.ts";
import { withProviderNetworkPolicy } from "../core/provider-network-policy.ts";
import { OAuthClientConfigService } from "../oauth/oauth-client-config-service.ts";
import { OAuthCredentialRefreshService } from "../oauth/oauth-credential-refresh-service.ts";
import { ProviderLoader } from "../providers/provider-loader.ts";
import { executorModules } from "../providers/registry.generated.ts";
import { TriggerMaintenance } from "../triggers/maintenance.ts";
import { TriggerRunner } from "../triggers/trigger-runner.ts";
import {
  createActionPolicyJwtVerifier,
  createSaasJwtVerifier,
  readJwksBearerTokenFile,
} from "./auth/saas-jwt-verifier.ts";
import { readSaasConfig } from "./config.ts";
import { ProviderSaasCredentialRevoker } from "./connections/provider-credential-revoker.ts";
import { createScopedConnectionService } from "./connections/scoped-connection-service.ts";
import { createSeaweedFsS3Client } from "./files/seaweedfs-transit-files.ts";
import { SaasOAuthService } from "./oauth/saas-oauth-service.ts";
import { SaasCleanupService } from "./saas-cleanup-service.ts";
import { createScopedNativeServices } from "./scoped-native-services.ts";
import { OpenBaoClient } from "./secrets/openbao-client.ts";
import { OpenBaoConnectionSecretStore } from "./secrets/openbao-connection-store.ts";
import { OpenBaoOAuthClientConfigStore } from "./secrets/openbao-oauth-client-config-store.ts";
import { OpenBaoOAuthStateSecretStore } from "./secrets/openbao-oauth-state-secret-store.ts";
import { OpenBaoSecretCodec } from "./secrets/secret-codec.ts";
import { SaasConnectServer } from "./server/saas-connect-server.ts";
import { createPostgresPool } from "./storage/postgres-pool.ts";
import { probeSaasRuntimeDatabase, SaasRuntimeDatabaseFactory } from "./storage/postgres-runtime-database.ts";
import { SaasTriggerRunner } from "./triggers/saas-trigger-runner.ts";
import { triggerCapability } from "./triggers/trigger-capability.ts";

const config = readSaasConfig();
const jwksBearerToken = await readJwksBearerTokenFile(config.jwksBearerTokenFile);
const openBaoClient = await OpenBaoClient.fromTokenFile({
  address: config.openBaoAddress,
  tokenFile: config.openBaoTokenFile,
  requestTimeoutMs: config.openBaoRequestTimeoutMs,
  maxRequestBytes: config.openBaoMaxRequestBytes,
  maxResponseBytes: config.openBaoMaxResponseBytes,
});
const pool = createPostgresPool(config.postgresUrl);
const connectionSecrets = new OpenBaoConnectionSecretStore(openBaoClient);
await openBaoClient.probeCapabilities();
await probeSaasRuntimeDatabase(pool);
const seaweedFsClient = createSeaweedFsS3Client(config);
await seaweedFsClient.send(new HeadBucketCommand({ Bucket: config.seaweedFsBucket }), {
  abortSignal: AbortSignal.timeout(5_000),
});
const registryServices = Object.keys(executorModules);
const catalog = await loadCatalog(fileURLToPath(new URL("../../catalog/apps/", import.meta.url)), {
  executableServices: registryServices,
  lazySchemas: true,
  lazySchemaIndexFile: fileURLToPath(new URL("../../catalog/apps-index.json", import.meta.url)),
});
assertGeneratedCatalog(catalog, registryServices);
const providerLoader = new ProviderLoader(executorModules);
const runtimeDatabaseFactory = new SaasRuntimeDatabaseFactory({
  pool,
  catalog,
  secretCodecForScope: (scope) => new OpenBaoSecretCodec(openBaoClient, scope),
  connectionSecrets,
  oauthStateSecrets: new OpenBaoOAuthStateSecretStore(openBaoClient),
  transitFiles: {
    client: seaweedFsClient,
    bucket: config.seaweedFsBucket,
    publicOrigin: config.internalOrigin,
    ttlSeconds: 86_400,
    maxBytes: 100 * 1024 * 1024,
    requestTimeoutMs: 30_000,
  },
});
const oauthClientConfigs = new OpenBaoOAuthClientConfigStore(openBaoClient);
const oauthCallbackOrigin = config.oauthCallbackOrigin;
const allowedCustomOAuth = new Set(config.allowedCustomOAuth);
const isCustomClientConfigAllowed = (service: string): boolean =>
  allowedCustomOAuth.has("*") || allowedCustomOAuth.has(service);
const oauthClientConfigService = new OAuthClientConfigService({
  catalog,
  origin: oauthCallbackOrigin,
  store: oauthClientConfigs,
  isCustomClientConfigAvailable: isCustomClientConfigAllowed,
});
const oauthProviders = catalog.providers.flatMap((provider) => {
  const auth = provider.auth.find((method) => method.type === "oauth2");
  return auth?.type === "oauth2" ? [{ service: provider.service, auth }] : [];
});
const oauthClientReadiness = await oauthClientConfigs.probeAll(oauthProviders);
const oauthReadinessSummary = {
  checked: oauthClientReadiness.size,
  operational: 0,
  missing: 0,
  invalid: 0,
  accessDenied: 0,
};
for (const readiness of oauthClientReadiness.values()) {
  if (readiness.status === "operational") oauthReadinessSummary.operational += 1;
  else if (readiness.reasonCode === "oauth_client_config_missing") oauthReadinessSummary.missing += 1;
  else if (readiness.reasonCode === "oauth_client_config_invalid") oauthReadinessSummary.invalid += 1;
  else oauthReadinessSummary.accessDenied += 1;
}
console.info(JSON.stringify({ event: "oauth_client_readiness", ...oauthReadinessSummary }));
const oauthCredentials = new OAuthCredentialRefreshService(oauthClientConfigService, providerLoader);
const authentication = createSaasJwtVerifier(config, jwksBearerToken);
const policyAuthentication = createActionPolicyJwtVerifier(config);
if (!(await authentication.checkJwks()) || !(await policyAuthentication.checkJwks())) {
  throw new Error("Both execution and action-policy trust profiles must provide usable keys before listening");
}
const server = new SaasConnectServer({
  catalog,
  providerLoader,
  verifyJwt: authentication.verify,
  verifyActionPolicyJwt: policyAuthentication.verify,
  policyControlActiveKid: config.policyControlActiveKid,
  readiness: async () =>
    Object.freeze({
      postgres: true,
      openBao: true,
      jwks: (await authentication.checkJwks()) && (await policyAuthentication.checkJwks()),
      seaweedFs: true,
      providerRegistry: true,
      catalogFingerprint: true,
    }),
  oauthCredentials,
  oauthClientReadiness,
  refreshOAuthClientReadiness: () => oauthClientConfigs.probeAll(oauthProviders),
  scopedOAuthClientReadiness: (scope, local) => nativeServices(scope).getOAuthReadiness(local),
  nativeExecutionForScope: (scope, runtime) => nativeServices(scope, runtime),
  triggerRunnerForScope(scope) {
    const { database, runner } = scopedTriggerRunner(scope);
    return new SaasTriggerRunner({
      scope,
      catalog,
      actionPolicy: database.actionPolicy,
      connectionStore: database.connectionStore,
      store: database.triggers,
      runner,
    });
  },
  triggerCleanupForScope(scope) {
    const { runner } = scopedTriggerRunner(scope);
    return (record, save, signal) => runner.cleanup(record, save, signal);
  },
  async maintenanceForScope(scope) {
    const signal = getRequestSignal(scope);
    if (!signal) throw new Error("Native maintenance requires the original request cancellation");
    const { database, runner } = scopedTriggerRunner(scope);
    const cleanup = new SaasCleanupService({
      ...scope,
      store: database.saasProjects,
      requests: database.connectionRequests,
    });
    try {
      await cleanup.run();
    } finally {
      await cleanup.close();
    }
    assertProcessingActive(scope);
    await new TriggerMaintenance({
      store: database.triggers,
      runner,
      mayContinue: async (record) => {
        const capability = triggerCapability(catalog, record.service, record.triggerId);
        const decisions = await database.actionPolicy.getEffectiveForActor(scope, [capability]);
        if (
          decisions.length !== 1 ||
          decisions[0]?.actionId !== capability ||
          typeof decisions[0].enabled !== "boolean"
        )
          throw new Error("Incomplete Trigger maintenance permission decision");
        return decisions[0].enabled && (await database.triggers.hasCurrentConnection(record));
      },
    }).run(signal);
    assertProcessingActive(scope);
  },
  credentialRevoker: new ProviderSaasCredentialRevoker(),
  runtimeDatabaseFactory,
  oauthServiceFactory: {
    forScope(scope) {
      const database = runtimeDatabaseFactory.forScope(scope);
      return new SaasOAuthService({
        scope,
        connectionRequests: database.connectionRequests,
        secretCodec: database.secretCodec,
        isCustomClientConfigAllowed,
        managedOAuth: nativeServices(scope, database).managedOAuth,
        catalog,
        providerLoader,
        connectionStore: database.connectionStore,
        oauthStateStore: database.oauthStateStore,
        oauthClientConfigStore: oauthClientConfigs,
        callbackOrigin: oauthCallbackOrigin,
      });
    },
  },
});
await server.getCatalogFingerprint();
const app = server.createApp();
app.use("/web-saas/*", serveStatic({ root: "./dist" }));

const providerNetwork = Object.freeze({ trustedHosts: config.egressTrustedHosts });
serve({
  fetch: (request) => withProviderNetworkPolicy(providerNetwork, () => app.fetch(request)),
  hostname: config.host,
  port: config.port,
});

function nativeServices(
  scope: Readonly<SaasRequestScope>,
  runtime: SaasRuntimeDatabase = runtimeDatabaseFactory.forScope(scope),
) {
  return createScopedNativeServices({
    scope,
    catalog,
    runtime,
    configuredOrigin: oauthCallbackOrigin,
    managedCompletionUri: config.managedCompletionUri,
  });
}

function scopedTriggerRunner(scope: Readonly<SaasRequestScope>) {
  const database = runtimeDatabaseFactory.forScope(scope);
  const native = nativeServices(scope, database);
  const connections = createScopedConnectionService({
    catalog,
    providerLoader,
    store: database.connectionStore,
    oauthCredentials,
    refreshCoordinator: database.refreshCoordinator,
    marketplace: native.marketplace,
  });
  const runner = new TriggerRunner({
    catalog,
    providerLoader,
    connections,
    store: database.triggers,
    oauthClientConfigs: oauthClientConfigService,
    cleanupConnection: (record) => database.triggers.getCleanupConnection(record, connectionSecrets),
  });
  return { database, runner };
}

function assertGeneratedCatalog(catalog: CatalogStore, registryServices: string[]): void {
  const catalogServices = new Set(catalog.providers.map((provider) => provider.service));
  const missing = registryServices.filter((service) => !catalogServices.has(service));
  if (missing.length > 0) {
    throw new Error(`Generated provider registry is absent from the catalog: ${missing.join(", ")}`);
  }
  if (!/^W\/"[0-9a-f]+-[0-9a-f]{8}"$/.test(catalog.providerSummariesEtag)) {
    throw new Error("Catalog fingerprint generation failed");
  }
}
