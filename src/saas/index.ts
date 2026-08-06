import type { CatalogStore } from "../catalog-store.ts";

import { HeadBucketCommand } from "@aws-sdk/client-s3";
import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { loadCatalog } from "../catalog-store.ts";
import { parsePrivateNetworkAccessFlag, setPrivateNetworkAccessAllowed } from "../core/request.ts";
import { OAuthClientConfigService } from "../oauth/oauth-client-config-service.ts";
import { OAuthCredentialRefreshService } from "../oauth/oauth-credential-refresh-service.ts";
import { ProviderLoader } from "../providers/provider-loader.ts";
import { executorModules } from "../providers/registry.generated.ts";
import { createSaasJwtVerifier, readJwksBearerTokenFile } from "./auth/saas-jwt-verifier.ts";
import { readSaasConfig } from "./config.ts";
import { ProviderSaasCredentialRevoker } from "./connections/provider-credential-revoker.ts";
import { createSeaweedFsS3Client } from "./files/seaweedfs-transit-files.ts";
import { SaasOAuthService } from "./oauth/saas-oauth-service.ts";
import { OpenBaoClient } from "./secrets/openbao-client.ts";
import { OpenBaoConnectionSecretStore } from "./secrets/openbao-connection-store.ts";
import { OpenBaoOAuthClientConfigStore } from "./secrets/openbao-oauth-client-config-store.ts";
import { OpenBaoOAuthStateSecretStore } from "./secrets/openbao-oauth-state-secret-store.ts";
import { SaasConnectServer } from "./server/saas-connect-server.ts";
import { createPostgresPool } from "./storage/postgres-pool.ts";
import { probeSaasRuntimeDatabase, SaasRuntimeDatabaseFactory } from "./storage/postgres-runtime-database.ts";

const config = readSaasConfig();
setPrivateNetworkAccessAllowed(parsePrivateNetworkAccessFlag(process.env.OOMOL_CONNECT_ALLOW_PRIVATE_NETWORK));
const jwksBearerToken = await readJwksBearerTokenFile(config.jwksBearerTokenFile);
const openBaoClient = await OpenBaoClient.fromTokenFile({
  address: config.openBaoAddress,
  tokenFile: config.openBaoTokenFile,
  requestTimeoutMs: config.openBaoRequestTimeoutMs,
  maxRequestBytes: config.openBaoMaxRequestBytes,
  maxResponseBytes: config.openBaoMaxResponseBytes,
});
const pool = createPostgresPool(config.postgresUrl);
await openBaoClient.probeCapabilities();
await probeSaasRuntimeDatabase(pool);
const seaweedFsClient = createSeaweedFsS3Client(config);
await seaweedFsClient.send(new HeadBucketCommand({ Bucket: config.seaweedFsBucket }), {
  abortSignal: AbortSignal.timeout(5_000),
});
const runtimeDatabaseFactory = new SaasRuntimeDatabaseFactory({
  pool,
  connectionSecrets: new OpenBaoConnectionSecretStore(openBaoClient),
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
const registryServices = Object.keys(executorModules);
const catalog = await loadCatalog(undefined, { executableServices: registryServices });
assertGeneratedCatalog(catalog, registryServices);
const providerLoader = new ProviderLoader(executorModules);
const oauthCallbackOrigin = config.oauthCallbackOrigin;
const oauthClientConfigService = new OAuthClientConfigService({
  catalog,
  origin: oauthCallbackOrigin,
  store: oauthClientConfigs,
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
const oauthCredentials = new OAuthCredentialRefreshService(oauthClientConfigService);
const app = new SaasConnectServer({
  catalog,
  providerLoader,
  verifyJwt: createSaasJwtVerifier(config, jwksBearerToken),
  readiness: Object.freeze({
    postgres: true,
    openBao: true,
    jwks: true,
    seaweedFs: true,
    providerRegistry: true,
    catalogFingerprint: true,
  }),
  oauthCredentials,
  oauthClientReadiness,
  credentialRevoker: new ProviderSaasCredentialRevoker(),
  runtimeDatabaseFactory,
  oauthServiceFactory: {
    forScope(scope) {
      const database = runtimeDatabaseFactory.forScope(scope);
      return new SaasOAuthService({
        scope,
        catalog,
        providerLoader,
        connectionStore: database.connectionStore,
        oauthStateStore: database.oauthStateStore,
        oauthClientConfigStore: oauthClientConfigs,
        callbackOrigin: oauthCallbackOrigin,
      });
    },
  },
}).createApp();
app.use("/web-saas/*", serveStatic({ root: "./dist" }));

serve({ fetch: app.fetch, hostname: config.host, port: config.port });

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
