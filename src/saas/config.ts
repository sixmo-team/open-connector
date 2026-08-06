export interface SaasConfig {
  postgresUrl: string;
  openBaoAddress: string;
  openBaoTokenFile: string;
  openBaoRequestTimeoutMs: number;
  openBaoMaxRequestBytes: number;
  openBaoMaxResponseBytes: number;
  internalOrigin: string;
  oauthCallbackOrigin: string;
  jwksUrl: string;
  jwksBearerTokenFile: string;
  jwtIssuer: string;
  jwtAudience: "open-connector-saas";
  jwtActiveKid: string;
  seaweedFsEndpoint: string;
  seaweedFsBucket: string;
  seaweedFsAccessKeyId: string;
  seaweedFsSecretAccessKey: string;
  host: string;
  port: number;
}

const openBaoTokenPath = "/run/secrets/open_connector_openbao_token";
const jwksBearerTokenPath = "/run/secrets/open_connector_jwks_bearer_token";

const requiredVariables = {
  postgresUrl: "OPEN_CONNECTOR_POSTGRES_URL",
  openBaoAddress: "OPEN_CONNECTOR_OPENBAO_ADDR",
  openBaoTokenFile: "OPEN_CONNECTOR_OPENBAO_TOKEN_FILE",
  jwksUrl: "OPEN_CONNECTOR_JWKS_URL",
  jwksBearerTokenFile: "OPEN_CONNECTOR_JWKS_BEARER_TOKEN_FILE",
  internalOrigin: "OPEN_CONNECTOR_INTERNAL_URL",
  oauthCallbackOrigin: "OPEN_CONNECTOR_OAUTH_CALLBACK_ORIGIN",
  jwtIssuer: "OPEN_CONNECTOR_JWT_ISSUER",
  jwtAudience: "OPEN_CONNECTOR_JWT_AUDIENCE",
  jwtActiveKid: "OPEN_CONNECTOR_JWT_ACTIVE_KID",
  seaweedFsEndpoint: "OPEN_CONNECTOR_SEAWEEDFS_ENDPOINT",
  seaweedFsBucket: "OPEN_CONNECTOR_SEAWEEDFS_BUCKET",
  seaweedFsAccessKeyId: "OPEN_CONNECTOR_SEAWEEDFS_ACCESS_KEY_ID",
  seaweedFsSecretAccessKey: "OPEN_CONNECTOR_SEAWEEDFS_SECRET_ACCESS_KEY",
} as const;

/** Read the fail-closed configuration for the isolated SaaS listener. */
export function readSaasConfig(environment: NodeJS.ProcessEnv = process.env): SaasConfig {
  const values = Object.fromEntries(
    Object.entries(requiredVariables).map(([key, name]) => [key, requireValue(environment, name)]),
  ) as Record<keyof typeof requiredVariables, string>;

  requireUrl(values.postgresUrl, "OPEN_CONNECTOR_POSTGRES_URL", ["postgres:", "postgresql:"]);
  requireUrl(values.openBaoAddress, "OPEN_CONNECTOR_OPENBAO_ADDR", ["https:"]);
  const openBaoUrl = new URL(values.openBaoAddress);
  if (["openbao", "marketing-agent-openbao", "localhost", "127.0.0.1", "[::1]"].includes(openBaoUrl.hostname)) {
    throw new Error("OPEN_CONNECTOR_OPENBAO_ADDR must not target the local development OpenBao service");
  }
  if (openBaoUrl.username || openBaoUrl.password || openBaoUrl.search || openBaoUrl.hash) {
    throw new Error("OPEN_CONNECTOR_OPENBAO_ADDR must not contain credentials, a query, or a fragment");
  }
  requirePrivateServiceUrl(values.internalOrigin, "OPEN_CONNECTOR_INTERNAL_URL");
  requirePrivateServiceUrl(values.jwksUrl, "OPEN_CONNECTOR_JWKS_URL");
  requirePublicCallbackOrigin(values.oauthCallbackOrigin);
  requirePrivateServiceUrl(values.seaweedFsEndpoint, "OPEN_CONNECTOR_SEAWEEDFS_ENDPOINT");
  if (values.openBaoTokenFile !== openBaoTokenPath) {
    throw new Error(`OPEN_CONNECTOR_OPENBAO_TOKEN_FILE must be ${openBaoTokenPath}`);
  }
  if (values.jwksBearerTokenFile !== jwksBearerTokenPath) {
    throw new Error(`OPEN_CONNECTOR_JWKS_BEARER_TOKEN_FILE must be ${jwksBearerTokenPath}`);
  }
  if (values.jwtAudience !== "open-connector-saas") {
    throw new Error("OPEN_CONNECTOR_JWT_AUDIENCE must be open-connector-saas");
  }
  rejectUnsafeSaasOverrides(environment);

  return Object.freeze({
    ...values,
    jwtAudience: "open-connector-saas" as const,
    openBaoRequestTimeoutMs: readBoundedInteger(
      environment.OPEN_CONNECTOR_OPENBAO_REQUEST_TIMEOUT_MS,
      5_000,
      100,
      30_000,
      "OPEN_CONNECTOR_OPENBAO_REQUEST_TIMEOUT_MS",
    ),
    openBaoMaxRequestBytes: readBoundedInteger(
      environment.OPEN_CONNECTOR_OPENBAO_MAX_REQUEST_BYTES,
      262_144,
      1_024,
      1_048_576,
      "OPEN_CONNECTOR_OPENBAO_MAX_REQUEST_BYTES",
    ),
    openBaoMaxResponseBytes: readBoundedInteger(
      environment.OPEN_CONNECTOR_OPENBAO_MAX_RESPONSE_BYTES,
      1_048_576,
      1_024,
      4_194_304,
      "OPEN_CONNECTOR_OPENBAO_MAX_RESPONSE_BYTES",
    ),
    host: environment.HOST?.trim() || "0.0.0.0",
    port: readPort(environment.PORT),
  });
}

function requireValue(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name]?.trim();
  if (!value) {
    throw new Error(`${name} is required in SaaS mode`);
  }
  return value;
}

function requireUrl(value: string, name: string, protocols: string[]): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute URL`);
  }
  if (!protocols.includes(url.protocol)) {
    throw new Error(`${name} uses an unsupported protocol`);
  }
}

function requirePrivateServiceUrl(value: string, name: string): void {
  requireUrl(value, name, ["http:", "https:"]);
  const url = new URL(value);
  if (
    url.protocol === "http:" &&
    (url.hostname.includes(".") ||
      url.hostname === "localhost" ||
      url.hostname === "127.0.0.1" ||
      url.hostname === "[::1]")
  ) {
    throw new Error(`${name} must use HTTPS unless it targets a private Compose service`);
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error(`${name} must not contain credentials, a query, or a fragment`);
  }
}

function requirePublicCallbackOrigin(value: string): void {
  const name = "OPEN_CONNECTOR_OAUTH_CALLBACK_ORIGIN";
  requireUrl(value, name, ["https:"]);
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash) {
    throw new Error(`${name} must not contain credentials, a query, or a fragment`);
  }
}

function rejectUnsafeSaasOverrides(environment: NodeJS.ProcessEnv): void {
  for (const name of [
    "OPEN_CONNECTOR_OPENBAO_TOKEN",
    "OPEN_CONNECTOR_JWKS_BEARER_TOKEN",
    "OOMOL_CONNECT_ENCRYPTION_KEY",
    "OOMOL_CONNECT_DATA_DIR",
    "OPEN_CONNECTOR_TRANSIT_FILE_PATH",
    "OPEN_CONNECTOR_PUBLISHED_PORT",
    "OPEN_CONNECTOR_HOST_PORT",
  ]) {
    if (environment[name]?.trim()) {
      throw new Error(`${name} is not supported in SaaS mode`);
    }
  }

  if (environment.TRANSIT_FILES_BACKEND?.trim().toLowerCase() === "local") {
    throw new Error("TRANSIT_FILES_BACKEND must not use local storage in SaaS mode");
  }

  for (const name of ["OOMOL_CONNECT_ALLOWED_ACTIONS", "OOMOL_CONNECT_ALLOWED_PROXIES"]) {
    const rules = environment[name]?.split(",").map((value) => value.trim()) ?? [];
    if (rules.some((rule) => rule.includes("*"))) {
      throw new Error(`${name} must not contain wildcard permissions in SaaS mode`);
    }
  }
}

function readPort(value: string | undefined): number {
  const port = value === undefined ? 3000 : Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("PORT must be an integer between 1 and 65535");
  }
  return port;
}

function readBoundedInteger(
  value: string | undefined,
  defaultValue: number,
  minimum: number,
  maximum: number,
  name: string,
): number {
  const result = value === undefined ? defaultValue : Number(value);
  if (!Number.isSafeInteger(result) || result < minimum || result > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return result;
}
