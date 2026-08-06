import { describe, expect, it } from "vitest";
import { readSaasConfig } from "./config.ts";

const productionEnvironment: NodeJS.ProcessEnv = {
  OPEN_CONNECTOR_POSTGRES_URL: "postgresql://connector_runtime:secret@postgres/open_connector",
  OPEN_CONNECTOR_OPENBAO_ADDR: "https://openbao.production.example.com",
  OPEN_CONNECTOR_OPENBAO_TOKEN_FILE: "/run/secrets/open_connector_openbao_token",
  OPEN_CONNECTOR_INTERNAL_URL: "http://open-connector:3000",
  OPEN_CONNECTOR_JWKS_URL: "http://backend/internal/integrations/.well-known/jwks.json",
  OPEN_CONNECTOR_JWKS_BEARER_TOKEN_FILE: "/run/secrets/open_connector_jwks_bearer_token",
  OPEN_CONNECTOR_OAUTH_CALLBACK_ORIGIN: "https://api.example.com/integrations",
  OPEN_CONNECTOR_JWT_ISSUER: "https://backend.example.com",
  OPEN_CONNECTOR_JWT_AUDIENCE: "open-connector-saas",
  OPEN_CONNECTOR_JWT_ACTIVE_KID: "connector-2026-08",
  OPEN_CONNECTOR_SEAWEEDFS_ENDPOINT: "http://seaweedfs:8333",
  OPEN_CONNECTOR_SEAWEEDFS_BUCKET: "open-connector-transit",
  OPEN_CONNECTOR_SEAWEEDFS_ACCESS_KEY_ID: "connector-runtime",
  OPEN_CONNECTOR_SEAWEEDFS_SECRET_ACCESS_KEY: "secret",
};

function configured(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return { ...productionEnvironment, ...overrides };
}

describe("production SaaS configuration", () => {
  it("accepts only the scoped production storage and identity backends", () => {
    expect(readSaasConfig(configured())).toMatchObject({
      jwtAudience: "open-connector-saas",
      openBaoTokenFile: "/run/secrets/open_connector_openbao_token",
      jwksBearerTokenFile: "/run/secrets/open_connector_jwks_bearer_token",
      oauthCallbackOrigin: "https://api.example.com/integrations",
      seaweedFsBucket: "open-connector-transit",
    });
  });

  it.each([
    "OPEN_CONNECTOR_POSTGRES_URL",
    "OPEN_CONNECTOR_OPENBAO_ADDR",
    "OPEN_CONNECTOR_OPENBAO_TOKEN_FILE",
    "OPEN_CONNECTOR_INTERNAL_URL",
    "OPEN_CONNECTOR_JWKS_URL",
    "OPEN_CONNECTOR_JWKS_BEARER_TOKEN_FILE",
    "OPEN_CONNECTOR_OAUTH_CALLBACK_ORIGIN",
    "OPEN_CONNECTOR_JWT_ISSUER",
    "OPEN_CONNECTOR_JWT_AUDIENCE",
    "OPEN_CONNECTOR_JWT_ACTIVE_KID",
    "OPEN_CONNECTOR_SEAWEEDFS_ENDPOINT",
    "OPEN_CONNECTOR_SEAWEEDFS_BUCKET",
    "OPEN_CONNECTOR_SEAWEEDFS_ACCESS_KEY_ID",
    "OPEN_CONNECTOR_SEAWEEDFS_SECRET_ACCESS_KEY",
  ])("rejects absent %s", (name) => {
    const environment = configured();
    delete environment[name];
    expect(() => readSaasConfig(environment)).toThrow(`${name} is required`);
  });

  it.each([
    ["OPEN_CONNECTOR_POSTGRES_URL", "file:/data/open-connector.sqlite"],
    ["OPEN_CONNECTOR_OPENBAO_ADDR", "http://openbao:8200"],
    ["OPEN_CONNECTOR_OPENBAO_TOKEN_FILE", "/data/root-token"],
    ["OPEN_CONNECTOR_OPENBAO_ADDR", "https://openbao:8200"],
    ["OPEN_CONNECTOR_OPENBAO_ADDR", "https://root:secret@openbao.production.example.com"],
    ["OPEN_CONNECTOR_OAUTH_CALLBACK_ORIGIN", "http://api.example.com/integrations"],
    ["OPEN_CONNECTOR_OAUTH_CALLBACK_ORIGIN", "https://user:secret@api.example.com/integrations"],
    ["OPEN_CONNECTOR_JWKS_BEARER_TOKEN_FILE", "/data/jwks-token"],
    ["OPEN_CONNECTOR_JWKS_BEARER_TOKEN", "plaintext-internal-token"],
    ["OPEN_CONNECTOR_OPENBAO_TOKEN", "root"],
    ["OOMOL_CONNECT_ENCRYPTION_KEY", "plaintext-secret-fallback"],
    ["OOMOL_CONNECT_DATA_DIR", "/data"],
    ["TRANSIT_FILES_BACKEND", "local"],
    ["OPEN_CONNECTOR_TRANSIT_FILE_PATH", "/data/files"],
    ["OOMOL_CONNECT_ALLOWED_ACTIONS", "gmail.*"],
    ["OOMOL_CONNECT_ALLOWED_PROXIES", "*"],
    ["OPEN_CONNECTOR_PUBLISHED_PORT", "3000"],
    ["OPEN_CONNECTOR_HOST_PORT", "127.0.0.1:3000"],
  ])("rejects unsafe %s", (name, value) => {
    expect(() => readSaasConfig(configured({ [name]: value }))).toThrow();
  });

  it.each([
    ["OPEN_CONNECTOR_JWKS_URL", "http://127.0.0.1:4000/jwks.json"],
    ["OPEN_CONNECTOR_SEAWEEDFS_ENDPOINT", "http://localhost:8333"],
  ])("rejects loopback production dependency %s", (name, value) => {
    expect(() => readSaasConfig(configured({ [name]: value }))).toThrow("must use HTTPS");
  });
});
