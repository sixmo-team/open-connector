import type { SaasJwtVerifier } from "./saas-jwt-verifier.ts";
import type { AddressInfo } from "node:net";

import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { readSaasConfig } from "../config.ts";
import { createSaasJwtVerifier, readJwksBearerTokenFile } from "./saas-jwt-verifier.ts";

const completeEnvironment: NodeJS.ProcessEnv = {
  OPEN_CONNECTOR_POSTGRES_URL: "postgresql://connector@postgres/open_connector",
  OPEN_CONNECTOR_OPENBAO_ADDR: "https://openbao.production.example.com",
  OPEN_CONNECTOR_OPENBAO_TOKEN_FILE: "/run/secrets/open_connector_openbao_token",
  OPEN_CONNECTOR_INTERNAL_URL: "http://open-connector:3000",
  OPEN_CONNECTOR_JWKS_URL: "http://backend/internal/integrations/.well-known/jwks.json",
  OPEN_CONNECTOR_JWKS_BEARER_TOKEN_FILE: "/run/secrets/open_connector_jwks_bearer_token",
  OPEN_CONNECTOR_OAUTH_CALLBACK_ORIGIN: "https://api.example.com/integrations",
  OPEN_CONNECTOR_JWT_ISSUER: "integration-backend",
  OPEN_CONNECTOR_JWT_AUDIENCE: "open-connector-saas",
  OPEN_CONNECTOR_JWT_ACTIVE_KID: "current",
  OPEN_CONNECTOR_ACTION_POLICY_CONTROL_JWKS_URL:
    "http://integration-admin/internal/integrations/.well-known/action-policy-jwks.json",
  OPEN_CONNECTOR_ACTION_POLICY_CONTROL_JWT_ISSUER: "integration-admin",
  OPEN_CONNECTOR_ACTION_POLICY_CONTROL_JWT_AUDIENCE: "open-connector-action-policy",
  OPEN_CONNECTOR_ACTION_POLICY_CONTROL_JWT_ACTIVE_KID: "policy-current",
  OPEN_CONNECTOR_SEAWEEDFS_ENDPOINT: "http://seaweedfs:8333",
  OPEN_CONNECTOR_SEAWEEDFS_BUCKET: "integration-transit",
  OPEN_CONNECTOR_SEAWEEDFS_ACCESS_KEY_ID: "connector",
  OPEN_CONNECTOR_SEAWEEDFS_SECRET_ACCESS_KEY: "secret",
};

const requiredNames = Object.keys(completeEnvironment);
const temporaryDirectories: string[] = [];

describe("readSaasConfig", () => {
  it.each(requiredNames)("rejects missing %s", (name) => {
    const environment = { ...completeEnvironment };
    delete environment[name];
    expect(() => readSaasConfig(environment)).toThrow(`${name} is required`);
  });

  it("rejects a raw JWKS bearer token environment override", () => {
    expect(() => readSaasConfig({ ...completeEnvironment, OPEN_CONNECTOR_JWKS_BEARER_TOKEN: "raw-secret" })).toThrow(
      "OPEN_CONNECTOR_JWKS_BEARER_TOKEN is not supported",
    );
  });
});

describe("readJwksBearerTokenFile", () => {
  afterEach(async () => {
    await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
  });

  it("reads one nonempty token and trims a secret-file newline", async () => {
    const path = await tokenFile("jwks-secret\n");
    await expect(readJwksBearerTokenFile(path)).resolves.toBe("jwks-secret");
  });

  it.each([
    ["empty", ""],
    ["whitespace-only", " \n"],
    ["multiple tokens", "first second"],
    ["oversized", "x".repeat(16_385)],
  ])("rejects %s content", async (_label, content) => {
    await expect(readJwksBearerTokenFile(await tokenFile(content))).rejects.toThrow();
  });
});

let privateKey: CryptoKey;
let oldPrivateKey: CryptoKey;
let jwksUrl: string;
let closeJwksServer: () => Promise<void>;
let expectedJwksBearerToken = "jwks-secret";

afterEach(() => {
  expectedJwksBearerToken = "jwks-secret";
});

beforeAll(async () => {
  const current = await generateKeyPair("EdDSA");
  const old = await generateKeyPair("EdDSA");
  privateKey = current.privateKey;
  oldPrivateKey = old.privateKey;
  const keys = [
    { ...(await exportJWK(current.publicKey)), alg: "EdDSA", kid: "current", use: "sig" },
    { ...(await exportJWK(old.publicKey)), alg: "EdDSA", kid: "old", use: "sig" },
  ];
  const server = createServer((request, response) => {
    if (request.headers.authorization !== `Bearer ${expectedJwksBearerToken}`) {
      response.statusCode = 401;
      response.end();
      return;
    }
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ keys }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  jwksUrl = `http://127.0.0.1:${address.port}/jwks.json`;
  closeJwksServer = () =>
    new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
});

afterAll(async () => closeJwksServer());

describe("createSaasJwtVerifier", () => {
  it("accepts a current EdDSA token and returns a deeply immutable scope", async () => {
    const scope = await verifier()(header(await token()));
    expect(scope).toMatchObject({ tenantId: "tenant-1", purpose: "catalog:read" });
    expect(Object.isFrozen(scope)).toBe(true);
    expect(Object.isFrozen(scope.permissions)).toBe(true);
  });

  it("accepts only exact customer maintenance authority without execution bindings", async () => {
    const user = randomUUID();
    const claims = {
      sub: user,
      actor_user_id: user,
      subject_user_id: user,
      purpose: "maintenance:run",
      permissions: ["maintenance:run"],
    };
    expect(await verifier()(header(await token(claims)))).toMatchObject({
      actorUserId: user,
      subjectUserId: user,
      purpose: "maintenance:run",
      permissions: ["maintenance:run"],
    });
    for (const extra of [
      { actor_user_id: randomUUID() },
      { permissions: ["maintenance:run", "action:execute:v2"] },
      { local_connection_id: randomUUID() },
      { connector_connection_id: randomUUID() },
      { oauth_session_id: randomUUID() },
      { file_id: randomUUID() },
      { action_id: "example.run" },
      { request_hash: "a".repeat(43) },
      { max_output_bytes: 4096 },
      { subject_kind: "policy_control" },
    ])
      await expect(verifier()(header(await token({ ...claims, ...extra })))).rejects.toThrow("unauthorized");
  });

  it("retains a hashed connection-create binding without inventing a connector connection or action", async () => {
    const userId = randomUUID();
    const localConnectionId = randomUUID();
    const scope = await verifier()(
      header(
        await token({
          sub: userId,
          tenant_id: randomUUID(),
          workspace_id: randomUUID(),
          actor_user_id: userId,
          subject_user_id: userId,
          purpose: "connection:write",
          permissions: ["connection:write"],
          local_connection_id: localConnectionId,
          request_hash: "a".repeat(43),
        }),
      ),
    );
    expect(scope).toMatchObject({ purpose: "connection:write", localConnectionId, requestHash: "a".repeat(43) });
    expect(scope).not.toHaveProperty("connectorConnectionId", expect.anything());
    expect(scope).not.toHaveProperty("actionId", expect.anything());
  });

  it.each([
    { local_connection_id: undefined },
    { action_id: "example.run" },
    { oauth_session_id: randomUUID() },
    { max_output_bytes: 4096 },
  ])("keeps hashed connection-create claims restricted: %j", async (changes) => {
    await expect(
      verifier()(
        header(
          await token({
            purpose: "connection:write",
            permissions: ["connection:write"],
            local_connection_id: randomUUID(),
            request_hash: "a".repeat(43),
            ...changes,
          }),
        ),
      ),
    ).rejects.toThrow("unauthorized");
  });

  it("retains the signed reviewed output bound on action execution scopes", async () => {
    const scope = await verifier()(
      header(
        await token({
          purpose: "action:execute:v2",
          permissions: ["action:execute:v2"],
          local_connection_id: "local-1",
          connector_connection_id: "connector-1",
          action_id: "gmail.messages_list",
          max_output_bytes: 8_388_608,
          request_hash: "a".repeat(43),
        }),
      ),
    );

    expect(scope).toMatchObject({ purpose: "action:execute:v2", maxOutputBytes: 8_388_608 });
  });

  it("retains the signed file binding on file read scopes", async () => {
    const fileId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const scope = await verifier()(
      header(await token({ purpose: "file:read", permissions: ["file:read"], file_id: fileId })),
    );

    expect(scope).toMatchObject({ purpose: "file:read", fileId });
  });

  it("returns a distinct catalog service principal without tenant scope fields", async () => {
    const principal = await verifier()(
      header(
        await token({
          sub: "open-connector-catalog",
          subject_kind: "service",
          tenant_id: undefined,
          workspace_id: undefined,
          actor_user_id: undefined,
          subject_user_id: undefined,
          workspace_role: undefined,
        }),
      ),
    );
    expect(principal).toEqual({
      subjectKind: "service",
      subject: "open-connector-catalog",
      purpose: "catalog:read",
      permissions: ["catalog:read"],
    });
    expect(Object.isFrozen(principal)).toBe(true);
    expect(Object.isFrozen(principal.permissions)).toBe(true);
    expect(principal).not.toHaveProperty("tenantId");
  });

  it.each([
    ["tenant claim", { tenant_id: "tenant-1" }],
    ["wrong purpose", { purpose: "connection:read", permissions: ["connection:read"] }],
    ["wildcard permission", { permissions: ["*"] }],
    ["mixed permissions", { permissions: ["catalog:read", "connection:read"] }],
  ])("rejects a catalog service token with a %s", async (_label, serviceOverrides) => {
    await expect(
      verifier()(
        header(
          await token({
            sub: "open-connector-catalog",
            subject_kind: "service",
            tenant_id: undefined,
            workspace_id: undefined,
            actor_user_id: undefined,
            subject_user_id: undefined,
            workspace_role: undefined,
            ...serviceOverrides,
          }),
        ),
      ),
    ).rejects.toThrow("unauthorized");
  });

  it("rejects when the remote JWKS bearer credential is wrong", async () => {
    const badVerifier = createSaasJwtVerifier(
      {
        jwksUrl,
        jwtIssuer: "integration-backend",
        jwtAudience: "open-connector-saas",
        jwtActiveKid: "current",
      },
      "wrong-secret",
    );
    await expect(badVerifier.verify(header(await token()))).rejects.toThrow("unauthorized");
  });

  it("detects rejected bootstrap credentials with warm keys and recovers after rotation", async () => {
    const config: Parameters<typeof createSaasJwtVerifier>[0] = {
      jwksUrl,
      jwtIssuer: "integration-backend",
      jwtAudience: "open-connector-saas",
      jwtActiveKid: "current",
    };
    const authentication = createSaasJwtVerifier(config, "jwks-secret");
    const userId = randomUUID();
    const jwt = await token({
      sub: userId,
      tenant_id: randomUUID(),
      workspace_id: randomUUID(),
      actor_user_id: userId,
      subject_user_id: userId,
    });
    await authentication.verify(header(jwt));
    await expect(authentication.checkJwks()).resolves.toBe(true);

    expectedJwksBearerToken = "replacement-jwks-secret";
    await expect(authentication.checkJwks()).resolves.toBe(false);

    const replacement = createSaasJwtVerifier(config, expectedJwksBearerToken);
    await expect(replacement.checkJwks()).resolves.toBe(true);
    await expect(replacement.verify(header(jwt))).resolves.toMatchObject({ subjectUserId: userId });
  });

  it("reports unready when JWKS is accessible but the active key is missing", async () => {
    const authentication = createSaasJwtVerifier(
      {
        jwksUrl,
        jwtIssuer: "integration-backend",
        jwtAudience: "open-connector-saas",
        jwtActiveKid: randomUUID(),
      },
      "jwks-secret",
    );
    await expect(authentication.checkJwks()).resolves.toBe(false);
  });

  it("rejects an OAuth completion token exceeding 60 seconds", async () => {
    const issuedAt = now();
    await expect(
      verifier()(
        header(
          await token({
            purpose: "oauth:complete",
            permissions: ["oauth:complete"],
            oauth_session_id: "oauth-1",
            local_connection_id: "local-1",
            iat: issuedAt,
            nbf: issuedAt,
            exp: issuedAt + 120,
          }),
        ),
      ),
    ).rejects.toThrow("unauthorized");
  });

  it.each([
    ["issuer", { iss: "other-issuer" }],
    ["audience", { aud: "other-audience" }],
    ["expiry", { iat: now() - 61, nbf: now() - 61, exp: now() - 1 }],
    ["not-before", { nbf: now() + 30, exp: now() + 60 }],
    ["issued-at", { iat: now() + 3_600, nbf: now(), exp: now() + 3_660 }],
    ["lifetime", { iat: now(), nbf: now(), exp: now() + 61 }],
  ])("rejects a token with the wrong %s", async (_label, overrides) => {
    await expect(verifier()(header(await token(overrides)))).rejects.toThrow("unauthorized");
  });

  it("rejects a token using a non-EdDSA algorithm", async () => {
    const jwt = await new SignJWT(claims())
      .setProtectedHeader({ alg: "HS256", kid: "current" })
      .sign(new TextEncoder().encode("a-secret-that-is-long-enough"));
    await expect(verifier()(header(jwt))).rejects.toThrow("unauthorized");
  });

  it("rejects a valid signature from a non-current kid", async () => {
    const jwt = await token({}, "old", oldPrivateKey);
    await expect(verifier()(header(jwt))).rejects.toThrow("unauthorized");
  });

  it("rejects incomplete purpose-specific bindings", async () => {
    const jwt = await token({
      purpose: "action:execute:v2",
      permissions: ["action:execute:v2"],
      request_hash: undefined,
    });
    await expect(verifier()(header(jwt))).rejects.toThrow("unauthorized");
  });

  it("rejects missing and malformed bearer authorization generically", async () => {
    await expect(verifier()(undefined)).rejects.toThrow("unauthorized");
    await expect(verifier()("Bearer static-runtime-token")).rejects.toThrow("unauthorized");
  });
});

function verifier(): SaasJwtVerifier {
  return createSaasJwtVerifier(
    {
      jwksUrl,
      jwtIssuer: "integration-backend",
      jwtAudience: "open-connector-saas",
      jwtActiveKid: "current",
    },
    "jwks-secret",
  ).verify;
}

async function tokenFile(content: string): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "saas-jwks-"));
  temporaryDirectories.push(directory);
  const path = join(directory, "token");
  await writeFile(path, content);
  return path;
}

function now(): number {
  return Math.floor(Date.now() / 1000);
}

function claims(): Record<string, unknown> {
  const issuedAt = now();
  return {
    iss: "integration-backend",
    aud: "open-connector-saas",
    sub: "subject-1",
    jti: crypto.randomUUID(),
    iat: issuedAt,
    nbf: issuedAt,
    exp: issuedAt + 60,
    tenant_id: "tenant-1",
    workspace_id: "workspace-1",
    actor_user_id: "actor-1",
    subject_user_id: "subject-1",
    workspace_role: "member",
    purpose: "catalog:read",
    permissions: ["catalog:read"],
  };
}

async function token(
  overrides: Record<string, unknown> = {},
  kid = "current",
  signingKey: CryptoKey = privateKey,
): Promise<string> {
  return new SignJWT({ ...claims(), ...overrides }).setProtectedHeader({ alg: "EdDSA", kid }).sign(signingKey);
}

function header(jwt: string): string {
  return `Bearer ${jwt}`;
}
