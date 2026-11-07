import type { SaasConfig } from "../config.ts";
import type { ActionPolicyControlPrincipal, SaasPrincipal } from "../contracts.ts";

import { createRemoteJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { open } from "node:fs/promises";
import { parseActionPolicyControlClaims, parseConnectorIdentityClaims } from "../contracts.ts";

export type SaasJwtVerifier = (authorization: string | undefined) => Promise<Readonly<SaasPrincipal>>;
export type ActionPolicyJwtVerifier = (
  authorization: string | undefined,
) => Promise<Readonly<ActionPolicyControlPrincipal>>;

export class SaasAuthorizationError extends Error {
  readonly status: 401 | 403;

  constructor(status: 401 | 403) {
    super(status === 401 ? "unauthorized" : "forbidden");
    this.name = "SaasAuthorizationError";
    this.status = status;
  }
}

/** Share one key resolver between scoped JWT verification and authenticated JWKS readiness. */
export function createSaasJwtVerifier(
  config: Pick<SaasConfig, "jwksUrl" | "jwtIssuer" | "jwtAudience" | "jwtActiveKid">,
  jwksBearerToken: string,
): { verify: SaasJwtVerifier; checkJwks: () => Promise<boolean> } {
  assertBearerToken(jwksBearerToken);
  const jwks = createRemoteJWKSet(new URL(config.jwksUrl), {
    headers: { authorization: `Bearer ${jwksBearerToken}` },
    timeoutDuration: 3_000,
  });

  const verify: SaasJwtVerifier = async (authorization): Promise<Readonly<SaasPrincipal>> => {
    const token = readBearerToken(authorization);
    try {
      const protectedHeader = decodeProtectedHeader(token);
      if (protectedHeader.alg !== "EdDSA" || protectedHeader.kid !== config.jwtActiveKid) {
        throw new Error("unexpected JWT header");
      }

      const { payload } = await jwtVerify(token, jwks, {
        algorithms: ["EdDSA"],
        issuer: config.jwtIssuer,
        audience: config.jwtAudience,
        requiredClaims: ["iss", "aud", "sub", "jti", "iat", "nbf", "exp"],
        clockTolerance: 0,
        maxTokenAge: 120,
      });
      const claims = parseConnectorIdentityClaims(payload);
      if ("subjectKind" in claims) {
        const permissions = [...claims.permissions];
        Object.freeze(permissions);
        if (claims.purpose === "catalog:read") {
          return Object.freeze({
            subjectKind: "service" as const,
            subject: claims.sub,
            purpose: claims.purpose,
            permissions: permissions as ["catalog:read"],
          });
        }
        if (claims.purpose === "action-policy:subjects" || claims.purpose === "action-policy:purge") {
          return Object.freeze({
            subjectKind: "service" as const,
            subject: claims.sub,
            purpose: claims.purpose,
            permissions,
            target: Object.freeze({ ...claims.target }),
            requestId: claims.jti,
            requestHash: claims.requestHash,
          });
        }
        const target = claims.target;
        if (target.kind !== "tenant" && target.kind !== "workspace") throw new Error("Invalid native lifecycle target");
        return Object.freeze({
          subjectKind: "service" as const,
          subject: claims.sub,
          purpose: claims.purpose,
          permissions,
          target: Object.freeze({ ...target }),
          requestId: claims.jti,
          requestHash: claims.requestHash,
        });
      }

      const permissions = [...claims.permissions];
      Object.freeze(permissions);
      return Object.freeze({
        tenantId: claims.tenantId,
        workspaceId: claims.workspaceId,
        actorUserId: claims.actorUserId,
        subjectUserId: claims.subjectUserId,
        workspaceRole: claims.workspaceRole,
        purpose: claims.purpose,
        permissions,
        localConnectionId: claims.localConnectionId,
        connectorConnectionId: claims.connectorConnectionId,
        oauthSessionId: claims.oauthSessionId,
        actionId: claims.actionId,
        maxOutputBytes: claims.maxOutputBytes,
        requestHash: claims.requestHash,
        fileId: claims.fileId,
      });
    } catch {
      throw new SaasAuthorizationError(401);
    }
  };

  return {
    verify,
    async checkJwks(): Promise<boolean> {
      try {
        // Cached signing keys must not hide a rejected bootstrap credential.
        await jwks.reload();
        await jwks({ alg: "EdDSA", kid: config.jwtActiveKid });
        return true;
      } catch {
        return false;
      }
    },
  };
}

/** Control public keys are resolved separately and can never authorize customer execution. */
export function createActionPolicyJwtVerifier(
  config: Pick<
    SaasConfig,
    "policyControlJwksUrl" | "policyControlIssuer" | "policyControlAudience" | "policyControlActiveKid"
  >,
): { verify: ActionPolicyJwtVerifier; checkJwks: () => Promise<boolean> } {
  const jwks = createRemoteJWKSet(new URL(config.policyControlJwksUrl), { timeoutDuration: 3_000 });
  const verify: ActionPolicyJwtVerifier = async (authorization) => {
    const token = readBearerToken(authorization);
    try {
      const header = decodeProtectedHeader(token);
      if (header.alg !== "EdDSA" || header.kid !== config.policyControlActiveKid)
        throw new Error("unexpected control header");
      const { payload } = await jwtVerify(token, jwks, {
        algorithms: ["EdDSA"],
        issuer: config.policyControlIssuer,
        audience: config.policyControlAudience,
        requiredClaims: ["iss", "aud", "sub", "jti", "iat", "nbf", "exp"],
        clockTolerance: 0,
        maxTokenAge: 120,
      });
      const claims = parseActionPolicyControlClaims(payload);
      const permissions = [...claims.permissions];
      Object.freeze(permissions);
      return Object.freeze({
        subjectKind: claims.subjectKind,
        subject: claims.sub,
        purpose: claims.purpose,
        permissions,
        target: Object.freeze({ ...claims.target }),
        requestId: claims.jti,
        requestHash: claims.requestHash,
      });
    } catch {
      throw new SaasAuthorizationError(401);
    }
  };
  return {
    verify,
    async checkJwks(): Promise<boolean> {
      try {
        await jwks.reload();
        await jwks({ alg: "EdDSA", kid: config.policyControlActiveKid });
        return true;
      } catch {
        return false;
      }
    },
  };
}

const maximumJwksBearerTokenBytes = 16_384;

/** Read a bounded JWKS credential from its Docker secret file. */
export async function readJwksBearerTokenFile(path: string): Promise<string> {
  const handle = await open(path, "r");
  try {
    const buffer = Buffer.allocUnsafe(maximumJwksBearerTokenBytes + 1);
    let totalBytesRead = 0;
    while (totalBytesRead < buffer.length) {
      const { bytesRead } = await handle.read(buffer, totalBytesRead, buffer.length - totalBytesRead, totalBytesRead);
      if (bytesRead === 0) break;
      totalBytesRead += bytesRead;
    }
    if (totalBytesRead > maximumJwksBearerTokenBytes) {
      throw new Error("JWKS bearer token file is too large");
    }
    const token = buffer.subarray(0, totalBytesRead).toString("utf8").trim();
    assertBearerToken(token);
    return token;
  } finally {
    await handle.close();
  }
}

function assertBearerToken(token: string): void {
  if (!/^[\x21-\x7e]+$/.test(token)) {
    throw new Error("JWKS bearer token file must contain one nonempty token");
  }
}

export function readBearerToken(authorization: string | undefined): string {
  const match = /^Bearer ([^\s]+)$/.exec(authorization ?? "");
  if (!match) {
    throw new SaasAuthorizationError(401);
  }
  return match[1]!;
}
