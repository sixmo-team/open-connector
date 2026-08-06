import type { SaasPurpose, SaasRequestScope } from "../contracts.ts";
import type { SaasJwtVerifier } from "./saas-jwt-verifier.ts";
import type { Context, MiddlewareHandler } from "hono";

import { SaasAuthorizationError } from "./saas-jwt-verifier.ts";

export interface SaasHonoEnvironment {
  Variables: {
    saasRequestScope: Readonly<SaasRequestScope>;
  };
}

/** Verify a bearer token and capture its immutable scope on the request context. */
export function requireSaasPurpose(
  verifier: SaasJwtVerifier,
  expectedPurpose: SaasPurpose,
): MiddlewareHandler<SaasHonoEnvironment> {
  return async (context, next): Promise<Response | void> => {
    try {
      const principal = await verifier(context.req.header("authorization"));
      if ("subjectKind" in principal) {
        throw new SaasAuthorizationError(403);
      }
      context.set("saasRequestScope", principal);
      getSaasRequestScope(context, expectedPurpose);
    } catch (error) {
      const status = error instanceof SaasAuthorizationError ? error.status : 401;
      return context.json({ error: status === 401 ? "unauthorized" : "forbidden" }, status);
    }
    await next();
  };
}

/** Admit the catalog service identity without making it a tenant request scope. */
export function requireCatalogPurpose(verifier: SaasJwtVerifier): MiddlewareHandler<SaasHonoEnvironment> {
  return async (context, next): Promise<Response | void> => {
    try {
      const principal = await verifier(context.req.header("authorization"));
      if (!("subjectKind" in principal)) {
        context.set("saasRequestScope", principal);
        getSaasRequestScope(context, "catalog:read");
      }
    } catch (error) {
      const status = error instanceof SaasAuthorizationError ? error.status : 401;
      return context.json({ error: status === 401 ? "unauthorized" : "forbidden" }, status);
    }
    await next();
  };
}

/** Return the verified request scope only when it grants the route's exact purpose. */
export function getSaasRequestScope(
  context: Context<SaasHonoEnvironment>,
  expectedPurpose: SaasPurpose,
): Readonly<SaasRequestScope> {
  const scope = context.get("saasRequestScope");
  if (!scope) {
    throw new SaasAuthorizationError(401);
  }
  if (scope.purpose !== expectedPurpose || !scope.permissions.includes(expectedPurpose)) {
    throw new SaasAuthorizationError(403);
  }
  return scope;
}
