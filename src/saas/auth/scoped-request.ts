import type {
  ActionPolicyControlPrincipal,
  ActionPolicyServicePrincipal,
  NativeLifecycleServicePrincipal,
  SaasPrincipal,
  SaasPurpose,
  SaasRequestScope,
} from "../contracts.ts";
import type { SaasJwtVerifier } from "./saas-jwt-verifier.ts";
import type { Context, MiddlewareHandler } from "hono";

import { captureRequestProcessing } from "../../core/cancellation.ts";
import { SaasAuthorizationError } from "./saas-jwt-verifier.ts";

export interface SaasHonoEnvironment {
  Variables: {
    saasRequestScope: Readonly<SaasRequestScope>;
    controlPrincipal: Readonly<
      ActionPolicyControlPrincipal | ActionPolicyServicePrincipal | NativeLifecycleServicePrincipal
    >;
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
      context.set("saasRequestScope", captureRequestProcessing(principal));
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
        context.set("saasRequestScope", captureRequestProcessing(principal));
        getSaasRequestScope(context, "catalog:read");
      } else if (
        principal.purpose !== "catalog:read" ||
        principal.permissions.length !== 1 ||
        principal.permissions[0] !== "catalog:read"
      ) {
        throw new SaasAuthorizationError(403);
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
  if (scope.purpose !== expectedPurpose || scope.permissions.length !== 1 || scope.permissions[0] !== expectedPurpose) {
    throw new SaasAuthorizationError(403);
  }
  return scope;
}

/** Policy management and lifecycle services do not masquerade as tenant execution scopes. */
export function requireScopedControlPurpose(
  verifier: (authorization: string | undefined) => Promise<Readonly<SaasPrincipal | ActionPolicyControlPrincipal>>,
  expectedPurpose:
    | ActionPolicyControlPrincipal["purpose"]
    | ActionPolicyServicePrincipal["purpose"]
    | NativeLifecycleServicePrincipal["purpose"],
): MiddlewareHandler<SaasHonoEnvironment> {
  return async (context, next): Promise<Response | void> => {
    try {
      const principal = await verifier(context.req.header("authorization"));
      const control = expectedPurpose === "action-policy:read" || expectedPurpose === "action-policy:write";
      if (
        !("subjectKind" in principal) ||
        (control ? principal.subjectKind !== "policy_control" : principal.subjectKind !== "service") ||
        principal.purpose !== expectedPurpose ||
        principal.permissions.length !== 1 ||
        principal.permissions[0] !== expectedPurpose ||
        !("target" in principal)
      )
        throw new SaasAuthorizationError(403);
      context.set(
        "controlPrincipal",
        captureRequestProcessing<
          ActionPolicyControlPrincipal | ActionPolicyServicePrincipal | NativeLifecycleServicePrincipal
        >(principal),
      );
    } catch (error) {
      const status = error instanceof SaasAuthorizationError ? error.status : 401;
      return context.json({ error: status === 401 ? "unauthorized" : "forbidden" }, status);
    }
    await next();
  };
}
