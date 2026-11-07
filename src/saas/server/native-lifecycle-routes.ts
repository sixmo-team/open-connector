import type { SaasHonoEnvironment } from "../auth/scoped-request.ts";
import type { NativeLifecycleServicePrincipal } from "../contracts.ts";
import type { SaasConnectServerOptions } from "./saas-connect-server.ts";
import type { Context, Hono } from "hono";

import { canonicalActionPolicyRequestHash } from "../actions/canonical-request.ts";
import { SaasAuthorizationError } from "../auth/saas-jwt-verifier.ts";
import { requireScopedControlPurpose } from "../auth/scoped-request.ts";
import { lifecyclePurgeInputSchema } from "../contracts.ts";
import { exactQuery, readBoundedJson, readBoundedPage, runScopedHttpOperation } from "./http-input.ts";

type Options = Pick<SaasConnectServerOptions, "verifyJwt" | "runtimeDatabaseFactory">;
const unavailable = "native_lifecycle_unavailable";

export function registerNativeLifecycleRoutes(app: Hono<SaasHonoEnvironment>, options: Options): void {
  app.get(
    "/internal/saas/lifecycle/subjects",
    requireScopedControlPurpose(options.verifyJwt, "lifecycle:subjects"),
    (context) =>
      runScopedHttpOperation(context, unavailable, async () => {
        const principal = servicePrincipal(context);
        const page = readBoundedPage(context);
        const store = options.runtimeDatabaseFactory?.nativeLifecycleInventory;
        if (!store) throw new Error("Native customer owner inventory is unavailable");
        return context.json(await store.listSubjects(principal, page));
      }),
  );
  app.get(
    "/internal/saas/lifecycle/configuration",
    requireScopedControlPurpose(options.verifyJwt, "lifecycle:configuration:read"),
    (context) =>
      runScopedHttpOperation(context, unavailable, async () => {
        const principal = servicePrincipal(context);
        const page = readBoundedPage(context);
        const store = options.runtimeDatabaseFactory?.nativeConfiguration;
        if (!store) throw new Error("Native technical configuration owner is unavailable");
        const result = await store.readForLifecycle(principal, page);
        return context.json({ ...result, nextCursor: result.nextCursor ?? null });
      }),
  );
  app.post(
    "/internal/saas/lifecycle/configuration/purge",
    requireScopedControlPurpose(options.verifyJwt, "lifecycle:configuration:purge"),
    (context) =>
      runScopedHttpOperation(context, unavailable, async () => {
        const principal = servicePrincipal(context);
        if (!exactQuery(context, [])) throw new SyntaxError("Unexpected query");
        const raw = await readBoundedJson(context);
        const { correlationId } = lifecyclePurgeInputSchema.parse(raw);
        if (
          canonicalActionPolicyRequestHash(context.req.method, context.req.path, principal.target, raw) !==
          principal.requestHash
        )
          throw new SaasAuthorizationError(403);
        const store = options.runtimeDatabaseFactory?.nativeConfiguration;
        if (!store) throw new Error("Native technical configuration owner is unavailable");
        return context.json(await store.purgeForLifecycle(principal, correlationId));
      }),
  );
}

function servicePrincipal(context: Context<SaasHonoEnvironment>): Readonly<NativeLifecycleServicePrincipal> {
  const principal = context.get("controlPrincipal");
  if (
    principal.subjectKind !== "service" ||
    (principal.purpose !== "lifecycle:subjects" &&
      principal.purpose !== "lifecycle:configuration:read" &&
      principal.purpose !== "lifecycle:configuration:purge")
  )
    throw new SaasAuthorizationError(403);
  return principal;
}
