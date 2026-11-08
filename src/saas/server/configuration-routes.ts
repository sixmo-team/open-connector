import type { SaasHonoEnvironment } from "../auth/scoped-request.ts";
import type { ConfigurationControlPrincipal } from "../contracts.ts";
import type { SaasConnectServerOptions } from "./saas-connect-server.ts";
import type { Context, Hono, MiddlewareHandler } from "hono";

import { z } from "zod";
import { getRequestSignal } from "../../core/cancellation.ts";
import { canonicalActionPolicyRequestHash } from "../actions/canonical-request.ts";
import { SaasAuthorizationError } from "../auth/saas-jwt-verifier.ts";
import { requireScopedControlPurpose } from "../auth/scoped-request.ts";
import { SaasError } from "../saas-client.ts";
import { exactQuery, readBoundedJson, runScopedHttpOperation } from "./http-input.ts";

type Options = Pick<SaasConnectServerOptions, "verifyControlJwt" | "projectsForControl">;
const prefix = "/internal/saas/configuration";
const emptyBody = z.strictObject({});

/** Workspace technical control never supplies customer identity, execution authority, or project keys in responses. */
export function registerConfigurationRoutes(app: Hono<SaasHonoEnvironment>, options: Options): void {
  app.get(`${prefix}/project`, authority(options, "configuration:read"), (context) =>
    runConfigurationOperation(context, async () => {
      const principal = configurationPrincipal(context, "configuration:read");
      if (!options.projectsForControl) return unavailable(context);
      return context.json(await options.projectsForControl(principal).getState(getRequestSignal(principal)));
    }),
  );
  app.put(`${prefix}/project`, authority(options, "configuration:write"), (context) =>
    runConfigurationOperation(context, async () => {
      const principal = configurationPrincipal(context, "configuration:write");
      const raw = await mutationBody(context, principal);
      if (!options.projectsForControl) return unavailable(context);
      return context.json(await options.projectsForControl(principal).configure(raw, getRequestSignal(principal)));
    }),
  );
  app.delete(`${prefix}/project`, authority(options, "configuration:write"), (context) =>
    runConfigurationOperation(context, async () => {
      const principal = configurationPrincipal(context, "configuration:write");
      emptyBody.parse(await mutationBody(context, principal));
      if (!options.projectsForControl) return unavailable(context);
      await options.projectsForControl(principal).remove();
      return context.body(null, 204);
    }),
  );
  app.get(`${prefix}/provider-configs`, authority(options, "configuration:read"), (context) =>
    runConfigurationOperation(context, async () => {
      const principal = configurationPrincipal(context, "configuration:read");
      if (!options.projectsForControl) return unavailable(context);
      return context.json(await options.projectsForControl(principal).listProviderConfigs(getRequestSignal(principal)));
    }),
  );
  app.get(`${prefix}/sources/:service`, authority(options, "configuration:read"), (context) =>
    runConfigurationOperation(context, async () => {
      const principal = configurationPrincipal(context, "configuration:read");
      if (!options.projectsForControl) return unavailable(context);
      return context.json(await options.projectsForControl(principal).getSource(context.req.param("service")));
    }),
  );
  app.put(`${prefix}/sources/:service`, authority(options, "configuration:write"), (context) =>
    runConfigurationOperation(context, async () => {
      const principal = configurationPrincipal(context, "configuration:write");
      const raw = await mutationBody(context, principal);
      if (!options.projectsForControl) return unavailable(context);
      return context.json(
        await options
          .projectsForControl(principal)
          .setSource(context.req.param("service"), raw, getRequestSignal(principal)),
      );
    }),
  );
}

function authority(
  options: Options,
  purpose: ConfigurationControlPrincipal["purpose"],
): MiddlewareHandler<SaasHonoEnvironment> {
  return options.verifyControlJwt
    ? requireScopedControlPurpose(options.verifyControlJwt, purpose)
    : async (context) => unavailable(context);
}
function configurationPrincipal(
  context: Context<SaasHonoEnvironment>,
  purpose: ConfigurationControlPrincipal["purpose"],
): Readonly<ConfigurationControlPrincipal> {
  const principal = context.get("controlPrincipal");
  if (
    principal.subjectKind !== "policy_control" ||
    principal.purpose !== purpose ||
    principal.target.kind !== "workspace" ||
    principal.permissions.length !== 1 ||
    principal.permissions[0] !== purpose
  )
    throw new SaasAuthorizationError(403);
  return principal;
}
async function mutationBody(
  context: Context<SaasHonoEnvironment>,
  principal: Readonly<ConfigurationControlPrincipal>,
): Promise<unknown> {
  const raw = await readBoundedJson(context);
  if (
    canonicalActionPolicyRequestHash(context.req.method, context.req.path, principal.target, raw) !==
    principal.requestHash
  )
    throw new SaasAuthorizationError(403);
  return raw;
}
function runConfigurationOperation(
  context: Context<SaasHonoEnvironment>,
  work: () => Promise<Response>,
): Promise<Response> {
  return runScopedHttpOperation(context, "configuration_unavailable", async () => {
    if (!exactQuery(context, [])) throw new SyntaxError("Unexpected query");
    try {
      return await work();
    } catch (error) {
      if (error instanceof SaasError) return context.json({ error: error.code }, error.status);
      throw error;
    }
  });
}
function unavailable(context: Context<SaasHonoEnvironment>): Response {
  return context.json({ error: "configuration_unavailable" }, 503);
}
