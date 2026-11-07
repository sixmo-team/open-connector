import type { SaasHonoEnvironment } from "../auth/scoped-request.ts";
import type {
  ActionPolicyControlPrincipal,
  ActionPolicyServicePrincipal,
  ActionPolicyTarget,
  SaasRequestScope,
} from "../contracts.ts";
import type { SaasConnectServerOptions } from "./saas-connect-server.ts";
import type { Context, Hono, MiddlewareHandler } from "hono";

import { decodeProtectedHeader } from "jose";
import { captureRequestProcessing } from "../../core/cancellation.ts";
import { canonicalActionPolicyRequestHash } from "../actions/canonical-request.ts";
import { readBearerToken, SaasAuthorizationError } from "../auth/saas-jwt-verifier.ts";
import { requireScopedControlPurpose } from "../auth/scoped-request.ts";
import {
  actionAccessInputSchema,
  actionPolicyMutationInputSchema,
  actionPolicySingleMutationInputSchema,
  lifecyclePurgeInputSchema,
} from "../contracts.ts";
import { exactQuery, readBoundedJson, readBoundedPage, runScopedHttpOperation } from "./http-input.ts";

type Options = Pick<
  SaasConnectServerOptions,
  "verifyJwt" | "verifyActionPolicyJwt" | "policyControlActiveKid" | "runtimeDatabaseFactory"
>;
type PolicyPurpose = ActionPolicyControlPrincipal["purpose"] | ActionPolicyServicePrincipal["purpose"];
const prefix = "/internal/saas/action-policy";

/** Platform operations use their own verified authority, never a fabricated customer scope. */
export function registerActionPolicyRoutes(app: Hono<SaasHonoEnvironment>, options: Options): void {
  app.post("/internal/saas/action-access", (context) =>
    runScopedHttpOperation(context, "action_policy_unavailable", async () => {
      if (!exactQuery(context, [])) throw new SyntaxError("Unexpected query");
      const authorization = context.req.header("authorization");
      let control: Readonly<ActionPolicyControlPrincipal> | undefined;
      let actor: Readonly<SaasRequestScope> | undefined;
      try {
        const header = decodeProtectedHeader(readBearerToken(authorization));
        if (options.policyControlActiveKid && header.kid === options.policyControlActiveKid) {
          if (!options.verifyActionPolicyJwt) return unavailable(context);
          control = captureRequestProcessing(await options.verifyActionPolicyJwt(authorization));
          if (
            control.purpose !== "action-policy:read" ||
            control.permissions.length !== 1 ||
            control.permissions[0] !== control.purpose ||
            !["platform", "user"].includes(control.target.kind)
          )
            throw new SaasAuthorizationError(403);
        } else {
          const verified = await options.verifyJwt(authorization);
          if (
            "subjectKind" in verified ||
            verified.purpose !== "action:search" ||
            verified.permissions.length !== 1 ||
            verified.permissions[0] !== verified.purpose ||
            verified.actorUserId !== verified.subjectUserId
          )
            throw new SaasAuthorizationError(403);
          actor = captureRequestProcessing(verified);
        }
      } catch (error) {
        throw error instanceof SaasAuthorizationError ? error : new SaasAuthorizationError(401);
      }
      const { actionIds } = actionAccessInputSchema.parse(await readBoundedJson(context, 1_048_576));
      const store = options.runtimeDatabaseFactory?.actionPolicy;
      if (!store) return unavailable(context);
      if (control) return context.json({ decisions: await store.getEffectiveForControl(control, actionIds) });
      if (!actor) throw new SaasAuthorizationError(403);
      return context.json({ decisions: await store.getEffectiveForActor(actor, actionIds) });
    }),
  );

  for (const [mode, targetKind] of [
    ["defaults", "platform"],
    ["grants", "user"],
  ] as const) {
    const path = `${prefix}/${mode}`;
    app.get(path, authority(options, "action-policy:read"), (context) =>
      runScopedHttpOperation(context, "action_policy_unavailable", async () => {
        const principal = controlPrincipal(context, targetKind);
        const page = readBoundedPage(context);
        const store = options.runtimeDatabaseFactory?.actionPolicy;
        return store ? context.json(await store.readForControl(principal, page)) : unavailable(context);
      }),
    );
    const write = (single: boolean) => (context: Context<SaasHonoEnvironment>) =>
      runScopedHttpOperation(context, "action_policy_unavailable", async () => {
        const principal = controlPrincipal(context, targetKind);
        if (!exactQuery(context, [])) throw new SyntaxError("Unexpected query");
        const raw = await readBoundedJson(context, 1_048_576);
        const parsed = single
          ? actionPolicySingleMutationInputSchema.parse(raw)
          : actionPolicyMutationInputSchema.parse(raw);
        verifyMutation(context, principal, raw);
        if (targetKind === "platform" && parsed.enabled === null)
          throw new SyntaxError("Common rules require an explicit boolean");
        const input = single
          ? actionPolicyMutationInputSchema.parse({ ...parsed, actionIds: [context.req.param("actionId")] })
          : actionPolicyMutationInputSchema.parse(parsed);
        const store = options.runtimeDatabaseFactory?.actionPolicy;
        return store ? context.json(await store.applyForControl(principal, input)) : unavailable(context);
      });
    app.put(path, authority(options, "action-policy:write"), write(false));
    app.put(`${path}/:actionId`, authority(options, "action-policy:write"), write(true));
  }

  app.get(`${prefix}/subjects`, authority(options, "action-policy:subjects"), (context) =>
    runScopedHttpOperation(context, "action_policy_unavailable", async () => {
      const principal = servicePrincipal(context, ["tenant", "workspace"]);
      const page = readBoundedPage(context);
      const store = options.runtimeDatabaseFactory?.actionPolicy;
      return store ? context.json(await store.listSubjects(principal, page)) : unavailable(context);
    }),
  );
  app.post(`${prefix}/purge`, authority(options, "action-policy:purge"), (context) =>
    runScopedHttpOperation(context, "action_policy_unavailable", async () => {
      const principal = servicePrincipal(context, ["tenant", "workspace", "user"]);
      if (!exactQuery(context, [])) throw new SyntaxError("Unexpected query");
      const raw = await readBoundedJson(context);
      const { correlationId } = lifecyclePurgeInputSchema.parse(raw);
      verifyMutation(context, principal, raw);
      const store = options.runtimeDatabaseFactory?.actionPolicy;
      return store ? context.json(await store.purge(principal, correlationId)) : unavailable(context);
    }),
  );
}

function authority(options: Options, purpose: PolicyPurpose): MiddlewareHandler<SaasHonoEnvironment> {
  const verifier =
    purpose === "action-policy:read" || purpose === "action-policy:write"
      ? options.verifyActionPolicyJwt
      : options.verifyJwt;
  return verifier ? requireScopedControlPurpose(verifier, purpose) : async (context) => unavailable(context);
}
function controlPrincipal(
  context: Context<SaasHonoEnvironment>,
  kind: "platform" | "user",
): Readonly<ActionPolicyControlPrincipal> {
  const principal = context.get("controlPrincipal");
  if (principal.subjectKind !== "policy_control" || principal.target.kind !== kind)
    throw new SaasAuthorizationError(403);
  return principal;
}
function servicePrincipal(
  context: Context<SaasHonoEnvironment>,
  kinds: ActionPolicyTarget["kind"][],
): Readonly<ActionPolicyServicePrincipal> {
  const principal = context.get("controlPrincipal");
  if (
    principal.subjectKind !== "service" ||
    (principal.purpose !== "action-policy:subjects" && principal.purpose !== "action-policy:purge") ||
    !kinds.includes(principal.target.kind)
  )
    throw new SaasAuthorizationError(403);
  return principal;
}
function verifyMutation(
  context: Context<SaasHonoEnvironment>,
  principal: Readonly<ActionPolicyControlPrincipal | ActionPolicyServicePrincipal>,
  raw: unknown,
): void {
  if (
    canonicalActionPolicyRequestHash(context.req.method, context.req.path, principal.target, raw) !==
    principal.requestHash
  )
    throw new SaasAuthorizationError(403);
}
function unavailable(context: Context<SaasHonoEnvironment>): Response {
  return context.json({ error: "action_policy_unavailable" }, 503);
}
