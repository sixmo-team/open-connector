import type { SaasJwtVerifier } from "../auth/saas-jwt-verifier.ts";
import type { SaasHonoEnvironment } from "../auth/scoped-request.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { SaasTriggerRunner } from "./saas-trigger-runner.ts";
import type { Hono } from "hono";

import { z } from "zod";
import { ExecutionError } from "../../core/execution-error.ts";
import { getSaasRequestScope, requireSaasPurpose } from "../auth/scoped-request.ts";
import { exactQuery, JsonBodyTooLargeError, readBoundedJson } from "../server/http-input.ts";

export interface ScopedTriggerRouteOptions {
  verifyJwt: SaasJwtVerifier;
  createRunner: (scope: Readonly<SaasRequestScope>) => Pick<SaasTriggerRunner, "run">;
}
const bodySchema = z
  .strictObject({ connectorConnectionId: z.uuid(), input: z.unknown() })
  .refine((body) => Object.hasOwn(body, "input"));

/** No public callback/proxy listener: the trusted host signs every complete native request. */
export function registerScopedTriggerRoutes(app: Hono<SaasHonoEnvironment>, options: ScopedTriggerRouteOptions): void {
  app.post(
    "/internal/saas/triggers/:service/:triggerId",
    requireSaasPurpose(options.verifyJwt, "action:execute:v2"),
    async (context) => {
      try {
        if (!exactQuery(context, [])) return context.json({ error: "invalid_input" }, 400);
        const body = bodySchema.parse(await readBoundedJson(context, 262144));
        const scope = getSaasRequestScope(context, "action:execute:v2");
        const output = await options.createRunner(scope).run({
          service: context.req.param("service"),
          triggerId: context.req.param("triggerId"),
          connectorConnectionId: body.connectorConnectionId,
          input: body.input,
          signal: context.req.raw.signal,
        });
        return context.json({ ok: true, output });
      } catch (error) {
        if (error instanceof JsonBodyTooLargeError) return context.json({ error: "payload_too_large" }, 413);
        if (error instanceof z.ZodError || error instanceof SyntaxError || error instanceof TypeError)
          return context.json({ error: "invalid_input" }, 400);
        if (error instanceof ExecutionError) {
          const status =
            error.kind === "forbidden"
              ? 403
              : error.kind === "not_found"
                ? 404
                : error.kind === "conflict"
                  ? 409
                  : error.kind === "too_large"
                    ? 413
                    : error.kind === "unavailable"
                      ? 503
                      : error.kind === "upstream"
                        ? 502
                        : error.kind === "timeout"
                          ? 504
                          : 400;
          return context.json({ error: error.code }, status);
        }
        return context.json({ error: "trigger_unavailable" }, 503);
      }
    },
  );
}
