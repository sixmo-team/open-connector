import type { SaasHonoEnvironment } from "../auth/scoped-request.ts";
import type { SaasConnectServerOptions } from "./saas-connect-server.ts";
import type { Hono } from "hono";

import { z } from "zod/v4";
import { MarketplaceError } from "../../marketplace/marketplace-service.ts";
import { canonicalActionPolicyRequestHash } from "../actions/canonical-request.ts";
import { SaasAuthorizationError } from "../auth/saas-jwt-verifier.ts";
import { getSaasRequestScope, requireSaasPurpose } from "../auth/scoped-request.ts";
import { toSafeConnectionSummary } from "../connections/safe-connection-summary.ts";
import { exactQuery, readBoundedJson, runScopedHttpOperation } from "./http-input.ts";

const connectInputSchema = z
  .object({
    localConnectionId: z.guid(),
    service: z.string().trim().min(1).max(128),
    connectionName: z.string().trim().min(1).max(255),
    apiKey: z
      .string()
      .min(1)
      .max(8192)
      .refine((value) => !!value.trim() && !/[\r\n]/.test(value)),
    discoveryUrl: z.url().max(4096).optional(),
    actionIds: z
      .array(z.string().min(1).max(255))
      .min(1)
      .max(5000)
      .refine((ids) => new Set(ids).size === ids.length),
  })
  .strict();

type Options = Pick<SaasConnectServerOptions, "verifyJwt" | "runtimeDatabaseFactory" | "nativeExecutionForScope">;

/** Select native Marketplace routing only through a signed, interactive credential creation request. */
export function registerMarketplaceRoutes(app: Hono<SaasHonoEnvironment>, options: Options): void {
  app.post(
    "/internal/saas/connections/marketplace",
    requireSaasPurpose(options.verifyJwt, "connection:write"),
    (context) =>
      runScopedHttpOperation(context, "service_unavailable", async () => {
        if (!exactQuery(context, [])) throw new SyntaxError("Unexpected query");
        const raw = await readBoundedJson(context, 65_536);
        const input = connectInputSchema.parse(raw);
        const scope = getSaasRequestScope(context, "connection:write");
        const target = {
          kind: "user" as const,
          tenantId: scope.tenantId,
          workspaceId: scope.workspaceId,
          userId: scope.subjectUserId,
        };
        if (
          scope.actorUserId !== scope.subjectUserId ||
          scope.connectorConnectionId ||
          input.localConnectionId !== scope.localConnectionId ||
          canonicalActionPolicyRequestHash(context.req.method, context.req.path, target, raw) !== scope.requestHash
        )
          throw new SaasAuthorizationError(403);
        const runtime = options.runtimeDatabaseFactory?.forScope(scope);
        if (!runtime) throw new Error("Scoped database is unavailable");
        const native = options.nativeExecutionForScope?.(scope, runtime);
        if (!native) throw new Error("Scoped native Marketplace is unavailable");
        try {
          const connected = await native.marketplace.connect(input.service, input);
          const stored = await runtime.connectionStore.getSafeConnection(connected.id);
          if (!stored) throw new Error("Stored connection metadata is unavailable");
          return context.json(toSafeConnectionSummary(stored), 201);
        } catch (error) {
          if (error instanceof MarketplaceError) {
            switch (error.status) {
              case 400:
              case 401:
              case 403:
              case 404:
              case 409:
              case 502:
              case 504:
                return context.json({ error: error.code }, error.status);
            }
          }
          throw error;
        }
      }),
  );
}
