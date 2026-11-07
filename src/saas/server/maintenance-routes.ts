import type { SaasHonoEnvironment } from "../auth/scoped-request.ts";
import type { SaasConnectServerOptions } from "./saas-connect-server.ts";
import type { Hono } from "hono";

import { z } from "zod/v4";
import { assertProcessingActive } from "../../core/cancellation.ts";
import { SaasAuthorizationError } from "../auth/saas-jwt-verifier.ts";
import { getSaasRequestScope, requireSaasPurpose } from "../auth/scoped-request.ts";
import { exactQuery, readBoundedJson, runScopedHttpOperation } from "./http-input.ts";

const emptyInput = z.object({}).strict();

/** A completed bounded pass is not a promise that retries or manual work have drained. */
export function registerMaintenanceRoutes(
  app: Hono<SaasHonoEnvironment>,
  options: Pick<SaasConnectServerOptions, "verifyJwt" | "maintenanceForScope">,
): void {
  app.post("/internal/saas/maintenance", requireSaasPurpose(options.verifyJwt, "maintenance:run"), (context) =>
    runScopedHttpOperation(context, "maintenance_unavailable", async () => {
      if (!exactQuery(context, [])) throw new SyntaxError("Unexpected query");
      emptyInput.parse(await readBoundedJson(context, 65_536));
      const scope = getSaasRequestScope(context, "maintenance:run");
      if (
        scope.actorUserId !== scope.subjectUserId ||
        scope.permissions.length !== 1 ||
        scope.permissions[0] !== scope.purpose ||
        scope.localConnectionId !== undefined ||
        scope.connectorConnectionId !== undefined ||
        scope.oauthSessionId !== undefined ||
        scope.fileId !== undefined ||
        scope.actionId !== undefined ||
        scope.requestHash !== undefined ||
        scope.maxOutputBytes !== undefined
      )
        throw new SaasAuthorizationError(403);
      if (!options.maintenanceForScope) throw new Error("Native maintenance is unavailable");
      assertProcessingActive(scope);
      await options.maintenanceForScope(scope);
      assertProcessingActive(scope);
      return context.body(null, 204);
    }),
  );
}
