import type { ActionPolicyPage, ActionPolicyUserTarget, NativeLifecycleServicePrincipal } from "../contracts.ts";
import type { Pool } from "pg";

import { SaasAuthorizationError } from "../auth/saas-jwt-verifier.ts";
import { actionPolicyTargetSchema } from "../contracts.ts";
import { encodeScopedCursor, readScopedPage } from "./scoped-page.ts";
import { withNativeLifecycleClient } from "./scoped-query.ts";

/** Actual customer owners only; technical workspace configuration does not manufacture a user. */
export const nativeCustomerOwnerRowsSql: string = [
  "connections",
  "oauth_states",
  "run_intents",
  "idempotency_records",
  "refresh_leases",
  "transit_files",
  "connection_revocation_receipts",
  "connection_retirements",
  "connection_requests",
  "saas_cleanup",
  "trigger_subscriptions",
  "trigger_source_applications",
  "trigger_secret_cleanup",
  "trigger_execution_leases",
]
  .map((table) => `SELECT tenant_id, workspace_id, subject_user_id AS user_id FROM integration_runtime.${table}`)
  .concat(
    ["trigger_subscriptions", "trigger_source_applications", "trigger_execution_leases"].map(
      (table) => `SELECT tenant_id, workspace_id, credential_owner_id AS user_id FROM integration_runtime.${table}`,
    ),
  )
  .join(" UNION ALL ");

export class PostgresNativeLifecycleInventory {
  private readonly pool: Pool;
  constructor(pool: Pool) {
    this.pool = pool;
  }
  async listSubjects(
    principal: Readonly<NativeLifecycleServicePrincipal>,
    page: ActionPolicyPage = {},
  ): Promise<{ items: ActionPolicyUserTarget[]; nextCursor: string | null }> {
    if (
      principal.subjectKind !== "service" ||
      principal.purpose !== "lifecycle:subjects" ||
      principal.permissions.length !== 1 ||
      principal.permissions[0] !== principal.purpose
    )
      throw new SaasAuthorizationError(403);
    const { limit, key } = readScopedPage(page, principal.target, "native-lifecycle-subjects", 3);
    return withNativeLifecycleClient(this.pool, principal, async (client) => {
      const rows = (
        await client.query<{ tenant_id: string; workspace_id: string; user_id: string }>(
          `SELECT DISTINCT tenant_id, workspace_id, user_id FROM (${nativeCustomerOwnerRowsSql}) owners
       WHERE tenant_id = $1 AND ($2::text IS NULL OR workspace_id = $2)
         AND ($3::text IS NULL OR (tenant_id,workspace_id,user_id) > ($3,$4,$5))
       ORDER BY tenant_id,workspace_id,user_id LIMIT $6`,
          [
            principal.target.tenantId,
            principal.target.kind === "workspace" ? principal.target.workspaceId : null,
            ...(key.length ? key : [null, null, null]),
            limit + 1,
          ],
        )
      ).rows;
      const selected = rows.slice(0, limit);
      const last = selected.at(-1);
      return {
        items: selected.map(
          (row) =>
            actionPolicyTargetSchema.parse({
              kind: "user",
              tenantId: row.tenant_id,
              workspaceId: row.workspace_id,
              userId: row.user_id,
            }) as ActionPolicyUserTarget,
        ),
        nextCursor:
          rows.length > limit && last
            ? encodeScopedCursor(principal.target, "native-lifecycle-subjects", [
                last.tenant_id,
                last.workspace_id,
                last.user_id,
              ])
            : null,
      };
    });
  }
}
