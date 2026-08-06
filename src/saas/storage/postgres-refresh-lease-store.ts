import type { SaasRequestScope } from "../contracts.ts";
import type { Pool } from "pg";

import { withScopedClient } from "./scoped-query.ts";

export type RefreshLeaseAcquireResult =
  | { kind: "acquired" }
  | { kind: "busy"; retryAfterMs: number }
  | { kind: "missing" };

export interface RefreshLeaseStore {
  acquire(connectionId: string, holder: string, leaseDurationMs: number): Promise<RefreshLeaseAcquireResult>;
  release(connectionId: string, holder: string): Promise<void>;
}

interface AcquireRow {
  connection_exists: boolean;
  acquired: boolean;
  retry_after_ms: string | number | null;
}

/** Atomic, expiring refresh leases bound to one immutable SaaS request scope. */
export class PostgresRefreshLeaseStore implements RefreshLeaseStore {
  private readonly pool: Pool;
  private readonly scope: Readonly<SaasRequestScope>;

  constructor(pool: Pool, scope: Readonly<SaasRequestScope>) {
    this.pool = pool;
    this.scope = scope;
  }

  async acquire(connectionId: string, holder: string, leaseDurationMs: number): Promise<RefreshLeaseAcquireResult> {
    if (!connectionId || !holder || !Number.isInteger(leaseDurationMs) || leaseDurationMs <= 0) {
      throw new Error("A connection, holder, and positive lease duration are required");
    }

    return await withScopedClient(this.pool, this.scope, async (client) => {
      const row = (
        await client.query<AcquireRow>(
          `WITH visible_connection AS (
             SELECT tenant_id, workspace_id, subject_user_id, visibility, id
             FROM integration_runtime.connections
             WHERE tenant_id = $1 AND workspace_id = $2
               AND (visibility = 'workspace' OR subject_user_id = $3)
               AND id = $4 AND status = 'active'
           ), acquired AS (
             INSERT INTO integration_runtime.refresh_leases (
               tenant_id, workspace_id, subject_user_id, visibility, connection_id,
               lease_holder, expires_at, created_at, updated_at
             )
             SELECT tenant_id, workspace_id, subject_user_id, visibility, id,
                    $5, clock_timestamp() + ($6 * interval '1 millisecond'),
                    clock_timestamp(), clock_timestamp()
             FROM visible_connection
             ON CONFLICT (connection_id) DO UPDATE
               SET lease_holder = EXCLUDED.lease_holder,
                   expires_at = EXCLUDED.expires_at,
                   updated_at = clock_timestamp()
               WHERE integration_runtime.refresh_leases.expires_at <= clock_timestamp()
             RETURNING connection_id
           )
           SELECT
             EXISTS (SELECT 1 FROM visible_connection) AS connection_exists,
             EXISTS (SELECT 1 FROM acquired) AS acquired,
             CASE WHEN EXISTS (SELECT 1 FROM acquired) THEN 0 ELSE
               GREATEST(0, COALESCE((
                 SELECT EXTRACT(EPOCH FROM (expires_at - clock_timestamp())) * 1000
                 FROM integration_runtime.refresh_leases
                 WHERE connection_id = $4
               ), 0))
             END AS retry_after_ms`,
          [
            this.scope.tenantId,
            this.scope.workspaceId,
            this.scope.subjectUserId,
            connectionId,
            holder,
            leaseDurationMs,
          ],
        )
      ).rows[0];

      if (!row?.connection_exists) return { kind: "missing" };
      if (row.acquired) return { kind: "acquired" };
      return { kind: "busy", retryAfterMs: Math.max(1, Math.ceil(Number(row.retry_after_ms ?? 1))) };
    });
  }

  async release(connectionId: string, holder: string): Promise<void> {
    if (!connectionId || !holder) throw new Error("A connection and holder are required");
    await withScopedClient(this.pool, this.scope, async (client) => {
      await client.query(
        `DELETE FROM integration_runtime.refresh_leases
         WHERE tenant_id = $1 AND workspace_id = $2 AND connection_id = $3 AND lease_holder = $4`,
        [this.scope.tenantId, this.scope.workspaceId, connectionId, holder],
      );
    });
  }
}
