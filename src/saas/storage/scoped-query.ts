import type { SaasRequestScope } from "../contracts.ts";
import type { Pool, PoolClient } from "pg";

/** Run a callback in one transaction whose RLS identity cannot leak through pool reuse. */
export async function withScopedClient<T>(
  pool: Pool,
  scope: SaasRequestScope,
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  if (!scope.tenantId || !scope.workspaceId || !scope.subjectUserId) {
    throw new Error("A complete tenant, workspace, and subject scope is required");
  }

  const client = await pool.connect();
  let releaseError: Error | undefined;
  try {
    await client.query("BEGIN");
    await client.query(
      `SELECT
        set_config('integration.tenant_id', $1, true),
        set_config('integration.workspace_id', $2, true),
        set_config('integration.subject_user_id', $3, true),
        set_config('integration.workspace_role', $4, true)`,
      [scope.tenantId, scope.workspaceId, scope.subjectUserId, scope.workspaceRole],
    );
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (rollbackError) {
      releaseError = rollbackError instanceof Error ? rollbackError : new Error("PostgreSQL rollback failed");
    }
    throw error;
  } finally {
    client.release(releaseError);
  }
}
