import type { PoolClient } from "pg";

/** Hold active project admission through the caller's reference publication transaction. */
export async function lockActiveManagedProject(client: PoolClient, managedProjectId: string): Promise<boolean> {
  const admitted = (
    await client.query<{ admitted: boolean }>(
      "SELECT integration_runtime.lock_active_managed_project($1::uuid) AS admitted",
      [managedProjectId],
    )
  ).rows[0]?.admitted;
  if (typeof admitted !== "boolean") throw new Error("Managed project admission is unavailable");
  return admitted;
}
