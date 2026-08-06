import type { Client, Pool, PoolClient } from "pg";

import * as z from "zod/v4";

export const MAX_LOCAL_CONNECTION_MAPPINGS = 10_000;

export interface LocalConnectionIdentityMapping {
  tenantId: string;
  workspaceId: string;
  subjectUserId: string;
  connectorConnectionId: string;
  localConnectionId: string;
}

const scopedIdSchema = z
  .string()
  .min(1)
  .max(255)
  .refine((value) => value.trim() === value, "must not have surrounding whitespace");
const uuidSchema = scopedIdSchema
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i)
  .transform((value) => value.toLowerCase());
const mappingListSchema = z
  .array(
    z
      .object({
        tenantId: scopedIdSchema,
        workspaceId: scopedIdSchema,
        subjectUserId: scopedIdSchema,
        connectorConnectionId: uuidSchema,
        localConnectionId: uuidSchema,
      })
      .strict(),
  )
  .max(MAX_LOCAL_CONNECTION_MAPPINGS);

/** Parse a bounded, strict backend-produced connector-to-local identity mapping. */
export function parseLocalConnectionIdentityMappings(value: unknown): LocalConnectionIdentityMapping[] {
  const mappings = mappingListSchema.parse(value);
  const connectorIds = new Set<string>();
  const localIds = new Set<string>();
  for (const [index, mapping] of mappings.entries()) {
    const connectorKey = `${mapping.tenantId}\0${mapping.workspaceId}\0${mapping.connectorConnectionId}`;
    const localKey = `${mapping.tenantId}\0${mapping.workspaceId}\0${mapping.localConnectionId}`;
    if (connectorIds.has(connectorKey) || localIds.has(localKey)) {
      throw new Error(`Mapping row ${index} duplicates a scoped connector or local connection id`);
    }
    connectorIds.add(connectorKey);
    localIds.add(localKey);
  }
  return mappings;
}

/**
 * Atomically backfill one bounded mapping batch through runtime RLS.
 * Run the separate global gate after all batches and old images are stopped.
 */
export async function backfillLocalConnectionIdentities(
  runtimePool: Pool,
  auditor: Client | Pool,
  mappings: readonly LocalConnectionIdentityMapping[],
): Promise<number> {
  if (mappings.length > MAX_LOCAL_CONNECTION_MAPPINGS) {
    throw new Error(`At most ${MAX_LOCAL_CONNECTION_MAPPINGS} mappings can be applied at once`);
  }

  const auditRole = await auditor.query<{ rolsuper: boolean; rolbypassrls: boolean }>(
    "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user",
  );
  if (!auditRole.rows[0]?.rolsuper && !auditRole.rows[0]?.rolbypassrls) {
    throw new Error("Zero-null verification requires a separate PostgreSQL audit role with BYPASSRLS");
  }

  const client = await runtimePool.connect();
  let releaseError: Error | undefined;
  try {
    await client.query("BEGIN");
    for (const mapping of mappings) {
      await client.query(
        `SELECT
          set_config('integration.tenant_id', $1, true),
          set_config('integration.workspace_id', $2, true),
          set_config('integration.subject_user_id', $3, true)`,
        [mapping.tenantId, mapping.workspaceId, mapping.subjectUserId],
      );
      const updated = await client.query(
        `UPDATE integration_runtime.connections
         SET local_connection_id = $1, updated_at = now()
         WHERE id = $2
           AND tenant_id = $3
           AND workspace_id = $4
           AND subject_user_id = $5
           AND (local_connection_id IS NULL OR local_connection_id = $1)`,
        [
          mapping.localConnectionId,
          mapping.connectorConnectionId,
          mapping.tenantId,
          mapping.workspaceId,
          mapping.subjectUserId,
        ],
      );
      if (updated.rowCount !== 1) {
        throw new Error(`Mapping did not match exactly one scoped connector row: ${mapping.connectorConnectionId}`);
      }
    }
    await client.query("COMMIT");
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

  return mappings.length;
}

/** Global readiness/contract gate run with a non-runtime audit credential. */
export async function assertLocalConnectionIdentityBackfillComplete(
  auditor: Client | Pool | PoolClient,
): Promise<void> {
  const auditRole = await auditor.query<{ rolsuper: boolean; rolbypassrls: boolean }>(
    "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user",
  );
  if (!auditRole.rows[0]?.rolsuper && !auditRole.rows[0]?.rolbypassrls) {
    throw new Error("Zero-null verification requires a separate PostgreSQL audit role with BYPASSRLS");
  }
  const remaining = await auditor.query<{ count: string }>(
    "SELECT count(*)::text AS count FROM integration_runtime.connections WHERE local_connection_id IS NULL",
  );
  const remainingCount = Number(remaining.rows[0]?.count ?? "0");
  if (remainingCount !== 0) {
    throw new Error(`Local connection identity backfill is incomplete: ${remainingCount} null rows remain`);
  }
}
