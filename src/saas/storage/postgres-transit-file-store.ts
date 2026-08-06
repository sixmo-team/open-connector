import type { SaasRequestScope } from "../contracts.ts";
import type { Pool } from "pg";

import { withScopedClient } from "./scoped-query.ts";

export type TransitFileStatus = "pending" | "available" | "deleting" | "reconcile";

export interface TransitFileRecord {
  id: string;
  objectKey: string;
  contentType?: string;
  byteSize: number;
  contentSha256?: string;
  status: TransitFileStatus;
  expiresAt: string;
}

export interface LifecycleTransitFilePage {
  items: TransitFileRecord[];
  nextCursor?: string;
}

export interface TransitFileMetadataStore {
  create(record: TransitFileRecord): Promise<void>;
  get(id: string): Promise<TransitFileRecord | undefined>;
  setStatus(id: string, expected: TransitFileStatus, status: TransitFileStatus): Promise<boolean>;
  markReconcile(id: string): Promise<boolean>;
  delete(id: string): Promise<boolean>;
  listExpired(limit: number): Promise<TransitFileRecord[]>;
}

interface TransitFileRow {
  id: string;
  object_key: string;
  content_type: string | null;
  byte_size: string | number;
  content_sha256: string | null;
  status: TransitFileStatus;
  expires_at: Date | string;
}

const selectColumns = `SELECT id, object_key, content_type, byte_size, content_sha256, status, expires_at
  FROM integration_runtime.transit_files`;

/** Safe transit-file metadata bound to one immutable SaaS request scope. */
export class PostgresTransitFileStore implements TransitFileMetadataStore {
  private readonly pool: Pool;
  private readonly scope: Readonly<SaasRequestScope>;

  constructor(pool: Pool, scope: Readonly<SaasRequestScope>) {
    this.pool = pool;
    this.scope = scope;
  }

  async create(record: TransitFileRecord): Promise<void> {
    await withScopedClient(this.pool, this.scope, async (client) => {
      await client.query(
        `INSERT INTO integration_runtime.transit_files (
           id, tenant_id, workspace_id, subject_user_id, object_key, content_type,
           byte_size, content_sha256, status, expires_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          record.id,
          this.scope.tenantId,
          this.scope.workspaceId,
          this.scope.subjectUserId,
          record.objectKey,
          record.contentType ?? null,
          record.byteSize,
          record.contentSha256 ?? null,
          record.status,
          record.expiresAt,
        ],
      );
    });
  }

  async get(id: string): Promise<TransitFileRecord | undefined> {
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const row = (
        await client.query<TransitFileRow>(
          `${selectColumns}
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3 AND id = $4`,
          [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, id],
        )
      ).rows[0];
      return row ? fromRow(row) : undefined;
    });
  }

  async listExactOwnedForLifecycle(cursor: string | undefined, limit: number): Promise<LifecycleTransitFilePage> {
    if (!Number.isSafeInteger(limit) || limit <= 0 || limit > 100) throw new Error("Invalid lifecycle page limit");
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const values: unknown[] = [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId];
      const after = cursor ? "AND id > $4::uuid" : "";
      if (cursor) values.push(cursor);
      values.push(limit + 1);
      const rows = (
        await client.query<TransitFileRow>(
          `${selectColumns}
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3 ${after}
           ORDER BY id
           LIMIT $${values.length}`,
          values,
        )
      ).rows;
      const items = rows.slice(0, limit).map(fromRow);
      return {
        items,
        ...(rows.length > limit && items.length > 0 ? { nextCursor: items[items.length - 1]!.id } : {}),
      };
    });
  }

  async setStatus(id: string, expected: TransitFileStatus, status: TransitFileStatus): Promise<boolean> {
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const result = await client.query(
        `UPDATE integration_runtime.transit_files
         SET status = $5, updated_at = now()
         WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3 AND id = $4 AND status = $6`,
        [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, id, status, expected],
      );
      return result.rowCount === 1;
    });
  }

  async markReconcile(id: string): Promise<boolean> {
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const result = await client.query(
        `UPDATE integration_runtime.transit_files
         SET status = 'reconcile', updated_at = now()
         WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3 AND id = $4`,
        [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, id],
      );
      return result.rowCount === 1;
    });
  }

  async delete(id: string): Promise<boolean> {
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const result = await client.query(
        `DELETE FROM integration_runtime.transit_files
         WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3 AND id = $4`,
        [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, id],
      );
      return result.rowCount === 1;
    });
  }

  async listExpired(limit: number): Promise<TransitFileRecord[]> {
    if (!Number.isInteger(limit) || limit <= 0) throw new Error("Transit cleanup limit must be a positive integer");
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const rows = (
        await client.query<TransitFileRow>(
          `${selectColumns}
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
             AND expires_at <= clock_timestamp()
           ORDER BY expires_at ASC
           LIMIT $4`,
          [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, limit],
        )
      ).rows;
      return rows.map(fromRow);
    });
  }
}

function fromRow(row: TransitFileRow): TransitFileRecord {
  return {
    id: row.id,
    objectKey: row.object_key,
    contentType: row.content_type ?? undefined,
    byteSize: Number(row.byte_size),
    contentSha256: row.content_sha256 ?? undefined,
    status: row.status,
    expiresAt: new Date(row.expires_at).toISOString(),
  };
}
