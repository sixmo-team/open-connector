import type { SaasRequestScope } from "../contracts.ts";
import type { ISecretCodec } from "../secrets/secret-codec.ts";
import type { Pool, PoolClient } from "pg";

import { createHash, randomUUID } from "node:crypto";
import { assertProcessingActive } from "../../core/cancellation.ts";
import { OpenBaoError } from "../secrets/openbao-client.ts";
import { withSecretCleanup } from "../secrets/secret-codec.ts";
import { withScopedClient } from "./scoped-query.ts";

export interface ManagedProject {
  id: string;
  projectId: string;
  baseUrl: string;
  apiKey: string;
}
export interface OAuthSourceRecord {
  service: string;
  managedProjectId: string;
  projectId: string;
  providerConfigId: string;
}
export interface SaasCleanup {
  id: string;
  managedProjectId: string;
  providerConfigId: string;
  externalUserId: string;
  remoteRequestId: string | null;
  connectedAccountId: string | null;
  leaseId: string;
  attempts: number;
  service: string | null;
  requestExpiresAt: string | null;
}
export interface SaasProjectStore {
  externalUserId(): string;
  getProject(): Promise<ManagedProject | undefined>;
  saveProject(project: ManagedProject): Promise<boolean>;
  deleteProject(id: string): Promise<boolean>;
  listSources(): Promise<OAuthSourceRecord[]>;
  getSource(service: string): Promise<{ managedProjectId: string; providerConfigId: string } | undefined>;
  setSource(
    service: string,
    source: { managedProjectId: string; providerConfigId: string } | undefined,
  ): Promise<boolean>;
  getCleanupStats(): Promise<{ pending: number; manual: number; paused: boolean }>;
  claimCleanup(now: number, leaseMs?: number): Promise<SaasCleanup | undefined>;
  saveCleanupAccount(task: SaasCleanup, accountId: string): Promise<boolean>;
  cleanupAccountIfUnreferenced(
    task: SaasCleanup,
    accountId: string,
    removeRemote: () => Promise<void>,
  ): Promise<"referenced" | "deleted" | "lease_lost">;
  pauseCleanup(task: SaasCleanup, rejectedKey: string): Promise<void>;
  finishCleanup(task: SaasCleanup): Promise<boolean>;
  retryCleanup(task: SaasCleanup, nextAttemptAt: number, errorCode: string, manual?: boolean): Promise<boolean>;
}
/** Configuration is workspace technical state; cleanup tasks remain exact customer-owner state. */
export class PostgresSaasProjectStore implements SaasProjectStore {
  private readonly pool: Pool;
  private readonly scope: Readonly<SaasRequestScope>;
  private readonly codec: ISecretCodec;
  constructor(pool: Pool, scope: Readonly<SaasRequestScope>, codec: ISecretCodec) {
    this.pool = pool;
    this.scope = scope;
    this.codec = codec;
  }
  externalUserId(): string {
    return scopedExternalUserId(this.scope);
  }
  async getProject(): Promise<ManagedProject | undefined> {
    const row = await withScopedClient(
      this.pool,
      this.scope,
      async (client) =>
        (
          await client.query<{ id: string; project_id: string; base_url: string; secret_ref: string }>(
            `SELECT id,project_id,base_url,secret_ref FROM integration_runtime.managed_projects WHERE tenant_id=$1 AND workspace_id=$2`,
            [this.scope.tenantId, this.scope.workspaceId],
          )
        ).rows[0],
    );
    return row
      ? {
          id: row.id,
          projectId: row.project_id,
          baseUrl: row.base_url,
          apiKey: await this.codec.decode(row.secret_ref),
        }
      : undefined;
  }
  async saveProject(project: ManagedProject): Promise<boolean> {
    this.assertTechnicalWrite();
    assertProcessingActive(this.scope);
    let ref: string;
    try {
      ref = await this.codec.encode(project.apiKey);
    } catch (error) {
      if (error instanceof OpenBaoError && error.code !== "OPENBAO_CONFLICT")
        await this.retainOrphanProjectRef(project, error.path);
      throw error;
    }
    let saved = false;
    try {
      saved = await withScopedClient(
        this.pool,
        this.scope,
        async (client) =>
          (
            await client.query(
              `INSERT INTO integration_runtime.managed_projects (id,tenant_id,workspace_id,subject_user_id,project_id,base_url,secret_ref)
       VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id,workspace_id) DO UPDATE
       SET secret_ref=EXCLUDED.secret_ref,retired_secret_refs=array_append(managed_projects.retired_secret_refs,managed_projects.secret_ref),cleanup_paused=false,updated_at=now()
       WHERE managed_projects.id=EXCLUDED.id AND managed_projects.project_id=EXCLUDED.project_id AND managed_projects.base_url=EXCLUDED.base_url RETURNING id`,
              [
                project.id,
                this.scope.tenantId,
                this.scope.workspaceId,
                this.scope.subjectUserId,
                project.projectId,
                project.baseUrl,
                ref,
              ],
            )
          ).rowCount === 1,
      );
    } catch (error) {
      await this.retainOrphanProjectRef(project, ref);
      throw error;
    }
    if (!saved) {
      try {
        await withSecretCleanup(this.scope, () => this.codec.delete(ref));
      } catch {
        await this.retainOrphanProjectRef(project, ref);
      }
    }
    return saved;
  }
  private async retainOrphanProjectRef(project: ManagedProject, ref: string): Promise<void> {
    await withSecretCleanup(this.scope, (cleanupScope) =>
      withScopedClient(this.pool, cleanupScope, async (client) => {
        await client.query(
          `INSERT INTO integration_runtime.managed_projects
      (id,tenant_id,workspace_id,subject_user_id,project_id,base_url,secret_ref)
      VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id,workspace_id)
      DO UPDATE SET retired_secret_refs=array_append(managed_projects.retired_secret_refs,EXCLUDED.secret_ref),updated_at=now()`,
          [
            project.id,
            this.scope.tenantId,
            this.scope.workspaceId,
            this.scope.subjectUserId,
            project.projectId,
            project.baseUrl,
            ref,
          ],
        );
      }),
    );
  }
  async deleteProject(id: string): Promise<boolean> {
    this.assertTechnicalWrite();
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const row = (
        await client.query<{ secret_ref: string; retired_secret_refs: string[] }>(
          `DELETE FROM integration_runtime.managed_projects
      WHERE tenant_id=$1 AND workspace_id=$2 AND id=$3
      AND NOT EXISTS (SELECT 1 FROM integration_runtime.oauth_sources WHERE managed_project_id=$3)
      AND NOT EXISTS (SELECT 1 FROM integration_runtime.connections WHERE managed_project_id=$3)
      AND NOT EXISTS (SELECT 1 FROM integration_runtime.connection_requests WHERE managed_project_id=$3)
      AND NOT EXISTS (SELECT 1 FROM integration_runtime.saas_cleanup WHERE managed_project_id=$3)
      RETURNING secret_ref,retired_secret_refs`,
          [this.scope.tenantId, this.scope.workspaceId, id],
        )
      ).rows[0];
      if (!row) return false;
      for (const ref of [row.secret_ref, ...row.retired_secret_refs]) await this.codec.delete(ref);
      return true;
    });
  }
  async listSources(): Promise<OAuthSourceRecord[]> {
    return await withScopedClient(
      this.pool,
      this.scope,
      async (client) =>
        (
          await client.query<OAuthSourceRecord>(
            `SELECT s.service,s.managed_project_id AS "managedProjectId",p.project_id AS "projectId",s.provider_config_id AS "providerConfigId"
     FROM integration_runtime.oauth_sources s JOIN integration_runtime.managed_projects p ON p.id=s.managed_project_id
     WHERE s.tenant_id=$1 AND s.workspace_id=$2`,
            [this.scope.tenantId, this.scope.workspaceId],
          )
        ).rows,
    );
  }
  async getSource(service: string): Promise<{ managedProjectId: string; providerConfigId: string } | undefined> {
    return (await this.listSources()).find((source) => source.service === service);
  }
  async setSource(
    service: string,
    source: { managedProjectId: string; providerConfigId: string } | undefined,
  ): Promise<boolean> {
    this.assertTechnicalWrite();
    return await withScopedClient(this.pool, this.scope, async (client) => {
      if (!source) {
        await client.query(
          `DELETE FROM integration_runtime.oauth_sources WHERE tenant_id=$1 AND workspace_id=$2 AND service=$3`,
          [this.scope.tenantId, this.scope.workspaceId, service],
        );
        return true;
      }
      return (
        (
          await client.query(
            `INSERT INTO integration_runtime.oauth_sources (tenant_id,workspace_id,subject_user_id,service,managed_project_id,provider_config_id)
      SELECT $1,$2,$3,$4,$5,$6 WHERE EXISTS (SELECT 1 FROM integration_runtime.managed_projects WHERE tenant_id=$1 AND workspace_id=$2 AND id=$5)
      ON CONFLICT (tenant_id,workspace_id,service) DO UPDATE SET managed_project_id=EXCLUDED.managed_project_id,provider_config_id=EXCLUDED.provider_config_id,updated_at=now() RETURNING service`,
            [
              this.scope.tenantId,
              this.scope.workspaceId,
              this.scope.subjectUserId,
              service,
              source.managedProjectId,
              source.providerConfigId,
            ],
          )
        ).rowCount === 1
      );
    });
  }
  async getCleanupStats(): Promise<{ pending: number; manual: number; paused: boolean }> {
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const counts = (
        await client.query<{ status: string; count: string }>(
          `SELECT status,count(*) FROM integration_runtime.saas_cleanup WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 GROUP BY status`,
          this.values(),
        )
      ).rows;
      const project = (
        await client.query<{ cleanup_paused: boolean }>(
          `SELECT cleanup_paused FROM integration_runtime.managed_projects WHERE tenant_id=$1 AND workspace_id=$2`,
          this.values().slice(0, 2),
        )
      ).rows[0];
      return {
        pending: Number(counts.find((row) => row.status === "pending")?.count ?? 0),
        manual: Number(counts.find((row) => row.status === "manual")?.count ?? 0),
        paused: project?.cleanup_paused ?? false,
      };
    });
  }
  async claimCleanup(now: number, leaseMs = 45000): Promise<SaasCleanup | undefined> {
    const leaseId = randomUUID();
    return await withScopedClient(
      this.pool,
      this.scope,
      async (client) =>
        (
          await client.query<SaasCleanup>(
            `UPDATE integration_runtime.saas_cleanup c SET lease_id=$4,lease_until=to_timestamp($5::double precision/1000)
     WHERE c.tenant_id=$1 AND c.workspace_id=$2 AND c.subject_user_id=$3 AND c.id=(SELECT id FROM integration_runtime.saas_cleanup
       WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND status='pending' AND next_attempt_at<=$6
       AND (lease_until IS NULL OR lease_until<=to_timestamp($6::double precision/1000))
       AND EXISTS (SELECT 1 FROM integration_runtime.managed_projects p WHERE p.id=managed_project_id AND NOT p.cleanup_paused)
       ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED)
     RETURNING c.id,c.managed_project_id AS "managedProjectId",c.provider_config_id AS "providerConfigId",c.external_user_id AS "externalUserId",
       c.remote_request_id AS "remoteRequestId",c.remote_account_id AS "connectedAccountId",c.lease_id AS "leaseId",c.attempts,c.service,c.request_expires_at::text AS "requestExpiresAt"`,
            [...this.values(), leaseId, now + leaseMs, now],
          )
        ).rows[0],
    );
  }
  async saveCleanupAccount(task: SaasCleanup, accountId: string): Promise<boolean> {
    return withScopedClient(this.pool, this.scope, async (client) => {
      await lockManagedAccount(client, task.managedProjectId, accountId);
      assertProcessingActive(this.scope);
      const saved =
        (
          await client.query(
            `UPDATE integration_runtime.saas_cleanup SET remote_account_id=$6
      WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$4 AND lease_id=$5
        AND lease_until>clock_timestamp() AND managed_project_id=$7
        AND (remote_account_id IS NULL OR remote_account_id=$6) RETURNING id`,
            [...this.values(), task.id, task.leaseId, accountId, task.managedProjectId],
          )
        ).rowCount === 1;
      if (saved) await retireManagedAccount(client, task.managedProjectId, accountId);
      return saved;
    });
  }
  async cleanupAccountIfUnreferenced(
    task: SaasCleanup,
    accountId: string,
    removeRemote: () => Promise<void>,
  ): Promise<"referenced" | "deleted" | "lease_lost"> {
    return withScopedClient(this.pool, this.scope, async (client) => {
      await lockManagedAccount(client, task.managedProjectId, accountId);
      assertProcessingActive(this.scope);
      const owned = await client.query(
        `SELECT 1 FROM integration_runtime.saas_cleanup
      WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$4 AND lease_id=$5
        AND lease_until>clock_timestamp() AND managed_project_id=$6 AND remote_account_id=$7
        AND provider_config_id=$8 AND external_user_id=$9 FOR UPDATE`,
        [
          ...this.values(),
          task.id,
          task.leaseId,
          task.managedProjectId,
          accountId,
          task.providerConfigId,
          task.externalUserId,
        ],
      );
      if (owned.rowCount !== 1) return "lease_lost";
      const referenced = (
        await client.query<{ referenced: boolean }>(
          "SELECT integration_runtime.is_managed_account_referenced($1::uuid,$2::text) AS referenced",
          [task.managedProjectId, accountId],
        )
      ).rows[0]?.referenced;
      if (typeof referenced !== "boolean") throw new Error("Managed account reference guard is unavailable");
      if (referenced !== true) {
        await removeRemote();
        assertProcessingActive(this.scope);
        // Allocate AFTER the external deletion, so an earlier cached candidate stays fenced after queue removal.
        await retireManagedAccount(client, task.managedProjectId, accountId);
      }
      const finished = await client.query(
        `DELETE FROM integration_runtime.saas_cleanup
      WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$4 AND lease_id=$5
        AND lease_until>clock_timestamp() RETURNING id`,
        [...this.values(), task.id, task.leaseId],
      );
      if (finished.rowCount !== 1) throw new Error("Managed account cleanup lost its lease after remote work");
      return referenced ? "referenced" : "deleted";
    });
  }
  async pauseCleanup(task: SaasCleanup, rejectedKey: string): Promise<void> {
    const project = await withScopedClient(
      this.pool,
      this.scope,
      async (client) =>
        (
          await client.query<{ id: string; secret_ref: string }>(
            `SELECT id,secret_ref FROM integration_runtime.managed_projects WHERE tenant_id=$1 AND workspace_id=$2 AND id=$3`,
            [this.scope.tenantId, this.scope.workspaceId, task.managedProjectId],
          )
        ).rows[0],
    );
    if (!project || (await this.codec.decode(project.secret_ref)) !== rejectedKey) return;
    await withScopedClient(this.pool, this.scope, async (client) => {
      await client.query(
        `UPDATE integration_runtime.managed_projects SET cleanup_paused=true,updated_at=now() WHERE tenant_id=$1 AND workspace_id=$2 AND id=$4 AND secret_ref=$7
      AND EXISTS (SELECT 1 FROM integration_runtime.saas_cleanup WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$5 AND lease_id=$6 AND lease_until>now())`,
        [...this.values(), project.id, task.id, task.leaseId, project.secret_ref],
      );
    });
  }
  async finishCleanup(task: SaasCleanup): Promise<boolean> {
    return this.updateCleanup(task, "", [], true);
  }
  async retryCleanup(task: SaasCleanup, nextAttemptAt: number, errorCode: string, manual = false): Promise<boolean> {
    return this.updateCleanup(
      task,
      `SET lease_id=NULL,lease_until=NULL,attempts=attempts+1,next_attempt_at=$6,error_code=$7,status=$8`,
      [nextAttemptAt, errorCode, manual ? "manual" : "pending"],
    );
  }
  private async updateCleanup(task: SaasCleanup, set: string, extra: unknown[], remove = false): Promise<boolean> {
    return await withScopedClient(
      this.pool,
      this.scope,
      async (client) =>
        (
          await client.query(
            `${remove ? "DELETE FROM" : "UPDATE"} integration_runtime.saas_cleanup ${set}
    WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$4 AND lease_id=$5 AND lease_until>now() RETURNING id`,
            [...this.values(), task.id, task.leaseId, ...extra],
          )
        ).rowCount === 1,
    );
  }
  async listExactOwnedCleanupForLifecycle(
    cursor: string | undefined,
    limit: number,
  ): Promise<{ items: Array<{ id: string; status: string }>; nextCursor?: string }> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100)
      throw new Error("Invalid cleanup lifecycle page limit");
    return withScopedClient(this.pool, this.scope, async (client) => {
      const rows = (
        await client.query<{ id: string; status: string }>(
          `SELECT id,status FROM integration_runtime.saas_cleanup
      WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND ($4::text IS NULL OR id>$4) ORDER BY id LIMIT $5`,
          [...this.values(), cursor ?? null, limit + 1],
        )
      ).rows;
      return { items: rows.slice(0, limit), nextCursor: rows.length > limit ? rows[limit - 1]?.id : undefined };
    });
  }
  async countExactOwnedCleanupForLifecycle(): Promise<{
    total: number;
    statuses: Array<{ status: string; count: number }>;
  }> {
    return withScopedClient(this.pool, this.scope, async (client) => {
      const rows = (
        await client.query<{ status: string; count: string }>(
          `SELECT status,count(*) FROM integration_runtime.saas_cleanup
      WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 GROUP BY status ORDER BY status`,
          this.values(),
        )
      ).rows;
      const statuses = rows.map((row) => ({ status: row.status, count: Number(row.count) }));
      return { total: statuses.reduce((sum, row) => sum + row.count, 0), statuses };
    });
  }
  async drainExactOwnedCleanupForLifecycle(runCleanup: () => Promise<void>): Promise<{ deletedCleanup: number }> {
    const before = await this.countExactOwnedCleanupForLifecycle();
    let remaining = before.total;
    while (remaining > 0) {
      assertProcessingActive(this.scope);
      await runCleanup();
      const after = (await this.countExactOwnedCleanupForLifecycle()).total;
      if (after >= remaining) throw new SaasCleanupDrainError(before.total - after, after);
      remaining = after;
    }
    return { deletedCleanup: before.total };
  }
  private assertTechnicalWrite(): void {
    assertProcessingActive(this.scope);
    if (this.scope.actorUserId !== this.scope.subjectUserId || !["owner", "admin"].includes(this.scope.workspaceRole))
      throw new Error("Technical source configuration requires the verified workspace owner or admin");
  }
  private values(): string[] {
    return [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId];
  }
}
/** Capture the exact immutable remote selector before deleting its local owner. */
export async function queueSaasConnectionCleanup(
  client: PoolClient,
  scope: Readonly<SaasRequestScope>,
  connectionId: string,
): Promise<void> {
  const reference = (
    await client.query<{ project: string; account: string }>(
      `SELECT source_reference->>'managedProjectId' AS project,
    source_reference->>'connectedAccountId' AS account FROM integration_runtime.connections
    WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$4 AND source='saas' FOR SHARE`,
      [scope.tenantId, scope.workspaceId, scope.subjectUserId, connectionId],
    )
  ).rows[0];
  if (reference) await retireManagedAccount(client, reference.project, reference.account);
  await client.query(
    `INSERT INTO integration_runtime.saas_cleanup (id,tenant_id,workspace_id,subject_user_id,managed_project_id,provider_config_id,external_user_id,remote_account_id,service)
    SELECT 'account:'||(source_reference->>'managedProjectId')||':'||(source_reference->>'connectedAccountId'),tenant_id,workspace_id,subject_user_id,(source_reference->>'managedProjectId')::uuid,source_reference->>'providerConfigId',source_reference->>'externalUserId',source_reference->>'connectedAccountId',service
    FROM integration_runtime.connections WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$4 AND source='saas'
    ON CONFLICT DO NOTHING`,
    [scope.tenantId, scope.workspaceId, scope.subjectUserId, connectionId],
  );
}

/** Stable across owner transfer, distinct across genuine tenant/workspace/local lineage. */
export function scopedExternalUserId(scope: Readonly<SaasRequestScope>): string {
  if (!scope.localConnectionId) throw new Error("Managed OAuth requires the verified local connection lineage");
  return `open-connector:${createHash("sha256")
    .update(JSON.stringify([scope.tenantId, scope.workspaceId, scope.localConnectionId]))
    .digest("base64url")}`;
}

export class SaasCleanupDrainError extends Error {
  readonly deletedCleanup: number;
  readonly remaining: number;
  constructor(deletedCleanup: number, remaining: number) {
    super("Remote customer cleanup is incomplete; retry state was retained");
    this.deletedCleanup = deletedCleanup;
    this.remaining = remaining;
    this.name = "SaasCleanupDrainError";
  }
}

/** One database-owned vendor resource key shared by adoption, queueing, recovery and remote cleanup. */
export async function lockManagedAccount(client: PoolClient, projectId: string, accountId: string): Promise<void> {
  await client.query("SELECT integration_runtime.lock_managed_account($1::uuid,$2::text)", [projectId, accountId]);
}
export async function retireManagedAccount(client: PoolClient, projectId: string, accountId: string): Promise<void> {
  await client.query("SELECT integration_runtime.retire_managed_account($1::uuid,$2::text)", [projectId, accountId]);
}
