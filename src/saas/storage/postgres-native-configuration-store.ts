import type { NativeLifecycleServicePrincipal, NativeConfigurationMetadata } from "../contracts.ts";
import type { ISecretCodec, NativeSecretScope } from "../secrets/secret-codec.ts";
import type { Pool } from "pg";

import { lifecyclePurgeInputSchema } from "../contracts.ts";
import { nativeCustomerOwnerRowsSql } from "./postgres-native-lifecycle-inventory.ts";
import { encodeScopedCursor, readScopedPage } from "./scoped-page.ts";
import { withNativeLifecycleClient } from "./scoped-query.ts";

export interface NativeConfigurationPage {
  items: NativeConfigurationMetadata[];
  nextCursor?: string;
}
export interface NativeConfigurationPurgeResult {
  correlationId: string;
  deletedProjects: number;
  deletedSources: number;
  deletedSecrets: number;
}
export interface NativeConfigurationPageInput {
  cursor?: string;
  limit?: number;
}
interface ConfigurationRow {
  kind: "managed_project" | "oauth_source";
  tenant_id: string;
  workspace_id: string;
  id: string;
  service: string | null;
  managed_project_id: string;
  created_at: Date;
  updated_at: Date;
}
/** Workspace technical state uses the actual SERVICE target, never a fabricated customer/role. */
export class PostgresNativeConfigurationStore {
  private readonly pool: Pool;
  private readonly secretCodecForScope: (scope: Readonly<NativeSecretScope>) => ISecretCodec;
  constructor(pool: Pool, secretCodecForScope: (scope: Readonly<NativeSecretScope>) => ISecretCodec) {
    this.pool = pool;
    this.secretCodecForScope = secretCodecForScope;
  }
  async readForLifecycle(
    principal: Readonly<NativeLifecycleServicePrincipal>,
    page: NativeConfigurationPageInput = {},
  ): Promise<NativeConfigurationPage> {
    this.assertPrincipal(principal, "lifecycle:configuration:read");
    const { limit, key } = readScopedPage(page, principal.target, "native-configuration", 4);
    const after = key.length ? key : null;
    return withNativeLifecycleClient(this.pool, principal, async (client) => {
      const rows = (
        await client.query<ConfigurationRow>(
          `SELECT * FROM (
      SELECT 'managed_project'::text kind,tenant_id,workspace_id,id::text,NULL::text service,id::text managed_project_id,created_at,updated_at FROM integration_runtime.managed_projects
      UNION ALL SELECT 'oauth_source',tenant_id,workspace_id,service,service,managed_project_id::text,created_at,updated_at FROM integration_runtime.oauth_sources
    ) c WHERE tenant_id=$1 AND ($2::text IS NULL OR workspace_id=$2)
      AND ($3::text IS NULL OR (tenant_id,workspace_id,kind,id)>($3,$4,$5,$6)) ORDER BY tenant_id,workspace_id,kind,id LIMIT $7`,
          [
            principal.target.tenantId,
            principal.target.kind === "workspace" ? principal.target.workspaceId : null,
            ...(after ?? [null, null, null, null]),
            limit + 1,
          ],
        )
      ).rows;
      const selected = rows.slice(0, limit);
      const last = selected.at(-1);
      return {
        items: selected.map((row) => ({
          kind: row.kind,
          tenantId: row.tenant_id,
          workspaceId: row.workspace_id,
          id: row.id,
          service: row.service ?? undefined,
          source: row.kind === "oauth_source" ? "saas" : undefined,
          managedProjectId: row.managed_project_id,
          createdAt: row.created_at.toISOString(),
          updatedAt: row.updated_at.toISOString(),
        })),
        nextCursor:
          rows.length > limit && last
            ? encodeScopedCursor(principal.target, "native-configuration", [
                last.tenant_id,
                last.workspace_id,
                last.kind,
                last.id,
              ])
            : undefined,
      };
    });
  }
  async purgeForLifecycle(
    principal: Readonly<NativeLifecycleServicePrincipal>,
    correlationId: string,
  ): Promise<NativeConfigurationPurgeResult> {
    this.assertPrincipal(principal, "lifecycle:configuration:purge");
    lifecyclePurgeInputSchema.parse({ correlationId });
    return withNativeLifecycleClient(this.pool, principal, async (client) => {
      const values = [
        principal.target.tenantId,
        principal.target.kind === "workspace" ? principal.target.workspaceId : null,
      ];
      // The tenant-exclusive lifecycle fence already blocks every scoped configuration writer.
      const projects = (
        await client.query<{
          id: string;
          tenant_id: string;
          workspace_id: string;
          secret_ref: string;
          retired_secret_refs: string[];
        }>(
          `SELECT id,tenant_id,workspace_id,secret_ref,retired_secret_refs
      FROM integration_runtime.managed_projects WHERE tenant_id=$1 AND ($2::text IS NULL OR workspace_id=$2) ORDER BY workspace_id,id`,
          values,
        )
      ).rows;
      const references = await client.query(
        `SELECT 1 FROM (${nativeCustomerOwnerRowsSql}) r
      WHERE tenant_id=$1 AND ($2::text IS NULL OR workspace_id=$2) LIMIT 1`,
        values,
      );
      if (references.rowCount)
        throw new Error("Customer references and remote cleanup must be purged before technical configuration");
      let deletedSecrets = 0;
      for (const project of projects) {
        const codec = this.secretCodecForScope({
          tenantId: project.tenant_id,
          workspaceId: project.workspace_id,
          requestSignal: principal.requestSignal,
          processingDeadlineMs: principal.processingDeadlineMs,
        });
        for (const ref of new Set([project.secret_ref, ...project.retired_secret_refs]))
          if (await codec.delete(ref)) deletedSecrets++;
      }
      const sources = await client.query(
        `DELETE FROM integration_runtime.oauth_sources WHERE tenant_id=$1 AND ($2::text IS NULL OR workspace_id=$2)`,
        values,
      );
      const removed = await client.query(
        `DELETE FROM integration_runtime.managed_projects WHERE tenant_id=$1 AND ($2::text IS NULL OR workspace_id=$2)`,
        values,
      );
      return {
        correlationId,
        deletedProjects: removed.rowCount ?? 0,
        deletedSources: sources.rowCount ?? 0,
        deletedSecrets,
      };
    });
  }
  private assertPrincipal(
    principal: Readonly<NativeLifecycleServicePrincipal>,
    purpose: "lifecycle:configuration:read" | "lifecycle:configuration:purge",
  ): void {
    principal.requestSignal?.throwIfAborted();
    if (
      principal.subjectKind !== "service" ||
      principal.purpose !== purpose ||
      principal.permissions.length !== 1 ||
      principal.permissions[0] !== purpose ||
      !principal.subject?.trim() ||
      !["workspace", "tenant"].includes(principal.target.kind)
    )
      throw new Error("Technical lifecycle requires its exact SERVICE authority and tenant/workspace target");
  }
}
