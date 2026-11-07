import type { CatalogStore } from "../../catalog-store.ts";
import type {
  ActionPermissionDecision,
  ActionPolicyAuditRecord,
  ActionPolicyControlPrincipal,
  ActionPolicyMutationInput,
  ActionPolicyPage,
  ActionPolicyPurgeResult,
  ActionPolicyRecord,
  ActionPolicyServicePrincipal,
  ActionPolicyTarget,
  ActionPolicyUserTarget,
  ActionPolicyWriteResult,
  SaasRequestScope,
} from "../contracts.ts";
import type { Pool, PoolClient } from "pg";

import { randomUUID } from "node:crypto";
import { resolveActionPermission } from "../actions/action-permission-policy.ts";
import { SaasAuthorizationError } from "../auth/saas-jwt-verifier.ts";
import {
  actionAccessInputSchema,
  actionPolicyMutationInputSchema,
  actionPolicyTargetSchema,
  lifecyclePurgeInputSchema,
} from "../contracts.ts";
import { triggerCapability } from "../triggers/trigger-capability.ts";
import { encodeScopedCursor, readScopedPage } from "./scoped-page.ts";
import { withActionPolicyClient, withScopedClient } from "./scoped-query.ts";

interface PolicyRow {
  action_id: string;
  enabled: boolean;
  created_by_subject: string;
  updated_by_subject: string;
  created_at: Date | string;
  updated_at: Date | string;
  tenant_id?: string;
  workspace_id?: string;
  user_id?: string;
}
interface AuditRow {
  id: string;
  target_kind: "platform" | "user";
  tenant_id: string | null;
  workspace_id: string | null;
  user_id: string | null;
  operator_subject: string;
  action_ids: string[];
  enabled: boolean | null;
  reason: string;
  created_at: Date | string;
  request_id: string;
}
export interface ActionPolicyReadPage {
  items: ActionPolicyRecord[];
  nextCursor: string | null;
}
export interface ActionPolicySubjectsPage {
  items: ActionPolicyUserTarget[];
  nextCursor: string | null;
}
export interface ActionPolicyLifecyclePage {
  items: ActionPolicyRecord[];
  audit: ActionPolicyAuditRecord[];
  nextCursor: string | null;
}

/** The only persisted source of action enablement. Database errors deliberately propagate, never become absence. */
export class PostgresActionPolicyStore {
  private readonly pool: Pool;
  private readonly catalog: Pick<CatalogStore, "actionsById" | "providers">;
  constructor(pool: Pool, catalog: Pick<CatalogStore, "actionsById" | "providers">) {
    this.pool = pool;
    this.catalog = catalog;
  }
  async getEffectiveForActor(
    scope: Readonly<SaasRequestScope>,
    actionIds: string[],
  ): Promise<ActionPermissionDecision[]> {
    if (scope.purpose === "maintenance:run") {
      if (
        scope.actorUserId !== scope.subjectUserId ||
        scope.permissions.length !== 1 ||
        scope.permissions[0] !== scope.purpose
      )
        throw new SaasAuthorizationError(403);
      const target = userTarget(scope, scope.actorUserId);
      this.validateActions(actionIds);
      return withScopedClient(this.pool, scope, (client) => this.effective(client, target, actionIds));
    }
    return this.withEffectiveForActor(scope, actionIds, async (decisions) => decisions);
  }

  /** Bind the current actor decision and durable admission to one original scoped lifecycle transaction. */
  async withEffectiveForActor<T>(
    scope: Readonly<SaasRequestScope>,
    actionIds: string[],
    admit: (decisions: ActionPermissionDecision[], client: PoolClient) => Promise<T>,
  ): Promise<T> {
    if (
      !["action:search", "action:execute:v2"].includes(scope.purpose) ||
      scope.permissions.length !== 1 ||
      scope.permissions[0] !== scope.purpose ||
      (scope.purpose === "action:search" && scope.actorUserId !== scope.subjectUserId)
    )
      throw new SaasAuthorizationError(403);
    const target = userTarget(scope, scope.actorUserId);
    this.validateActions(actionIds);
    return withScopedClient(this.pool, scope, async (client) =>
      admit(await this.effective(client, target, actionIds), client),
    );
  }

  async getEffectiveForControl(
    principal: Readonly<ActionPolicyControlPrincipal>,
    actionIds: string[],
  ): Promise<ActionPermissionDecision[]> {
    requirePurpose(principal, "action-policy:read");
    this.validateActions(actionIds);
    const target = actionPolicyTargetSchema.parse(principal.target);
    if (target.kind !== "platform" && target.kind !== "user") throw new SaasAuthorizationError(403);
    return withActionPolicyClient(this.pool, principal, (client) => this.effective(client, target, actionIds));
  }

  async readForControl(
    principal: Readonly<ActionPolicyControlPrincipal>,
    page: ActionPolicyPage = {},
  ): Promise<ActionPolicyReadPage> {
    requirePurpose(principal, "action-policy:read");
    const target = actionPolicyTargetSchema.parse(principal.target);
    if (target.kind !== "platform" && target.kind !== "user") throw new SaasAuthorizationError(403);
    const { limit, key } = readScopedPage(page, target, "rules", 1);
    return withActionPolicyClient(this.pool, principal, async (client) => {
      const result =
        target.kind === "platform"
          ? await client.query<PolicyRow>(
              `SELECT * FROM integration_runtime.action_defaults WHERE action_id > $1 COLLATE "C" ORDER BY action_id COLLATE "C" LIMIT $2`,
              [key[0] ?? "", limit + 1],
            )
          : await client.query<PolicyRow>(
              `SELECT * FROM integration_runtime.action_grants WHERE tenant_id = $1 AND workspace_id = $2 AND user_id = $3 AND action_id > $4 COLLATE "C" ORDER BY action_id COLLATE "C" LIMIT $5`,
              [target.tenantId, target.workspaceId, target.userId, key[0] ?? "", limit + 1],
            );
      const rows = result.rows.slice(0, limit);
      return {
        items: rows.map(toRecord),
        nextCursor:
          result.rows.length > limit ? encodeScopedCursor(target, "rules", [rows[rows.length - 1]!.action_id]) : null,
      };
    });
  }

  async applyForControl(
    principal: Readonly<ActionPolicyControlPrincipal>,
    input: ActionPolicyMutationInput,
  ): Promise<ActionPolicyWriteResult> {
    requirePurpose(principal, "action-policy:write");
    const target = actionPolicyTargetSchema.parse(principal.target);
    const body = actionPolicyMutationInputSchema.parse(input);
    this.validateActions(body.actionIds);
    if (target.kind !== "platform" && target.kind !== "user") throw new SaasAuthorizationError(403);
    if (target.kind === "platform" && body.enabled === null) throw new TypeError("Platform defaults require a boolean");
    return withActionPolicyClient(this.pool, principal, async (client) => {
      let updatedCount = 0;
      let removedCount = 0;
      if (target.kind === "platform") {
        const result = await client.query(
          `INSERT INTO integration_runtime.action_defaults (action_id, enabled, created_by_subject, updated_by_subject)
        SELECT action_id, $2, $3, $3 FROM unnest($1::text[]) AS requested(action_id) WHERE true
        ON CONFLICT (action_id) DO UPDATE SET enabled = EXCLUDED.enabled, updated_by_subject = EXCLUDED.updated_by_subject, updated_at = now()`,
          [body.actionIds, body.enabled, principal.subject],
        );
        updatedCount = result.rowCount ?? 0;
      } else if (body.enabled === null) {
        const result = await client.query(
          `DELETE FROM integration_runtime.action_grants WHERE tenant_id = $1 AND workspace_id = $2 AND user_id = $3 AND action_id = ANY($4::text[])`,
          [target.tenantId, target.workspaceId, target.userId, body.actionIds],
        );
        removedCount = result.rowCount ?? 0;
      } else {
        const result = await client.query(
          `INSERT INTO integration_runtime.action_grants (id, tenant_id, workspace_id, user_id, action_id, enabled, created_by_subject, updated_by_subject)
        SELECT requested.id, $1, $2, $3, requested.action_id, $4, $5, $5 FROM unnest($6::uuid[], $7::text[]) AS requested(id, action_id) WHERE true
        ON CONFLICT (tenant_id, workspace_id, user_id, action_id) DO UPDATE SET enabled = EXCLUDED.enabled, updated_by_subject = EXCLUDED.updated_by_subject, updated_at = now()`,
          [
            target.tenantId,
            target.workspaceId,
            target.userId,
            body.enabled,
            principal.subject,
            body.actionIds.map(() => randomUUID()),
            body.actionIds,
          ],
        );
        updatedCount = result.rowCount ?? 0;
      }
      const auditId = randomUUID();
      await client.query(
        `INSERT INTO integration_runtime.action_policy_audit
      (id, target_kind, tenant_id, workspace_id, user_id, operator_subject, action_ids, enabled, reason, request_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          auditId,
          target.kind,
          target.kind === "user" ? target.tenantId : null,
          target.kind === "user" ? target.workspaceId : null,
          target.kind === "user" ? target.userId : null,
          principal.subject,
          body.actionIds,
          body.enabled,
          body.reason.trim(),
          principal.requestId,
        ],
      );
      return { updatedCount, removedCount, auditId };
    });
  }

  async listSubjects(
    principal: Readonly<ActionPolicyServicePrincipal>,
    page: ActionPolicyPage = {},
  ): Promise<ActionPolicySubjectsPage> {
    requirePurpose(principal, "action-policy:subjects");
    const target = actionPolicyTargetSchema.parse(principal.target);
    if (target.kind !== "tenant" && target.kind !== "workspace") throw new SaasAuthorizationError(403);
    const { limit, key } = readScopedPage(page, target, "subjects", 3);
    return withActionPolicyClient(this.pool, principal, async (client) => {
      const result = await client.query<{ tenant_id: string; workspace_id: string; user_id: string }>(
        `SELECT tenant_id, workspace_id, user_id FROM (
      SELECT tenant_id, workspace_id, user_id FROM integration_runtime.action_grants
      UNION SELECT tenant_id, workspace_id, user_id FROM integration_runtime.action_policy_audit WHERE target_kind = 'user'
    ) AS subjects WHERE tenant_id = $1 AND ($2::uuid IS NULL OR workspace_id = $2)
      AND (tenant_id::text, workspace_id::text, user_id::text) > ($3, $4, $5)
      ORDER BY tenant_id::text, workspace_id::text, user_id::text LIMIT $6`,
        [
          target.tenantId,
          target.kind === "workspace" ? target.workspaceId : null,
          key[0] ?? "",
          key[1] ?? "",
          key[2] ?? "",
          limit + 1,
        ],
      );
      const items: ActionPolicyUserTarget[] = result.rows
        .slice(0, limit)
        .map((row) => ({ kind: "user", tenantId: row.tenant_id, workspaceId: row.workspace_id, userId: row.user_id }));
      const last = items[items.length - 1];
      return {
        items,
        nextCursor:
          result.rows.length > limit && last
            ? encodeScopedCursor(target, "subjects", [last.tenantId, last.workspaceId, last.userId])
            : null,
      };
    });
  }

  async purge(
    principal: Readonly<ActionPolicyServicePrincipal>,
    correlationId: string,
  ): Promise<ActionPolicyPurgeResult> {
    requirePurpose(principal, "action-policy:purge");
    lifecyclePurgeInputSchema.parse({ correlationId });
    const target = actionPolicyTargetSchema.parse(principal.target);
    if (target.kind === "platform") throw new SaasAuthorizationError(403);
    return withActionPolicyClient(this.pool, principal, async (client) => {
      const parameters = [
        target.tenantId,
        "workspaceId" in target ? target.workspaceId : null,
        "userId" in target ? target.userId : null,
      ];
      const where = `tenant_id = $1 AND ($2::uuid IS NULL OR workspace_id = $2) AND ($3::uuid IS NULL OR user_id = $3)`;
      const grants = await client.query(`DELETE FROM integration_runtime.action_grants WHERE ${where}`, parameters);
      const audit = await client.query(
        `DELETE FROM integration_runtime.action_policy_audit WHERE target_kind = 'user' AND ${where}`,
        parameters,
      );
      return { correlationId, deletedGrants: grants.rowCount ?? 0, deletedAudit: audit.rowCount ?? 0 };
    });
  }

  async getLifecycleCounts(
    scope: Readonly<SaasRequestScope>,
  ): Promise<{ actionGrants: number; actionPolicyAudit: number }> {
    requireLifecycle(scope, true);
    const target = userTarget(scope, scope.subjectUserId);
    return withScopedClient(this.pool, scope, async (client) => {
      const result = await client.query<{ grants: string; audit: string }>(
        `SELECT
      (SELECT count(*) FROM integration_runtime.action_grants WHERE tenant_id = $1 AND workspace_id = $2 AND user_id = $3) AS grants,
      (SELECT count(*) FROM integration_runtime.action_policy_audit WHERE target_kind = 'user' AND tenant_id = $1 AND workspace_id = $2 AND user_id = $3) AS audit`,
        [target.tenantId, target.workspaceId, target.userId],
      );
      return { actionGrants: Number(result.rows[0]!.grants), actionPolicyAudit: Number(result.rows[0]!.audit) };
    });
  }

  async exportForLifecycle(
    scope: Readonly<SaasRequestScope>,
    page: ActionPolicyPage = {},
  ): Promise<ActionPolicyLifecyclePage> {
    requireLifecycle(scope);
    const target = userTarget(scope, scope.subjectUserId);
    const { limit, key } = readScopedPage(page, target, "lifecycle", 1);
    return withScopedClient(this.pool, scope, async (client) => {
      const result = await client.query<{ kind: "grant" | "audit"; key: string; data: PolicyRow | AuditRow }>(
        `SELECT * FROM (
      SELECT 'grant' AS kind, 'g:' || action_id AS key, to_jsonb(grants) AS data FROM integration_runtime.action_grants AS grants WHERE tenant_id = $1 AND workspace_id = $2 AND user_id = $3
      UNION ALL SELECT 'audit' AS kind, 'a:' || id::text AS key, to_jsonb(audit) AS data FROM integration_runtime.action_policy_audit AS audit WHERE target_kind = 'user' AND tenant_id = $1 AND workspace_id = $2 AND user_id = $3
    ) AS records WHERE key > $4 COLLATE "C" ORDER BY key COLLATE "C" LIMIT $5`,
        [target.tenantId, target.workspaceId, target.userId, key[0] ?? "", limit + 1],
      );
      const rows = result.rows.slice(0, limit);
      const items: ActionPolicyRecord[] = [];
      const audit: ActionPolicyAuditRecord[] = [];
      for (const row of rows) {
        if (row.kind === "grant") items.push(toRecord(row.data as PolicyRow));
        else audit.push(toAudit(row.data as AuditRow));
      }
      return {
        items,
        audit,
        nextCursor:
          result.rows.length > limit ? encodeScopedCursor(target, "lifecycle", [rows[rows.length - 1]!.key]) : null,
      };
    });
  }

  private validateActions(actionIds: string[]): void {
    actionAccessInputSchema.parse({ actionIds });
    for (const id of actionIds) {
      if (id.startsWith("trigger:")) {
        const triggerId = id.slice("trigger:".length);
        if (triggerCapability(this.catalog, triggerId.split(".")[0]!, triggerId) !== id)
          throw new TypeError(`Unknown Trigger: ${id}`);
      } else if (!this.catalog.actionsById.has(id)) throw new TypeError(`Unknown action: ${id}`);
    }
  }

  private async effective(
    client: PoolClient,
    target: Extract<ActionPolicyTarget, { kind: "platform" | "user" }>,
    actionIds: string[],
  ): Promise<ActionPermissionDecision[]> {
    const result =
      target.kind === "platform"
        ? await client.query<{ actionId: string; individualEnabled: boolean | null; defaultEnabled: boolean | null }>(
            `SELECT requested.action_id AS "actionId", NULL::boolean AS "individualEnabled", defaults.enabled AS "defaultEnabled" FROM unnest($1::text[]) WITH ORDINALITY AS requested(action_id, position) LEFT JOIN integration_runtime.action_defaults AS defaults ON defaults.action_id = requested.action_id ORDER BY requested.position`,
            [actionIds],
          )
        : await client.query<{ actionId: string; individualEnabled: boolean | null; defaultEnabled: boolean | null }>(
            `SELECT requested.action_id AS "actionId", personal.enabled AS "individualEnabled", defaults.enabled AS "defaultEnabled" FROM unnest($4::text[]) WITH ORDINALITY AS requested(action_id, position)
      LEFT JOIN integration_runtime.action_grants AS personal ON personal.tenant_id = $1 AND personal.workspace_id = $2 AND personal.user_id = $3 AND personal.action_id = requested.action_id
      LEFT JOIN integration_runtime.action_defaults AS defaults ON defaults.action_id = requested.action_id ORDER BY requested.position`,
            [target.tenantId, target.workspaceId, target.userId, actionIds],
          );
    if (result.rows.length !== actionIds.length || result.rows.some((row, index) => row.actionId !== actionIds[index]))
      throw new Error("Incomplete action policy decision result");
    return result.rows.map((row) => resolveActionPermission(row.actionId, row.individualEnabled, row.defaultEnabled));
  }
}

function requirePurpose(
  principal: Readonly<ActionPolicyControlPrincipal | ActionPolicyServicePrincipal>,
  purpose: string,
): void {
  const kind = purpose === "action-policy:read" || purpose === "action-policy:write" ? "policy_control" : "service";
  if (
    principal.subjectKind !== kind ||
    principal.purpose !== purpose ||
    principal.permissions.length !== 1 ||
    principal.permissions[0] !== purpose
  )
    throw new SaasAuthorizationError(403);
}
function requireLifecycle(scope: Readonly<SaasRequestScope>, allowDelete = false): void {
  if (
    (scope.purpose !== "lifecycle:read" && !(allowDelete && scope.purpose === "lifecycle:delete")) ||
    scope.permissions.length !== 1 ||
    scope.permissions[0] !== scope.purpose
  )
    throw new SaasAuthorizationError(403);
}
function userTarget(scope: Readonly<SaasRequestScope>, userId: string): ActionPolicyUserTarget {
  return actionPolicyTargetSchema.parse({
    kind: "user",
    tenantId: scope.tenantId,
    workspaceId: scope.workspaceId,
    userId,
  }) as ActionPolicyUserTarget;
}
function toRecord(row: PolicyRow): ActionPolicyRecord {
  const record: ActionPolicyRecord = {
    actionId: row.action_id,
    enabled: row.enabled,
    createdBySubject: row.created_by_subject,
    updatedBySubject: row.updated_by_subject,
    createdAt: isoString(row.created_at),
    updatedAt: isoString(row.updated_at),
  };
  if (row.tenant_id !== undefined) {
    record.tenantId = row.tenant_id;
    record.workspaceId = row.workspace_id;
    record.userId = row.user_id;
  }
  return record;
}
function toAudit(row: AuditRow): ActionPolicyAuditRecord {
  return {
    id: row.id,
    target:
      row.target_kind === "platform"
        ? { kind: "platform" }
        : { kind: "user", tenantId: row.tenant_id!, workspaceId: row.workspace_id!, userId: row.user_id! },
    operatorSubject: row.operator_subject,
    actionIds: row.action_ids,
    enabled: row.enabled,
    reason: row.reason,
    createdAt: isoString(row.created_at),
    requestId: row.request_id,
  };
}
function isoString(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}
