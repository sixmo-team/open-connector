import type { StoredLocalConnection } from "../../connection-store.ts";
import type { CredentialProfile } from "../../core/types.ts";
import type { SourceApplication } from "../../triggers/sources/persistent.ts";
import type { TriggerStore, TriggerSubscription } from "../../triggers/store.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { ISecretCodec } from "../secrets/secret-codec.ts";
import type { PostgresActionPolicyStore } from "../storage/postgres-action-policy-store.ts";
import type { ConnectionSecretStore } from "../storage/postgres-connection-store.ts";
import type { Pool, PoolClient } from "pg";

import { randomUUID } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { z } from "zod";
import { assertProcessingActive, captureRequestProcessing, remainingProcessingMs } from "../../core/cancellation.ts";
import { ExecutionError } from "../../core/execution-error.ts";
import { withSubscription } from "../../triggers/subscriptions.ts";
import { OpenBaoError } from "../secrets/openbao-client.ts";
import { withSecretCleanup } from "../secrets/secret-codec.ts";
import { mergeCredential } from "../storage/postgres-connection-store.ts";
import { encodeScopedCursor, readScopedPage } from "../storage/scoped-page.ts";
import { withScopedClient } from "../storage/scoped-query.ts";

interface ConnectionRow {
  id: string;
  local_connection_id: string;
  service: string;
  connection_name: string;
  subject_user_id: string;
  visibility: string;
  status: string;
  source: string;
  source_status: string | null;
  provider_account_id: string | null;
  source_reference: Record<string, string> | null;
  revision: string;
  auth_type: string;
  secret_revision: string;
  credential_profile: CredentialProfile | null;
  trigger_cleanup_fenced: boolean;
}
interface Binding {
  connectionId: string;
  localConnectionId: string;
  credentialOwnerId: string;
  account: Record<string, string>;
}
interface PrivateRow {
  id: string;
  subject_user_id: string;
  actor_user_id: string;
  credential_owner_id: string;
  secret_ref: string;
  retired_secret_refs: string[];
  revision: string;
  owner_id: string;
}
interface SubscriptionRow extends PrivateRow {
  mode: TriggerSubscription["mode"];
  service: string;
  trigger_id: string;
  connection_id: string;
  local_connection_id: string;
  account_binding: Record<string, string>;
  request_key: string;
  status: TriggerSubscription["status"];
  reconcile_at: string;
  lease_id: string | null;
  lease_until: Date | null;
}
interface ApplicationRow extends PrivateRow {
  namespace: string;
  service: string;
  trigger_id: string;
  bindings: Binding[];
  retired: boolean;
}
export interface TriggerSubscriptionMetadata {
  id: string;
  service: string;
  triggerId: string;
  status: string;
}
export interface TriggerSourceApplicationMetadata {
  id: string;
  revision: number;
}
export interface TriggerLifecyclePage {
  subscriptions: TriggerSubscriptionMetadata[];
  sourceApplications: TriggerSourceApplicationMetadata[];
  nextCursor?: string;
}
export type TriggerLifecycleCleanup = (
  record: TriggerSubscription,
  save: () => Promise<void>,
  signal: AbortSignal,
) => Promise<void>;
export interface TriggerLifecycleCounts {
  subscriptions: { total: number; statuses: Array<{ status: string; count: number }> };
  sourceApplications: number;
  secrets: number;
  pendingSecrets: number;
  executionLeases: number;
  pendingExecutions: number;
  requiresCleanup: boolean;
}
export interface TriggerPurgeResult {
  deletedSubscriptions: number;
  deletedSourceApplications: number;
  deletedTriggerSecrets: number;
  deletedExecutionLeases: number;
}

/** Stable real credential-owner and actor authority; never a JWT jti/global token. */
export function scopedTriggerOwner(scope: Readonly<SaasRequestScope>): string {
  for (const value of [scope.tenantId, scope.workspaceId, scope.subjectUserId, scope.actorUserId])
    z.uuid().parse(value);
  return JSON.stringify([scope.tenantId, scope.workspaceId, scope.subjectUserId, scope.actorUserId]);
}

/** SQL owns account/actor relationships and leases; private immutable state lives in OpenBao. */
export class PostgresTriggerStore implements TriggerStore {
  private readonly scope: Readonly<SaasRequestScope>;
  private readonly ownerId: string;
  private readonly dataUserId: string;
  private readonly pool: Pool;
  private readonly codec: ISecretCodec;
  constructor(pool: Pool, scope: Readonly<SaasRequestScope>, codec: ISecretCodec) {
    this.pool = pool;
    this.codec = codec;
    const captured = { ...captureRequestProcessing(scope), permissions: [...scope.permissions] };
    Object.freeze(captured.permissions);
    this.scope = Object.freeze(captured);
    this.ownerId = scopedTriggerOwner(this.scope);
    this.dataUserId = ["lifecycle:read", "lifecycle:delete"].includes(scope.purpose)
      ? scope.subjectUserId
      : scope.actorUserId;
    if (!codec.encrypted) throw new Error("Trigger state requires a real private secret codec");
    if (
      scope.purpose === "maintenance:run" &&
      (scope.actorUserId !== scope.subjectUserId ||
        scope.permissions.length !== 1 ||
        scope.permissions[0] !== scope.purpose)
    )
      throw new Error("Exact actor maintenance authority required");
  }
  resourceOwnerId(ownerId: string): string {
    const owner = z.tuple([z.string(), z.string(), z.uuid(), z.uuid()]).parse(JSON.parse(ownerId));
    if (owner[0] !== this.scope.tenantId || owner[1] !== this.scope.workspaceId)
      throw new Error("Foreign resource owner namespace");
    return JSON.stringify(owner.slice(0, 3));
  }
  private values(): string[] {
    return [this.scope.tenantId, this.scope.workspaceId, this.dataUserId];
  }
  private maintenance(): boolean {
    return this.scope.purpose === "lifecycle:delete" || this.scope.purpose === "maintenance:run";
  }
  private lifecycle(write = false): void {
    if (
      ![write ? "lifecycle:delete" : "lifecycle:read", "lifecycle:delete"].includes(this.scope.purpose) ||
      this.scope.permissions.length !== 1 ||
      this.scope.permissions[0] !== this.scope.purpose
    )
      throw new Error("Exact lifecycle authority required");
  }
  private namespace(namespace: string): { service: string; triggerId: string } {
    let parts: unknown;
    try {
      parts = JSON.parse(namespace);
    } catch {
      throw new Error("Invalid Source namespace");
    }
    if (
      !Array.isArray(parts) ||
      parts.length !== 3 ||
      parts[0] !== this.ownerId ||
      typeof parts[1] !== "string" ||
      !parts[1] ||
      typeof parts[2] !== "string" ||
      !/^[a-z0-9_]+\.[A-Za-z0-9_.-]+$/.test(parts[2])
    )
      throw new Error("Source namespace does not match verified authority");
    return { service: parts[2].split(".")[0]!, triggerId: parts[2] };
  }
  private async connection(client: PoolClient, id: string, boundToRequest = false): Promise<ConnectionRow | undefined> {
    z.uuid().parse(id);
    if (this.maintenance())
      return (
        await client.query<ConnectionRow>("SELECT * FROM integration_runtime.trigger_cleanup_connection($1::uuid)", [
          id,
        ])
      ).rows[0];
    const row = (
      await client.query<ConnectionRow>(
        `SELECT * FROM integration_runtime.connections WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$4 FOR SHARE`,
        [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, id],
      )
    ).rows[0];
    if (
      !row ||
      row.status !== "active" ||
      row.trigger_cleanup_fenced ||
      (row.source === "saas" && row.source_status !== "active") ||
      (this.scope.actorUserId !== row.subject_user_id && row.visibility !== "workspace") ||
      (boundToRequest &&
        this.scope.connectorConnectionId &&
        (row.id !== this.scope.connectorConnectionId || row.local_connection_id !== this.scope.localConnectionId))
    )
      return undefined;
    return row;
  }
  private async binding(
    client: PoolClient,
    id: string,
    service: string,
    accountId?: string,
    boundToRequest = false,
  ): Promise<Binding> {
    const row = await this.connection(client, id, boundToRequest);
    if (!row || row.service !== service)
      throw new ExecutionError("connection_not_found", "Trigger connection is not currently authorized.", "not_found");
    let account: Record<string, string>;
    if (row.source === "local") {
      if (!row.provider_account_id || (accountId !== undefined && accountId !== row.provider_account_id))
        throw new Error("Trigger requires the same verified provider account");
      account = { source: "local", providerAccountId: row.provider_account_id };
    } else {
      const ref = row.source_reference;
      if (
        !ref ||
        ["managedProjectId", "providerConfigId", "externalUserId", "connectedAccountId"].some((key) => !ref[key])
      )
        throw new Error("Managed account identity is unverified");
      if (accountId !== undefined && accountId !== ref.connectedAccountId)
        throw new Error("Trigger account binding changed");
      account = {
        source: "saas",
        managedProjectId: ref.managedProjectId!,
        providerConfigId: ref.providerConfigId!,
        externalUserId: ref.externalUserId!,
        connectedAccountId: ref.connectedAccountId!,
      };
    }
    return {
      connectionId: row.id,
      localConnectionId: row.local_connection_id,
      credentialOwnerId: row.subject_user_id,
      account,
    };
  }
  async withConnectionForExecution<T>(
    service: string,
    id: string,
    actionPolicy: Pick<PostgresActionPolicyStore, "withEffectiveForActor">,
    work: () => Promise<T>,
  ): Promise<T> {
    if (
      this.scope.purpose !== "action:execute:v2" ||
      this.scope.permissions.length !== 1 ||
      this.scope.permissions[0] !== this.scope.purpose ||
      !this.scope.actionId?.startsWith(`trigger:${service}.`)
    )
      throw new Error("Exact private Trigger execution authority required");
    const leaseId = randomUUID();
    let recorded = false;
    try {
      try {
        await actionPolicy.withEffectiveForActor(this.scope, [this.scope.actionId], async (decisions, client) => {
          const decision = decisions[0];
          if (
            decisions.length !== 1 ||
            decision?.actionId !== this.scope.actionId ||
            typeof decision.enabled !== "boolean"
          )
            throw new Error("Incomplete permission decision");
          if (!decision.enabled)
            throw new ExecutionError("action_not_granted", "This Trigger is not permitted.", "forbidden");
          const row = await this.connection(client, id, true);
          if (!row || row.service !== service)
            throw new ExecutionError(
              "connection_not_found",
              "Trigger connection is not currently authorized.",
              "not_found",
            );
          const account =
            row.source === "local" && !row.provider_account_id
              ? {
                  source: "local",
                  unverified: true,
                  secretRevision: String(row.secret_revision),
                  authType: row.auth_type,
                }
              : (await this.binding(client, id, service, undefined, true)).account;
          await client.query(
            `WITH budget AS (SELECT clock_timestamp() AS started)
        INSERT INTO integration_runtime.trigger_execution_leases (id,tenant_id,workspace_id,subject_user_id,credential_owner_id,connection_id,local_connection_id,service,capability_id,account_binding,created_at,lease_until)
        SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,started,started+$11::integer*interval '1 millisecond' FROM budget`,
            [
              leaseId,
              this.scope.tenantId,
              this.scope.workspaceId,
              this.scope.actorUserId,
              row.subject_user_id,
              id,
              row.local_connection_id,
              service,
              this.scope.actionId,
              account,
              Math.min(120000, remainingProcessingMs(this.scope) ?? 120000),
            ],
          );
          recorded = true;
        });
      } catch (error) {
        if (error instanceof ExecutionError) throw error;
        throw new ExecutionError(
          "action_policy_unavailable",
          "Trigger permission could not be verified.",
          "unavailable",
        );
      }
      // The durable intent now fences account/owner changes. No pool client or SQL transaction spans native work.
      assertProcessingActive(this.scope);
      return await work();
    } finally {
      if (recorded)
        await withSecretCleanup(this.scope, (scope) =>
          withScopedClient(this.pool, scope, async (client) => {
            await client.query(
              `DELETE FROM integration_runtime.trigger_execution_leases WHERE tenant_id=$1 AND workspace_id=$2 AND id=$3 AND subject_user_id=$4 AND credential_owner_id=$5`,
              [scope.tenantId, scope.workspaceId, leaseId, scope.actorUserId, scope.subjectUserId],
            );
          }),
        );
    }
  }
  private async subscription(client: PoolClient, id: string, lock = false): Promise<SubscriptionRow | undefined> {
    return (
      await client.query<SubscriptionRow>(
        `SELECT * FROM integration_runtime.trigger_subscriptions WHERE tenant_id=$1 AND workspace_id=$2 AND id=$3 AND (
    (subject_user_id=$4 AND (credential_owner_id=$5 OR $6::boolean)) OR (mode='resource-set' AND (credential_owner_id=$5 OR ($6::boolean AND integration_runtime.can_cleanup_trigger_connection(connection_id))))
    OR ($7::boolean AND credential_owner_id=$4)) ${lock ? "FOR UPDATE" : ""}`,
        [
          this.scope.tenantId,
          this.scope.workspaceId,
          id,
          this.dataUserId,
          this.scope.subjectUserId,
          this.maintenance(),
          this.scope.purpose === "lifecycle:delete",
        ],
      )
    ).rows[0];
  }
  private async decodeSubscription(client: PoolClient, row: SubscriptionRow): Promise<TriggerSubscription> {
    const binding = await this.binding(client, row.connection_id, row.service, undefined, true);
    if (
      !isDeepStrictEqual(binding, {
        connectionId: row.connection_id,
        localConnectionId: row.local_connection_id,
        credentialOwnerId: row.credential_owner_id,
        account: row.account_binding,
      })
    )
      throw new Error("Trigger account or connection lineage changed");
    const value = JSON.parse(await this.codec.decode(row.secret_ref)) as TriggerSubscription;
    if (
      value.id !== row.id ||
      value.ownerId !== row.owner_id ||
      value.service !== row.service ||
      value.triggerId !== row.trigger_id ||
      value.connectionId !== row.connection_id ||
      value.requestKey !== row.request_key ||
      value.mode !== row.mode ||
      value.status !== row.status ||
      value.reconcileAt !== Number(row.reconcile_at) ||
      value.providerAccountId !== (row.account_binding.providerAccountId ?? row.account_binding.connectedAccountId)
    )
      throw new Error("Trigger private envelope binding mismatch");
    return value;
  }
  async getFlowTrigger(id: string): Promise<TriggerSubscription | null> {
    return withScopedClient(this.pool, this.scope, async (client) => {
      const row = await this.subscription(client, id);
      if (!row) return null;
      try {
        return await this.decodeSubscription(client, row);
      } catch (error) {
        if (error instanceof ExecutionError && error.code === "connection_not_found") return null;
        throw error;
      }
    });
  }
  async list(): Promise<TriggerSubscription[]> {
    return withScopedClient(this.pool, this.scope, async (client) => {
      const rows = (
        await client.query<SubscriptionRow>(
          `SELECT * FROM integration_runtime.trigger_subscriptions WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 ORDER BY id`,
          this.values(),
        )
      ).rows;
      const result: TriggerSubscription[] = [];
      for (const row of rows) result.push(await this.decodeSubscription(client, row));
      return result;
    });
  }
  async listFlowTriggersForMaintenance(now: number, limit: number): Promise<TriggerSubscription[]> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new Error("Invalid Trigger maintenance limit");
    return withScopedClient(this.pool, this.scope, async (client) => {
      const rows = (
        await client.query<SubscriptionRow>(
          `SELECT * FROM integration_runtime.trigger_subscriptions WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND mode<>'resource-set' AND status<>'deleted' AND reconcile_at<=$4 ORDER BY reconcile_at,id LIMIT $5`,
          [...this.values(), now, limit],
        )
      ).rows;
      const result: TriggerSubscription[] = [];
      for (const row of rows) result.push(await this.decodeSubscription(client, row));
      return result;
    });
  }
  /** Read current visibility/status separately from the original cleanup proof; never rewrite the signed owner. */
  async hasCurrentConnection(record: TriggerSubscription): Promise<boolean> {
    if (this.scope.purpose !== "maintenance:run") throw new Error("Exact actor maintenance authority required");
    return withScopedClient(this.pool, this.scope, async (client) => {
      const row = await this.subscription(client, record.id);
      if (
        !row ||
        row.mode === "resource-set" ||
        row.subject_user_id !== this.scope.actorUserId ||
        row.owner_id !== record.ownerId ||
        row.connection_id !== record.connectionId ||
        row.service !== record.service ||
        row.trigger_id !== record.triggerId
      )
        return false;
      const connection = await this.connection(client, row.connection_id);
      if (
        !connection ||
        connection.status !== "active" ||
        connection.trigger_cleanup_fenced ||
        (connection.source === "saas" && connection.source_status !== "active") ||
        (connection.subject_user_id !== this.scope.actorUserId && connection.visibility !== "workspace")
      )
        return false;
      const binding = await this.binding(client, row.connection_id, row.service, record.providerAccountId);
      return isDeepStrictEqual(binding, {
        connectionId: row.connection_id,
        localConnectionId: row.local_connection_id,
        credentialOwnerId: row.credential_owner_id,
        account: row.account_binding,
      });
    });
  }
  async insertFlowTrigger(record: TriggerSubscription): Promise<TriggerSubscription> {
    if (!this.maintenance() && record.ownerId !== this.ownerId)
      throw new Error("Trigger owner does not match verified authority");
    if (this.maintenance() && record.mode !== "resource-set") throw new Error("Lifecycle cannot create a new consumer");
    let ref: string | undefined;
    try {
      return await withScopedClient(this.pool, this.scope, async (client) => {
        const binding = await this.binding(client, record.connectionId, record.service, record.providerAccountId, true);
        const owner = z.tuple([z.string(), z.string(), z.uuid(), z.uuid()]).parse(JSON.parse(record.ownerId));
        if (
          owner[0] !== this.scope.tenantId ||
          owner[1] !== this.scope.workspaceId ||
          owner[2] !== binding.credentialOwnerId
        )
          throw new Error("Trigger owner and credential lineage differ");
        const dataOwner = record.mode === "resource-set" ? binding.credentialOwnerId : owner[3];
        await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
          JSON.stringify([this.scope.tenantId, this.scope.workspaceId, record.id]),
        ]);
        const existing = await this.subscription(client, record.id, true);
        if (existing) return this.decodeSubscription(client, existing);
        ref = await this.encode(record);
        await client.query(
          `INSERT INTO integration_runtime.trigger_subscriptions (tenant_id,workspace_id,subject_user_id,actor_user_id,credential_owner_id,id,owner_id,mode,service,trigger_id,connection_id,local_connection_id,account_binding,request_key,status,secret_ref,reconcile_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
          [
            this.scope.tenantId,
            this.scope.workspaceId,
            dataOwner,
            owner[3],
            binding.credentialOwnerId,
            record.id,
            record.ownerId,
            record.mode,
            record.service,
            record.triggerId,
            record.connectionId,
            binding.localConnectionId,
            binding.account,
            record.requestKey,
            record.status,
            ref,
            record.reconcileAt,
          ],
        );
        return record;
      });
    } catch (error) {
      await this.recoverFailure(error, ref);
      throw error;
    }
  }
  async claimFlowTrigger(id: string, owner: string, _now: number, until: number): Promise<boolean> {
    if (!owner || !Number.isSafeInteger(until) || until <= Date.now() || until > Date.now() + 120000)
      throw new Error("Invalid Trigger lease");
    return withScopedClient(this.pool, this.scope, async (client) => {
      const row = await this.subscription(client, id, true);
      if (!row) return false;
      await this.decodeSubscription(client, row);
      return (
        (
          await client.query(
            `UPDATE integration_runtime.trigger_subscriptions SET lease_id=$6,lease_until=to_timestamp($7::double precision/1000) WHERE tenant_id=$1 AND workspace_id=$2 AND id=$3 AND subject_user_id=$4 AND credential_owner_id=$5 AND (lease_until IS NULL OR lease_until<=clock_timestamp())`,
            [
              this.scope.tenantId,
              this.scope.workspaceId,
              id,
              row.subject_user_id,
              row.credential_owner_id,
              owner,
              until,
            ],
          )
        ).rowCount === 1
      );
    });
  }
  async saveFlowTrigger(record: TriggerSubscription, owner: string, _now: number): Promise<boolean> {
    let ref: string | undefined;
    try {
      const saved = await withScopedClient(this.pool, this.scope, async (client) => {
        const row = await this.subscription(client, record.id, true);
        if (!row || row.lease_id !== owner || !row.lease_until || row.lease_until.getTime() <= Date.now()) return false;
        const original = await this.decodeSubscription(client, row);
        for (const key of [
          "ownerId",
          "mode",
          "service",
          "triggerId",
          "connectionId",
          "providerAccountId",
          "requestKey",
        ] as const)
          if (record[key] !== original[key]) throw new Error("Trigger identity is immutable");
        ref = await this.encode(record);
        return (
          (
            await client.query(
              `UPDATE integration_runtime.trigger_subscriptions SET secret_ref=$6,retired_secret_refs=array_append(retired_secret_refs,secret_ref),revision=revision+1,status=$7,reconcile_at=$8
        WHERE tenant_id=$1 AND workspace_id=$2 AND id=$3 AND subject_user_id=$4 AND credential_owner_id=$5 AND revision=$9 AND lease_id=$10 AND lease_until>clock_timestamp()`,
              [
                this.scope.tenantId,
                this.scope.workspaceId,
                record.id,
                row.subject_user_id,
                row.credential_owner_id,
                ref,
                record.status,
                record.reconcileAt,
                row.revision,
                owner,
              ],
            )
          ).rowCount === 1
        );
      });
      if (!saved && ref) await this.recover(ref);
      if (saved) await this.drainRetired("trigger_subscriptions", record.id);
      return saved;
    } catch (error) {
      await this.recoverFailure(error, ref);
      throw error;
    }
  }
  async releaseFlowTrigger(id: string, owner: string): Promise<void> {
    await withSecretCleanup(this.scope, (scope) =>
      withScopedClient(this.pool, scope, async (client) => {
        const row = await this.subscription(client, id, true);
        if (row)
          await client.query(
            `UPDATE integration_runtime.trigger_subscriptions SET lease_id=NULL,lease_until=NULL WHERE tenant_id=$1 AND workspace_id=$2 AND id=$3 AND subject_user_id=$4 AND credential_owner_id=$5 AND lease_id=$6`,
            [scope.tenantId, scope.workspaceId, id, row.subject_user_id, row.credential_owner_id, owner],
          );
      }),
    );
  }
  async getSourceApplication(
    namespace: string,
    id: string,
  ): Promise<{ revision: number; application: SourceApplication } | null> {
    const { service } = this.namespace(namespace);
    return withScopedClient(this.pool, this.scope, async (client) => {
      const row = (
        await client.query<ApplicationRow>(
          `SELECT * FROM integration_runtime.trigger_source_applications WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND namespace=$4 AND id=$5 AND credential_owner_id=$6`,
          [...this.values(), namespace, id, this.scope.subjectUserId],
        )
      ).rows[0];
      if (!row || row.retired) return null;
      for (const binding of row.bindings)
        if (!isDeepStrictEqual(await this.binding(client, binding.connectionId, service), binding))
          throw new Error("Source connection lineage changed");
      const payload = JSON.parse(await this.codec.decode(row.secret_ref)) as {
        namespace: string;
        id: string;
        application: SourceApplication;
      };
      if (payload.namespace !== namespace || payload.id !== id || row.owner_id !== this.ownerId)
        throw new Error("Source envelope scope mismatch");
      return { revision: Number(row.revision), application: payload.application };
    });
  }
  async saveSourceApplication(
    namespace: string,
    id: string,
    revision: number | null,
    application: SourceApplication,
  ): Promise<boolean> {
    const { service, triggerId } = this.namespace(namespace);
    let ref: string | undefined;
    try {
      const saved = await withScopedClient(this.pool, this.scope, async (client) => {
        await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
          JSON.stringify([this.scope.tenantId, this.scope.workspaceId, namespace, id]),
        ]);
        const row = (
          await client.query<ApplicationRow>(
            `SELECT * FROM integration_runtime.trigger_source_applications WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND namespace=$4 AND id=$5 AND credential_owner_id=$6 FOR UPDATE`,
            [...this.values(), namespace, id, this.scope.subjectUserId],
          )
        ).rows[0];
        if (row?.retired || (row ? Number(row.revision) : null) !== revision) return false;
        const bindings: Binding[] = [];
        for (const source of Object.values(application.sources))
          if (!source.deleted)
            bindings.push(await this.binding(client, source.connectionId, service, source.accountId));
        ref = await this.encode({ namespace, id, application });
        if (row)
          await client.query(
            `UPDATE integration_runtime.trigger_source_applications SET revision=revision+1,secret_ref=$6,retired_secret_refs=array_append(retired_secret_refs,secret_ref),bindings=$7 WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND namespace=$4 AND id=$5 AND credential_owner_id=$8`,
            [...this.values(), namespace, id, ref, JSON.stringify(bindings), this.scope.subjectUserId],
          );
        else
          await client.query(
            `INSERT INTO integration_runtime.trigger_source_applications (tenant_id,workspace_id,subject_user_id,actor_user_id,credential_owner_id,namespace,id,owner_id,service,trigger_id,secret_ref,bindings) VALUES ($1,$2,$3,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
            [
              ...this.values(),
              this.scope.subjectUserId,
              namespace,
              id,
              this.ownerId,
              service,
              triggerId,
              ref,
              JSON.stringify(bindings),
            ],
          );
        return true;
      });
      if (saved) await this.drainRetired("trigger_source_applications", id, namespace);
      return saved;
    } catch (error) {
      await this.recoverFailure(error, ref);
      throw error;
    }
  }
  private async encode(value: unknown): Promise<string> {
    assertProcessingActive(this.scope);
    const json = JSON.stringify(value);
    if (Buffer.byteLength(json) > 1048576) throw new Error("Trigger private state exceeds 1 MiB");
    return this.codec.encode(json);
  }
  private async recoverFailure(error: unknown, ref: string | undefined): Promise<void> {
    if (ref) await this.recover(ref);
    else if (error instanceof OpenBaoError && error.code !== "OPENBAO_CONFLICT") await this.recover(error.path);
  }
  private async recover(ref: string): Promise<void> {
    await withSecretCleanup(this.scope, (scope) =>
      withScopedClient(this.pool, scope, async (client) => {
        const used = (
          await client.query<{ used: boolean }>("SELECT integration_runtime.is_trigger_secret_referenced($1) AS used", [
            ref,
          ])
        ).rows[0]?.used;
        if (typeof used !== "boolean") throw new Error("Trigger secret reference proof is unavailable");
        if (used) return;
        try {
          await this.codec.delete(ref);
        } catch {
          await client.query(
            `INSERT INTO integration_runtime.trigger_secret_cleanup (tenant_id,workspace_id,subject_user_id,secret_ref) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
            [...this.values(), ref],
          );
        }
      }),
    );
  }
  private async drainRetired(
    table: "trigger_subscriptions" | "trigger_source_applications",
    id: string,
    namespace?: string,
  ): Promise<void> {
    await withSecretCleanup(this.scope, (scope) =>
      withScopedClient(this.pool, scope, async (client) => {
        const row =
          table === "trigger_subscriptions"
            ? await this.subscription(client, id, true)
            : (
                await client.query<ApplicationRow>(
                  `SELECT * FROM integration_runtime.trigger_source_applications WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$4 AND namespace=$5 FOR UPDATE`,
                  [...this.values(), id, namespace],
                )
              ).rows[0];
        if (!row) return;
        for (const ref of row.retired_secret_refs) await this.codec.delete(ref);
        await client.query(
          `UPDATE integration_runtime.${table} SET retired_secret_refs='{}' WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$4 ${namespace ? "AND namespace=$5" : ""}`,
          [scope.tenantId, scope.workspaceId, row.subject_user_id, id, ...(namespace ? [namespace] : [])],
        );
      }),
    );
  }
  /** Narrow internal read: proof comes from persisted actor↔owner↔connection lineage, not a caller owner parameter. */
  async getCleanupConnection(
    record: TriggerSubscription,
    secrets: ConnectionSecretStore,
  ): Promise<StoredLocalConnection | undefined> {
    if (!this.maintenance()) throw new Error("Exact trigger cleanup authority required");
    if (this.scope.purpose === "lifecycle:delete") this.lifecycle(true);
    return withScopedClient(this.pool, this.scope, async (client) => {
      const row = await this.subscription(client, record.id);
      if (
        !row ||
        row.connection_id !== record.connectionId ||
        row.service !== record.service ||
        row.owner_id !== record.ownerId
      )
        return undefined;
      const binding = await this.binding(client, row.connection_id, row.service, record.providerAccountId);
      if (
        !isDeepStrictEqual(binding, {
          connectionId: row.connection_id,
          localConnectionId: row.local_connection_id,
          credentialOwnerId: row.credential_owner_id,
          account: row.account_binding,
        })
      )
        throw new Error("Cleanup account lineage changed");
      const connection = await this.connection(client, row.connection_id);
      if (!connection || connection.source !== "local" || connection.auth_type === "no_auth") return undefined;
      if (connection.credential_profile?.accountId !== record.providerAccountId)
        throw new Error("Cleanup credential profile is not the bound verified account");
      assertProcessingActive(this.scope);
      const secret = await secrets.read(this.scope, connection.id, Number(connection.secret_revision));
      if (
        !secret ||
        secret.provider !== connection.service ||
        secret.revision !== Number(connection.secret_revision) ||
        secret.authType !== connection.auth_type
      )
        throw new Error("Cleanup credential revision does not match its actual connection");
      return {
        source: "local",
        id: connection.id,
        revision: connection.revision,
        service: connection.service,
        connectionName: connection.connection_name,
        credential: mergeCredential(secret, connection.credential_profile),
        credentialCacheOwner: {
          tenantId: this.scope.tenantId,
          workspaceId: this.scope.workspaceId,
          credentialOwnerId: row.credential_owner_id,
          connectionId: row.local_connection_id,
        },
      };
    });
  }
  async listExactOwnedForLifecycle(cursor: string | undefined, limit: number): Promise<TriggerLifecyclePage> {
    this.lifecycle();
    const target = {
      kind: "user" as const,
      tenantId: this.scope.tenantId,
      workspaceId: this.scope.workspaceId,
      userId: this.dataUserId,
    };
    const page = readScopedPage({ cursor, limit }, target, "native-triggers", 2);
    return withScopedClient(this.pool, this.scope, async (client) => {
      const rows = (
        await client.query<{
          kind: string;
          id: string;
          service: string;
          trigger_id: string;
          status: string;
          revision: string;
        }>(
          `SELECT * FROM (
      SELECT 'subscription' AS kind,id,service,trigger_id,status,revision FROM integration_runtime.trigger_subscriptions WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3
      UNION ALL SELECT 'source',id,service,trigger_id,'' AS status,revision FROM integration_runtime.trigger_source_applications WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3
    ) records WHERE (kind,id)>($4,$5) ORDER BY kind,id LIMIT $6`,
          [...this.values(), page.key[0] ?? "", page.key[1] ?? "", limit + 1],
        )
      ).rows;
      const chosen = rows.slice(0, limit),
        last = chosen[chosen.length - 1];
      return {
        subscriptions: chosen
          .filter((row) => row.kind === "subscription")
          .map((row) => ({ id: row.id, service: row.service, triggerId: row.trigger_id, status: row.status })),
        sourceApplications: chosen
          .filter((row) => row.kind === "source")
          .map((row) => ({ id: row.id, revision: Number(row.revision) })),
        nextCursor:
          rows.length > limit && last ? encodeScopedCursor(target, "native-triggers", [last.kind, last.id]) : undefined,
      };
    });
  }
  async countExactOwnedForLifecycle(): Promise<TriggerLifecycleCounts> {
    this.lifecycle();
    return withScopedClient(this.pool, this.scope, async (client) => {
      const statuses = (
        await client.query<{ status: string; count: string }>(
          `SELECT status,count(*) FROM integration_runtime.trigger_subscriptions WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 GROUP BY status ORDER BY status`,
          this.values(),
        )
      ).rows.map((row) => ({ status: row.status, count: Number(row.count) }));
      const count = (
        await client.query<{
          sources: string;
          secrets: string;
          pending: string;
          executions: string;
          active: string;
          cleanup: boolean;
        }>(
          `WITH owned_refs AS (
      SELECT secret_ref AS ref FROM integration_runtime.trigger_subscriptions WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3
      UNION SELECT unnest(retired_secret_refs) FROM integration_runtime.trigger_subscriptions WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3
      UNION SELECT secret_ref FROM integration_runtime.trigger_source_applications WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3
      UNION SELECT unnest(retired_secret_refs) FROM integration_runtime.trigger_source_applications WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3
      UNION SELECT secret_ref FROM integration_runtime.trigger_secret_cleanup WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND NOT integration_runtime.is_trigger_secret_referenced(secret_ref)
    ) SELECT (SELECT count(*) FROM owned_refs) AS secrets,
      (SELECT count(*) FROM integration_runtime.trigger_source_applications WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3) AS sources,
      ((SELECT count(*) FROM integration_runtime.trigger_secret_cleanup WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3)+(SELECT COALESCE(sum(cardinality(retired_secret_refs)),0) FROM integration_runtime.trigger_subscriptions WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3)+(SELECT COALESCE(sum(cardinality(retired_secret_refs)),0) FROM integration_runtime.trigger_source_applications WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3)) AS pending,
      (SELECT count(*) FROM integration_runtime.trigger_execution_leases WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3) AS executions,
      (SELECT count(*) FROM integration_runtime.trigger_execution_leases WHERE tenant_id=$1 AND workspace_id=$2 AND (subject_user_id=$3 OR credential_owner_id=$3) AND lease_until>clock_timestamp()) AS active,
      (EXISTS(SELECT 1 FROM integration_runtime.trigger_subscriptions WHERE tenant_id=$1 AND workspace_id=$2 AND (subject_user_id=$3 OR credential_owner_id=$3) AND status<>'deleted') OR EXISTS(SELECT 1 FROM integration_runtime.trigger_source_applications WHERE tenant_id=$1 AND workspace_id=$2 AND (subject_user_id=$3 OR credential_owner_id=$3) AND NOT retired)) AS cleanup`,
          this.values(),
        )
      ).rows[0]!;
      return {
        subscriptions: { total: statuses.reduce((sum, row) => sum + row.count, 0), statuses },
        sourceApplications: Number(count.sources),
        secrets: Number(count.secrets),
        pendingSecrets: Number(count.pending),
        executionLeases: Number(count.executions),
        pendingExecutions: Number(count.active),
        requiresCleanup: count.cleanup || Number(count.active) > 0,
      };
    });
  }
  async cleanupExactOwnedForLifecycle(cleanup: TriggerLifecycleCleanup): Promise<void> {
    this.lifecycle(true);
    const admission = await withScopedClient(this.pool, this.scope, async (client) => {
      // Fence only the target's OWN credentials. Deleting Bob must not stop Carol on Alice's connection.
      await client.query(
        `UPDATE integration_runtime.connections SET trigger_cleanup_fenced=true WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3`,
        this.values(),
      );
      const pending =
        (
          await client.query(
            `SELECT 1 FROM integration_runtime.trigger_execution_leases WHERE tenant_id=$1 AND workspace_id=$2 AND (subject_user_id=$3 OR credential_owner_id=$3) AND lease_until>clock_timestamp() LIMIT 1`,
            this.values(),
          )
        ).rowCount !== 0;
      const consumers = (
        await client.query<SubscriptionRow>(
          `SELECT * FROM integration_runtime.trigger_subscriptions WHERE tenant_id=$1 AND workspace_id=$2 AND (subject_user_id=$3 OR credential_owner_id=$3) AND mode<>'resource-set' AND status<>'deleted' ORDER BY id`,
          this.values(),
        )
      ).rows;
      return { pending, consumers };
    });
    // Keep the credential fence committed while genuine in-flight work drains; never claim it completed.
    if (admission.pending)
      throw new ExecutionError(
        "trigger_execution_in_progress",
        "A Trigger execution is still processing; retry cleanup after it drains.",
        "conflict",
      );
    const signal = this.scope.requestSignal ?? AbortSignal.timeout(120000);
    const remove = async (row: SubscriptionRow): Promise<void> =>
      withSubscription(this, row.id, signal, async (record, save) => {
        record.status = "deleting";
        await save();
        await cleanup(record, save, signal);
        const completed = await withScopedClient(this.pool, this.scope, (client) => this.subscription(client, row.id));
        if (completed?.status !== "deleted") throw new Error("Remote Trigger cleanup remains pending");
      });
    for (const row of admission.consumers) await remove(row);
    const groups = await withScopedClient(
      this.pool,
      this.scope,
      async (client) =>
        (
          await client.query<SubscriptionRow>(
            `SELECT * FROM integration_runtime.trigger_subscriptions WHERE tenant_id=$1 AND workspace_id=$2 AND credential_owner_id=$3 AND mode='resource-set' AND status<>'deleted' ORDER BY id`,
            this.values(),
          )
        ).rows,
    );
    for (const row of groups) await remove(row);
    await withScopedClient(this.pool, this.scope, async (client) => {
      if (
        (
          await client.query(
            `SELECT 1 FROM integration_runtime.trigger_subscriptions WHERE tenant_id=$1 AND workspace_id=$2 AND (subject_user_id=$3 OR credential_owner_id=$3) AND status<>'deleted'`,
            this.values(),
          )
        ).rowCount
      )
        throw new Error("Trigger cleanup remains pending");
      // Retire attached actors' source references without reading/exporting or purging their private envelopes.
      await client.query(
        `UPDATE integration_runtime.trigger_source_applications SET bindings='[]',retired=true WHERE tenant_id=$1 AND workspace_id=$2 AND (subject_user_id=$3 OR credential_owner_id=$3)`,
        this.values(),
      );
    });
  }
  async purgeExactOwnedForLifecycle(): Promise<TriggerPurgeResult> {
    this.lifecycle(true);
    return withScopedClient(this.pool, this.scope, async (client) => {
      const subscriptions = (
        await client.query<SubscriptionRow>(
          `SELECT * FROM integration_runtime.trigger_subscriptions WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 FOR UPDATE`,
          this.values(),
        )
      ).rows;
      const applications = (
        await client.query<ApplicationRow>(
          `SELECT * FROM integration_runtime.trigger_source_applications WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 FOR UPDATE`,
          this.values(),
        )
      ).rows;
      if (
        subscriptions.some((row) => row.status !== "deleted") ||
        applications.some((row) => row.bindings.length || !row.retired)
      )
        throw new Error("Real Trigger cleanup must finish before private state purge");
      if (
        (
          await client.query(
            `SELECT 1 FROM integration_runtime.trigger_execution_leases WHERE tenant_id=$1 AND workspace_id=$2 AND (subject_user_id=$3 OR credential_owner_id=$3) AND lease_until>clock_timestamp() LIMIT 1`,
            this.values(),
          )
        ).rowCount
      )
        throw new Error("Trigger execution must drain before private state purge");
      const pending = (
        await client.query<{ secret_ref: string }>(
          `SELECT secret_ref FROM integration_runtime.trigger_secret_cleanup WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 FOR UPDATE`,
          this.values(),
        )
      ).rows;
      let deletedTriggerSecrets = 0;
      const ownedRefs = new Set(
        [...subscriptions, ...applications].flatMap((row) => [row.secret_ref, ...row.retired_secret_refs]),
      );
      for (const ref of ownedRefs) if (await this.codec.delete(ref)) deletedTriggerSecrets++;
      for (const { secret_ref: ref } of pending)
        if (!ownedRefs.has(ref)) {
          const used = (
            await client.query<{ used: boolean }>(
              "SELECT integration_runtime.is_trigger_secret_referenced($1) AS used",
              [ref],
            )
          ).rows[0]?.used;
          if (typeof used !== "boolean") throw new Error("Trigger secret reference proof is unavailable");
          if (!used && (await this.codec.delete(ref))) deletedTriggerSecrets++;
        }
      const deletedSubscriptions =
        (
          await client.query(
            `DELETE FROM integration_runtime.trigger_subscriptions WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3`,
            this.values(),
          )
        ).rowCount ?? 0;
      const deletedSourceApplications =
        (
          await client.query(
            `DELETE FROM integration_runtime.trigger_source_applications WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3`,
            this.values(),
          )
        ).rowCount ?? 0;
      await client.query(
        `DELETE FROM integration_runtime.trigger_secret_cleanup WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3`,
        this.values(),
      );
      const deletedExecutionLeases =
        (
          await client.query(
            `DELETE FROM integration_runtime.trigger_execution_leases WHERE tenant_id=$1 AND workspace_id=$2 AND (subject_user_id=$3 OR credential_owner_id=$3) AND lease_until<=clock_timestamp()`,
            this.values(),
          )
        ).rowCount ?? 0;
      return { deletedSubscriptions, deletedSourceApplications, deletedTriggerSecrets, deletedExecutionLeases };
    });
  }
}
