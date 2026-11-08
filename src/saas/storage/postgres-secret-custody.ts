import type { SaasRequestScope } from "../contracts.ts";
import type { ISecretCodec } from "../secrets/secret-codec.ts";
import type { Pool, PoolClient } from "pg";

import { OpenBaoError } from "../secrets/openbao-client.ts";
import { withSecretCleanup } from "../secrets/secret-codec.ts";
import { withScopedClient } from "./scoped-query.ts";

export type SecretCustodyKind =
  | "trigger-subscription"
  | "trigger-source"
  | "connection-request"
  | "connection-candidate";
export type SecretCustodyTarget = {
  kind: SecretCustodyKind;
  id: string;
  dataUserId: string;
  credentialOwnerId: string;
  identity: Readonly<Record<string, unknown>>;
  connectionId?: string;
};

/** Only an authoritative rejection of this original immutable write proves it cannot land later. */
export function isOriginalSecretWriteRejected(error: unknown, ref: string): boolean {
  return (
    error instanceof OpenBaoError &&
    error.path === ref &&
    (error.code === "OPENBAO_REQUEST_TOO_LARGE" ||
      error.code === "OPENBAO_CONFLICT" ||
      [401, 403, 404, 409, 412].includes(error.status ?? 0))
  );
}

const exactTargetSql = `tenant_id=$1 AND workspace_id=$2 AND secret_ref=$3
  AND kind=$4 AND target_id=$5 AND subject_user_id=$6 AND actor_user_id=$7
  AND credential_owner_id=$8 AND identity=$9::jsonb AND connection_id IS NOT DISTINCT FROM $10::uuid`;

/** One durable custody row per immutable write attempt. Unknown original writes remain pending. */
export class PostgresSecretCustodyStore {
  private readonly pool: Pool;
  private readonly scope: Readonly<SaasRequestScope>;
  private readonly codec: ISecretCodec;
  constructor(pool: Pool, scope: Readonly<SaasRequestScope>, codec: ISecretCodec) {
    this.pool = pool;
    this.scope = scope;
    this.codec = codec;
  }

  async encode(plaintext: string, target: SecretCustodyTarget): Promise<string> {
    const captured = this.capture(target);
    let reserved: string | undefined;
    try {
      const ref = await this.codec.encode(plaintext, async (allocated) => {
        if (reserved) throw new Error("Secret codec attempted multiple reservations");
        reserved = allocated;
        await withScopedClient(this.pool, this.scope, async (client) => {
          await client.query(
            `INSERT INTO integration_runtime.secret_custody
            (tenant_id,workspace_id,secret_ref,kind,target_id,subject_user_id,actor_user_id,credential_owner_id,identity,connection_id,state)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,'pending')`,
            this.parameters(allocated, captured),
          );
        });
      });
      if (!reserved || ref !== reserved)
        throw new Error("Secret codec did not return its reserved immutable reference");
      return ref;
    } catch (error) {
      if (reserved && isOriginalSecretWriteRejected(error, reserved)) {
        await withSecretCleanup(this.scope, (scope) =>
          withScopedClient(this.pool, scope, async (client) => {
            await client.query(
              `DELETE FROM integration_runtime.secret_custody WHERE ${exactTargetSql} AND state='pending'`,
              this.parameters(reserved!, captured),
            );
          }),
        );
      }
      throw error;
    }
  }

  async consume(client: PoolClient, ref: string, target: SecretCustodyTarget): Promise<void> {
    const result = await client.query(
      `DELETE FROM integration_runtime.secret_custody WHERE ${exactTargetSql} AND state='pending'`,
      this.parameters(ref, this.capture(target)),
    );
    if (result.rowCount !== 1) throw new Error("Secret publication lost exact pending custody");
  }

  /** Caller must have observed the ORIGINAL encode fulfill, never an absence/read after an unknown POST. */
  async abandonWritten(ref: string, target: SecretCustodyTarget): Promise<void> {
    const captured = this.capture(target);
    await withSecretCleanup(this.scope, async (scope) => {
      const changed = await withScopedClient(
        this.pool,
        scope,
        async (client) =>
          (
            await client.query(
              `UPDATE integration_runtime.secret_custody SET state='deleting'
          WHERE ${exactTargetSql} AND state='pending'`,
              this.parameters(ref, captured),
            )
          ).rowCount === 1,
      );
      // The publisher's DELETE and this UPDATE contend on the same row. Missing means publication won.
      if (changed) await this.erase(ref, scope);
    });
  }

  /** Run in the same transaction as the settled owner's terminal fence or removal. */
  async adoptDeleting(client: PoolClient, refs: readonly string[], target: SecretCustodyTarget): Promise<void> {
    const captured = this.capture(target);
    for (const ref of new Set(refs)) {
      const parameters = this.parameters(ref, captured);
      const inserted = await client.query(
        `INSERT INTO integration_runtime.secret_custody
        (tenant_id,workspace_id,secret_ref,kind,target_id,subject_user_id,actor_user_id,credential_owner_id,identity,connection_id,state)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,'deleting') ON CONFLICT DO NOTHING`,
        parameters,
      );
      if (inserted.rowCount === 1) continue;
      // Forced RLS authorizes the disposal actor; retain the existing row's immutable audit actor.
      const existing = await client.query(
        `SELECT secret_ref FROM integration_runtime.secret_custody
        WHERE tenant_id=$1 AND workspace_id=$2 AND secret_ref=$3
          AND kind=$4 AND target_id=$5 AND subject_user_id=$6
          AND credential_owner_id=$7 AND identity=$8::jsonb AND connection_id IS NOT DISTINCT FROM $9::uuid
          AND state='deleting' FOR UPDATE`,
        [
          this.scope.tenantId,
          this.scope.workspaceId,
          ref,
          captured.kind,
          captured.id,
          captured.dataUserId,
          captured.credentialOwnerId,
          JSON.stringify(captured.identity),
          captured.connectionId ?? null,
        ],
      );
      if (existing.rowCount !== 1) throw new Error("Cannot adopt pending or mismatched secret custody");
    }
  }

  async assertNoPending(client: PoolClient, kinds: readonly SecretCustodyKind[]): Promise<void> {
    const result = await client.query(
      `SELECT secret_ref FROM integration_runtime.secret_custody
      WHERE tenant_id=$1 AND workspace_id=$2 AND kind=ANY($3::text[]) AND state='pending' LIMIT 1`,
      [this.scope.tenantId, this.scope.workspaceId, kinds],
    );
    if (result.rowCount)
      throw new Error("Original secret write outcome is unknown; pending custody requires reconciliation");
  }

  async drain(kinds: readonly SecretCustodyKind[]): Promise<number> {
    const refs = await withScopedClient(
      this.pool,
      this.scope,
      async (client) =>
        (
          await client.query<{ secret_ref: string }>(
            `SELECT secret_ref FROM integration_runtime.secret_custody
        WHERE tenant_id=$1 AND workspace_id=$2 AND kind=ANY($3::text[]) AND state='deleting'`,
            [this.scope.tenantId, this.scope.workspaceId, kinds],
          )
        ).rows,
    );
    let erased = 0;
    for (const { secret_ref: ref } of refs) {
      if (await this.erase(ref, this.scope)) erased++;
    }
    return erased;
  }

  private async erase(ref: string, scope: Readonly<SaasRequestScope>): Promise<boolean> {
    // Selection/transition has committed and released its client before any KV call.
    const deleted = await this.codec.delete(ref);
    await withScopedClient(this.pool, scope, async (client) => {
      await client.query(
        `DELETE FROM integration_runtime.secret_custody
        WHERE tenant_id=$1 AND workspace_id=$2 AND secret_ref=$3 AND state='deleting'`,
        [scope.tenantId, scope.workspaceId, ref],
      );
    });
    return deleted;
  }

  private capture(target: SecretCustodyTarget): SecretCustodyTarget {
    if (
      !target.id ||
      !target.dataUserId ||
      !target.credentialOwnerId ||
      !target.identity ||
      typeof target.identity !== "object" ||
      Array.isArray(target.identity)
    )
      throw new Error("An exact secret owner identity is required");
    return { ...target, identity: structuredClone(target.identity) };
  }

  private parameters(ref: string, target: SecretCustodyTarget): unknown[] {
    return [
      this.scope.tenantId,
      this.scope.workspaceId,
      ref,
      target.kind,
      target.id,
      target.dataUserId,
      this.scope.actorUserId,
      target.credentialOwnerId,
      JSON.stringify(target.identity),
      target.connectionId ?? null,
    ];
  }
}
