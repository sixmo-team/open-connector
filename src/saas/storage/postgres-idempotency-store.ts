import type {
  SaasActionIdempotencyStore,
  SaasIdempotencyClaimInput,
  SaasIdempotencyClaimResult,
  SaasIdempotencyCompletionInput,
} from "../actions/saas-action-runner.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { Pool } from "pg";

import { randomUUID } from "node:crypto";
import { parseSaasActionRunResult } from "../actions/saas-action-runner.ts";
import { withScopedClient } from "./scoped-query.ts";

interface IdempotencyRow {
  request_hash: string;
  status: string;
  response: unknown;
}

type RawClaimResult =
  | { kind: "acquired" }
  | { kind: "in_progress" }
  | { kind: "completed"; response: unknown }
  | { kind: "conflict" };

interface CompletionRecordInput {
  keyHash: string;
  requestHash: string;
  claimId: string;
  response: unknown;
  expiresAt: string;
  resultFingerprint?: string;
  safeErrorCode?: string;
}

/** Upstream idempotency storage bound to one immutable SaaS request scope. */
export class PostgresIdempotencyStore implements SaasActionIdempotencyStore {
  private readonly pool: Pool;
  private readonly scope: Readonly<SaasRequestScope>;

  constructor(pool: Pool, scope: Readonly<SaasRequestScope>) {
    this.pool = pool;
    this.scope = scope;
  }

  async claimAction(input: SaasIdempotencyClaimInput): Promise<SaasIdempotencyClaimResult> {
    if (input.requestHash !== this.scope.requestHash) {
      throw new Error("Idempotency claim does not match its scoped authorization");
    }
    const claim = await this.claimRecord(input);
    return claim.kind === "completed"
      ? { kind: "completed", response: parseSaasActionRunResult(claim.response) }
      : claim;
  }

  async completeAction(input: SaasIdempotencyCompletionInput): Promise<boolean> {
    if (input.requestHash !== this.scope.requestHash) return false;
    if (input.safeErrorCode && !/^[a-z][a-z0-9_]{0,63}$/.test(input.safeErrorCode)) return false;
    return await this.completeRecord(input);
  }

  private async claimRecord(input: SaasIdempotencyClaimInput): Promise<RawClaimResult> {
    return await withScopedClient(this.pool, this.scope, async (client) => {
      await client.query(
        `DELETE FROM integration_runtime.idempotency_records
         WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
           AND expires_at <= $4 AND status <> 'in_progress'`,
        [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, input.now],
      );
      const inserted = await client.query(
        `INSERT INTO integration_runtime.idempotency_records (
           id, tenant_id, workspace_id, subject_user_id, connection_id, action_id,
           key_hash, request_hash, claim_id, status, expires_at, created_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'in_progress', $10, $11)
         ON CONFLICT (tenant_id, workspace_id, subject_user_id, key_hash) DO NOTHING`,
        [
          randomUUID(),
          this.scope.tenantId,
          this.scope.workspaceId,
          this.scope.subjectUserId,
          this.scope.connectorConnectionId ?? null,
          this.scope.actionId ?? null,
          input.keyHash,
          input.requestHash,
          input.claimId,
          input.expiresAt,
          input.now,
        ],
      );
      if (inserted.rowCount === 1) return { kind: "acquired" };

      const row = (
        await client.query<IdempotencyRow>(
          `SELECT request_hash, status, response
           FROM integration_runtime.idempotency_records
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3 AND key_hash = $4
           FOR UPDATE`,
          [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, input.keyHash],
        )
      ).rows[0];
      if (!row) throw new Error("Idempotency record disappeared while claiming it");
      if (row.request_hash !== input.requestHash) return { kind: "conflict" };
      if (row.status === "in_progress") return { kind: "in_progress" };
      if (row.status !== "completed" || !row.response) {
        throw new Error("Completed idempotency record has no replayable response");
      }
      return { kind: "completed", response: row.response };
    });
  }

  private async completeRecord(input: CompletionRecordInput): Promise<boolean> {
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const result = await client.query(
        `UPDATE integration_runtime.idempotency_records
         SET status = 'completed', response = $7, expires_at = $8,
             result_fingerprint = $9, safe_error_code = $10, updated_at = now()
         WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
           AND key_hash = $4 AND claim_id = $5 AND request_hash = $6 AND status = 'in_progress'`,
        [
          this.scope.tenantId,
          this.scope.workspaceId,
          this.scope.subjectUserId,
          input.keyHash,
          input.claimId,
          input.requestHash,
          input.response,
          input.expiresAt,
          input.resultFingerprint ?? null,
          input.safeErrorCode ?? null,
        ],
      );
      return result.rowCount === 1;
    });
  }
}
