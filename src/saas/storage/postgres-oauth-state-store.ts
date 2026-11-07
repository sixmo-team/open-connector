import type { IOAuthStateStore, OAuthAuthorizationState, OAuthStateBinding } from "../../oauth/oauth-flow-service.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { Pool } from "pg";

import { createHash } from "node:crypto";
import { assertProcessingActive } from "../../core/cancellation.ts";
import { OpenBaoError } from "../secrets/openbao-client.ts";
import { withSecretCleanup } from "../secrets/secret-codec.ts";
import { withScopedClient } from "./scoped-query.ts";

export interface OAuthStateSecretStore {
  put(
    scope: Readonly<SaasRequestScope>,
    oauthSessionId: string,
    pkceCodeVerifier: string | undefined,
    expiresAt: string,
    authorizationState?: OAuthAuthorizationState,
  ): Promise<{ secretRef: string; secretRevision: number }>;
  take(
    scope: Readonly<SaasRequestScope>,
    oauthSessionId: string,
  ): Promise<{ pkceCodeVerifier?: string; authorizationState?: OAuthAuthorizationState } | undefined>;
  delete(scope: Readonly<SaasRequestScope>, oauthSessionId: string): Promise<void>;
}

export interface LifecycleOAuthStateMetadata {
  id: string;
  status: string;
}

export interface LifecycleOAuthStatePage {
  items: LifecycleOAuthStateMetadata[];
  nextCursor?: string;
}

interface OAuthStateReconciliation {
  id: string;
  stateHash: string;
  service: string;
  connectionName: string | undefined;
  secretRef: string;
  expiresAt: string;
  createdAt: string;
}

/** Redacted OAuth metadata failure safe for logs and traces. */
export class OAuthStateMetadataReconciliationError extends Error {
  readonly code = "OAUTH_STATE_METADATA_RECONCILIATION_REQUIRED";
  readonly cleanupFailed: boolean;
  readonly markerWritten: boolean;

  constructor(cleanupFailed: boolean, markerWritten: boolean) {
    super("OAuth state metadata write failed after secret storage");
    this.name = "OAuthStateMetadataReconciliationError";
    this.cleanupFailed = cleanupFailed;
    this.markerWritten = markerWritten;
  }
}

/** Fail-closed OAuth consumption result requiring a fresh authorization attempt. */
export class OAuthStateConsumeReconciliationError extends Error {
  readonly code = "OAUTH_STATE_RECONNECT_REQUIRED";
  readonly phase: "secret_take_failed" | "completion_write_failed";
  readonly markerWritten: boolean;

  constructor(phase: "secret_take_failed" | "completion_write_failed", markerWritten: boolean) {
    super("OAuth state consumption could not be confirmed; reconnect is required");
    this.phase = phase;
    this.markerWritten = markerWritten;
    this.name = "OAuthStateConsumeReconciliationError";
  }
}

/** One-time OAuth state storage bound to one immutable SaaS request scope. */
export class PostgresOAuthStateStore implements IOAuthStateStore {
  private readonly pool: Pool;
  private readonly scope: Readonly<SaasRequestScope>;
  private readonly secrets: OAuthStateSecretStore;
  private readonly stateMaxAgeMs: number;

  constructor(
    pool: Pool,
    scope: Readonly<SaasRequestScope>,
    secrets: OAuthStateSecretStore,
    stateMaxAgeMs: number = 15 * 60 * 1_000,
  ) {
    this.pool = pool;
    this.scope = scope;
    this.secrets = secrets;
    this.stateMaxAgeMs = stateMaxAgeMs;
  }

  async set(state: OAuthAuthorizationState): Promise<void> {
    assertProcessingActive(this.scope);
    const id = this.scope.oauthSessionId;
    if (!id || !this.scope.localConnectionId || this.scope.actorUserId !== this.scope.subjectUserId)
      throw new Error("OAuth requires an exact interactive session and local connection");
    const stateHash = hashState(state.state);
    const expiresAt = new Date(new Date(state.createdAt).getTime() + this.stateMaxAgeMs).toISOString();
    let secret: { secretRef: string; secretRevision: number };
    try {
      secret = await this.secrets.put(this.scope, id, state.pkceCodeVerifier, expiresAt, state);
    } catch (error) {
      if (!(error instanceof OpenBaoError) || error.code === "OPENBAO_CONFLICT") throw error;
      throw await withSecretCleanup(this.scope, async (cleanupScope) => {
        let cleanupFailed = false;
        try {
          await this.secrets.delete(cleanupScope, id);
        } catch {
          cleanupFailed = true;
        }
        const markerWritten =
          cleanupFailed &&
          (await this.writeReconciliationMarker({
            id,
            stateHash,
            service: state.service,
            connectionName: state.connectionName,
            secretRef: error.path,
            expiresAt,
            createdAt: state.createdAt,
          }));
        return new OAuthStateMetadataReconciliationError(cleanupFailed, markerWritten);
      });
    }
    try {
      await withScopedClient(this.pool, this.scope, async (client) => {
        const inserted = await client.query(
          `INSERT INTO integration_runtime.oauth_states (
             id, tenant_id, workspace_id, subject_user_id, connection_id, service, connection_name,
             state_hash, secret_ref, status, expires_at, created_at, local_connection_id, retirement_generation
           ) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10,$11,$12,$13
             WHERE EXISTS (SELECT 1 FROM integration_runtime.connection_retirements r
               WHERE r.tenant_id=$2 AND r.workspace_id=$3 AND r.subject_user_id=$4 AND r.local_connection_id=$12
                 AND r.service=$6 AND r.connection_name=$7 AND r.generation=$13)`,
          [
            id,
            this.scope.tenantId,
            this.scope.workspaceId,
            this.scope.subjectUserId,
            this.scope.connectorConnectionId ?? null,
            state.service,
            state.connectionName ?? null,
            stateHash,
            secret.secretRef,
            expiresAt,
            state.createdAt,
            this.scope.localConnectionId,
            state.retirementGeneration,
          ],
        );
        if (inserted.rowCount !== 1) throw new Error("Connection retired before OAuth state admission");
      });
    } catch {
      throw await withSecretCleanup(this.scope, async (cleanupScope) => {
        try {
          await this.secrets.delete(cleanupScope, id);
        } catch {
          const markerWritten = await this.writeReconciliationMarker({
            id,
            stateHash,
            service: state.service,
            connectionName: state.connectionName,
            secretRef: secret.secretRef,
            expiresAt,
            createdAt: state.createdAt,
          });
          return new OAuthStateMetadataReconciliationError(true, markerWritten);
        }
        return new OAuthStateMetadataReconciliationError(false, false);
      });
    }
  }

  async take(state: string, binding?: OAuthStateBinding): Promise<OAuthAuthorizationState | undefined> {
    assertProcessingActive(this.scope);
    if (
      !this.scope.oauthSessionId ||
      !this.scope.localConnectionId ||
      this.scope.actorUserId !== this.scope.subjectUserId
    )
      return undefined;
    if (binding && binding.oauthSessionId !== this.scope.oauthSessionId) return undefined;
    const row = await withScopedClient(this.pool, this.scope, async (client) => {
      return (
        await client.query<{
          id: string;
          service: string;
          connection_name: string | null;
          created_at: Date | string;
          retirement_generation: string;
        }>(
          `UPDATE integration_runtime.oauth_states
           SET status = 'reserved', updated_at = now()
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
             AND state_hash = $4 AND status = 'pending' AND expires_at > now()
             AND id = $5 AND local_connection_id = $6
             AND ($7::text IS NULL OR connection_name = $7)
             AND EXISTS (SELECT 1 FROM integration_runtime.connection_retirements r
               WHERE r.tenant_id=oauth_states.tenant_id AND r.workspace_id=oauth_states.workspace_id
                 AND r.subject_user_id=oauth_states.subject_user_id AND r.local_connection_id=oauth_states.local_connection_id
                 AND r.service=oauth_states.service AND r.connection_name=oauth_states.connection_name
                 AND r.generation=oauth_states.retirement_generation)
           RETURNING id, service, connection_name, created_at, retirement_generation`,
          [
            this.scope.tenantId,
            this.scope.workspaceId,
            this.scope.subjectUserId,
            hashState(state),
            this.scope.oauthSessionId,
            this.scope.localConnectionId,
            binding?.connectionName ?? null,
          ],
        )
      ).rows[0];
    });
    if (!row) return undefined;

    let secret: { pkceCodeVerifier?: string; authorizationState?: OAuthAuthorizationState } | undefined;
    try {
      secret = await this.secrets.take(this.scope, row.id);
    } catch {
      const markerWritten = await this.writeTerminalFailure(row.id, "secret_take_failed");
      throw new OAuthStateConsumeReconciliationError("secret_take_failed", markerWritten);
    }

    try {
      await withScopedClient(this.pool, this.scope, async (client) => {
        const result = await client.query(
          `UPDATE integration_runtime.oauth_states
           SET status = $5, consumed_at = now(), updated_at = now()
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
             AND id = $4 AND status = 'reserved'`,
          [
            this.scope.tenantId,
            this.scope.workspaceId,
            this.scope.subjectUserId,
            row.id,
            secret ? "completed" : "expired",
          ],
        );
        if (result.rowCount !== 1) throw new Error("OAuth state completion lost its reservation");
      });
    } catch {
      const markerWritten = await this.writeTerminalFailure(row.id, "completion_write_failed");
      throw new OAuthStateConsumeReconciliationError("completion_write_failed", markerWritten);
    }
    if (!secret) return undefined;

    const pending = secret.authorizationState;
    if (
      !pending ||
      pending.state !== state ||
      pending.service !== row.service ||
      pending.connectionName !== row.connection_name ||
      pending.retirementGeneration !== row.retirement_generation
    )
      return undefined;
    return pending;
  }

  async deleteCreatedBefore(cutoff: string): Promise<void> {
    if (!Number.isFinite(Date.parse(cutoff))) throw new Error("Invalid OAuth state cutoff");
    const rows = await withScopedClient(
      this.pool,
      this.scope,
      async (client) =>
        (
          await client.query<{ id: string }>(
            `UPDATE integration_runtime.oauth_states
        SET status='expired',updated_at=now() WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3
          AND created_at<$4 RETURNING id`,
            [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, cutoff],
          )
        ).rows,
    );
    for (const row of rows) {
      await this.secrets.delete(this.scope, row.id);
      await withScopedClient(this.pool, this.scope, async (client) => {
        await client.query(
          `DELETE FROM integration_runtime.oauth_states WHERE tenant_id=$1 AND workspace_id=$2
          AND subject_user_id=$3 AND id=$4 AND status='expired'`,
          [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, row.id],
        );
      });
    }
  }

  async listExactOwnedForLifecycle(cursor: string | undefined, limit: number): Promise<LifecycleOAuthStatePage> {
    if (!Number.isSafeInteger(limit) || limit <= 0 || limit > 100) throw new Error("Invalid lifecycle page limit");
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const values: unknown[] = [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId];
      const after = cursor ? "AND id > $4::uuid" : "";
      if (cursor) values.push(cursor);
      values.push(limit + 1);
      const rows = (
        await client.query<LifecycleOAuthStateMetadata>(
          `SELECT id, status
           FROM integration_runtime.oauth_states
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3 ${after}
           ORDER BY id
           LIMIT $${values.length}`,
          values,
        )
      ).rows;
      const items = rows.slice(0, limit);
      return {
        items,
        ...(rows.length > limit && items.length > 0 ? { nextCursor: items[items.length - 1]!.id } : {}),
      };
    });
  }

  async deleteExactOwnedLifecycleSecret(oauthSessionId: string): Promise<void> {
    const owned = await withScopedClient(this.pool, this.scope, async (client) => {
      return (
        (
          await client.query(
            `SELECT 1 FROM integration_runtime.oauth_states
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3 AND id = $4`,
            [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, oauthSessionId],
          )
        ).rowCount === 1
      );
    });
    if (!owned) return;
    await this.secrets.delete(this.scope, oauthSessionId);
  }
  private async writeTerminalFailure(
    id: string,
    phase: OAuthStateConsumeReconciliationError["phase"],
  ): Promise<boolean> {
    try {
      return await withSecretCleanup(this.scope, (cleanupScope) =>
        withScopedClient(this.pool, cleanupScope, async (client) => {
          const result = await client.query(
            `UPDATE integration_runtime.oauth_states
           SET status = 'failed', callback_result_fingerprint = $5,
               consumed_at = now(), updated_at = now()
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
             AND id = $4 AND status IN ('reserved', 'completed', 'expired')`,
            [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, id, `reconcile:${phase}`],
          );
          return result.rowCount === 1;
        }),
      );
    } catch {
      return false;
    }
  }

  private async writeReconciliationMarker(marker: OAuthStateReconciliation): Promise<boolean> {
    try {
      await withSecretCleanup(this.scope, (cleanupScope) =>
        withScopedClient(this.pool, cleanupScope, async (client) => {
          await client.query(
            `INSERT INTO integration_runtime.oauth_states (
             id, tenant_id, workspace_id, subject_user_id, connection_id, service, connection_name,
             state_hash, secret_ref, status, expires_at, created_at
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'failed', $10, $11)
           ON CONFLICT (id) DO UPDATE
           SET status = 'failed', secret_ref = EXCLUDED.secret_ref,
               expires_at = EXCLUDED.expires_at, updated_at = now()`,
            [
              marker.id,
              this.scope.tenantId,
              this.scope.workspaceId,
              this.scope.subjectUserId,
              this.scope.connectorConnectionId ?? null,
              marker.service,
              marker.connectionName ?? null,
              marker.stateHash,
              marker.secretRef,
              marker.expiresAt,
              marker.createdAt,
            ],
          );
        }),
      );
      return true;
    } catch {
      return false;
    }
  }
}

function hashState(state: string): string {
  return createHash("sha256").update(state).digest("hex");
}
