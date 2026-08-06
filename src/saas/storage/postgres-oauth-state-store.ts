import type { IOAuthStateStore, OAuthAuthorizationState } from "../../oauth/oauth-flow-service.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { Pool } from "pg";

import { createHash, randomUUID } from "node:crypto";
import { withScopedClient } from "./scoped-query.ts";

export interface OAuthStateSecretStore {
  put(
    scope: Readonly<SaasRequestScope>,
    oauthSessionId: string,
    pkceCodeVerifier: string | undefined,
    expiresAt: string,
  ): Promise<{ secretRef: string; secretRevision: number }>;
  take(scope: Readonly<SaasRequestScope>, oauthSessionId: string): Promise<{ pkceCodeVerifier?: string } | undefined>;
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
    const id = this.scope.oauthSessionId ?? randomUUID();
    const stateHash = hashState(state.state);
    const expiresAt = new Date(new Date(state.createdAt).getTime() + this.stateMaxAgeMs).toISOString();
    const secret = await this.secrets.put(this.scope, id, state.pkceCodeVerifier, expiresAt);
    try {
      await withScopedClient(this.pool, this.scope, async (client) => {
        await client.query(
          `INSERT INTO integration_runtime.oauth_states (
             id, tenant_id, workspace_id, subject_user_id, connection_id, service, connection_name,
             state_hash, secret_ref, status, expires_at, created_at
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', $10, $11)`,
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
          ],
        );
      });
    } catch {
      try {
        await this.secrets.take(this.scope, id);
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
        throw new OAuthStateMetadataReconciliationError(true, markerWritten);
      }
      throw new OAuthStateMetadataReconciliationError(false, false);
    }
  }

  async take(state: string): Promise<OAuthAuthorizationState | undefined> {
    const row = await withScopedClient(this.pool, this.scope, async (client) => {
      return (
        await client.query<{
          id: string;
          service: string;
          connection_name: string | null;
          created_at: Date | string;
        }>(
          `UPDATE integration_runtime.oauth_states
           SET status = 'reserved', updated_at = now()
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
             AND state_hash = $4 AND status = 'pending' AND expires_at > now()
           RETURNING id, service, connection_name, created_at`,
          [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, hashState(state)],
        )
      ).rows[0];
    });
    if (!row) return undefined;

    let secret: { pkceCodeVerifier?: string } | undefined;
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

    return {
      service: row.service,
      ...(row.connection_name === null ? {} : { connectionName: row.connection_name }),
      state,
      createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : new Date(row.created_at).toISOString(),
      ...(secret.pkceCodeVerifier === undefined ? {} : { pkceCodeVerifier: secret.pkceCodeVerifier }),
    };
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
      return await withScopedClient(this.pool, this.scope, async (client) => {
        const result = await client.query(
          `UPDATE integration_runtime.oauth_states
           SET status = 'failed', callback_result_fingerprint = $5,
               consumed_at = now(), updated_at = now()
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
             AND id = $4 AND status IN ('reserved', 'completed', 'expired')`,
          [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, id, `reconcile:${phase}`],
        );
        return result.rowCount === 1;
      });
    } catch {
      return false;
    }
  }

  private async writeReconciliationMarker(marker: OAuthStateReconciliation): Promise<boolean> {
    try {
      await withScopedClient(this.pool, this.scope, async (client) => {
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
      });
      return true;
    } catch {
      return false;
    }
  }
}

function hashState(state: string): string {
  return createHash("sha256").update(state).digest("hex");
}
