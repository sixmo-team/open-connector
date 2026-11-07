import type {
  IConnectionStore,
  StoredConnection,
  StoredLocalConnection,
  StoredSaasConnection,
} from "../../connection-store.ts";
import type { CredentialProfile, ResolvedCredential } from "../../core/types.ts";
import type { ProviderCredentialRevocationOutcome } from "../connections/provider-credential-revoker.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { PendingConnectionRequest } from "./connection-request-store.ts";
import type { Pool, PoolClient } from "pg";

import { randomUUID } from "node:crypto";
import { z } from "zod";
import { ConnectionError } from "../../connection-error.ts";
import { assertProcessingActive } from "../../core/cancellation.ts";
import { OpenBaoError } from "../secrets/openbao-client.ts";
import { withSecretCleanup } from "../secrets/secret-codec.ts";
import { queueSaasConnectionCleanup } from "./postgres-saas-project-store.ts";
import { withScopedClient } from "./scoped-query.ts";

const connectionIdSchema = z.uuid();

interface ConnectionSecretBase {
  provider: string;
  metadata: Record<string, unknown>;
  revision: number;
}

export type ConnectionSecret = ConnectionSecretBase &
  (
    | { authType: "no_auth"; value: Record<string, never> }
    | { authType: "api_key"; value: { apiKey: string; values: Record<string, string> } }
    | { authType: "custom_credential"; value: { values: Record<string, string> } }
    | {
        authType: "oauth2";
        value: {
          accessToken: string;
          tokenType: string;
          expiresAt?: string;
          refreshToken?: string;
          providerSecret?: Record<string, unknown>;
        };
      }
  );

export interface ConnectionSecretStore {
  create(
    scope: Readonly<SaasRequestScope>,
    connectionId: string,
    provider: string,
    credential: ResolvedCredential,
  ): Promise<{ secretRef: string; secretRevision: number }>;
  read(
    scope: Readonly<SaasRequestScope>,
    connectionId: string,
    secretRevision: number,
  ): Promise<ConnectionSecret | undefined>;
  update(
    scope: Readonly<SaasRequestScope>,
    connectionId: string,
    provider: string,
    expectedRevision: number,
    credential: ResolvedCredential,
  ): Promise<number | false>;
  delete(scope: Readonly<SaasRequestScope>, connectionId: string): Promise<void>;
}

export type SaasConnectionStatus = "pending" | "active" | "reconnect_required" | "failed" | "expired" | "revoked";

/** Display-safe connection metadata read without loading credential secrets. */
export interface SafeStoredConnection {
  id: string;
  subjectUserId: string;
  localConnectionId: string;
  service: string;
  connectionName: string;
  visibility: "user" | "workspace";
  status: SaasConnectionStatus;
  profile?: CredentialProfile;
  createdAt: string;
  updatedAt: string;
}

export interface LifecycleConnectionCursor {
  createdAt: string;
  id: string;
}

export interface LifecycleConnectionPage {
  items: SafeStoredConnection[];
  nextCursor?: LifecycleConnectionCursor;
}

export interface LifecyclePurgeConnection {
  id: string;
  service: string;
  credential?: ResolvedCredential;
  providerRevocationOutcome?: ProviderCredentialRevocationOutcome;
  secretDeleted: boolean;
}

interface LifecycleConnectionRow extends ConnectionRow {
  safe_metadata: Record<string, unknown>;
}

interface ConnectionRow {
  id: string;
  subject_user_id: string;
  source: "local" | "saas";
  source_reference: StoredSaasConnection["reference"] | null;
  source_status: StoredSaasConnection["status"] | null;
  source_comment: string | null;
  revision: string;
  service: string;
  connection_name: string;
  secret_ref: string;
  secret_revision: string | number;
  local_connection_id: string;
  visibility: "user" | "workspace";
  status: SaasConnectionStatus;
  created_at: Date | string;
  updated_at: Date | string;
  credential_profile: CredentialProfile | null;
}

interface TransferConnectionRow extends ConnectionRow {
  subject_user_id: string;
}

interface PendingConnectionReconciliation {
  id: string;
  service: string;
  connectionName: string;
  authType: ResolvedCredential["authType"];
  secretRef: string;
  secretRevision: number;
  cleanup: "delete_pending" | "deleted" | "delete_failed" | "preserved";
}

/** Redacted marker failure safe for logs and traces. */
export class ConnectionMetadataReconciliationError extends Error {
  readonly code = "CONNECTION_METADATA_RECONCILIATION_REQUIRED";
  readonly cleanup: PendingConnectionReconciliation["cleanup"];
  readonly markerWritten: boolean;

  constructor(cleanup: PendingConnectionReconciliation["cleanup"], markerWritten: boolean) {
    super("Connection metadata write failed after credential storage");
    this.name = "ConnectionMetadataReconciliationError";
    this.cleanup = cleanup;
    this.markerWritten = markerWritten;
  }
}

export class LifecyclePurgeClaimConflictError extends Error {
  constructor() {
    super("The exact scope is already being purged by another correlation");
    this.name = "LifecyclePurgeClaimConflictError";
  }
}

export interface LifecycleConnectionRetirement {
  localConnectionId: string;
  service: string;
  connectionName: string;
  generation: string;
}

/** Upstream connection storage bound to one immutable SaaS request scope. */
export class PostgresConnectionStore implements IConnectionStore {
  private readonly pool: Pool;
  private readonly scope: Readonly<SaasRequestScope>;
  private readonly secrets: ConnectionSecretStore;

  constructor(pool: Pool, scope: Readonly<SaasRequestScope>, secrets: ConnectionSecretStore) {
    this.pool = pool;
    this.scope = scope;
    this.secrets = secrets;
  }

  async get(service: string, connectionName: string): Promise<StoredConnection | undefined> {
    assertSaasConnectionName(connectionName);
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const row = (
        await client.query<ConnectionRow>(
          `${connectionColumns}
           WHERE tenant_id = $1 AND workspace_id = $2
             AND subject_user_id = $3 AND (visibility = 'workspace' OR subject_user_id = $6)
             AND service = $4 AND connection_name = $5 AND status = 'active'
             AND ($7::uuid IS NULL OR local_connection_id = $7) FOR SHARE`,
          [
            this.scope.tenantId,
            this.scope.workspaceId,
            this.scope.subjectUserId,
            service,
            connectionName,
            this.scope.actorUserId,
            this.scope.localConnectionId ?? null,
          ],
        )
      ).rows[0];
      return row ? await this.readStoredConnection(row) : undefined;
    });
  }

  async getById(id: string): Promise<StoredConnection | undefined> {
    if (!connectionIdSchema.safeParse(id).success) return undefined;
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const row = (
        await client.query<ConnectionRow>(
          `${connectionColumns} WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
          AND id = $4 AND status = 'active' AND (visibility = 'workspace' OR subject_user_id = $5)
          AND ($6::uuid IS NULL OR local_connection_id = $6) FOR SHARE`,
          [
            this.scope.tenantId,
            this.scope.workspaceId,
            this.scope.subjectUserId,
            id,
            this.scope.actorUserId,
            this.scope.localConnectionId ?? null,
          ],
        )
      ).rows[0];
      return row ? await this.readStoredConnection(row) : undefined;
    });
  }

  async listExactOwnedRetirementsForLifecycle(
    cursor: string | undefined,
    limit: number,
  ): Promise<{ items: LifecycleConnectionRetirement[]; nextCursor?: string }> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100)
      throw new Error("Invalid retirement lifecycle page limit");
    let after: string[] | null = null;
    if (cursor !== undefined) {
      try {
        if (cursor.length > 4096) throw new Error();
        const decoded = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as {
          scope: unknown;
          after: unknown;
        };
        if (
          JSON.stringify(decoded.scope) !==
            JSON.stringify([this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId]) ||
          !Array.isArray(decoded.after) ||
          decoded.after.length !== 3 ||
          decoded.after.some((value) => typeof value !== "string")
        )
          throw new Error();
        after = decoded.after;
      } catch {
        throw new Error("Invalid retirement lifecycle cursor");
      }
    }
    return withScopedClient(this.pool, this.scope, async (client) => {
      const rows = (
        await client.query<LifecycleConnectionRetirement>(
          `SELECT local_connection_id AS "localConnectionId",service,connection_name AS "connectionName",generation
        FROM integration_runtime.connection_retirements WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3
          AND ($4::uuid IS NULL OR (local_connection_id,service,connection_name)>($4::uuid,$5::text,$6::text))
        ORDER BY local_connection_id,service,connection_name LIMIT $7`,
          [
            this.scope.tenantId,
            this.scope.workspaceId,
            this.scope.subjectUserId,
            ...(after ?? [null, null, null]),
            limit + 1,
          ],
        )
      ).rows;
      const items = rows.slice(0, limit);
      const last = items.at(-1);
      return {
        items,
        nextCursor:
          rows.length > limit && last
            ? Buffer.from(
                JSON.stringify({
                  scope: [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId],
                  after: [last.localConnectionId, last.service, last.connectionName],
                }),
              ).toString("base64url")
            : undefined,
      };
    });
  }
  async countExactOwnedRetirementsForLifecycle(): Promise<number> {
    return withScopedClient(this.pool, this.scope, async (client) =>
      Number(
        (
          await client.query<{ count: string }>(
            `SELECT count(*) FROM integration_runtime.connection_retirements
      WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3`,
            [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId],
          )
        ).rows[0]?.count ?? 0,
      ),
    );
  }
  async purgeExactOwnedRetirementsForLifecycle(): Promise<number> {
    return withScopedClient(this.pool, this.scope, async (client) => {
      const values = [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId];
      const remaining = await client.query(
        `SELECT 1 FROM (
        SELECT tenant_id,workspace_id,subject_user_id FROM integration_runtime.connections
        UNION ALL SELECT tenant_id,workspace_id,subject_user_id FROM integration_runtime.oauth_states
        UNION ALL SELECT tenant_id,workspace_id,subject_user_id FROM integration_runtime.connection_requests
      ) r WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 LIMIT 1`,
        values,
      );
      if (remaining.rowCount)
        throw new Error("Connections, OAuth states and requests must be drained before retirement markers");
      return (
        (
          await client.query(
            `DELETE FROM integration_runtime.connection_retirements
        WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3`,
            values,
          )
        ).rowCount ?? 0
      );
    });
  }

  async getRetirementGeneration(service: string, connectionName: string): Promise<string> {
    assertSaasConnectionName(connectionName);
    const generation = await withScopedClient(this.pool, this.scope, (client) =>
      this.lockGeneration(client, service, connectionName),
    );
    if (!generation) throw new ConnectionError("connection_not_found", "Connection lineage ownership changed.");
    return generation;
  }

  private async lockGeneration(
    client: PoolClient,
    service: string,
    connectionName: string,
  ): Promise<string | undefined> {
    const localId = this.requiredLocalConnectionId();
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
      JSON.stringify([this.scope.tenantId, this.scope.workspaceId, localId]),
    ]);
    await client.query(
      `INSERT INTO integration_runtime.connection_retirements
         (tenant_id,workspace_id,local_connection_id,service,connection_name,generation,subject_user_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id,workspace_id,local_connection_id,service,connection_name) DO NOTHING`,
      [
        this.scope.tenantId,
        this.scope.workspaceId,
        localId,
        service,
        connectionName,
        randomUUID(),
        this.scope.subjectUserId,
      ],
    );
    const row = (
      await client.query<{ generation: string }>(
        `SELECT generation FROM integration_runtime.connection_retirements
      WHERE tenant_id=$1 AND workspace_id=$2 AND local_connection_id=$3 AND service=$4 AND connection_name=$5 AND subject_user_id=$6 FOR UPDATE`,
        [this.scope.tenantId, this.scope.workspaceId, localId, service, connectionName, this.scope.subjectUserId],
      )
    ).rows[0];
    return row?.generation;
  }

  async setIfCurrentGeneration(
    service: string,
    connectionName: string,
    credential: ResolvedCredential,
    retirementGeneration: string,
  ): Promise<StoredLocalConnection | undefined> {
    return this.writeConnection(service, connectionName, credential, retirementGeneration);
  }

  async completeOAuthRequest(
    pending: PendingConnectionRequest,
    credential: ResolvedCredential,
  ): Promise<string | undefined> {
    const result = await this.writeConnection(
      pending.service,
      pending.connectionName,
      credential,
      pending.retirementGeneration,
      pending,
    );
    return result?.id;
  }

  async listSafeConnections(): Promise<SafeStoredConnection[]> {
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const rows = (
        await client.query<ConnectionRow>(
          `${safeConnectionColumns}
           WHERE tenant_id = $1 AND workspace_id = $2
             AND (visibility = 'workspace' OR subject_user_id = $3)
             AND status = 'active'
           ORDER BY service, connection_name`,
          [this.scope.tenantId, this.scope.workspaceId, this.scope.actorUserId],
        )
      ).rows;
      return rows.map(toSafeStoredConnection);
    });
  }

  async listExactOwnedForLifecycle(
    cursor: LifecycleConnectionCursor | undefined,
    limit: number,
  ): Promise<LifecycleConnectionPage> {
    if (!Number.isSafeInteger(limit) || limit <= 0 || limit > 100) throw new Error("Invalid lifecycle page limit");
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const values: unknown[] = [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId];
      const after = cursor ? `AND (created_at > $4 OR (created_at = $4 AND id > $5::uuid))` : "";
      if (cursor) values.push(cursor.createdAt, cursor.id);
      values.push(limit + 1);
      const rows = (
        await client.query<ConnectionRow>(
          `${safeConnectionColumns}
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
             ${after}
           ORDER BY created_at, id
           LIMIT $${values.length}`,
          values,
        )
      ).rows;
      const items = rows.slice(0, limit).map(toSafeStoredConnection);
      const last = items[items.length - 1];
      return {
        items,
        ...(rows.length > limit && last ? { nextCursor: { createdAt: last.createdAt, id: last.id } } : {}),
      };
    });
  }

  async prepareExactOwnedForLifecyclePurge(correlationId: string): Promise<LifecyclePurgeConnection[]> {
    await withScopedClient(this.pool, this.scope, async (client) => {
      const conflict = await client.query(
        `SELECT 1 FROM integration_runtime.connections
         WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
           AND safe_metadata ? 'lifecyclePurgeCorrelationId'
           AND safe_metadata->>'lifecyclePurgeCorrelationId' <> $4
         LIMIT 1
         FOR UPDATE`,
        [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, correlationId],
      );
      if (conflict.rowCount) throw new LifecyclePurgeClaimConflictError();
      await client.query(
        `UPDATE integration_runtime.connections
         SET status = CASE WHEN status = 'active' THEN 'reconnect_required' ELSE status END,
             safe_metadata = safe_metadata || jsonb_build_object(
               'reconciliation', 'lifecycle_purge_pending',
               'lifecyclePurgeCorrelationId', $4::text
             ),
             updated_at = now()
         WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3`,
        [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, correlationId],
      );
    });

    const connections: LifecyclePurgeConnection[] = [];
    let cursor: string | undefined;
    do {
      const rows = await withScopedClient(this.pool, this.scope, async (client) => {
        const values: unknown[] = [
          this.scope.tenantId,
          this.scope.workspaceId,
          this.scope.subjectUserId,
          correlationId,
        ];
        const after = cursor ? "AND id > $5::uuid" : "";
        if (cursor) values.push(cursor);
        values.push(100);
        return (
          await client.query<LifecycleConnectionRow>(
            `SELECT ${connectionColumnNames}, local_connection_id, visibility, status, created_at, updated_at,
                    safe_metadata
             FROM integration_runtime.connections
             WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
               AND safe_metadata->>'lifecyclePurgeCorrelationId' = $4 ${after}
             ORDER BY id
             LIMIT $${values.length}`,
            values,
          )
        ).rows;
      });
      connections.push(
        ...(await Promise.all(
          rows.map(async (row): Promise<LifecyclePurgeConnection> => {
            const secretRevision = Number(row.secret_revision);
            const secret = secretRevision > 0 ? await this.secrets.read(this.scope, row.id, secretRevision) : undefined;
            const providerRevocationOutcome = row.safe_metadata.lifecycleProviderRevocationOutcome;
            return {
              id: row.id,
              service: row.service,
              ...(secret && secret.provider === row.service && secret.revision === secretRevision
                ? { credential: mergeCredential(secret, row.credential_profile) }
                : {}),
              providerRevocationOutcome:
                providerRevocationOutcome === "revoked" ||
                providerRevocationOutcome === "unsupported" ||
                providerRevocationOutcome === "failed"
                  ? providerRevocationOutcome
                  : undefined,
              secretDeleted: row.safe_metadata.lifecycleSecretDeleted === true,
            };
          }),
        )),
      );
      cursor = rows.length === 100 ? rows[rows.length - 1]!.id : undefined;
    } while (cursor);
    return connections;
  }

  async markExactOwnedLifecycleProviderRevocation(
    connectionId: string,
    correlationId: string,
    outcome: ProviderCredentialRevocationOutcome,
  ): Promise<void> {
    await withScopedClient(this.pool, this.scope, async (client) => {
      const result = await client.query(
        `UPDATE integration_runtime.connections
         SET safe_metadata = jsonb_set(
               safe_metadata,
               '{lifecycleProviderRevocationOutcome}',
               to_jsonb($6::text),
               true
             ),
             updated_at = now()
         WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3 AND id = $4
           AND safe_metadata->>'lifecyclePurgeCorrelationId' = $5`,
        [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, connectionId, correlationId, outcome],
      );
      if (result.rowCount !== 1) throw new LifecyclePurgeClaimConflictError();
    });
  }

  async deleteExactOwnedLifecycleSecret(connectionId: string, correlationId: string): Promise<void> {
    const owned = await withScopedClient(this.pool, this.scope, async (client) => {
      return (
        (
          await client.query(
            `SELECT 1 FROM integration_runtime.connections
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3 AND id = $4
             AND safe_metadata->>'lifecyclePurgeCorrelationId' = $5`,
            [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, connectionId, correlationId],
          )
        ).rowCount === 1
      );
    });
    if (!owned) throw new LifecyclePurgeClaimConflictError();
    await this.secrets.delete(this.scope, connectionId);
    await this.markLifecycleProgress(connectionId, correlationId, "lifecycleSecretDeleted");
  }

  async getSafeConnection(connectionId: string): Promise<SafeStoredConnection | undefined> {
    if (!connectionIdSchema.safeParse(connectionId).success) return undefined;
    const localConnectionId = this.requiredLocalConnectionId();
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const row = (
        await client.query<ConnectionRow>(
          `${safeConnectionColumns}
           WHERE tenant_id = $1 AND workspace_id = $2
             AND subject_user_id = $3 AND (visibility = 'workspace' OR subject_user_id = $6)
             AND id = $4 AND local_connection_id = $5 AND status = 'active'`,
          [
            this.scope.tenantId,
            this.scope.workspaceId,
            this.scope.subjectUserId,
            connectionId,
            localConnectionId,
            this.scope.actorUserId,
          ],
        )
      ).rows[0];
      return row ? toSafeStoredConnection(row) : undefined;
    });
  }
  async getCredentialReplacementTarget(connectionId: string): Promise<StoredConnection | undefined> {
    const localConnectionId = this.requiredLocalConnectionId();
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const row = (
        await client.query<ConnectionRow>(
          `${connectionColumns}
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
             AND id = $4 AND local_connection_id = $5
             AND auth_type IN ('api_key', 'custom_credential')
             AND status IN ('active', 'expired', 'failed', 'reconnect_required')`,
          [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, connectionId, localConnectionId],
        )
      ).rows[0];
      return row ? await this.readStoredConnection(row) : undefined;
    });
  }

  async set(service: string, connectionName: string, credential: ResolvedCredential): Promise<StoredLocalConnection> {
    const result = await this.writeConnection(service, connectionName, credential);
    if (!result) throw new ConnectionError("connection_changed", "The connection changed.");
    return result;
  }

  private async writeConnection(
    service: string,
    connectionName: string,
    credential: ResolvedCredential,
    generation?: string,
    pending?: PendingConnectionRequest,
  ): Promise<StoredLocalConnection | undefined> {
    assertSaasConnectionName(connectionName);
    const localConnectionId = this.requiredLocalConnectionId();
    const outcome: { reconciliation?: PendingConnectionReconciliation } = {};
    try {
      return await withScopedClient(this.pool, this.scope, async (client) => {
        assertProcessingActive(this.scope);
        const currentGeneration = await this.lockGeneration(client, service, connectionName);
        if (currentGeneration === undefined || (generation !== undefined && generation !== currentGeneration))
          return undefined;
        if (pending) {
          const request = await client.query(
            `SELECT 1 FROM integration_runtime.connection_requests WHERE tenant_id=$1 AND workspace_id=$2
              AND subject_user_id=$3 AND local_connection_id=$4 AND id=$5 AND oauth_session_id=$6
              AND phase='processing' AND status='initiated' AND expires_at>now() FOR UPDATE`,
            [
              this.scope.tenantId,
              this.scope.workspaceId,
              this.scope.subjectUserId,
              localConnectionId,
              pending.connectionRequestId,
              this.scope.oauthSessionId,
            ],
          );
          if (request.rowCount !== 1) return undefined;
        }
        const existing = (
          await client.query<ConnectionRow>(
            `${connectionColumns}
             WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
               AND service = $4 AND connection_name = $5 AND local_connection_id = $6
             FOR UPDATE`,
            [
              this.scope.tenantId,
              this.scope.workspaceId,
              this.scope.subjectUserId,
              service,
              connectionName,
              localConnectionId,
            ],
          )
        ).rows[0];
        if (existing && (existing.source === "saas" || existing.status !== "active")) return undefined;
        if (
          pending?.target &&
          (!existing || existing.id !== pending.target.id || existing.revision !== pending.target.revision)
        )
          return undefined;
        if (pending && !pending.target && existing) return undefined;
        const id = existing?.id ?? randomUUID();
        const revision = randomUUID();
        const profile = profileOf(credential);
        const metadata = {};

        if (existing) {
          outcome.reconciliation = {
            id,
            service,
            connectionName,
            authType: credential.authType,
            secretRef: existing.secret_ref,
            secretRevision: Number(existing.secret_revision) + 1,
            cleanup: "preserved",
          };
          const secretRevision = await this.secrets.update(
            this.scope,
            id,
            service,
            Number(existing.secret_revision),
            credential,
          );
          if (secretRevision === false) throw new Error("Connection credential changed concurrently");
          outcome.reconciliation = {
            id,
            service,
            connectionName,
            authType: credential.authType,
            secretRef: existing.secret_ref,
            secretRevision,
            cleanup: "preserved",
          };
          try {
            await client.query(
              `UPDATE integration_runtime.connections
               SET revision = $6, auth_type = $7, secret_revision = $8,
                   credential_profile = $9, auth_metadata = $10, display_name = $11,
                   provider_account_id = $12, granted_scopes = $13, status = 'active'
               WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
                 AND service = $4 AND connection_name = $5 AND local_connection_id = $14`,
              [
                this.scope.tenantId,
                this.scope.workspaceId,
                this.scope.subjectUserId,
                service,
                connectionName,
                revision,
                credential.authType,
                secretRevision,
                profile ?? null,
                metadata,
                profile?.displayName ?? null,
                verifiedAccountId(credential),
                JSON.stringify(profile?.grantedScopes ?? []),
                localConnectionId,
              ],
            );
          } catch {
            outcome.reconciliation = {
              id,
              service,
              connectionName,
              authType: credential.authType,
              secretRef: existing.secret_ref,
              secretRevision,
              cleanup: "preserved",
            };
            throw new ConnectionMetadataReconciliationError("preserved", false);
          }
        } else {
          let secret: { secretRef: string; secretRevision: number };
          try {
            secret = await this.secrets.create(this.scope, id, service, credential);
          } catch (error) {
            if (error instanceof OpenBaoError && error.code !== "OPENBAO_CONFLICT")
              outcome.reconciliation = {
                id,
                service,
                connectionName,
                authType: credential.authType,
                secretRef: error.path,
                secretRevision: 1,
                cleanup: "delete_pending",
              };
            throw error;
          }
          outcome.reconciliation = {
            id,
            service,
            connectionName,
            authType: credential.authType,
            secretRef: secret.secretRef,
            secretRevision: secret.secretRevision,
            cleanup: "delete_pending",
          };
          try {
            await client.query(
              `INSERT INTO integration_runtime.connections (
                 id, tenant_id, workspace_id, subject_user_id, local_connection_id, visibility,
                 service, connection_name, auth_type, revision, secret_ref, secret_revision,
                 status, credential_profile, auth_metadata, display_name, provider_account_id,
                 granted_scopes
               ) VALUES ($1, $2, $3, $4, $5, 'user', $6, $7, $8, $9, $10, $11, 'active', $12, $13, $14, $15, $16)`,
              [
                id,
                this.scope.tenantId,
                this.scope.workspaceId,
                this.scope.subjectUserId,
                localConnectionId,
                service,
                connectionName,
                credential.authType,
                revision,
                secret.secretRef,
                secret.secretRevision,
                profile ?? null,
                metadata,
                profile?.displayName ?? null,
                verifiedAccountId(credential),
                JSON.stringify(profile?.grantedScopes ?? []),
              ],
            );
          } catch {
            outcome.reconciliation = {
              id,
              service,
              connectionName,
              authType: credential.authType,
              secretRef: secret.secretRef,
              secretRevision: secret.secretRevision,
              cleanup: "delete_pending",
            };
            throw new ConnectionMetadataReconciliationError("delete_pending", false);
          }
        }

        if (pending) {
          const completed = await client.query(
            `UPDATE integration_runtime.connection_requests SET phase='completed',status='connected',app_id=$6,updated_at=now()
             WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND local_connection_id=$4
               AND id=$5 AND phase='processing'`,
            [
              this.scope.tenantId,
              this.scope.workspaceId,
              this.scope.subjectUserId,
              localConnectionId,
              pending.connectionRequestId,
              id,
            ],
          );
          if (completed.rowCount !== 1) throw new Error("OAuth request completion lost its claim");
        }
        return { id, revision, service, connectionName, credential };
      });
    } catch (error) {
      const reconciliation = outcome.reconciliation;
      if (reconciliation === undefined) throw error;
      throw await withSecretCleanup(this.scope, async (cleanupScope) => {
        if (reconciliation.cleanup === "delete_pending") {
          try {
            await this.secrets.delete(cleanupScope, reconciliation.id);
            reconciliation.cleanup = "deleted";
          } catch {
            reconciliation.cleanup = "delete_failed";
          }
        }
        const markerWritten = await this.writeReconciliationMarker(reconciliation);
        return new ConnectionMetadataReconciliationError(reconciliation.cleanup, markerWritten);
      });
    }
  }

  async updateCredential(input: StoredLocalConnection, refresh = false): Promise<boolean> {
    assertSaasConnectionName(input.connectionName);
    if (refresh && input.credential.authType !== "oauth2") return false;
    const localConnectionId = this.requiredLocalConnectionId();
    const outcome: { reconciliation?: PendingConnectionReconciliation } = {};
    try {
      return await withScopedClient(this.pool, this.scope, async (client) => {
        assertProcessingActive(this.scope);
        if ((await this.lockGeneration(client, input.service, input.connectionName)) === undefined) return false;
        const existing = (
          await client.query<ConnectionRow>(
            `${connectionColumns}
             WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
               AND id = $4 AND revision = $5 AND service = $6 AND connection_name = $7
               AND local_connection_id = $8 AND (NOT $9::boolean OR auth_type='oauth2')
               AND (visibility='workspace' OR subject_user_id=$10)
               AND source = 'local'
               AND ${refresh ? "status = 'active'" : "status IN ('active', 'expired', 'failed', 'reconnect_required')"}
               AND NOT safe_metadata ? 'lifecyclePurgeCorrelationId'
               AND NOT safe_metadata ? 'reconciliation'
             FOR UPDATE`,
            [
              this.scope.tenantId,
              this.scope.workspaceId,
              this.scope.subjectUserId,
              input.id,
              input.revision,
              input.service,
              input.connectionName,
              localConnectionId,
              refresh,
              this.scope.actorUserId,
            ],
          )
        ).rows[0];
        if (!existing) return false;

        outcome.reconciliation = {
          id: input.id,
          service: input.service,
          connectionName: input.connectionName,
          authType: input.credential.authType,
          secretRef: existing.secret_ref,
          secretRevision: Number(existing.secret_revision) + 1,
          cleanup: "preserved",
        };
        const secretRevision = await this.secrets.update(
          this.scope,
          input.id,
          input.service,
          Number(existing.secret_revision),
          input.credential,
        );
        if (secretRevision === false) return false;
        outcome.reconciliation = {
          id: input.id,
          service: input.service,
          connectionName: input.connectionName,
          authType: input.credential.authType,
          secretRef: existing.secret_ref,
          secretRevision,
          cleanup: "preserved",
        };
        const profile = profileOf(input.credential);
        try {
          const result = await client.query(
            `UPDATE integration_runtime.connections
             SET revision = $10, secret_revision = $11, auth_type=$9,
                 credential_profile = $12, auth_metadata = $13, display_name = $14,
                 provider_account_id = $15, granted_scopes = $16, status = 'active',
                 revoked_at = NULL, updated_at = now()
             WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
               AND id = $4 AND revision = $5 AND service = $6 AND connection_name = $7
               AND local_connection_id = $8 AND (NOT $17::boolean OR auth_type='oauth2')
               AND (visibility='workspace' OR subject_user_id=$18)
               AND source = 'local'
               AND ${refresh ? "status = 'active'" : "status IN ('active', 'expired', 'failed', 'reconnect_required')"}
               AND NOT safe_metadata ? 'lifecyclePurgeCorrelationId'`,
            [
              this.scope.tenantId,
              this.scope.workspaceId,
              this.scope.subjectUserId,
              input.id,
              input.revision,
              input.service,
              input.connectionName,
              localConnectionId,
              input.credential.authType,
              randomUUID(),
              secretRevision,
              profile ?? null,
              {},
              profile?.displayName ?? null,
              verifiedAccountId(input.credential),
              JSON.stringify(profile?.grantedScopes ?? []),
              refresh,
              this.scope.actorUserId,
            ],
          );
          if (result.rowCount !== 1) throw new Error("Connection metadata update lost its scope");
          return true;
        } catch {
          outcome.reconciliation = {
            id: input.id,
            service: input.service,
            connectionName: input.connectionName,
            authType: input.credential.authType,
            secretRef: existing.secret_ref,
            secretRevision,
            cleanup: "preserved",
          };
          throw new ConnectionMetadataReconciliationError("preserved", false);
        }
      });
    } catch (error) {
      const reconciliation = outcome.reconciliation;
      if (reconciliation === undefined) throw error;
      const markerWritten = await this.writeReconciliationMarker(reconciliation);
      throw new ConnectionMetadataReconciliationError(reconciliation.cleanup, markerWritten);
    }
  }

  async delete(
    service: string,
    connectionName: string,
    target?: Pick<StoredConnection, "id" | "revision">,
  ): Promise<void> {
    assertSaasConnectionName(connectionName);
    const id = await withScopedClient(this.pool, this.scope, async (client) => {
      await this.lockGeneration(client, service, connectionName);
      const current = (
        await client.query<ConnectionRow>(
          `${connectionColumns}
        WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND local_connection_id=$4
          AND service=$5 AND connection_name=$6 FOR UPDATE`,
          [
            this.scope.tenantId,
            this.scope.workspaceId,
            this.scope.subjectUserId,
            this.requiredLocalConnectionId(),
            service,
            connectionName,
          ],
        )
      ).rows[0];
      if (target && (!current || current.id !== target.id || current.revision !== target.revision))
        throw new ConnectionError("connection_changed", "The connection changed.");
      await client.query(
        `UPDATE integration_runtime.connection_retirements SET generation=$6
        WHERE tenant_id=$1 AND workspace_id=$2 AND local_connection_id=$3 AND service=$4 AND connection_name=$5`,
        [
          this.scope.tenantId,
          this.scope.workspaceId,
          this.requiredLocalConnectionId(),
          service,
          connectionName,
          randomUUID(),
        ],
      );
      if (current) await queueSaasConnectionCleanup(client, this.scope, current.id);
      const row = (
        await client.query<{ id: string }>(
          `UPDATE integration_runtime.connections
           SET status = 'revoked', revoked_at = now(),
               safe_metadata = '{"reconciliation":"secret_delete_pending"}'::jsonb,
               updated_at = now()
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
             AND service = $4 AND connection_name = $5 AND local_connection_id=$6
           RETURNING id`,
          [
            this.scope.tenantId,
            this.scope.workspaceId,
            this.scope.subjectUserId,
            service,
            connectionName,
            this.requiredLocalConnectionId(),
          ],
        )
      ).rows[0];
      return row?.id;
    });
    if (!id) return;

    await withSecretCleanup(this.scope, async (cleanupScope) => {
      try {
        await this.secrets.delete(cleanupScope, id);
      } catch (error) {
        await withScopedClient(this.pool, cleanupScope, async (client) => {
          await client.query(
            `UPDATE integration_runtime.connections SET safe_metadata='{"reconciliation":"secret_delete_failed"}'::jsonb,updated_at=now()
            WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$4`,
            [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, id],
          );
        });
        throw error;
      }
      await withScopedClient(this.pool, cleanupScope, async (client) => {
        await client.query(
          `DELETE FROM integration_runtime.connections WHERE tenant_id=$1 AND workspace_id=$2
          AND subject_user_id=$3 AND id=$4 AND status='revoked'`,
          [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, id],
        );
      });
    });
  }
  async transferById(connectionId: string, targetSubjectUserId: string): Promise<SafeStoredConnection | undefined> {
    const localConnectionId = this.requiredLocalConnectionId();
    if (this.scope.workspaceRole !== "owner" && this.scope.workspaceRole !== "admin") {
      throw new Error("Workspace ownership transfer requires an owner or admin");
    }
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const existing = (
        await client.query<TransferConnectionRow>(
          `SELECT ${safeConnectionColumnNames}, subject_user_id
           FROM integration_runtime.connections
           WHERE tenant_id = $1 AND workspace_id = $2 AND id = $3
             AND local_connection_id = $4 AND visibility = 'workspace' AND status = 'active'
           FOR UPDATE`,
          [this.scope.tenantId, this.scope.workspaceId, connectionId, localConnectionId],
        )
      ).rows[0];
      if (!existing) return undefined;
      if (existing.subject_user_id === targetSubjectUserId) return toSafeStoredConnection(existing);
      if (existing.subject_user_id !== this.scope.subjectUserId) return undefined;

      await client.query(
        `DELETE FROM integration_runtime.refresh_leases
         WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
           AND connection_id = $4`,
        [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, connectionId],
      );
      const transferred = (
        await client.query<ConnectionRow>(
          `UPDATE integration_runtime.connections
           SET subject_user_id = $5, revision = gen_random_uuid()::text, updated_at = now()
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
             AND id = $4 AND local_connection_id = $6
             AND visibility = 'workspace' AND status = 'active'
           RETURNING ${safeConnectionColumnNames}`,
          [
            this.scope.tenantId,
            this.scope.workspaceId,
            this.scope.subjectUserId,
            connectionId,
            targetSubjectUserId,
            localConnectionId,
          ],
        )
      ).rows[0];
      return transferred ? toSafeStoredConnection(transferred) : undefined;
    });
  }
  async updateVisibilityById(
    connectionId: string,
    visibility: SafeStoredConnection["visibility"],
  ): Promise<SafeStoredConnection | undefined> {
    const localConnectionId = this.requiredLocalConnectionId();
    if (this.scope.workspaceRole !== "owner" && this.scope.workspaceRole !== "admin") {
      throw new Error("Connection visibility changes require an owner or admin");
    }
    return await withScopedClient(this.pool, this.scope, async (client) => {
      await client.query(
        `DELETE FROM integration_runtime.refresh_leases WHERE tenant_id=$1 AND workspace_id=$2
        AND subject_user_id=$3 AND connection_id=$4`,
        [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, connectionId],
      );
      const row = (
        await client.query<ConnectionRow>(
          `UPDATE integration_runtime.connections
           SET visibility = $6,
               revision = CASE WHEN visibility = $6 THEN revision ELSE gen_random_uuid()::text END,
               updated_at = CASE WHEN visibility = $6 THEN updated_at ELSE now() END
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
             AND id = $4 AND local_connection_id = $5 AND status = 'active'
           RETURNING ${safeConnectionColumnNames}`,
          [
            this.scope.tenantId,
            this.scope.workspaceId,
            this.scope.subjectUserId,
            connectionId,
            localConnectionId,
            visibility,
          ],
        )
      ).rows[0];
      return row ? toSafeStoredConnection(row) : undefined;
    });
  }

  async blockForRevocation(connectionId: string): Promise<StoredConnection | undefined> {
    if (!connectionIdSchema.safeParse(connectionId).success) return undefined;
    const localConnectionId = this.requiredLocalConnectionId();
    const row = await withScopedClient(this.pool, this.scope, async (client) => {
      return (
        await client.query<ConnectionRow>(
          `UPDATE integration_runtime.connections
           SET status = 'reconnect_required',
               safe_metadata = '{"reconciliation":"provider_revocation_pending"}'::jsonb,
               updated_at = now()
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
             AND id = $4 AND local_connection_id = $5
             AND status IN ('active', 'reconnect_required')
           RETURNING ${connectionColumnNames}`,
          [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, connectionId, localConnectionId],
        )
      ).rows[0];
    });
    return row ? await this.readStoredConnection(row) : undefined;
  }
  async hasRevocationReceipt(connectionId: string): Promise<boolean> {
    if (!connectionIdSchema.safeParse(connectionId).success) return false;
    const localConnectionId = this.requiredLocalConnectionId();
    return await withScopedClient(this.pool, this.scope, async (client) => {
      return (
        (
          await client.query(
            `SELECT 1 FROM integration_runtime.connection_revocation_receipts
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
             AND local_connection_id = $4 AND connector_connection_id = $5`,
            [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, localConnectionId, connectionId],
          )
        ).rowCount === 1
      );
    });
  }

  async resumeRevocation(connectionId: string): Promise<boolean> {
    if (!connectionIdSchema.safeParse(connectionId).success) return false;
    const localConnectionId = this.requiredLocalConnectionId();
    const pending = await withScopedClient(this.pool, this.scope, async (client) => {
      return (
        await client.query<Pick<ConnectionRow, "id" | "source"> & { outcome: string }>(
          `SELECT id, source, safe_metadata->>'providerRevocationOutcome' AS outcome
           FROM integration_runtime.connections
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
             AND id = $4 AND local_connection_id = $5 AND status = 'revoked'`,
          [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, connectionId, localConnectionId],
        )
      ).rows[0];
    });
    if (!pending) return false;
    if (pending.outcome !== "revoked" && pending.outcome !== "unsupported") {
      throw new Error("Connection revocation outcome is invalid");
    }
    return await this.finalizeRevocation(pending, localConnectionId, pending.outcome);
  }

  async deleteById(
    connectionId: string,
    outcome: Exclude<ProviderCredentialRevocationOutcome, "failed">,
  ): Promise<boolean> {
    const localConnectionId = this.requiredLocalConnectionId();
    const pending = await withScopedClient(this.pool, this.scope, async (client) => {
      const row = (
        await client.query<Pick<ConnectionRow, "id" | "source">>(
          `UPDATE integration_runtime.connections
           SET status = 'revoked', revoked_at = now(),
               safe_metadata = jsonb_build_object(
                 'reconciliation', 'secret_delete_pending',
                 'providerRevocationOutcome', $6::text
               ),
               updated_at = now()
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
             AND id = $4 AND local_connection_id = $5 AND status = 'reconnect_required'
           RETURNING id, source`,
          [
            this.scope.tenantId,
            this.scope.workspaceId,
            this.scope.subjectUserId,
            connectionId,
            localConnectionId,
            outcome,
          ],
        )
      ).rows[0];
      return row;
    });
    if (!pending) return await this.hasRevocationReceipt(connectionId);
    return await this.finalizeRevocation(pending, localConnectionId, outcome);
  }

  private async finalizeRevocation(
    connection: Pick<ConnectionRow, "id" | "source">,
    localConnectionId: string,
    outcome: Exclude<ProviderCredentialRevocationOutcome, "failed">,
  ): Promise<boolean> {
    const connectionId = connection.id;
    return await withSecretCleanup(this.scope, async (cleanupScope) => {
      if (connection.source === "local") {
        try {
          await this.secrets.delete(cleanupScope, connectionId);
        } catch (error) {
          await withScopedClient(this.pool, cleanupScope, async (client) => {
            await client.query(
              `UPDATE integration_runtime.connections
           SET safe_metadata = safe_metadata || '{"reconciliation":"secret_delete_failed"}'::jsonb,
               updated_at = now()
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
             AND id = $4 AND local_connection_id = $5 AND status = 'revoked'`,
              [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, connectionId, localConnectionId],
            );
          });
          throw error;
        }
      }

      await withScopedClient(this.pool, cleanupScope, async (client) => {
        const parameters = [
          this.scope.tenantId,
          this.scope.workspaceId,
          this.scope.subjectUserId,
          connectionId,
          localConnectionId,
        ];
        const deleted = await client.query(
          `DELETE FROM integration_runtime.connections
         WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
           AND id = $4 AND local_connection_id = $5 AND status = 'revoked'`,
          parameters,
        );
        if (deleted.rowCount !== 1) {
          const receipt = await client.query(
            `SELECT 1 FROM integration_runtime.connection_revocation_receipts
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
             AND connector_connection_id = $4 AND local_connection_id = $5`,
            parameters,
          );
          if (receipt.rowCount === 1) return;
          throw new Error("Connection revocation state changed during cleanup");
        }
        await client.query(
          `INSERT INTO integration_runtime.connection_revocation_receipts
           (tenant_id, workspace_id, subject_user_id, connector_connection_id, local_connection_id, outcome)
         VALUES ($1, $2, $3, $4, $5, $6)`,
          [...parameters, outcome],
        );
      });
      return true;
    });
  }

  async list(): Promise<StoredConnection[]> {
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const rows = (
        await client.query<ConnectionRow>(
          `${connectionColumns}
           WHERE tenant_id = $1 AND workspace_id = $2
             AND subject_user_id = $3 AND (visibility = 'workspace' OR subject_user_id = $5)
             AND ($4::uuid IS NULL OR local_connection_id = $4)
             AND connection_name <> 'default' AND status = 'active'
           ORDER BY service, connection_name FOR SHARE`,
          [
            this.scope.tenantId,
            this.scope.workspaceId,
            this.scope.subjectUserId,
            this.scope.localConnectionId ?? null,
            this.scope.actorUserId,
          ],
        )
      ).rows;
      const stored = await Promise.all(rows.map((row) => this.readStoredConnection(row)));
      return stored.filter((connection): connection is StoredConnection => connection !== undefined);
    });
  }

  private async markLifecycleProgress(
    connectionId: string,
    correlationId: string,
    key: "lifecycleSecretDeleted",
  ): Promise<void> {
    await withScopedClient(this.pool, this.scope, async (client) => {
      const result = await client.query(
        `UPDATE integration_runtime.connections
         SET safe_metadata = jsonb_set(safe_metadata, ARRAY[$6::text], 'true'::jsonb, true), updated_at = now()
         WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3 AND id = $4
           AND safe_metadata->>'lifecyclePurgeCorrelationId' = $5`,
        [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, connectionId, correlationId, key],
      );
      if (result.rowCount !== 1) throw new LifecyclePurgeClaimConflictError();
    });
  }

  private async writeReconciliationMarker(marker: PendingConnectionReconciliation): Promise<boolean> {
    if (marker.cleanup === "preserved") {
      try {
        await withSecretCleanup(this.scope, (cleanupScope) =>
          withScopedClient(this.pool, cleanupScope, async (client) => {
            await client.query(
              `UPDATE integration_runtime.connections
             SET safe_metadata = $5, updated_at = now()
             WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3 AND id = $4`,
              [
                this.scope.tenantId,
                this.scope.workspaceId,
                this.scope.subjectUserId,
                marker.id,
                { reconciliation: "orphan_secret_version", orphanSecretRevision: marker.secretRevision },
              ],
            );
          }),
        );
        return true;
      } catch {
        return false;
      }
    }
    return await this.writeFailedReconciliationMarker(marker);
  }

  private async writeFailedReconciliationMarker(marker: PendingConnectionReconciliation): Promise<boolean> {
    try {
      await withSecretCleanup(this.scope, (cleanupScope) =>
        withScopedClient(this.pool, cleanupScope, async (client) => {
          await client.query(
            `INSERT INTO integration_runtime.connections (
             id, tenant_id, workspace_id, subject_user_id, local_connection_id, visibility,
             service, connection_name, auth_type, revision, secret_ref, secret_revision, status,
             safe_metadata
           ) VALUES ($1, $2, $3, $4, $5, 'user', $6, $7, $8, $9, $10, $11, 'failed', $12)
           ON CONFLICT (id) DO UPDATE
           SET status = 'failed', secret_ref = EXCLUDED.secret_ref,
               secret_revision = EXCLUDED.secret_revision, safe_metadata = EXCLUDED.safe_metadata,
               updated_at = now()`,
            [
              marker.id,
              this.scope.tenantId,
              this.scope.workspaceId,
              this.scope.subjectUserId,
              this.requiredLocalConnectionId(),
              marker.service,
              marker.id,
              marker.authType,
              randomUUID(),
              marker.secretRef,
              marker.secretRevision,
              {
                reconciliation: "metadata_write_failed",
                requestedConnectionName: marker.connectionName,
                secretCleanup: marker.cleanup,
              },
            ],
          );
        }),
      );
      return true;
    } catch {
      return false;
    }
  }

  private async readStoredConnection(row: ConnectionRow): Promise<StoredConnection | undefined> {
    if (row.source === "saas") {
      if (!row.source_reference || !row.credential_profile || !row.source_status) return undefined;
      return {
        source: "saas",
        id: row.id,
        revision: row.revision,
        service: row.service,
        connectionName: row.connection_name,
        reference: row.source_reference,
        profile: row.credential_profile,
        status: row.source_status,
        comment: row.source_comment,
      };
    }
    assertProcessingActive(this.scope);
    const secret = await this.secrets.read(this.scope, row.id, Number(row.secret_revision));
    if (!secret || secret.provider !== row.service || secret.revision !== Number(row.secret_revision)) return undefined;
    return {
      id: row.id,
      revision: row.revision,
      service: row.service,
      connectionName: row.connection_name,
      credential: mergeCredential(secret, row.credential_profile),
      credentialCacheOwner: {
        tenantId: this.scope.tenantId,
        workspaceId: this.scope.workspaceId,
        credentialOwnerId: row.subject_user_id,
        connectionId: row.local_connection_id,
      },
    };
  }

  private requiredLocalConnectionId(): string {
    if (!this.scope.localConnectionId) throw new Error("SaaS connection write requires localConnectionId");
    return this.scope.localConnectionId;
  }
}

const connectionColumnNames =
  "id, revision, service, connection_name, secret_ref, secret_revision, credential_profile, subject_user_id, local_connection_id, visibility, status, source, source_reference, source_status, source_comment";
const connectionColumns = `SELECT ${connectionColumnNames} FROM integration_runtime.connections`;
const safeConnectionColumnNames =
  "id, subject_user_id, local_connection_id, service, connection_name, visibility, status, credential_profile, created_at, updated_at";
const safeConnectionColumns = `SELECT ${safeConnectionColumnNames} FROM integration_runtime.connections`;

function profileOf(credential: ResolvedCredential): CredentialProfile | undefined {
  return "profile" in credential ? credential.profile : undefined;
}

function toSafeStoredConnection(row: ConnectionRow): SafeStoredConnection {
  return {
    id: row.id,
    subjectUserId: row.subject_user_id,
    localConnectionId: row.local_connection_id,
    service: row.service,
    connectionName: row.connection_name,
    visibility: row.visibility,
    status: row.status,
    ...(row.credential_profile ? { profile: row.credential_profile } : {}),
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
  };
}

function verifiedAccountId(credential: ResolvedCredential): string | null {
  return credential.authType !== "no_auth" && credential.metadata.providerAccountVerified === true
    ? credential.profile.accountId
    : null;
}

export function mergeCredential(secret: ConnectionSecret, profile: CredentialProfile | null): ResolvedCredential {
  if (secret.authType === "no_auth") return { authType: "no_auth" };
  if (!profile) throw new Error("Stored authenticated connection has no safe credential profile");
  if (secret.authType === "api_key") {
    return { authType: "api_key", ...secret.value, profile, metadata: secret.metadata };
  }
  if (secret.authType === "custom_credential") {
    return { authType: "custom_credential", ...secret.value, profile, metadata: secret.metadata };
  }
  return { authType: "oauth2", ...secret.value, profile, metadata: secret.metadata };
}

function assertSaasConnectionName(connectionName: string): void {
  if (!connectionName || connectionName === "default") {
    throw new Error("SaaS connections require an opaque non-default connection name");
  }
}
