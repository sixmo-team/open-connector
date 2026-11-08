import type { SaasConnectionReference } from "../../connection-store.ts";
import type { ResolvedCredential } from "../../core/types.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { ISecretCodec } from "../secrets/secret-codec.ts";
import type {
  ConnectionRequestStore,
  ConnectionRequest,
  PendingConnectionRequest,
  PendingSaasRequest,
  SaasRequestLease,
  SaasCandidate,
} from "./connection-request-store.ts";
import type { PostgresConnectionStore } from "./postgres-connection-store.ts";
import type { SecretCustodyTarget } from "./postgres-secret-custody.ts";
import type { Pool, PoolClient } from "pg";

import { createHash, randomUUID } from "node:crypto";
import { assertProcessingActive } from "../../core/cancellation.ts";
import { withSecretCleanup } from "../secrets/secret-codec.ts";
import { lockActiveManagedProject } from "./managed-project-admission.ts";
import {
  queueSaasConnectionCleanup,
  scopedExternalUserId,
  lockManagedAccount,
  retireManagedAccount,
} from "./postgres-saas-project-store.ts";
import { PostgresSecretCustodyStore } from "./postgres-secret-custody.ts";
import { withScopedClient } from "./scoped-query.ts";

const requestSecretKinds = ["connection-request", "connection-candidate"] as const;

interface RequestRow {
  id: string;
  kind: "local" | "saas";
  local_connection_id: string;
  oauth_session_id: string;
  service: string;
  connection_name: string;
  retirement_generation: string;
  status: ConnectionRequest["status"];
  app_id: string | null;
  error_code: string | null;
  error_message: string | null;
  expires_at: Date;
  created_at: Date;
  updated_at: Date;
  secret_ref: string;
  retired_secret_refs: string[];
  candidate_ref: string | null;
  lease_id: string | null;
  saas_phase: SaasRequestLease["phase"];
  remote_request_id: string | null;
  remote_account_id: string | null;
  poll_attempts: number;
  phase: string;
  account_fence_revision: string;
}
/** Real native request state machine. SQL owns claims/fences; private payloads exist only in OpenBao. */
export class PostgresConnectionRequestStore implements ConnectionRequestStore {
  private readonly pool: Pool;
  private readonly scope: Readonly<SaasRequestScope>;
  private readonly codec: ISecretCodec;
  private readonly connections: PostgresConnectionStore;
  private readonly custody: PostgresSecretCustodyStore;
  constructor(
    pool: Pool,
    scope: Readonly<SaasRequestScope>,
    codec: ISecretCodec,
    connections: PostgresConnectionStore,
  ) {
    this.pool = pool;
    this.scope = scope;
    this.codec = codec;
    this.connections = connections;
    this.custody = new PostgresSecretCustodyStore(pool, scope, codec);
  }
  private values(): unknown[] {
    return [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId];
  }
  private secretTarget(row: RequestRow): SecretCustodyTarget {
    return {
      kind: "connection-request",
      id: row.id,
      dataUserId: this.scope.subjectUserId,
      credentialOwnerId: this.scope.subjectUserId,
      identity: {
        requestKind: row.kind,
        service: row.service,
        connectionName: row.connection_name,
        retirementGeneration: row.retirement_generation,
        localConnectionId: row.local_connection_id,
        oauthSessionId: row.oauth_session_id,
        actorUserId: this.scope.subjectUserId,
      },
    };
  }
  private interactive(owner?: string): void {
    assertProcessingActive(this.scope);
    if (
      this.scope.actorUserId !== this.scope.subjectUserId ||
      (owner !== undefined && owner !== this.scope.subjectUserId) ||
      !this.scope.localConnectionId ||
      !this.scope.oauthSessionId
    )
      throw new Error("Authorization requests require the exact verified owner, local connection and session");
  }
  async create(pending: PendingConnectionRequest): Promise<void> {
    this.interactive(pending.owner);
    await this.createPending(pending, "local", pending.retirementGeneration, pending.state);
  }
  private async createPending(
    pending: PendingConnectionRequest | PendingSaasRequest,
    kind: "local" | "saas",
    generation: string,
    state: string,
  ): Promise<void> {
    const managed = kind === "saas" && "managedProjectId" in pending ? pending : undefined;
    if (kind === "saas" && !managed) throw new Error("Managed request identity is missing");
    const target: SecretCustodyTarget = {
      kind: "connection-request",
      id: pending.connectionRequestId,
      dataUserId: this.scope.subjectUserId,
      credentialOwnerId: this.scope.subjectUserId,
      identity: {
        requestKind: kind,
        service: pending.service,
        connectionName: pending.connectionName,
        retirementGeneration: generation,
        localConnectionId: this.scope.localConnectionId,
        oauthSessionId: this.scope.oauthSessionId,
        stateHash: hash(state),
      },
    };
    const ref = await this.custody.encode(JSON.stringify(pending), target);
    let committed = false;
    try {
      await withScopedClient(this.pool, this.scope, async (client) => {
        const current = (
          await client.query<{ generation: string }>(
            `SELECT generation FROM integration_runtime.connection_retirements WHERE tenant_id=$1 AND workspace_id=$2
        AND local_connection_id=$3 AND service=$4 AND connection_name=$5 FOR UPDATE`,
            [
              this.scope.tenantId,
              this.scope.workspaceId,
              this.scope.localConnectionId,
              pending.service,
              pending.connectionName,
            ],
          )
        ).rows[0];
        if (current?.generation !== generation) throw new Error("Connection retired during authorization");
        if (managed && !(await lockActiveManagedProject(client, managed.managedProjectId)))
          throw new Error("Managed project is unavailable for new authorization");
        await this.queueRequests(client, `local_connection_id=$4 AND phase IN ('pending','processing')`, [
          this.scope.localConnectionId,
        ]);
        await client.query(
          `UPDATE integration_runtime.connection_requests SET phase='completed',status='failed',error_code='request_superseded',lease_id=NULL,lease_until=NULL,updated_at=now()
        WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND local_connection_id=$4 AND phase IN ('pending','processing')`,
          [...this.values(), this.scope.localConnectionId],
        );
        await client.query(
          `INSERT INTO integration_runtime.connection_requests
        (id,tenant_id,workspace_id,subject_user_id,local_connection_id,oauth_session_id,service,connection_name,retirement_generation,state_hash,kind,phase,status,secret_ref,expires_at,created_at,managed_project_id,provider_config_id,external_user_id,saas_phase)
        VALUES ($4,$1,$2,$3,$5,$6,$7,$8,$9,$10,$11,'pending','initiated',$12,$13,$14,$15,$16,$17,$18)`,
          [
            ...this.values(),
            pending.connectionRequestId,
            this.scope.localConnectionId,
            this.scope.oauthSessionId,
            pending.service,
            pending.connectionName,
            generation,
            hash(state),
            kind,
            ref,
            pending.expiresAt,
            pending.createdAt,
            managed?.managedProjectId ?? null,
            managed?.providerConfigId ?? null,
            managed?.externalUserId ?? null,
            managed ? "creating" : null,
          ],
        );
        await this.custody.consume(client, ref, target);
      });
      committed = true;
    } finally {
      if (!committed) await this.custody.abandonWritten(ref, target);
    }
  }
  async get(id: string, owner: string): Promise<ConnectionRequest | undefined> {
    this.interactive(owner);
    const row = await this.row(id);
    if (!row) return undefined;
    return {
      connectionRequestId: row.id,
      service: row.service,
      status: row.status === "initiated" && row.expires_at.getTime() <= Date.now() ? "expired" : row.status,
      appId: row.app_id,
      errorCode: row.error_code,
      errorMessage: row.error_message,
      expiresAt: row.expires_at.toISOString(),
      createdAt: row.created_at.getTime(),
      updatedAt: row.updated_at.getTime(),
    };
  }
  private async row(id: string): Promise<RequestRow | undefined> {
    if (!/^[a-f0-9-]{36}$/.test(id)) return undefined;
    return await withScopedClient(
      this.pool,
      this.scope,
      async (client) =>
        (
          await client.query<RequestRow>(
            `SELECT * FROM integration_runtime.connection_requests
    WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$4 AND local_connection_id=$5 AND oauth_session_id=$6`,
            [...this.values(), id, this.scope.localConnectionId, this.scope.oauthSessionId],
          )
        ).rows[0],
    );
  }
  async claim(state: string): Promise<PendingConnectionRequest | undefined> {
    this.interactive();
    const row = await withScopedClient(
      this.pool,
      this.scope,
      async (client) =>
        (
          await client.query<RequestRow>(
            `UPDATE integration_runtime.connection_requests SET phase='processing',updated_at=now()
    WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND state_hash=$4 AND local_connection_id=$5 AND oauth_session_id=$6
      AND kind='local' AND phase='pending' AND status='initiated' AND expires_at>now()
      AND EXISTS (SELECT 1 FROM integration_runtime.connection_retirements r WHERE r.tenant_id=connection_requests.tenant_id
        AND r.workspace_id=connection_requests.workspace_id AND r.subject_user_id=connection_requests.subject_user_id
        AND r.local_connection_id=connection_requests.local_connection_id AND r.service=connection_requests.service
        AND r.connection_name=connection_requests.connection_name AND r.generation=connection_requests.retirement_generation)
      RETURNING *`,
            [...this.values(), hash(state), this.scope.localConnectionId, this.scope.oauthSessionId],
          )
        ).rows[0],
    );
    if (!row) return undefined;
    const pending = JSON.parse(await this.codec.decode(row.secret_ref)) as PendingConnectionRequest;
    if (
      pending.state !== state ||
      pending.owner !== this.scope.subjectUserId ||
      pending.connectionRequestId !== row.id ||
      pending.connectionName !== row.connection_name ||
      pending.retirementGeneration !== row.retirement_generation
    )
      throw new Error("Authorization private payload does not match its scoped claim");
    return pending;
  }
  async fail(id: string, errorCode: string, errorMessage: string): Promise<void> {
    this.interactive();
    await withScopedClient(this.pool, this.scope, async (client) => {
      await client.query(
        `UPDATE integration_runtime.connection_requests SET phase='completed',status='failed',error_code=$5,error_message=$6,updated_at=now()
    WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$4 AND kind='local' AND phase='processing' AND oauth_session_id=$7 AND local_connection_id=$8`,
        [...this.values(), id, errorCode, errorMessage, this.scope.oauthSessionId, this.scope.localConnectionId],
      );
    });
    await this.cleanupTerminal(id);
  }
  async complete(
    pending: PendingConnectionRequest,
    credential: ResolvedCredential,
    signal?: AbortSignal,
  ): Promise<string | undefined> {
    this.interactive(pending.owner);
    signal?.throwIfAborted();
    const id = await this.connections.completeOAuthRequest(pending, credential);
    if (id) await this.cleanupTerminal(pending.connectionRequestId);
    return id;
  }
  async createSaas(pending: PendingSaasRequest): Promise<SaasRequestLease> {
    this.interactive(pending.owner);
    if (pending.externalUserId !== scopedExternalUserId(this.scope))
      throw new Error("Managed identity does not match the verified connection lineage");
    const generation = await this.connections.getRetirementGeneration(pending.service, pending.connectionName);
    await this.createPending(pending, "saas", generation, pending.connectionRequestId);
    const lease = await this.claimSaas(pending.connectionRequestId, pending.owner);
    if (!lease) throw new Error("Managed request could not acquire its creation lease");
    return lease;
  }
  async claimSaas(id: string, owner: string, now: number = Date.now()): Promise<SaasRequestLease | undefined> {
    this.interactive(owner);
    const leaseId = randomUUID();
    const row = await withScopedClient(
      this.pool,
      this.scope,
      async (client) =>
        (
          await client.query<RequestRow>(
            `UPDATE integration_runtime.connection_requests SET lease_id=$5,lease_until=to_timestamp($6::double precision/1000),updated_at=now()
    WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$4 AND local_connection_id=$7 AND oauth_session_id=$8
      AND kind='saas' AND phase='pending' AND status='initiated' AND next_poll_at<=$9 AND (lease_until IS NULL OR lease_until<=to_timestamp($9::double precision/1000)) RETURNING *`,
            [...this.values(), id, leaseId, now + 45000, this.scope.localConnectionId, this.scope.oauthSessionId, now],
          )
        ).rows[0],
    );
    if (!row) return undefined;
    const pending = JSON.parse(await this.codec.decode(row.secret_ref)) as PendingSaasRequest;
    if (pending.owner !== owner || pending.connectionRequestId !== id || pending.connectionName !== row.connection_name)
      throw new Error("Managed request payload scope mismatch");
    const candidate = row.candidate_ref
      ? (JSON.parse(await this.codec.decode(row.candidate_ref)) as SaasCandidate)
      : undefined;
    return {
      pending,
      leaseId,
      phase: row.saas_phase,
      remoteRequestId: row.remote_request_id,
      pollAttempts: row.poll_attempts,
      candidate,
    };
  }
  async saveSaasRequest(lease: SaasRequestLease, remoteRequestId: string, expiresAt?: string): Promise<boolean> {
    if (lease.phase !== "creating" || !remoteRequestId) return false;
    return this.mutateLease(
      lease,
      `remote_request_id=$6,expires_at=coalesce($7::timestamptz,expires_at),saas_phase='pending'`,
      [remoteRequestId, expiresAt ?? null],
      "AND saas_phase='creating' AND remote_request_id IS NULL",
    );
  }
  async saveSaasCandidate(lease: SaasRequestLease, candidate: SaasCandidate): Promise<boolean> {
    this.interactive(lease.pending.owner);
    const target: SecretCustodyTarget = {
      kind: "connection-candidate",
      id: lease.pending.connectionRequestId,
      dataUserId: this.scope.subjectUserId,
      credentialOwnerId: this.scope.subjectUserId,
      identity: {
        leaseId: lease.leaseId,
        service: lease.pending.service,
        connectionName: lease.pending.connectionName,
        localConnectionId: this.scope.localConnectionId,
        oauthSessionId: this.scope.oauthSessionId,
      },
    };
    const ref = await this.custody.encode(JSON.stringify(candidate), target);
    let saved = false;
    try {
      saved = await withScopedClient(this.pool, this.scope, async (client) => {
        const changed = await this.mutateLeaseWithClient(
          client,
          lease,
          `remote_account_id=$6,retired_secret_refs=CASE WHEN candidate_ref IS NULL THEN retired_secret_refs ELSE array_append(retired_secret_refs,candidate_ref) END,candidate_ref=$7,saas_phase='candidate'`,
          [candidate.connectedAccountId, ref],
          "AND saas_phase='pending'",
        );
        if (changed) await this.custody.consume(client, ref, target);
        return changed;
      });
      return saved;
    } finally {
      if (!saved) await this.custody.abandonWritten(ref, target);
    }
  }
  async releaseSaas(lease: SaasRequestLease, nextPollAt: number, failed = false): Promise<boolean> {
    return this.mutateLease(lease, `lease_id=NULL,lease_until=NULL,next_poll_at=$6,poll_attempts=$7`, [
      Math.max(nextPollAt, Date.now() + 2000),
      failed ? lease.pollAttempts + 1 : 0,
    ]);
  }
  async failSaas(lease: SaasRequestLease, code: string, message: string): Promise<boolean> {
    this.interactive(lease.pending.owner);
    const failed = await withScopedClient(this.pool, this.scope, async (client) => {
      await this.queueRequests(client, `id=$4 AND lease_id=$5 AND lease_until>now() AND phase='pending'`, [
        lease.pending.connectionRequestId,
        lease.leaseId,
      ]);
      return await this.mutateLeaseWithClient(
        client,
        lease,
        `phase='completed',status='failed',error_code=$6,error_message=$7,lease_id=NULL,lease_until=NULL`,
        [code, message],
      );
    });
    if (failed) await this.cleanupTerminal(lease.pending.connectionRequestId);
    return failed;
  }
  async getSaasReturnUri(id: string, owner: string): Promise<string | undefined> {
    this.interactive(owner);
    const row = await this.row(id);
    if (!row || row.kind !== "saas" || row.phase !== "completed") return undefined;
    return (JSON.parse(await this.codec.decode(row.secret_ref)) as PendingSaasRequest).returnUri;
  }
  async cancelSaas(id: string, owner: string): Promise<void> {
    this.interactive(owner);
    if (!(await this.row(id))) return;
    await withScopedClient(this.pool, this.scope, async (client) => {
      await this.queueRequests(client, `id=$4 AND phase IN ('pending','processing')`, [id]);
      await client.query(
        `UPDATE integration_runtime.connection_requests SET phase='completed',status='failed',error_code='request_cancelled',lease_id=NULL,lease_until=NULL,updated_at=now()
      WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$4 AND local_connection_id=$5 AND oauth_session_id=$6 AND kind='saas' AND phase IN ('pending','processing')`,
        [...this.values(), id, this.scope.localConnectionId, this.scope.oauthSessionId],
      );
    });
  }
  async expireSaas(now: number = Date.now()): Promise<void> {
    await withScopedClient(this.pool, this.scope, async (client) => {
      await this.queueRequests(
        client,
        `expires_at<=to_timestamp($4::double precision/1000) AND phase IN ('pending','processing')`,
        [now],
      );
      await client.query(
        `UPDATE integration_runtime.connection_requests SET phase='completed',status='expired',error_code='request_expired',lease_id=NULL,lease_until=NULL,updated_at=now()
      WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND phase IN ('pending','processing') AND expires_at<=to_timestamp($4::double precision/1000)`,
        [...this.values(), now],
      );
    });
    const cutoff = now - 86400000;
    const retired = await withScopedClient(this.pool, this.scope, async (client) => {
      const rows = (
        await client.query<RequestRow>(
          `SELECT * FROM integration_runtime.connection_requests WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3
      AND phase IN ('completed','purging') AND expires_at<=to_timestamp($4::double precision/1000) ORDER BY id FOR UPDATE`,
          [...this.values(), cutoff],
        )
      ).rows;
      for (const row of rows) {
        await this.custody.adoptDeleting(
          client,
          [row.secret_ref, ...row.retired_secret_refs, ...(row.candidate_ref ? [row.candidate_ref] : [])],
          this.secretTarget(row),
        );
      }
      if (rows.length)
        await client.query(
          `UPDATE integration_runtime.connection_requests SET phase='purging',lease_id=NULL,lease_until=NULL,updated_at=now()
      WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=ANY($4::uuid[])`,
          [...this.values(), rows.map((row) => row.id)],
        );
      return rows.map((row) => row.id);
    });
    await this.custody.drain(requestSecretKinds);
    if (retired.length)
      await withScopedClient(this.pool, this.scope, async (client) => {
        await client.query(
          `DELETE FROM integration_runtime.connection_requests WHERE tenant_id=$1 AND workspace_id=$2
        AND subject_user_id=$3 AND id=ANY($4::uuid[]) AND phase='purging' AND expires_at<=to_timestamp($5::double precision/1000)`,
          [...this.values(), retired, cutoff],
        );
      });
  }
  async completeSaas(lease: SaasRequestLease): Promise<"connected" | "conflict" | "lease_lost"> {
    this.interactive(lease.pending.owner);
    const candidate = lease.candidate;
    if (!candidate) {
      const row = await this.row(lease.pending.connectionRequestId);
      if (!row?.candidate_ref || row.kind !== "saas" || row.phase !== "pending" || row.lease_id !== lease.leaseId)
        return "lease_lost";
      lease = { ...lease, candidate: JSON.parse(await this.codec.decode(row.candidate_ref)) as SaasCandidate };
    }
    const pending = lease.pending;
    const result = await withScopedClient(this.pool, this.scope, async (client) => {
      const current = (
        await client.query<RequestRow>(
          `SELECT * FROM integration_runtime.connection_requests WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$4
      AND local_connection_id=$5 AND oauth_session_id=$6 AND kind='saas' AND phase='pending' AND status='initiated' AND saas_phase='candidate' AND lease_id=$7 AND lease_until>now() AND expires_at>now() FOR UPDATE`,
          [
            ...this.values(),
            pending.connectionRequestId,
            this.scope.localConnectionId,
            this.scope.oauthSessionId,
            lease.leaseId,
          ],
        )
      ).rows[0];
      if (!current) return "lease_lost" as const;
      const retirement = (
        await client.query<{ generation: string }>(
          `SELECT generation FROM integration_runtime.connection_retirements WHERE tenant_id=$1 AND workspace_id=$2 AND local_connection_id=$3 AND service=$4 AND connection_name=$5 FOR UPDATE`,
          [
            this.scope.tenantId,
            this.scope.workspaceId,
            this.scope.localConnectionId,
            pending.service,
            pending.connectionName,
          ],
        )
      ).rows[0];
      const existing = (
        await client.query<{ id: string; revision: string; source_reference: SaasConnectionReference | null }>(
          `SELECT id,revision,source_reference FROM integration_runtime.connections WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND local_connection_id=$4 AND service=$5 AND connection_name=$6 AND status='active' FOR UPDATE`,
          [...this.values(), this.scope.localConnectionId, pending.service, pending.connectionName],
        )
      ).rows[0];
      if (
        retirement?.generation !== current.retirement_generation ||
        (pending.target
          ? existing?.id !== pending.target.id || existing?.revision !== pending.target.revision
          : !!existing)
      ) {
        await this.queueRequests(client, `id=$4 AND phase='pending'`, [pending.connectionRequestId]);
        await this.mutateLeaseWithClient(
          client,
          lease,
          `phase='completed',status='failed',error_code='request_key_conflict',lease_id=NULL,lease_until=NULL`,
          [],
        );
        return "conflict" as const;
      }
      if (
        existing &&
        (!existing.source_reference ||
          existing.source_reference.managedProjectId !== pending.managedProjectId ||
          existing.source_reference.providerConfigId !== pending.providerConfigId ||
          existing.source_reference.externalUserId !== pending.externalUserId)
      )
        throw new Error("Managed source reference cannot be rebound during reconnect");
      const value = lease.candidate!;
      if (value.connectedAccountId !== current.remote_account_id) throw new Error("Managed candidate selector changed");
      await lockManagedAccount(client, pending.managedProjectId, value.connectedAccountId);
      assertProcessingActive(this.scope);
      const blocked = (
        await client.query<{ blocked: boolean }>(
          `SELECT
      integration_runtime.is_managed_account_cleanup_pending($1::uuid,$2::text)
      OR integration_runtime.is_managed_account_retired($1::uuid,$2::text,$3::bigint) AS blocked`,
          [pending.managedProjectId, value.connectedAccountId, current.account_fence_revision],
        )
      ).rows[0]?.blocked;
      if (typeof blocked !== "boolean") throw new Error("Managed account cleanup fence is unavailable");
      if (blocked) {
        await this.queueRequests(client, `id=$4 AND phase='pending'`, [pending.connectionRequestId]);
        if (
          !(await this.mutateLeaseWithClient(
            client,
            lease,
            `phase='completed',status='failed',error_code='request_key_conflict',lease_id=NULL,lease_until=NULL`,
            [],
          ))
        )
          throw new Error("Managed request lost its lease while refusing a retired account");
        return "conflict" as const;
      }
      const id = existing?.id ?? pending.connectionId;
      if (existing?.source_reference && existing.source_reference.connectedAccountId !== value.connectedAccountId)
        await queueSaasConnectionCleanup(client, this.scope, id);
      const reference = {
        managedProjectId: pending.managedProjectId,
        providerConfigId: pending.providerConfigId,
        externalUserId: pending.externalUserId,
        connectedAccountId: value.connectedAccountId,
        localRequestId: pending.connectionRequestId,
      };
      await client.query(
        `INSERT INTO integration_runtime.connections (id,tenant_id,workspace_id,subject_user_id,local_connection_id,visibility,service,connection_name,auth_type,revision,secret_ref,secret_revision,status,credential_profile,source,source_reference,source_status,source_comment)
      VALUES ($4,$1,$2,$3,$5,'user',$6,$7,'oauth2',$8,'managed-source',0,'active',$9,'saas',$10,$11,$12)
      ON CONFLICT (id) DO UPDATE SET revision=EXCLUDED.revision,source='saas',source_reference=EXCLUDED.source_reference,source_status=EXCLUDED.source_status,source_comment=EXCLUDED.source_comment,credential_profile=EXCLUDED.credential_profile,status='active',updated_at=now()`,
        [
          ...this.values(),
          id,
          this.scope.localConnectionId,
          pending.service,
          pending.connectionName,
          randomUUID(),
          value.profile,
          reference,
          value.status,
          value.comment,
        ],
      );
      if (
        !(await this.mutateLeaseWithClient(
          client,
          lease,
          `phase='completed',status='connected',app_id=$6,lease_id=NULL,lease_until=NULL`,
          [id],
        ))
      )
        throw new Error("Managed request lost its completion lease");
      return "connected" as const;
    });
    return result;
  }
  private async mutateLease(lease: SaasRequestLease, set: string, extra: unknown[], where = ""): Promise<boolean> {
    this.interactive(lease.pending.owner);
    return withScopedClient(this.pool, this.scope, (client) =>
      this.mutateLeaseWithClient(client, lease, set, extra, where),
    );
  }
  private async mutateLeaseWithClient(
    client: PoolClient,
    lease: SaasRequestLease,
    set: string,
    extra: unknown[],
    where = "",
  ): Promise<boolean> {
    return (
      (
        await client.query(
          `UPDATE integration_runtime.connection_requests SET ${set},updated_at=now()
    WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$4 AND lease_id=$5 AND lease_until>clock_timestamp()
      AND local_connection_id=$${6 + extra.length} AND oauth_session_id=$${7 + extra.length}
      AND kind='saas' AND phase='pending' ${where} RETURNING id`,
          [
            ...this.values(),
            lease.pending.connectionRequestId,
            lease.leaseId,
            ...extra,
            this.scope.localConnectionId,
            this.scope.oauthSessionId,
          ],
        )
      ).rowCount === 1
    );
  }
  private async queueRequests(client: PoolClient, where: string, extra: unknown[]): Promise<void> {
    const candidates = (
      await client.query<{ project: string; account: string | null }>(
        `SELECT managed_project_id AS project,remote_account_id AS account
    FROM integration_runtime.connection_requests WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND kind='saas' AND ${where}
    ORDER BY managed_project_id,remote_account_id FOR UPDATE`,
        [...this.values(), ...extra],
      )
    ).rows;
    for (const candidate of candidates)
      if (candidate.account !== null) await retireManagedAccount(client, candidate.project, candidate.account);
    await client.query(
      `INSERT INTO integration_runtime.saas_cleanup (id,tenant_id,workspace_id,subject_user_id,managed_project_id,provider_config_id,external_user_id,remote_request_id,remote_account_id,service,request_expires_at,status)
    SELECT 'request:'||id,tenant_id,workspace_id,subject_user_id,managed_project_id,provider_config_id,external_user_id,remote_request_id,remote_account_id,service,expires_at,
      CASE WHEN remote_request_id IS NULL AND remote_account_id IS NULL THEN 'manual' ELSE 'pending' END
    FROM integration_runtime.connection_requests WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND kind='saas' AND ${where} ON CONFLICT DO NOTHING`,
      [...this.values(), ...extra],
    );
  }
  private async cleanupTerminal(id: string): Promise<void> {
    await withSecretCleanup(this.scope, async (scope) => {
      const custody = new PostgresSecretCustodyStore(this.pool, scope, this.codec);
      await withScopedClient(this.pool, scope, async (client) => {
        const row = (
          await client.query<RequestRow>(
            `SELECT * FROM integration_runtime.connection_requests
          WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$4
            AND local_connection_id=$5 AND oauth_session_id=$6 AND phase='completed' FOR UPDATE`,
            [...this.values(), id, this.scope.localConnectionId, this.scope.oauthSessionId],
          )
        ).rows[0];
        if (!row) return;
        // Managed callbacks retain their original return URI until the retention boundary.
        const refs =
          row.kind === "saas"
            ? [...row.retired_secret_refs, ...(row.candidate_ref ? [row.candidate_ref] : [])]
            : [row.secret_ref, ...row.retired_secret_refs];
        await custody.adoptDeleting(client, refs, this.secretTarget(row));
        await client.query(
          `UPDATE integration_runtime.connection_requests
          SET retired_secret_refs='{}',candidate_ref=NULL,phase=CASE WHEN kind='local' THEN 'purging' ELSE phase END,updated_at=now()
          WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND id=$4 AND phase='completed'`,
          [...this.values(), id],
        );
      });
      await custody.drain(requestSecretKinds);
    });
  }
  async listExactOwnedForLifecycle(
    cursor: string | undefined,
    limit: number,
  ): Promise<{ items: Array<{ id: string; status: string }>; nextCursor?: string }> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100)
      throw new Error("Invalid request lifecycle page limit");
    return withScopedClient(this.pool, this.scope, async (client) => {
      const rows = (
        await client.query<{ id: string; status: string }>(
          `SELECT id,status FROM integration_runtime.connection_requests WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND ($4::uuid IS NULL OR id>$4) ORDER BY id LIMIT $5`,
          [...this.values(), cursor ?? null, limit + 1],
        )
      ).rows;
      return { items: rows.slice(0, limit), nextCursor: rows.length > limit ? rows[limit - 1]?.id : undefined };
    });
  }
  async purgeExactOwnedForLifecycle(): Promise<{ deletedRequests: number; deletedRequestSecrets: number }> {
    const rows = await withScopedClient(this.pool, this.scope, async (client) => {
      await this.custody.assertNoPending(client, requestSecretKinds);
      await this.queueRequests(client, `phase IN ('pending','processing')`, []);
      await client.query(
        `UPDATE integration_runtime.connection_retirements r SET generation=gen_random_uuid()::text
      WHERE r.tenant_id=$1 AND r.workspace_id=$2 AND EXISTS (SELECT 1 FROM integration_runtime.connection_requests q
        WHERE q.tenant_id=r.tenant_id AND q.workspace_id=r.workspace_id AND q.local_connection_id=r.local_connection_id
          AND q.service=r.service AND q.connection_name=r.connection_name AND q.subject_user_id=$3)`,
        this.values(),
      );
      const fenced = (
        await client.query<RequestRow>(
          `UPDATE integration_runtime.connection_requests SET phase='purging',status='failed',lease_id=NULL,lease_until=NULL,error_code='owner_purged'
      WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 RETURNING *`,
          this.values(),
        )
      ).rows;
      for (const row of fenced)
        await this.custody.adoptDeleting(
          client,
          [row.secret_ref, ...row.retired_secret_refs, ...(row.candidate_ref ? [row.candidate_ref] : [])],
          this.secretTarget(row),
        );
      return fenced.map((row) => row.id);
    });
    const deletedRequestSecrets = await this.custody.drain(requestSecretKinds);
    const deletedRequests = rows.length
      ? await withScopedClient(
          this.pool,
          this.scope,
          async (client) =>
            (
              await client.query(
                `DELETE FROM integration_runtime.connection_requests WHERE tenant_id=$1 AND workspace_id=$2
          AND subject_user_id=$3 AND id=ANY($4::uuid[]) AND phase='purging' AND error_code='owner_purged'`,
                [...this.values(), rows],
              )
            ).rowCount ?? 0,
        )
      : 0;
    return { deletedRequests, deletedRequestSecrets };
  }

  async countExactOwnedForLifecycle(): Promise<{
    total: number;
    statuses: Array<{ status: string; count: number }>;
    secrets: number;
  }> {
    return withScopedClient(this.pool, this.scope, async (client) => {
      const rows = (
        await client.query<{ status: string; count: string }>(
          `SELECT status,count(*) FROM integration_runtime.connection_requests
      WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 GROUP BY status ORDER BY status`,
          this.values(),
        )
      ).rows;
      const references = (
        await client.query<{ count: string }>(
          `WITH refs AS (
          SELECT secret_ref AS ref FROM integration_runtime.connection_requests WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3
          UNION SELECT candidate_ref FROM integration_runtime.connection_requests WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3 AND candidate_ref IS NOT NULL
          UNION SELECT unnest(retired_secret_refs) FROM integration_runtime.connection_requests WHERE tenant_id=$1 AND workspace_id=$2 AND subject_user_id=$3
          UNION SELECT secret_ref FROM integration_runtime.secret_custody WHERE tenant_id=$1 AND workspace_id=$2 AND kind=ANY($4::text[])
            AND (subject_user_id=$3 OR actor_user_id=$3 OR credential_owner_id=$3)
        ) SELECT count(*) AS count FROM refs`,
          [...this.values(), requestSecretKinds],
        )
      ).rows[0];
      if (!references) throw new Error("Request secret reference inventory is unavailable");
      const statuses = rows.map((row) => ({ status: row.status, count: Number(row.count) }));
      return { total: statuses.reduce((sum, row) => sum + row.count, 0), statuses, secrets: Number(references.count) };
    });
  }
}
function hash(state: string): string {
  return createHash("sha256").update(state).digest("hex");
}
