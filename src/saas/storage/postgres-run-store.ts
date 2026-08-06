import type {
  ExecutionCompletion,
  ExecutionFailure,
  ExecutionIntent,
  ExecutionJournal,
} from "../actions/saas-action-runner.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { IRunLogStore, RunLog, RunLogListInput, RunLogPage, RunLogWriteResult } from "./run-store.ts";
import type { Pool } from "pg";

import { decodeRunLogCursor, DEFAULT_RUN_LIMIT, encodeRunLogCursor } from "./run-store.ts";
import { withScopedClient } from "./scoped-query.ts";

interface RunRow {
  id: string;
  service: string;
  action_id: string;
  caller: RunLog["caller"];
  started_at: Date | string;
  completed_at: Date | string | null;
  duration_ms: string | number | null;
  ok: boolean | null;
  connection_id: string | null;
  connection_profile: RunLog["connectionProfile"] | null;
  runtime_token_id: string | null;
  policy: RunLog["policy"] | null;
  safe_error_code: string | null;
}

/** Redacted upstream run-log storage bound to one immutable SaaS request scope. */
export class PostgresRunStore implements IRunLogStore, ExecutionJournal {
  private readonly pool: Pool;
  private readonly scope: Readonly<SaasRequestScope>;
  private readonly limit: number;

  constructor(pool: Pool, scope: Readonly<SaasRequestScope>, limit: number = DEFAULT_RUN_LIMIT) {
    this.pool = pool;
    this.scope = scope;
    this.limit = limit;
  }

  async start(intent: ExecutionIntent): Promise<void> {
    if (
      intent.actionId !== this.scope.actionId ||
      intent.connectionId !== this.scope.connectorConnectionId ||
      intent.requestHash !== this.scope.requestHash
    ) {
      throw new Error("Execution intent does not match its scoped authorization");
    }
    await withScopedClient(this.pool, this.scope, async (client) => {
      await client.query(
        `INSERT INTO integration_runtime.run_intents (
           id, tenant_id, workspace_id, actor_user_id, subject_user_id, connection_id,
           service, action_id, caller, request_hash, status, input_bytes, started_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'http', $9, 'running', $10, $11)`,
        [
          intent.executionId,
          this.scope.tenantId,
          this.scope.workspaceId,
          this.scope.actorUserId,
          this.scope.subjectUserId,
          intent.connectionId,
          intent.service,
          intent.actionId,
          intent.requestHash,
          intent.inputBytes,
          intent.startedAt,
        ],
      );
    });
  }

  async complete(completion: ExecutionCompletion): Promise<void> {
    await withScopedClient(this.pool, this.scope, async (client) => {
      const result = await client.query(
        `UPDATE integration_runtime.run_intents
         SET status = 'succeeded', ok = true, output_bytes = $5, duration_ms = $6,
             provider_request_count = $7, completed_at = $8, updated_at = now()
         WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
           AND id = $4 AND status = 'running'`,
        [
          this.scope.tenantId,
          this.scope.workspaceId,
          this.scope.subjectUserId,
          completion.executionId,
          completion.outputBytes,
          completion.durationMs,
          completion.providerRequestCount ?? null,
          completion.completedAt,
        ],
      );
      if (result.rowCount !== 1) throw new Error("Execution intent was not running at completion");
    });
  }

  async fail(failure: ExecutionFailure): Promise<void> {
    if (!/^[a-z][a-z0-9_]{0,63}$/.test(failure.safeErrorCode)) {
      throw new Error("Execution failure code is not safe for persistence");
    }
    await withScopedClient(this.pool, this.scope, async (client) => {
      const result = await client.query(
        `UPDATE integration_runtime.run_intents
         SET status = $5, ok = CASE WHEN $5 = 'unknown' THEN NULL ELSE false END,
             output_bytes = $6, duration_ms = $7,
             provider_request_count = $8, safe_error_code = $9,
             completed_at = $10, updated_at = now()
         WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
           AND id = $4 AND status = 'running'`,
        [
          this.scope.tenantId,
          this.scope.workspaceId,
          this.scope.subjectUserId,
          failure.executionId,
          failure.status,
          failure.outputBytes,
          failure.durationMs,
          failure.providerRequestCount ?? null,
          failure.safeErrorCode,
          failure.completedAt,
        ],
      );
      if (result.rowCount !== 1) throw new Error("Execution intent was not running at failure");
    });
  }

  async add(run: RunLog): Promise<RunLogWriteResult> {
    return await withScopedClient(this.pool, this.scope, async (client) => {
      await client.query(
        `INSERT INTO integration_runtime.run_intents (
           id, tenant_id, workspace_id, actor_user_id, subject_user_id, connection_id,
           service, action_id, caller, request_hash, status, ok, runtime_token_id,
           connection_profile, policy, duration_ms, safe_error_code, started_at, completed_at
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
           $11, $12, $13, $14, $15, $16, $17, $18, $19
         )
         ON CONFLICT (id) DO UPDATE SET
           service = EXCLUDED.service, action_id = EXCLUDED.action_id, caller = EXCLUDED.caller,
           status = EXCLUDED.status, ok = EXCLUDED.ok, runtime_token_id = EXCLUDED.runtime_token_id,
           connection_profile = EXCLUDED.connection_profile, policy = EXCLUDED.policy,
           duration_ms = EXCLUDED.duration_ms, safe_error_code = EXCLUDED.safe_error_code,
           started_at = EXCLUDED.started_at, completed_at = EXCLUDED.completed_at, updated_at = now()`,
        [
          run.id,
          this.scope.tenantId,
          this.scope.workspaceId,
          this.scope.actorUserId,
          this.scope.subjectUserId,
          run.connectionId ?? this.scope.connectorConnectionId ?? null,
          run.service,
          run.actionId,
          run.caller,
          this.scope.requestHash ?? null,
          run.ok ? "succeeded" : "failed",
          run.ok,
          run.runtimeTokenId ?? null,
          run.connectionProfile ?? null,
          run.policy ?? null,
          run.durationMs,
          run.errorCode ?? null,
          run.startedAt,
          run.completedAt,
        ],
      );

      await client.query("SAVEPOINT run_retention");
      try {
        await client.query(
          `DELETE FROM integration_runtime.run_intents
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
             AND id IN (
               SELECT id FROM integration_runtime.run_intents
               WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3
               ORDER BY started_at DESC, id DESC OFFSET $4
             )`,
          [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, this.limit],
        );
        await client.query("RELEASE SAVEPOINT run_retention");
        return { retentionApplied: true };
      } catch {
        await client.query("ROLLBACK TO SAVEPOINT run_retention");
        return { retentionApplied: false };
      }
    });
  }

  async get(id: string): Promise<RunLog | undefined> {
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const row = (
        await client.query<RunRow>(
          `${runColumns}
           WHERE tenant_id = $1 AND workspace_id = $2 AND subject_user_id = $3 AND id = $4`,
          [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId, id],
        )
      ).rows[0];
      return row ? readRun(row) : undefined;
    });
  }

  async list(input: RunLogListInput = {}): Promise<RunLogPage> {
    const pageLimit = Math.max(1, Math.min(input.limit ?? this.limit, this.limit));
    const cursor = decodeRunLogCursor(input.cursor);
    return await withScopedClient(this.pool, this.scope, async (client) => {
      const values: unknown[] = [this.scope.tenantId, this.scope.workspaceId, this.scope.subjectUserId];
      const conditions = ["tenant_id = $1", "workspace_id = $2", "subject_user_id = $3"];
      const addCondition = (condition: string, value: unknown): void => {
        values.push(value);
        conditions.push(condition.replace("?", `$${values.length}`));
      };
      if (cursor) {
        values.push(cursor.startedAt, cursor.id);
        conditions.push(
          `(started_at < $${values.length - 1} OR (started_at = $${values.length - 1} AND id < $${values.length}))`,
        );
      }
      if (input.service) addCondition("service = ?", input.service);
      if (input.actionId) addCondition("action_id = ?", input.actionId);
      if (input.caller) addCondition("caller = ?", input.caller);
      if (input.ok !== undefined) addCondition("ok = ?", input.ok);
      values.push(pageLimit + 1);

      const rows = (
        await client.query<RunRow>(
          `${runColumns} WHERE ${conditions.join(" AND ")}
           ORDER BY started_at DESC, id DESC LIMIT $${values.length}`,
          values,
        )
      ).rows.map(readRun);
      const items = rows.slice(0, pageLimit);
      return {
        items,
        nextCursor:
          rows.length > pageLimit && items.length > 0 ? encodeRunLogCursor(items[items.length - 1]) : undefined,
      };
    });
  }
}

const runColumns = `SELECT id, service, action_id, caller, started_at, completed_at, duration_ms,
  ok, connection_id, connection_profile, runtime_token_id, policy, safe_error_code
  FROM integration_runtime.run_intents`;

function readRun(row: RunRow): RunLog {
  return {
    id: row.id,
    service: row.service,
    actionId: row.action_id,
    caller: row.caller,
    startedAt: isoString(row.started_at),
    completedAt: isoString(row.completed_at ?? row.started_at),
    durationMs: Number(row.duration_ms ?? 0),
    ok: row.ok ?? false,
    connectionId: row.connection_id ?? undefined,
    connectionProfile: row.connection_profile ?? undefined,
    runtimeTokenId: row.runtime_token_id ?? undefined,
    policy: row.policy ?? undefined,
    errorCode: row.safe_error_code ?? undefined,
  };
}

function isoString(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}
