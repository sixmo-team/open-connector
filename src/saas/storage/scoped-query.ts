import type { RequestProcessingContext } from "../../core/cancellation.ts";
import type {
  ActionPolicyControlPrincipal,
  ActionPolicyServicePrincipal,
  ActionPolicyTarget,
  NativeLifecycleServicePrincipal,
  SaasRequestScope,
} from "../contracts.ts";
import type { Pool, PoolClient } from "pg";

import {
  assertProcessingActive,
  getRequestSignal,
  remainingProcessingMs,
  waitForSignal,
} from "../../core/cancellation.ts";
import { actionPolicyTargetSchema } from "../contracts.ts";

/** Run a callback in one transaction whose RLS identity cannot leak through pool reuse. */
export async function withScopedClient<T>(
  pool: Pool,
  scope: SaasRequestScope,
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  if (!scope.tenantId || !scope.workspaceId || !scope.subjectUserId || !scope.actorUserId || !scope.purpose) {
    throw new Error("A complete tenant, workspace, subject, actor and purpose scope is required");
  }
  return withTransaction(pool, scope, async (client) => {
    await client.query(
      `SELECT
      set_config('integration.tenant_id', $1, true),
      set_config('integration.workspace_id', $2, true),
      set_config('integration.subject_user_id', $3, true),
      set_config('integration.workspace_role', $4, true),
      set_config('integration.actor_user_id', $5, true),
      set_config('integration.purpose', $6, true),
      set_config('integration.principal_kind', 'user', true),
      set_config('integration.policy_target_kind', '', true),
      set_config('integration.policy_tenant_id', '', true),
      set_config('integration.policy_workspace_id', '', true),
      set_config('integration.policy_user_id', '', true),
      set_config('integration.operator_subject', '', true)`,
      [scope.tenantId, scope.workspaceId, scope.subjectUserId, scope.workspaceRole, scope.actorUserId, scope.purpose],
    );
    await lifecycleFence(client, scope.tenantId, scope.purpose === "lifecycle:delete");
    assertProcessingActive(scope);
    return fn(client);
  });
}

/** A separate verified policy context, without fabricated customer identities for platform operations. */
export async function withActionPolicyClient<T>(
  pool: Pool,
  principal: Readonly<ActionPolicyControlPrincipal | ActionPolicyServicePrincipal>,
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const target = actionPolicyTargetSchema.parse(principal.target);
  const control = principal.subjectKind === "policy_control";
  if (
    !principal.subject ||
    !principal.requestId ||
    principal.permissions.length !== 1 ||
    principal.permissions[0] !== principal.purpose ||
    (control
      ? !["action-policy:read", "action-policy:write"].includes(principal.purpose) ||
        !["platform", "user"].includes(target.kind)
      : principal.subjectKind !== "service" ||
        !["action-policy:subjects", "action-policy:purge"].includes(principal.purpose) ||
        target.kind === "platform" ||
        (principal.purpose === "action-policy:subjects" && target.kind === "user")) ||
    ((principal.purpose === "action-policy:write" || principal.purpose === "action-policy:purge") &&
      !/^[A-Za-z0-9_-]{43}$/.test(principal.requestHash ?? ""))
  ) {
    throw new Error("A verified exact policy principal is required");
  }
  return withTargetClient(pool, principal, target, fn);
}

/** Native maintenance authority is real service/target identity, never a customer execution scope. */
export async function withNativeLifecycleClient<T>(
  pool: Pool,
  principal: Readonly<NativeLifecycleServicePrincipal>,
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const target = actionPolicyTargetSchema.parse(principal.target);
  const write = principal.purpose === "lifecycle:configuration:purge";
  if (
    principal.subjectKind !== "service" ||
    !principal.subject ||
    !principal.requestId ||
    !["lifecycle:subjects", "lifecycle:configuration:read", "lifecycle:configuration:purge"].includes(
      principal.purpose,
    ) ||
    principal.permissions.length !== 1 ||
    principal.permissions[0] !== principal.purpose ||
    (target.kind !== "tenant" && target.kind !== "workspace") ||
    write !== (principal.requestHash !== undefined) ||
    (write && !/^[A-Za-z0-9_-]{43}$/.test(principal.requestHash ?? ""))
  ) {
    throw new Error("A verified exact native lifecycle principal is required");
  }
  return withTargetClient(pool, principal, target, fn);
}

function withTargetClient<T>(
  pool: Pool,
  principal: Readonly<ActionPolicyControlPrincipal | ActionPolicyServicePrincipal | NativeLifecycleServicePrincipal>,
  target: Readonly<ActionPolicyTarget>,
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  return withTransaction(pool, principal, async (client) => {
    await client.query(
      `SELECT
      set_config('integration.tenant_id', '', true),
      set_config('integration.workspace_id', '', true),
      set_config('integration.subject_user_id', '', true),
      set_config('integration.workspace_role', '', true),
      set_config('integration.actor_user_id', '', true),
      set_config('integration.purpose', $1, true),
      set_config('integration.principal_kind', $2, true),
      set_config('integration.policy_target_kind', $3, true),
      set_config('integration.policy_tenant_id', $4, true),
      set_config('integration.policy_workspace_id', $5, true),
      set_config('integration.policy_user_id', $6, true),
      set_config('integration.operator_subject', $7, true)`,
      [
        principal.purpose,
        principal.subjectKind,
        target.kind,
        "tenantId" in target ? target.tenantId : "",
        "workspaceId" in target ? target.workspaceId : "",
        "userId" in target ? target.userId : "",
        principal.subject,
      ],
    );
    if (target.kind !== "platform") {
      await lifecycleFence(
        client,
        target.tenantId,
        principal.purpose === "action-policy:purge" || principal.purpose === "lifecycle:configuration:purge",
      );
    }
    assertProcessingActive(principal);
    return fn(client);
  });
}

async function lifecycleFence(client: PoolClient, tenantId: string, exclusive: boolean): Promise<void> {
  // ponytail: tenant-wide maintenance fence; split by workspace only if contention becomes material.
  const lock = exclusive ? "pg_advisory_xact_lock" : "pg_advisory_xact_lock_shared";
  await client.query(`SELECT ${lock}(hashtextextended($1, 0))`, [`integration-lifecycle:${tenantId.toLowerCase()}`]);
}

async function withTransaction<T>(
  pool: Pool,
  context: Readonly<RequestProcessingContext>,
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  assertProcessingActive(context);
  const signal = getRequestSignal(context);
  const client = await waitForSignal(pool.connect(), signal, (late) => late.release());
  let releaseError: Error | undefined;
  let released = false;
  const abort = (): void => {
    if (released) return;
    released = true;
    // Destroying the session rolls back active work; a late callback cannot reuse this client.
    client.release(true);
  };
  signal?.addEventListener("abort", abort, { once: true });
  try {
    assertProcessingActive(context);
    await client.query("BEGIN");
    const remaining = remainingProcessingMs(context);
    if (remaining !== undefined)
      await client.query("SELECT set_config('statement_timeout', $1, true)", [`${remaining}ms`]);
    const result = await waitForSignal(Promise.resolve(fn(client)), signal);
    assertProcessingActive(context);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    if (!released) {
      try {
        await client.query("ROLLBACK");
      } catch (rollbackError) {
        releaseError = rollbackError instanceof Error ? rollbackError : new Error("PostgreSQL rollback failed");
      }
    }
    throw error;
  } finally {
    signal?.removeEventListener("abort", abort);
    if (!released) client.release(releaseError);
  }
}
