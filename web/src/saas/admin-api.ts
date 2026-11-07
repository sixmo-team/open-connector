import type {
  AdminAction,
  AdminActionIdempotency,
  AdminActionRisk,
  AdminConnectionStatus,
  AdminData,
  AdminOverview,
  AdminProvider,
  AdminMinimumRole,
  AdminScope,
  AdminRunStatus,
  AdminScopes,
  SafeAdminConnection,
  SafeAdminRun,
} from "./admin-model";

const adminRoot = "/internal/integration-admin";
let csrfToken = "";

type ScopeResource = "overview" | "providers" | "actions" | "connections" | "runs";

interface ScopeRow {
  tenantId: string;
  tenantName: string;
  workspaceId: string;
  workspaceName: string;
  subjectUserId: string;
  subjectName: string | null;
  subjectEmail: string | null;
}

interface RawOverview {
  connections: { total: number; active: number };
  providers: { total: number; active: number };
  actions: { total: number; enabled: number };
  runs: {
    total: number;
    succeeded: number;
    failed: number;
    inputBytes: number;
    outputBytes: number;
    durationMs: number;
    p50DurationMs: number;
    p95DurationMs: number;
  };
}

interface RawProvider {
  displayName: string;
  available: boolean;
  connectionCount: number;
  activeConnectionCount: number;
  runCount: number;
}

interface RawAction {
  actionId: string;
  providerId: string;
  actionDisplayName: string;
  providerDisplayName: string;
  risk: AdminActionRisk;
  requiresApproval: boolean;
  idempotency: AdminActionIdempotency;
  minimumRole: AdminMinimumRole;
  maxInputBytes: number;
  maxOutputBytes: number;
  permission: AdminAction["permission"];
  approvalOverride: "inherit" | "always";
  runCount: number | null;
  successCount: number | null;
  failureCount: number | null;
}

interface RawConnection {
  providerDisplayName: string;
  ownerDisplayName: string | null;
  visibility: "user" | "workspace";
  authType: string;
  status: AdminConnectionStatus;
  displayName: string | null;
  providerAccountId: string | null;
  lastVerifiedAt?: string | null;
  runCount: number;
  inputBytes: number;
  outputBytes: number;
  durationMs: number;
}

interface RawRun {
  actorDisplayName: string;
  subjectDisplayName: string;
  providerDisplayName: string;
  actionDisplayName: string;
  connectionDisplayName: string;
  status: string;
  durationMs: number | null;
  inputBytes: number;
  outputBytes: number;
  safeErrorCode?: string | null;
  createdAt: string;
}

interface ScopeEnvelope<T> {
  target: unknown;
  overview?: T;
  providers?: T;
  actions?: T;
  connections?: T;
  runs?: T;
}

export class AdminApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "AdminApiError";
  }
}

export async function getAdminScopes(fetcher: typeof fetch = fetch): Promise<AdminScopes> {
  const response = await requestJson<{
    actor: { displayName: string; email: string | null };
    scopes: ScopeRow[];
  }>(`${adminRoot}/scopes`, fetcher);
  const tenants: AdminScopes["tenants"] = [];
  for (const row of response.scopes) {
    let tenant = tenants.find((item) => item.id === row.tenantId);
    if (!tenant) {
      tenant = { id: row.tenantId, displayName: row.tenantName, workspaces: [] };
      tenants.push(tenant);
    }
    let workspace = tenant.workspaces.find((item) => item.id === row.workspaceId);
    if (!workspace) {
      workspace = { id: row.workspaceId, displayName: row.workspaceName, subjects: [] };
      tenant.workspaces.push(workspace);
    }
    if (!workspace.subjects.some((item) => item.id === row.subjectUserId)) {
      workspace.subjects.push({
        id: row.subjectUserId,
        displayName: row.subjectName ?? row.subjectEmail ?? row.subjectUserId,
        email: row.subjectEmail ?? undefined,
      });
    }
  }
  return {
    actor: { displayName: response.actor.displayName, email: response.actor.email ?? undefined },
    tenants,
  };
}

export async function getAdminOverview(scope: AdminScope, fetcher: typeof fetch = fetch): Promise<AdminOverview> {
  const raw = await getScopePayload<RawOverview>("overview", scope, fetcher);
  return {
    connections: raw.connections.total,
    activeConnections: raw.connections.active,
    providers: raw.providers.total,
    activeProviders: raw.providers.active,
    actions: raw.actions.total,
    enabledActions: raw.actions.enabled,
    calls: raw.runs.total,
    successes: raw.runs.succeeded,
    failures: raw.runs.failed,
    inputBytes: raw.runs.inputBytes,
    outputBytes: raw.runs.outputBytes,
    durationMs: raw.runs.durationMs,
    durationP50Ms: raw.runs.p50DurationMs,
    durationP95Ms: raw.runs.p95DurationMs,
  };
}

export async function getAdminProviders(scope: AdminScope, fetcher: typeof fetch = fetch): Promise<AdminProvider[]> {
  const providers = await getScopePayload<RawProvider[]>("providers", scope, fetcher);
  return providers.map(toAdminProvider);
}

export async function getAdminActions(scope: AdminScope, fetcher: typeof fetch = fetch): Promise<AdminAction[]> {
  const actions = await getScopePayload<RawAction[]>("actions", scope, fetcher);
  return actions.map(toAdminAction);
}

export async function getAdminActionDefaults(fetcher: typeof fetch = fetch): Promise<AdminAction[]> {
  const response = await requestJson<{ actions: RawAction[] }>(`${adminRoot}/action-defaults`, fetcher);
  return response.actions.map(toAdminAction);
}

export async function getAdminConnections(
  scope: AdminScope,
  fetcher: typeof fetch = fetch,
): Promise<SafeAdminConnection[]> {
  const connections = await getScopePayload<RawConnection[]>("connections", scope, fetcher);
  return connections.map(toSafeConnection);
}

export async function getAdminRuns(scope: AdminScope, fetcher: typeof fetch = fetch): Promise<SafeAdminRun[]> {
  const runs = await getScopePayload<RawRun[]>("runs", scope, fetcher);
  return runs.map(toSafeRun);
}

export async function loadAdminData(scope: AdminScope, fetcher: typeof fetch = fetch): Promise<AdminData> {
  const [overview, rawProviders, rawActions, rawConnections, rawRuns] = await Promise.all([
    getAdminOverview(scope, fetcher),
    getScopePayload<RawProvider[]>("providers", scope, fetcher),
    getScopePayload<RawAction[]>("actions", scope, fetcher),
    getScopePayload<RawConnection[]>("connections", scope, fetcher),
    getScopePayload<RawRun[]>("runs", scope, fetcher),
  ]);
  return {
    overview,
    providers: rawProviders.map(toAdminProvider),
    actions: rawActions.map(toAdminAction),
    connections: rawConnections.map(toSafeConnection),
    runs: rawRuns.map(toSafeRun),
  };
}

export async function putAdminActionGrant(
  actionId: string,
  scope: AdminScope,
  enabled: boolean | null,
  reason: string,
  fetcher: typeof fetch = fetch,
): Promise<void> {
  await putActionChange(
    withScope(`${adminRoot}/action-grants/${encodeURIComponent(actionId)}`, scope),
    {
      enabled,
      reason: validateReason(reason),
    },
    fetcher,
  );
}

export async function putAdminActionGrants(
  actionIds: string[],
  scope: AdminScope,
  enabled: boolean | null,
  reason: string,
  fetcher: typeof fetch = fetch,
): Promise<void> {
  validateActionBatch(actionIds);
  await putActionChange(
    withScope(`${adminRoot}/action-grants`, scope),
    {
      actionIds,
      enabled,
      reason: validateReason(reason),
    },
    fetcher,
  );
}

export async function putAdminActionDefault(
  actionId: string,
  enabled: boolean,
  reason: string,
  fetcher: typeof fetch = fetch,
): Promise<void> {
  await putActionChange(
    `${adminRoot}/action-defaults/${encodeURIComponent(actionId)}`,
    {
      enabled,
      reason: validateReason(reason),
    },
    fetcher,
  );
}

export async function putAdminActionDefaults(
  actionIds: string[],
  enabled: boolean,
  reason: string,
  fetcher: typeof fetch = fetch,
): Promise<void> {
  validateActionBatch(actionIds);
  await putActionChange(
    `${adminRoot}/action-defaults`,
    {
      actionIds,
      enabled,
      reason: validateReason(reason),
    },
    fetcher,
  );
}

export async function putAdminActionApprovalOverride(
  actionId: string,
  scope: AdminScope,
  approvalOverride: "inherit" | "always",
  reason: string,
  fetcher: typeof fetch = fetch,
): Promise<void> {
  await putActionChange(
    withScope(`${adminRoot}/action-approval-overrides/${encodeURIComponent(actionId)}`, scope),
    {
      approvalOverride,
      reason: validateReason(reason),
    },
    fetcher,
  );
}

function validateActionBatch(actionIds: string[]): void {
  if (
    actionIds.length === 0 ||
    actionIds.length > 5000 ||
    actionIds.some((id) => !id.trim()) ||
    new Set(actionIds).size !== actionIds.length
  )
    throw new Error("Invalid action batch");
}

function validateReason(reason: string): string {
  const trimmed = reason.trim();
  if (!trimmed || trimmed.length > 500) throw new Error("Invalid reason");
  return trimmed;
}

async function putActionChange(path: string, body: object, fetcher: typeof fetch): Promise<void> {
  if (!csrfToken) throw new Error("Admin CSRF token is unavailable");
  const response = await fetcher(path, {
    method: "PUT",
    credentials: "same-origin",
    mode: "same-origin",
    redirect: "error",
    cache: "no-store",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "x-csrf-token": csrfToken,
    },
    body: JSON.stringify(body),
  });
  await readResponse<void>(response, false);
}

function toAdminProvider(provider: RawProvider): AdminProvider {
  return {
    displayName: provider.displayName,
    available: provider.available,
    enabledConnections: provider.activeConnectionCount,
    connections: provider.connectionCount,
    calls: provider.runCount,
  };
}

function toAdminAction(action: RawAction): AdminAction {
  return {
    actionId: action.actionId,
    displayName: action.actionDisplayName,
    providerName: action.providerDisplayName,
    providerId: action.providerId,
    risk: action.risk,
    requiresApproval: action.requiresApproval,
    idempotency: action.idempotency,
    minimumRole: action.minimumRole,
    maxInputBytes: action.maxInputBytes,
    maxOutputBytes: action.maxOutputBytes,
    permission: action.permission,
    approvalOverride: action.approvalOverride,
    calls: action.runCount,
    successes: action.successCount,
    failures: action.failureCount,
  };
}

function toSafeConnection(connection: RawConnection): SafeAdminConnection {
  return {
    providerName: connection.providerDisplayName,
    accountName: connection.displayName ?? connection.providerAccountId ?? "—",
    ownerName: connection.ownerDisplayName ?? "—",
    visibility: connection.visibility,
    status: connection.status,
    authType: connection.authType,
    lastVerifiedAt: connection.lastVerifiedAt ?? undefined,
    calls: connection.runCount,
    inputBytes: connection.inputBytes,
    outputBytes: connection.outputBytes,
    durationMs: connection.durationMs,
  };
}

function toSafeRun(run: RawRun): SafeAdminRun {
  return {
    startedAt: run.createdAt,
    actorName: run.actorDisplayName,
    subjectName: run.subjectDisplayName,
    providerName: run.providerDisplayName,
    actionName: run.actionDisplayName,
    connectionName: run.connectionDisplayName,
    status: normalizeRunStatus(run.status),
    durationMs: run.durationMs ?? 0,
    inputBytes: run.inputBytes,
    outputBytes: run.outputBytes,
    errorCode: run.safeErrorCode ?? undefined,
  };
}

function normalizeRunStatus(status: string): AdminRunStatus {
  if (status === "pending" || status === "running") return status;
  if (status === "succeeded" || status === "completed" || status === "success") return "succeeded";
  if (status === "failed" || status === "error" || status === "cancelled") return "failed";
  return "unknown";
}

async function getScopePayload<T>(resource: ScopeResource, scope: AdminScope, fetcher: typeof fetch): Promise<T> {
  const envelope = await requestJson<ScopeEnvelope<T>>(withScope(`${adminRoot}/${resource}`, scope), fetcher);
  const payload = envelope[resource];
  if (payload === undefined) throw new Error(`Admin response omitted ${resource}`);
  return payload;
}

function withScope(path: string, scope: AdminScope): string {
  const query = new URLSearchParams({
    tenantId: scope.tenantId,
    workspaceId: scope.workspaceId,
    subjectUserId: scope.subjectId,
  });
  return `${path}?${query}`;
}

async function requestJson<T>(path: string, fetcher: typeof fetch): Promise<T> {
  const response = await fetcher(path, {
    method: "GET",
    credentials: "same-origin",
    mode: "same-origin",
    redirect: "error",
    cache: "no-store",
    headers: { Accept: "application/json" },
  });
  return readResponse<T>(response, true);
}

async function readResponse<T>(response: Response, parseBody: boolean): Promise<T> {
  const responseCsrfToken = response.headers.get("x-csrf-token");
  if (responseCsrfToken) csrfToken = responseCsrfToken;
  if (!response.ok) throw new AdminApiError(`Admin request failed (${response.status})`, response.status);
  return (parseBody ? await response.json() : undefined) as T;
}
