export interface AdminActor {
  displayName: string;
  email?: string;
}

export interface AdminSubject {
  id: string;
  displayName: string;
  email?: string;
}

export interface AdminWorkspace {
  id: string;
  displayName: string;
  subjects: AdminSubject[];
}

export interface AdminTenant {
  id: string;
  displayName: string;
  workspaces: AdminWorkspace[];
}

export interface AdminScopes {
  actor?: AdminActor;
  tenants: AdminTenant[];
}

export interface AdminScope {
  tenantId: string;
  workspaceId: string;
  subjectId: string;
}

export interface AdminOverview {
  connections: number;
  activeConnections: number;
  providers: number;
  activeProviders: number;
  actions: number;
  enabledActions: number;
  calls: number;
  successes: number;
  failures: number;
  inputBytes: number;
  outputBytes: number;
  durationMs: number;
  durationP50Ms: number;
  durationP95Ms: number;
}

export interface AdminProvider {
  displayName: string;
  available: boolean;
  enabledConnections: number;
  connections: number;
  calls: number;
}

export type AdminActionRisk = "read" | "write" | "destructive" | "access_change";
export type AdminActionIdempotency = "safe" | "keyed" | "unsafe";
export type AdminMinimumRole = "viewer" | "member" | "admin" | "owner";

export interface AdminAction {
  actionId: string;
  displayName: string;
  providerId: string;
  providerName: string;
  risk: AdminActionRisk;
  requiresApproval: boolean;
  idempotency: AdminActionIdempotency;
  minimumRole: AdminMinimumRole;
  maxInputBytes: number;
  maxOutputBytes: number;
  granted: boolean;
  approvalOverride: "inherit" | "always";
  calls: number;
  successes: number;
  failures: number;
}

export type AdminConnectionVisibility = "user" | "workspace";
export type AdminConnectionStatus = "pending" | "active" | "expired" | "revoked" | "failed" | "reconnect_required";

/** Deliberately contains only metadata approved for the administration console. */
export interface SafeAdminConnection {
  providerName: string;
  accountName: string;
  accountEmail?: string;
  ownerName: string;
  visibility: AdminConnectionVisibility;
  status: AdminConnectionStatus;
  authType: string;
  lastVerifiedAt?: string;
  calls: number;
  inputBytes: number;
  outputBytes: number;
  durationMs: number;
}

export type AdminRunStatus = "pending" | "running" | "succeeded" | "failed" | "unknown";

/** Run summaries omit identifiers, connector aliases, payloads, tokens, and storage references. */
export interface SafeAdminRun {
  startedAt: string;
  actorName: string;
  subjectName: string;
  providerName: string;
  actionName: string;
  connectionName: string;
  status: AdminRunStatus;
  durationMs: number;
  inputBytes: number;
  outputBytes: number;
  errorCode?: string;
}

export interface AdminData {
  overview: AdminOverview | null;
  providers: AdminProvider[];
  actions: AdminAction[];
  connections: SafeAdminConnection[];
  runs: SafeAdminRun[];
}

export const emptyAdminData: AdminData = {
  overview: null,
  providers: [],
  actions: [],
  connections: [],
  runs: [],
};
