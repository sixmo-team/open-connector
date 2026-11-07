import type { StoredConnection, StoredSaasConnection } from "../../connection-store.ts";
import type { ResolvedCredential } from "../../core/types.ts";
import type { OAuthAuthorizationState } from "../../oauth/oauth-flow-service.ts";

export interface ConnectionRequest {
  connectionRequestId: string;
  service: string;
  status: "initiated" | "connected" | "failed" | "expired";
  appId: string | null;
  errorCode: string | null;
  errorMessage: string | null;
  expiresAt: string;
  createdAt: number;
  updatedAt: number;
}
export interface PendingConnectionRequest extends OAuthAuthorizationState {
  connectionName: string;
  connectionRequestId: string;
  owner: string;
  expiresAt: string;
  returnUri?: string;
  target?: Pick<StoredConnection, "id" | "revision">;
}
export interface PendingSaasRequest {
  connectionRequestId: string;
  connectionId: string;
  owner: string;
  service: string;
  connectionName: string;
  managedProjectId: string;
  providerConfigId: string;
  externalUserId: string;
  createdAt: string;
  expiresAt: string;
  returnUri?: string;
  target?: Pick<StoredConnection, "id" | "revision">;
  comment?: string | null;
}
export interface SaasCandidate {
  connectedAccountId: string;
  profile: StoredSaasConnection["profile"];
  status: StoredSaasConnection["status"];
  comment: string | null;
}
export interface SaasRequestLease {
  pending: PendingSaasRequest;
  leaseId: string;
  phase: "creating" | "pending" | "candidate";
  remoteRequestId: string | null;
  candidate?: SaasCandidate;
  pollAttempts: number;
}
/** Native local and managed authorization lifecycle, captured to a verified customer scope. */
export interface ConnectionRequestStore {
  create(pending: PendingConnectionRequest): Promise<void>;
  get(id: string, owner: string): Promise<ConnectionRequest | undefined>;
  claim(state: string): Promise<PendingConnectionRequest | undefined>;
  fail(id: string, errorCode: string, errorMessage: string): Promise<void>;
  complete(
    pending: PendingConnectionRequest,
    credential: ResolvedCredential,
    signal?: AbortSignal,
  ): Promise<string | undefined>;
  createSaas(pending: PendingSaasRequest): Promise<SaasRequestLease>;
  claimSaas(id: string, owner: string, now?: number): Promise<SaasRequestLease | undefined>;
  saveSaasRequest(lease: SaasRequestLease, remoteRequestId: string, expiresAt?: string): Promise<boolean>;
  saveSaasCandidate(lease: SaasRequestLease, candidate: SaasCandidate): Promise<boolean>;
  releaseSaas(lease: SaasRequestLease, nextPollAt: number, failed?: boolean): Promise<boolean>;
  failSaas(lease: SaasRequestLease, code: string, message: string): Promise<boolean>;
  getSaasReturnUri(id: string, owner: string): Promise<string | undefined>;
  cancelSaas(id: string, owner: string): Promise<void>;
  expireSaas(now?: number): Promise<void>;
  completeSaas(lease: SaasRequestLease): Promise<"connected" | "conflict" | "lease_lost">;
}
