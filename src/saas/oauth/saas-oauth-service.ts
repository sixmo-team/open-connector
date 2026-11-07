import type { CatalogStore } from "../../catalog-store.ts";
import type { ConnectionSummary } from "../../connection-service.ts";
import type { IConnectionStore } from "../../connection-store.ts";
import type { CredentialProfile } from "../../core/types.ts";
import type { IOAuthClientConfigStore, OAuthClientConfigInput } from "../../oauth/oauth-client-config-service.ts";
import type {
  IOAuthStateStore,
  OAuthAuthorizationCompleteInput,
  LocalOAuthConnectionRequests,
} from "../../oauth/oauth-flow-service.ts";
import type { IProviderLoader } from "../../providers/provider-loader.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { SaasOAuthService as ManagedOAuthService } from "../saas-oauth-service.ts";
import type { ISecretCodec } from "../secrets/secret-codec.ts";
import type { ConnectionRequest, ConnectionRequestStore } from "../storage/connection-request-store.ts";
import type { SaasRuntimeConnectionStore } from "../storage/postgres-runtime-database.ts";

import { createHash } from "node:crypto";
import { ConnectionService } from "../../connection-service.ts";
import { assertProcessingActive, captureRequestProcessing, remainingProcessingMs } from "../../core/cancellation.ts";
import { OAuthClientConfigService, readOAuthClientConfigMetadata } from "../../oauth/oauth-client-config-service.ts";
import { OAuthFlowService, OAuthFlowError } from "../../oauth/oauth-flow-service.ts";

export interface SaasOAuthServiceOptions {
  scope: Readonly<SaasRequestScope>;
  catalog: CatalogStore;
  providerLoader: IProviderLoader;
  connectionStore: IConnectionStore & Pick<SaasRuntimeConnectionStore, "getSafeConnection">;
  oauthStateStore: IOAuthStateStore;
  connectionRequests: LocalOAuthConnectionRequests;
  oauthClientConfigStore: IOAuthClientConfigStore;
  callbackOrigin: string;
  secretCodec?: ISecretCodec;
  isCustomClientConfigAllowed?: (service: string) => boolean;
  managedOAuth?: ManagedOAuthService;
}
export interface SaasOAuthStartOptions {
  authorizationOptionIds?: string[];
  clientConfig?: OAuthClientConfigInput;
}
export interface SaasOAuthStart {
  authorizeUrl: string;
  connectionRequestId?: string;
  stateHandle?: string;
  status?: "initiated";
  expiresAt?: string;
}
export interface SaasOAuthRequestStatus {
  request: ConnectionRequest;
  connection?: SaasOAuthCompletion;
}
export interface SaasOAuthCompletion {
  id: string;
  localConnectionId: string;
  service: string;
  connectionName: string;
  visibility: "user" | "workspace";
  status: "active" | "reconnect_required";
  profile: CredentialProfile;
}
/** Native OAuth with no alternate storage or authority: all adapters capture the verified scope. */
export class SaasOAuthService {
  private readonly scope: Readonly<SaasRequestScope>;
  private readonly connections: ConnectionService;
  private readonly flow: OAuthFlowService;
  private readonly options: SaasOAuthServiceOptions;
  constructor(options: SaasOAuthServiceOptions) {
    this.options = options;
    const permissions = [...options.scope.permissions];
    Object.freeze(permissions);
    this.scope = captureRequestProcessing(Object.freeze({ ...options.scope, permissions }));
    required(this.scope.oauthSessionId, "oauthSessionId");
    this.requiredLocalConnectionId();
    if (this.scope.actorUserId !== this.scope.subjectUserId)
      throw new Error("OAuth requires the exact interactive owner");
    this.connections = new ConnectionService({
      catalog: options.catalog,
      providerLoader: options.providerLoader,
      store: options.connectionStore,
    });
    this.flow = new OAuthFlowService({
      connections: this.connections,
      clientConfigs: new OAuthClientConfigService({
        catalog: options.catalog,
        origin: options.callbackOrigin,
        store: options.oauthClientConfigStore,
      }),
      providerLoader: options.providerLoader,
      states: {
        set: (state) => options.oauthStateStore.set(state),
        deleteCreatedBefore: (cutoff) => options.oauthStateStore.deleteCreatedBefore(cutoff),
        take: (state) =>
          options.oauthStateStore.take(state, {
            connectionName: connectorAlias(this.requiredLocalConnectionId()),
            oauthSessionId: required(this.scope.oauthSessionId, "oauthSessionId"),
          }),
      },
      requests: options.connectionRequests,
      secretCodec: options.secretCodec,
      isCustomClientConfigAllowed: options.isCustomClientConfigAllowed,
      authorizationSessionId: this.scope.oauthSessionId,
    });
  }
  async start(service: string, options: SaasOAuthStartOptions = {}): Promise<SaasOAuthStart> {
    this.assertPurpose("oauth:start");
    assertProcessingActive(this.scope);
    service = required(service, "service");
    const connectionName = connectorAlias(this.requiredLocalConnectionId());
    const target = await this.options.connectionStore.get(service, connectionName);
    if (target && target.source !== "saas" && target.credential.authType !== "oauth2")
      throw new OAuthFlowError("unsupported_auth_type", "The selected connection does not use OAuth.");
    if (this.options.managedOAuth) {
      const remote = await this.options.managedOAuth.start({
        service,
        connectionName,
        owner: this.scope.subjectUserId,
        target,
        authorizationOptionIds: options.authorizationOptionIds,
        clientConfig: options.clientConfig,
        signal: this.signal(),
      });
      if (remote)
        return {
          authorizeUrl: remote.authorizationUrl,
          connectionRequestId: remote.connectionRequestId,
          stateHandle: remote.stateHandle,
          status: remote.status,
          expiresAt: remote.expiresAt,
        };
    }
    const existingConfig =
      target?.source !== "saas" && target?.credential.authType === "oauth2"
        ? readOAuthClientConfigMetadata(service, target.credential.metadata)
        : undefined;
    const started = await this.flow.startAuthorization({
      ...options,
      clientConfig: options.clientConfig ?? existingConfig,
      service,
      connectionName,
      signal: this.signal(),
    });
    return { authorizeUrl: started.authorizationUrl };
  }
  async getRequest(id: string): Promise<SaasOAuthRequestStatus | undefined> {
    this.assertPurpose("oauth:complete");
    assertProcessingActive(this.scope);
    const owner = this.scope.subjectUserId;
    const request = this.options.managedOAuth
      ? await this.options.managedOAuth.sync(required(id, "connectionRequestId"), owner, this.signal())
      : await this.options.connectionRequests.get(required(id, "connectionRequestId"), owner);
    if (!request) return undefined;
    if (request.status !== "connected") return { request };
    if (!request.appId) throw new Error("Connected OAuth request has no stored connection");
    const stored = await this.options.connectionStore.getById(request.appId);
    if (
      !stored ||
      stored.service !== request.service ||
      stored.connectionName !== connectorAlias(this.requiredLocalConnectionId())
    )
      throw new Error("Connected OAuth request no longer matches its connection");
    if (stored.source === "saas" && stored.reference.localRequestId !== id)
      throw new Error("Connected OAuth request was superseded");
    const summary = await this.connections.getConnectionSummary(stored.service, stored.connectionName, stored.id);
    if (!summary?.configured) throw new Error("Connected OAuth request is unavailable");
    return { request, connection: await this.toCompletion(summary) };
  }
  async cancelRequest(id: string): Promise<SaasOAuthRequestStatus | undefined> {
    this.assertPurpose("oauth:complete");
    assertProcessingActive(this.scope);
    const requests = this.options.connectionRequests as LocalOAuthConnectionRequests &
      Partial<Pick<ConnectionRequestStore, "cancelSaas">>;
    if (!requests.cancelSaas) throw new Error("Managed OAuth cancellation is not configured");
    // get() checks the original signed session and local lineage before any cancellation side effect.
    if (!(await requests.get(required(id, "connectionRequestId"), this.scope.subjectUserId))) return undefined;
    await requests.cancelSaas(id, this.scope.subjectUserId);
    const request = await requests.get(id, this.scope.subjectUserId);
    return request ? { request } : undefined;
  }
  async complete(input: OAuthAuthorizationCompleteInput): Promise<SaasOAuthCompletion> {
    this.assertPurpose("oauth:complete");
    assertProcessingActive(this.scope);
    validateOAuthCallback(input);
    const state = required(input.state, "state");
    const connectionName = connectorAlias(this.requiredLocalConnectionId());
    const completed = (await this.connections.listConnections()).find(
      (connection) => connection.connectionName === connectionName && connection.configured,
    );
    if (completed) {
      const stored = await this.options.connectionStore.getById(completed.id);
      if (
        stored?.source !== "saas" &&
        stored?.credential.authType === "oauth2" &&
        stored.credential.metadata.saasOAuthSessionId === this.scope.oauthSessionId &&
        stored.credential.metadata.oauthAuthorizationId === state
      )
        return this.toCompletion(completed);
    }
    const result = await this.flow.completeAuthorization({ ...input, signal: this.signal(input.signal) });
    const connection = await this.connections.getConnectionSummary(result.service, connectionName);
    if (!connection?.configured) throw new Error("OAuth completion did not create a scoped connection");
    return this.toCompletion(connection);
  }
  private async toCompletion(connection: ConnectionSummary): Promise<SaasOAuthCompletion> {
    if (connection.connectionName !== connectorAlias(this.requiredLocalConnectionId()))
      throw new Error("OAuth completion connection mismatch");
    const stored = await this.options.connectionStore.getSafeConnection(connection.id);
    if (
      !stored ||
      stored.service !== connection.service ||
      stored.localConnectionId !== this.requiredLocalConnectionId() ||
      stored.subjectUserId !== this.scope.subjectUserId
    )
      throw new Error("OAuth completion metadata no longer matches the current owner");
    return {
      id: connection.id,
      localConnectionId: this.requiredLocalConnectionId(),
      service: connection.service,
      connectionName: connection.connectionName,
      visibility: stored.visibility,
      status: connection.status === "reauth_required" ? "reconnect_required" : "active",
      profile: connection.profile,
    };
  }
  private signal(signal?: AbortSignal): AbortSignal | undefined {
    const remaining = remainingProcessingMs(this.scope);
    const signals = [
      this.scope.requestSignal,
      signal,
      remaining === undefined ? undefined : AbortSignal.timeout(remaining),
    ].filter((value): value is AbortSignal => value !== undefined);
    const bounded = signals.length ? AbortSignal.any(signals) : undefined;
    bounded?.throwIfAborted();
    return bounded;
  }
  private assertPurpose(purpose: "oauth:start" | "oauth:complete"): void {
    if (this.scope.purpose !== purpose) throw new Error("OAuth scope purpose mismatch");
  }
  private requiredLocalConnectionId(): string {
    return required(this.scope.localConnectionId, "localConnectionId");
  }
}
export function connectorAlias(localConnectionId: string): string {
  return `oauth-${createHash("sha256").update(required(localConnectionId, "localConnectionId")).digest("base64url")}`;
}
/** Check provenance before a state/request is consumed; the original query remains unmodified. */
export function validateOAuthCallback(input: OAuthAuthorizationCompleteInput): void {
  const fail = (): never => {
    throw new OAuthFlowError("invalid_oauth_state", "OAuth callback does not match the verified state and code.");
  };
  if (!input.state || !input.code || input.state.length > 4096 || input.code.length > 4096) fail();
  if (input.callbackQuery !== undefined) {
    if (Buffer.byteLength(input.callbackQuery) > 16384) fail();
    const params = new URLSearchParams(input.callbackQuery);
    for (const key of ["state", "code"] as const) {
      const values = params.getAll(key);
      if (values.length !== 1 || values[0] !== input[key]) fail();
    }
  }
  if (input.callbackParameters !== undefined) {
    const entries = Object.entries(input.callbackParameters);
    if (entries.length > 64 || Buffer.byteLength(JSON.stringify(input.callbackParameters)) > 32768) fail();
    for (const [key, value] of entries)
      if (key.length > 128 || typeof value !== "string" || value.length > 4096) fail();
    for (const key of ["state", "code"] as const) {
      if (input.callbackParameters[key] !== undefined && input.callbackParameters[key] !== input[key]) fail();
    }
    if (input.callbackQuery !== undefined) {
      const params = new URLSearchParams(input.callbackQuery);
      for (const [key, value] of entries) if (params.getAll(key).at(-1) !== value) fail();
    }
  }
}
function required(value: string | undefined, name: string): string {
  if (!value?.trim()) throw new Error(`OAuth requires ${name}`);
  return value;
}
