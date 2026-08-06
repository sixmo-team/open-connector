import type { CatalogStore } from "../../catalog-store.ts";
import type { ConnectionSummary, IConnectionStore } from "../../connection-service.ts";
import type { CredentialProfile } from "../../core/types.ts";
import type { IOAuthClientConfigStore } from "../../oauth/oauth-client-config-service.ts";
import type { IOAuthStateStore } from "../../oauth/oauth-flow-service.ts";
import type { IProviderLoader } from "../../providers/provider-loader.ts";
import type { SaasRequestScope } from "../contracts.ts";

import { createHash } from "node:crypto";
import { ConnectionService } from "../../connection-service.ts";
import { OAuthClientConfigService } from "../../oauth/oauth-client-config-service.ts";
import { OAuthFlowService } from "../../oauth/oauth-flow-service.ts";

export interface SaasOAuthServiceOptions {
  scope: Readonly<SaasRequestScope>;
  catalog: CatalogStore;
  providerLoader: IProviderLoader;
  connectionStore: IConnectionStore;
  oauthStateStore: IOAuthStateStore;
  oauthClientConfigStore: IOAuthClientConfigStore;
  callbackOrigin: string;
}

export interface SaasOAuthCompletion {
  id: string;
  localConnectionId: string;
  service: string;
  connectionName: string;
  visibility: "user";
  status: "active";
  profile: CredentialProfile;
}

/** Runs the unchanged upstream OAuth flow against stores bound to one verified SaaS scope. */
export class SaasOAuthService {
  private readonly scope: Readonly<SaasRequestScope>;
  private readonly connectionStore: IConnectionStore;
  private readonly connections: ConnectionService;
  private readonly flow: OAuthFlowService;

  constructor(options: SaasOAuthServiceOptions) {
    this.scope = options.scope;
    this.connectionStore = options.connectionStore;
    const oauthSessionId = required(this.scope.oauthSessionId, "oauthSessionId");
    this.connections = new ConnectionService({
      catalog: options.catalog,
      providerLoader: options.providerLoader,
      store: {
        get: (service, connectionName) => options.connectionStore.get(service, connectionName),
        set: (service, connectionName, credential) =>
          options.connectionStore.set(
            service,
            connectionName,
            credential.authType === "oauth2"
              ? {
                  ...credential,
                  metadata: { ...credential.metadata, saasOAuthSessionId: oauthSessionId },
                }
              : credential,
          ),
        updateCredential: (connection) => options.connectionStore.updateCredential(connection),
        delete: (service, connectionName) => options.connectionStore.delete(service, connectionName),
        list: () => options.connectionStore.list(),
      },
    });
    const clientConfigs = new OAuthClientConfigService({
      catalog: options.catalog,
      origin: options.callbackOrigin,
      store: options.oauthClientConfigStore,
    });
    const expectedConnectionName = connectorAlias(this.requiredLocalConnectionId());
    this.flow = new OAuthFlowService({
      clientConfigs,
      connections: this.connections,
      states: {
        set: async (state) => {
          if (state.connectionName !== expectedConnectionName) throw new Error("OAuth connection binding mismatch");
          await options.oauthStateStore.set(state);
        },
        take: async (state) => {
          const pending = await options.oauthStateStore.take(state);
          return pending?.connectionName === expectedConnectionName ? pending : undefined;
        },
      },
    });
  }

  async start(service: string): Promise<{ authorizeUrl: string }> {
    this.assertPurpose("oauth:start");
    const started = await this.flow.startAuthorization({
      service: required(service, "service"),
      connectionName: connectorAlias(this.requiredLocalConnectionId()),
    });
    return { authorizeUrl: started.authorizationUrl };
  }

  async complete(input: { state: string; code: string }): Promise<SaasOAuthCompletion> {
    this.assertPurpose("oauth:complete");
    const connectionName = connectorAlias(this.requiredLocalConnectionId());
    const state = required(input.state, "state");
    const code = required(input.code, "code");

    const completed = (await this.connections.listConnections()).find(
      (connection) => connection.connectionName === connectionName && connection.configured,
    );
    if (completed) {
      const stored = await this.connectionStore.get(completed.service, connectionName);
      if (
        stored?.credential.authType === "oauth2" &&
        stored.credential.metadata.saasOAuthSessionId === required(this.scope.oauthSessionId, "oauthSessionId")
      ) {
        return this.toCompletion(completed);
      }
    }

    const result = await this.flow.completeAuthorization({ state, code });
    const connection = await this.connections.getConnectionSummary(result.service, connectionName);
    if (!connection?.configured) throw new Error("OAuth completion did not create a scoped connection");
    return this.toCompletion(connection);
  }

  private toCompletion(connection: ConnectionSummary): SaasOAuthCompletion {
    if (connection.connectionName !== connectorAlias(this.requiredLocalConnectionId())) {
      throw new Error("OAuth completion connection mismatch");
    }
    return {
      id: connection.id,
      localConnectionId: this.requiredLocalConnectionId(),
      service: connection.service,
      connectionName: connection.connectionName,
      visibility: "user",
      status: "active",
      profile: connection.profile,
    };
  }

  private assertPurpose(expected: "oauth:start" | "oauth:complete"): void {
    if (this.scope.purpose !== expected) throw new Error("OAuth scope purpose mismatch");
  }

  private requiredLocalConnectionId(): string {
    return required(this.scope.localConnectionId, "localConnectionId");
  }
}

/** Opaque, deterministic connector-local alias; the backend stores the same derivation. */
export function connectorAlias(localConnectionId: string): string {
  return `oauth-${createHash("sha256").update(required(localConnectionId, "localConnectionId")).digest("base64url")}`;
}

function required(value: string | undefined, name: string): string {
  const normalized = value?.trim();
  if (!normalized) throw new TypeError(`${name} is required`);
  return normalized;
}
