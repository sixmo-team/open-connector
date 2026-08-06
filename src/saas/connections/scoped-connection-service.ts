import type {
  ConnectWithCredentialInput,
  ConnectWithoutAuthInput,
  ConnectionServiceOptions,
  ConnectionSummary,
  DisconnectedConnectionSummary,
  ExecutionConnection,
  IConnectionStore,
  StoredConnection,
} from "../../connection-service.ts";
import type { ResolvedCredential } from "../../core/types.ts";
import type { IOAuthCredentialRefresher } from "../../oauth/oauth-credential-refresh-service.ts";
import type { PostgresRefreshCoordinator } from "../oauth/postgres-refresh-coordinator.ts";

import { ConnectionService } from "../../connection-service.ts";

export type ScopedConnectionServiceOptions = ConnectionServiceOptions & {
  oauthCredentials: IOAuthCredentialRefresher;
  refreshCoordinator: PostgresRefreshCoordinator;
};

/** Build a fresh request-scoped service with distributed OAuth refresh enabled. */
export function createScopedConnectionService(options: ScopedConnectionServiceOptions): ScopedConnectionService {
  const { refreshCoordinator, ...upstreamOptions } = options;
  const upstream = new ConnectionService(upstreamOptions);
  return new ScopedConnectionService(upstream, options.store, refreshCoordinator);
}

/** Request-scoped facade that adds cross-replica refresh serialization without changing upstream code. */
export class ScopedConnectionService {
  private readonly upstream: ConnectionService;
  private readonly store: IConnectionStore;
  private readonly refreshes: PostgresRefreshCoordinator;

  constructor(upstream: ConnectionService, store: IConnectionStore, refreshes: PostgresRefreshCoordinator) {
    this.upstream = upstream;
    this.store = store;
    this.refreshes = refreshes;
  }

  async listConnections(): Promise<ConnectionSummary[]> {
    return await this.upstream.listConnections();
  }

  async listConnectionsByService(service: string): Promise<ConnectionSummary[]> {
    return await this.upstream.listConnectionsByService(service);
  }

  async listAuthenticatedServices(services: string[]): Promise<string[]> {
    return await this.upstream.listAuthenticatedServices(services);
  }

  async getConnectionSummary(service: string, connectionName?: string): Promise<ConnectionSummary | undefined> {
    return await this.upstream.getConnectionSummary(service, connectionName);
  }

  async resolveForExecution(service: string, connectionName?: string): Promise<ExecutionConnection> {
    return await this.withRefreshLease(service, connectionName, () =>
      this.upstream.resolveForExecution(service, connectionName),
    );
  }

  async getCredential(service: string, connectionName?: string): Promise<ResolvedCredential | undefined> {
    return await this.withRefreshLease(service, connectionName, () =>
      this.upstream.getCredential(service, connectionName),
    );
  }

  forConnection(connectionName?: string): Pick<ScopedConnectionService, "getCredential"> {
    return { getCredential: (service) => this.getCredential(service, connectionName) };
  }

  async connectWithoutAuth(service: string, input: ConnectWithoutAuthInput = {}): Promise<ConnectionSummary> {
    return await this.upstream.connectWithoutAuth(service, input);
  }

  async connectWithApiKey(service: string, input: ConnectWithCredentialInput): Promise<ConnectionSummary> {
    return await this.upstream.connectWithApiKey(service, input);
  }

  async connectWithCustomCredential(service: string, input: ConnectWithCredentialInput): Promise<ConnectionSummary> {
    return await this.upstream.connectWithCustomCredential(service, input);
  }
  async replaceWithApiKey(target: StoredConnection, input: ConnectWithCredentialInput): Promise<ConnectionSummary> {
    return await this.upstream.replaceWithApiKey(target, input);
  }

  async replaceWithCustomCredential(
    target: StoredConnection,
    input: ConnectWithCredentialInput,
  ): Promise<ConnectionSummary> {
    return await this.upstream.replaceWithCustomCredential(target, input);
  }

  async setOAuthCredential(
    service: string,
    credential: Extract<ResolvedCredential, { authType: "oauth2" }>,
    connectionName?: string,
  ): Promise<ConnectionSummary> {
    return await this.upstream.setOAuthCredential(service, credential, connectionName);
  }

  async disconnect(
    service: string,
    connectionName?: string,
  ): Promise<ConnectionSummary | DisconnectedConnectionSummary> {
    return await this.upstream.disconnect(service, connectionName);
  }

  assertProviderAvailable(service: string): void {
    this.upstream.assertProviderAvailable(service);
  }

  private async withRefreshLease<T>(service: string, connectionName: string | undefined, operation: () => Promise<T>) {
    if (connectionName === undefined) return await operation();
    const connection = await this.store.get(service, connectionName);
    if (!connection) return await operation();
    return await this.refreshes.runExclusive(connection.id, operation);
  }
}
