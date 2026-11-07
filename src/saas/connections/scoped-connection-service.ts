import type { ConnectionServiceOptions } from "../../connection-service.ts";
import type { IOAuthCredentialRefresher } from "../../oauth/oauth-credential-refresh-service.ts";
import type { PostgresRefreshCoordinator } from "../oauth/postgres-refresh-coordinator.ts";

import { ConnectionService } from "../../connection-service.ts";

export type ScopedConnectionServiceOptions = ConnectionServiceOptions & {
  oauthCredentials: IOAuthCredentialRefresher;
  refreshCoordinator: PostgresRefreshCoordinator;
};

/** Bind native connection behavior to scoped stores and distributed OAuth refresh. */
export function createScopedConnectionService(options: ScopedConnectionServiceOptions): ConnectionService {
  const { refreshCoordinator, ...upstreamOptions } = options;
  return new ConnectionService({
    ...upstreamOptions,
    withOAuthRefreshLease: (connectionId, work) => refreshCoordinator.runExclusive(connectionId, work),
  });
}
