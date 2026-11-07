import type { SafeConnectionSummary } from "../contracts.ts";
import type { SafeStoredConnection } from "../storage/postgres-connection-store.ts";

export function toSafeConnectionSummary(connection: SafeStoredConnection): SafeConnectionSummary {
  return {
    id: connection.id,
    localConnectionId: connection.localConnectionId,
    service: connection.service,
    connectionName: connection.connectionName,
    visibility: connection.visibility,
    status: connection.status,
    profile: connection.profile,
    createdAt: connection.createdAt,
    updatedAt: connection.updatedAt,
  };
}
