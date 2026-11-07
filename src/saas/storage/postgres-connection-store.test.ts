import type { Pool } from "pg";

import { randomUUID } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { ConnectionService } from "../../connection-service.ts";
import { PostgresConnectionStore } from "./postgres-connection-store.ts";

describe("PostgresConnectionStore", () => {
  it("returns connection_not_found through the native consumer for a foreign non-UUID connection ID", async () => {
    const store = new PostgresConnectionStore(
      {} as Pool,
      {
        tenantId: randomUUID(),
        workspaceId: randomUUID(),
        actorUserId: randomUUID(),
        subjectUserId: randomUUID(),
        workspaceRole: "owner",
        purpose: "connection:write",
        permissions: ["connection:write"],
        localConnectionId: randomUUID(),
      },
      {} as never,
    );
    const connections = new ConnectionService({
      store,
      catalog: {} as never,
      providerLoader: {} as never,
    });

    await expect(connections.getStoredConnection("foreign-opaque-connection")).rejects.toMatchObject({
      code: "connection_not_found",
    });
  });

  it("treats non-UUID legacy connector IDs as absent without querying PostgreSQL", async () => {
    const connect = vi.fn();
    const store = new PostgresConnectionStore(
      { connect } as unknown as Pool,
      {
        tenantId: "tenant",
        workspaceId: "workspace",
        actorUserId: "actor",
        subjectUserId: "subject",
        workspaceRole: "owner",
        purpose: "connection:write",
        permissions: ["connection:write"],
        localConnectionId: randomUUID(),
        connectorConnectionId: "legacy-opaque-id",
      },
      {} as never,
    );

    await expect(store.hasRevocationReceipt("legacy-opaque-id")).resolves.toBe(false);
    await expect(store.resumeRevocation("legacy-opaque-id")).resolves.toBe(false);
    await expect(store.blockForRevocation("legacy-opaque-id")).resolves.toBeUndefined();
    expect(connect).not.toHaveBeenCalled();
  });
});
