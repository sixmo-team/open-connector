import type { Pool } from "pg";

import { randomUUID } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { PostgresConnectionStore } from "./postgres-connection-store.ts";

describe("PostgresConnectionStore", () => {
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
