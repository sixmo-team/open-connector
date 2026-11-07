import type { SaasRequestScope } from "../contracts.ts";
import type { PostgresTestDatabase } from "../testing/postgres-test-database.ts";

import { Pool } from "pg";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { withSecretCleanup } from "../secrets/secret-codec.ts";
import { createPostgresTestDatabase, postgresTestUrl } from "../testing/postgres-test-database.ts";
import { withScopedClient } from "./scoped-query.ts";

const url = postgresTestUrl();
let database: PostgresTestDatabase;
let pool: Pool;
const scope: SaasRequestScope = {
  tenantId: "processing-tenant",
  workspaceId: "processing-workspace",
  actorUserId: "actual-actor",
  subjectUserId: "actual-actor",
  workspaceRole: "member",
  purpose: "connection:write",
  permissions: ["connection:write"],
};

describe.skipIf(!url)("actual PostgreSQL processing fences", () => {
  beforeAll(async () => {
    database = await createPostgresTestDatabase(url!);
    pool = new Pool({ connectionString: database.adminConnectionString, max: 1 });
    await pool.query("CREATE TEMP TABLE processing_probe (value integer)");
  }, 30_000);
  afterEach(async () => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    await pool.query("DELETE FROM processing_probe");
  });
  afterAll(async () => {
    await pool?.end();
    await database?.dispose();
  });

  it("rolls back a real write when its deadline expires before commit", async () => {
    let now = 10_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    const request = { ...scope, processingDeadlineMs: now + 120_000, requestSignal: new AbortController().signal };
    await expect(
      withScopedClient(pool, request, async (client) => {
        await client.query("INSERT INTO processing_probe VALUES (1)");
        now = request.processingDeadlineMs;
      }),
    ).rejects.toThrow(/deadline/i);
    expect((await pool.query("SELECT value FROM processing_probe")).rows).toEqual([]);
  });

  it.each([0, 100])(
    "never commits compensation beyond the original hard deadline with %i milliseconds remaining",
    async (remaining) => {
      let now = 10_000;
      vi.spyOn(Date, "now").mockImplementation(() => now);
      const request = {
        ...scope,
        processingDeadlineMs: now + remaining,
        requestSignal: AbortSignal.abort(new Error("caller cancelled")),
      };
      await expect(
        withSecretCleanup(request, (cleanup) =>
          withScopedClient(pool, cleanup, async (client) => {
            await client.query("INSERT INTO processing_probe VALUES (3)");
            now = request.processingDeadlineMs;
          }),
        ),
      ).rejects.toThrow(/deadline/i);
      expect((await pool.query("SELECT value FROM processing_probe")).rows).toEqual([]);
    },
  );

  it("cancels a queued caller without executing a late write after a pooled client becomes free", async () => {
    const held = await pool.connect();
    const controller = new AbortController();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    let invoked = false;
    const pending = withScopedClient(pool, { ...scope, requestSignal: controller.signal }, async (client) => {
      invoked = true;
      await client.query("INSERT INTO processing_probe VALUES (2)");
    });
    controller.abort(new Error("request cancelled"));
    const outcomePromise = Promise.race([
      pending.then(
        () => "executed",
        () => "cancelled",
      ),
      new Promise<string>((resolve) => setTimeout(() => resolve("still queued"), 25)),
    ]);
    await vi.advanceTimersByTimeAsync(25);
    const outcome = await outcomePromise;
    vi.useRealTimers();
    held.release();
    await pending.catch(() => undefined);
    expect(outcome).toBe("cancelled");
    expect(invoked).toBe(false);
    expect((await pool.query("SELECT value FROM processing_probe")).rows).toEqual([]);
  });
});
