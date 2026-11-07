import type { SaasRequestScope } from "../contracts.ts";
import type { S3Client } from "@aws-sdk/client-s3";

import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PostgresConnectionStore } from "../storage/postgres-connection-store.ts";
import { PostgresTransitFileStore } from "../storage/postgres-transit-file-store.ts";
import { withScopedClient } from "../storage/scoped-query.ts";
import { createNativePostgresHarness, MemoryConnectionSecrets } from "../testing/native-store-fixtures.ts";
import { createSeaweedFsS3Client, SeaweedFsTransitFileService } from "./seaweedfs-transit-files.ts";

const harness = createNativePostgresHarness();

// Real PostgreSQL and the installed S3 transport; this local protocol fixture is not a SeaweedFS/cloud acceptance test.
describe.skipIf(!harness.enabled)("native scoped transit files over PostgreSQL and S3 HTTP", () => {
  const objects = new Map<string, Buffer>();
  let requests = 0;
  let failDeletes = false;
  let corruptRead: Buffer | undefined;
  let client: S3Client;
  const server = createServer(async (request, response) => {
    requests += 1;
    const key = new URL(request.url!, "http://fixture").pathname;
    try {
      if (request.method === "PUT") {
        const chunks: Buffer[] = [];
        for await (const chunk of request) chunks.push(Buffer.from(chunk));
        objects.set(key, Buffer.concat(chunks));
        response.writeHead(200, { etag: '"fixture"' }).end();
      } else if (request.method === "GET") {
        const bytes = corruptRead ?? objects.get(key);
        if (!bytes) {
          response.writeHead(404).end();
          return;
        }
        // No content-length: the consumer must count actual bytes and check private PG metadata.
        response.writeHead(200, { "content-type": "application/octet-stream" });
        response.write(bytes.subarray(0, 2));
        response.end(bytes.subarray(2));
      } else if (request.method === "DELETE") {
        if (failDeletes) {
          response
            .writeHead(403, { "content-type": "application/xml" })
            .end("<Error><Code>AccessDenied</Code></Error>");
          return;
        }
        objects.delete(key);
        response.writeHead(204).end();
      } else response.writeHead(405).end();
    } catch {
      response.writeHead(500).end();
    }
  });

  beforeAll(async () => {
    const listening = once(server, "listening");
    server.listen(0, "127.0.0.1");
    await listening;
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("S3 fixture did not bind TCP");
    client = createSeaweedFsS3Client({
      seaweedFsEndpoint: `http://127.0.0.1:${address.port}`,
      seaweedFsAccessKeyId: "fixture-access-key",
      seaweedFsSecretAccessKey: "fixture-secret-key",
    });
  });
  afterAll(async () => {
    client?.destroy();
    if (server.listening) {
      server.closeAllConnections();
      const closed = Promise.withResolvers<void>();
      server.close((error) => (error ? closed.reject(error) : closed.resolve()));
      await closed.promise;
    }
  });

  function service(scope: Readonly<SaasRequestScope>): SeaweedFsTransitFileService {
    return new SeaweedFsTransitFileService({
      client,
      bucket: "transit",
      metadata: new PostgresTransitFileStore(harness.pool, scope),
      scope,
      publicOrigin: "https://connector.internal",
      ttlSeconds: 60,
      maxBytes: 4,
      requestTimeoutMs: 2_000,
    });
  }

  it("preserves native bytes/name/MIME with private RLS metadata and retries durable orphan deletion", async () => {
    const { scope } = harness.forScope({ purpose: "action:execute:v2", permissions: ["action:execute:v2"] });
    const owner = service(scope);
    const upload = await owner.create(
      new File([new Uint8Array([0, 127, 128, 255])], "résumé-文.bin", {
        type: "application/octet-stream",
      }),
    );
    const fresh = service(scope);
    const read = await fresh.read(upload.fileId);
    expect(read.file).toBeInstanceOf(File);
    expect(read.file.name).toBe("résumé-文.bin");
    expect(read.file.type).toBe("application/octet-stream");
    expect(new Uint8Array(await read.file.arrayBuffer())).toEqual(new Uint8Array([0, 127, 128, 255]));
    const response = await fresh.response(upload.fileId);
    expect(response.headers.get("content-length")).toBe("4");
    expect(response.headers.get("content-disposition")).toBe(
      "attachment; filename=\"r_sum_-_.bin\"; filename*=UTF-8''r%C3%A9sum%C3%A9-%E6%96%87.bin",
    );
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(new Uint8Array([0, 127, 128, 255]));
    const metadata = new PostgresTransitFileStore(harness.pool, scope);
    expect(await metadata.get(upload.fileId)).toMatchObject({
      name: "résumé-文.bin",
      status: "available",
      byteSize: 4,
    });
    for (const other of [
      { ...scope, tenantId: randomUUID() },
      { ...scope, workspaceId: randomUUID() },
      { ...scope, actorUserId: "another-user", subjectUserId: "another-user" },
    ]) {
      const before = requests;
      await expect(service(other).read(upload.fileId)).rejects.toMatchObject({ status: 404 });
      expect(await service(other).delete(upload.fileId)).toBe(false);
      expect(
        await withScopedClient(
          harness.pool,
          other,
          async (sql) =>
            (await sql.query("SELECT file_name FROM integration_runtime.transit_files WHERE id = $1", [upload.fileId]))
              .rows,
        ),
      ).toEqual([]);
      expect(requests).toBe(before);
    }
    corruptRead = Buffer.from([0, 127, 128, 254]);
    try {
      await expect(fresh.response(upload.fileId)).rejects.toThrow(/digest does not match/);
    } finally {
      corruptRead = undefined;
    }
    corruptRead = Buffer.from([0, 127, 128, 255, 1]);
    try {
      await expect(fresh.response(upload.fileId)).rejects.toMatchObject({ status: 413 });
    } finally {
      corruptRead = undefined;
    }

    const neighborScope = { ...scope, actorUserId: "neighbor", subjectUserId: "neighbor" };
    const neighbor = await service(neighborScope).create(new File(["safe"], "neighbor.txt", { type: "text/plain" }));
    failDeletes = true;
    try {
      await expect(owner.delete(upload.fileId)).rejects.toMatchObject({
        code: "transit_file_reconciliation_required",
        stage: "object_delete",
        markerWritten: true,
      });
    } finally {
      failDeletes = false;
    }
    expect(await metadata.get(upload.fileId)).toMatchObject({ status: "reconcile", name: "résumé-文.bin" });
    await withScopedClient(harness.pool, scope, (sql) =>
      sql.query(
        "UPDATE integration_runtime.transit_files SET expires_at = clock_timestamp() - interval '1 second' WHERE id = $1",
        [upload.fileId],
      ),
    );
    await service(scope).cleanupExpired();
    expect(await metadata.get(upload.fileId)).toBeUndefined();
    expect(await service(neighborScope).read(neighbor.fileId)).toMatchObject({ name: "neighbor.txt", sizeBytes: 4 });
    expect(objects.size).toBe(1);
    expect(await service(neighborScope).delete(neighbor.fileId)).toBe(true);
    expect(objects.size).toBe(0);
  });

  it("keeps shared-credential output private to Bob and erases only Bob files through exact lifecycle authority", async () => {
    const alice = harness.forScope({ purpose: "connection:write", permissions: ["connection:write"] }).scope;
    const secrets = new MemoryConnectionSecrets();
    const connections = new PostgresConnectionStore(harness.pool, alice, secrets);
    const shared = await connections.set("slackbot", "shared", {
      authType: "api_key",
      apiKey: "alice-private-credential",
      values: {},
      profile: { accountId: "shared-account", displayName: "Shared", grantedScopes: [] },
      metadata: { providerAccountVerified: true },
    });
    await connections.updateVisibilityById(shared.id, "workspace");
    const privateConnections = new PostgresConnectionStore(
      harness.pool,
      { ...alice, localConnectionId: randomUUID() },
      secrets,
    );
    const privateConnection = await privateConnections.set("slackbot", "private", {
      authType: "api_key",
      apiKey: "alice-other-private-credential",
      values: {},
      profile: { accountId: "private-account", displayName: "Private", grantedScopes: [] },
      metadata: { providerAccountVerified: true },
    });
    const bob = randomUUID();
    const sharedAction: SaasRequestScope = {
      ...alice,
      actorUserId: bob,
      connectorConnectionId: shared.id,
      purpose: "action:execute:v2",
      permissions: ["action:execute:v2"],
    };
    const bobFiles: SaasRequestScope = {
      ...sharedAction,
      subjectUserId: bob,
      purpose: "file:read",
      permissions: ["file:read"],
    };
    const neighborId = randomUUID();
    const neighbor: SaasRequestScope = { ...alice, actorUserId: neighborId, subjectUserId: neighborId };
    expect(await new PostgresConnectionStore(harness.pool, sharedAction, secrets).getById(shared.id)).toBeDefined();
    expect(
      await new PostgresConnectionStore(
        harness.pool,
        { ...sharedAction, localConnectionId: undefined },
        secrets,
      ).getById(privateConnection.id),
    ).toBeUndefined();
    const aliceFile = await service(alice).create(new File(["alic"], "alice.txt"));
    const neighborFile = await service(neighbor).create(new File(["safe"], "neighbor.txt"));
    const output = await service(sharedAction).create(new File(["bob!"], "bob.txt"));
    expect(await service(bobFiles).read(output.fileId)).toMatchObject({ name: "bob.txt", sizeBytes: 4 });
    expect(await service(sharedAction).read(output.fileId)).toMatchObject({ name: "bob.txt" });
    const row = await withScopedClient(
      harness.pool,
      sharedAction,
      async (sql) =>
        (
          await sql.query<{ subject_user_id: string }>(
            "SELECT subject_user_id FROM integration_runtime.transit_files WHERE id=$1",
            [output.fileId],
          )
        ).rows[0],
    );
    expect(row?.subject_user_id).toBe(bob);
    for (const denied of [
      alice,
      neighbor,
      { ...bobFiles, tenantId: randomUUID() },
      { ...bobFiles, workspaceId: randomUUID() },
    ]) {
      const before = requests;
      await expect(service(denied).read(output.fileId)).rejects.toMatchObject({ status: 404 });
      expect(await service(denied).delete(output.fileId)).toBe(false);
      expect(
        await withScopedClient(
          harness.pool,
          denied,
          async (sql) =>
            (await sql.query("SELECT id FROM integration_runtime.transit_files WHERE id=$1", [output.fileId])).rows,
        ),
      ).toEqual([]);
      expect(requests).toBe(before);
    }
    await expect(service(sharedAction).read(aliceFile.fileId)).rejects.toMatchObject({ status: 404 });
    expect(await service(sharedAction).delete(aliceFile.fileId)).toBe(false);
    const lifecycle: SaasRequestScope = {
      ...bobFiles,
      actorUserId: randomUUID(),
      purpose: "lifecycle:delete",
      permissions: ["lifecycle:delete"],
    };
    const metadata = new PostgresTransitFileStore(harness.pool, lifecycle);
    expect((await metadata.listExactOwnedForLifecycle(undefined, 100)).items.map((file) => file.id)).toEqual([
      output.fileId,
    ]);
    expect(await service(lifecycle).delete(output.fileId)).toBe(true);
    expect(await new PostgresTransitFileStore(harness.pool, bobFiles).get(output.fileId)).toBeUndefined();
    expect((await metadata.listExactOwnedForLifecycle(undefined, 100)).items).toEqual([]);
    expect(await service(alice).read(aliceFile.fileId)).toMatchObject({ name: "alice.txt" });
    expect(await service(neighbor).read(neighborFile.fileId)).toMatchObject({ name: "neighbor.txt" });
    expect(await privateConnections.getById(privateConnection.id)).toBeDefined();
    expect(await service(alice).delete(aliceFile.fileId)).toBe(true);
    expect(await service(neighbor).delete(neighborFile.fileId)).toBe(true);
  });
});
