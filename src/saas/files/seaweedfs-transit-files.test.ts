import type { SaasRequestScope } from "../contracts.ts";
import type {
  TransitFileMetadataStore,
  TransitFileRecord,
  TransitFileStatus,
} from "../storage/postgres-transit-file-store.ts";
import type { S3Client } from "@aws-sdk/client-s3";

import { describe, expect, it } from "vitest";
import { SeaweedFsTransitFileService } from "./seaweedfs-transit-files.ts";

const scopeA = scope("tenant-a", "workspace-a", "user@example.com");
const scopeB = scope("tenant-b", "workspace-a", "other@example.com");

describe("SeaweedFsTransitFileService", () => {
  it("uses opaque scoped keys without user filenames or subject emails", async () => {
    const shared = new Map<string, TransitFileRecord>();
    const s3 = new MemoryS3();
    const service = createService(scopeA, shared, s3);
    const upload = await service.create(new File(["safe bytes"], "finance-user@example.com.csv", { type: "text/csv" }));

    const objectKey = s3.keys()[0];
    expect(objectKey).toMatch(/^tenant-a\/workspace-a\/[0-9a-f-]{36}$/);
    expect(objectKey).not.toContain("finance-user@example.com.csv");
    expect(objectKey).not.toContain(scopeA.subjectUserId);
    expect(upload.name).toBe("file");
    expect(s3.abortSignals.every((signal) => signal instanceof AbortSignal)).toBe(true);
  });

  it("denies cross-scope reads and deletes before making an S3 request", async () => {
    const shared = new Map<string, TransitFileRecord>();
    const s3 = new MemoryS3();
    const owner = createService(scopeA, shared, s3);
    const foreign = createService(scopeB, shared, s3);
    const upload = await owner.create(new File(["owner only"], "private.txt", { type: "text/plain" }));
    const requestsBefore = s3.requestCount;

    await expect(foreign.read(upload.fileId)).rejects.toMatchObject({ status: 404 });
    await expect(foreign.delete(upload.fileId)).resolves.toBe(false);
    expect(s3.requestCount).toBe(requestsBefore);
    await expect(owner.read(upload.fileId)).resolves.toMatchObject({ sizeBytes: 10, name: "file" });
  });

  it("deletes the S3 object before removing scoped PostgreSQL metadata", async () => {
    const shared = new Map<string, TransitFileRecord>();
    const events: string[] = [];
    const s3 = new MemoryS3(events);
    const metadata = new ScopedMemoryMetadata(scopeA, shared, events);
    const service = createService(scopeA, shared, s3, metadata);
    const upload = await service.create(new File(["delete me"], "delete.txt"));
    events.length = 0;

    await expect(service.delete(upload.fileId)).resolves.toBe(true);
    expect(events).toEqual(["metadata:deleting", "s3:delete", "metadata:delete"]);
    expect(await metadata.get(upload.fileId)).toBeUndefined();
    expect(s3.keys()).toHaveLength(0);
  });

  it("can preserve exact metadata for lifecycle finalization and treats an absent object as deleted", async () => {
    const shared = new Map<string, TransitFileRecord>();
    const events: string[] = [];
    const s3 = new MemoryS3(events);
    const metadata = new ScopedMemoryMetadata(scopeA, shared, events);
    const service = createService(scopeA, shared, s3, metadata);
    const upload = await service.create(new File(["lifecycle"], "ignored.txt"));
    events.length = 0;
    s3.deleteNotFound = true;

    await expect(service.delete(upload.fileId, true)).resolves.toBe(true);
    expect(events).toEqual(["metadata:deleting", "s3:delete"]);
    expect(await metadata.get(upload.fileId)).toMatchObject({ status: "deleting" });
  });

  it("leaves a safe reconciliation marker when S3 deletion partially fails", async () => {
    const shared = new Map<string, TransitFileRecord>();
    const s3 = new MemoryS3();
    const metadata = new ScopedMemoryMetadata(scopeA, shared);
    const service = createService(scopeA, shared, s3, metadata);
    const upload = await service.create(new File(["keep marker"], "secret-name.txt"));
    s3.failDelete = true;

    await expect(service.delete(upload.fileId)).rejects.toMatchObject({
      code: "transit_file_reconciliation_required",
      stage: "object_delete",
      markerWritten: true,
    });
    expect(await metadata.get(upload.fileId)).toMatchObject({ status: "reconcile" });
    expect(JSON.stringify(await metadata.get(upload.fileId))).not.toContain("secret-name.txt");
    expect(JSON.stringify(await metadata.get(upload.fileId))).not.toContain(scopeA.subjectUserId);
  });

  it("marks reconciliation if metadata removal fails after successful S3 deletion", async () => {
    const shared = new Map<string, TransitFileRecord>();
    const s3 = new MemoryS3();
    const metadata = new ScopedMemoryMetadata(scopeA, shared);
    const service = createService(scopeA, shared, s3, metadata);
    const upload = await service.create(new File(["metadata failure"], "ignored.txt"));
    metadata.failDelete = true;

    await expect(service.delete(upload.fileId)).rejects.toMatchObject({
      code: "transit_file_reconciliation_required",
      stage: "metadata_delete",
      markerWritten: true,
    });
    expect(s3.keys()).toHaveLength(0);
    expect(await metadata.get(upload.fileId)).toMatchObject({ status: "reconcile" });
  });

  it("rejects oversized uploads without sending bytes to S3", async () => {
    const shared = new Map<string, TransitFileRecord>();
    const s3 = new MemoryS3();
    const service = createService(scopeA, shared, s3, undefined, 4);
    await expect(service.create(new File(["12345"], "large.bin"))).rejects.toMatchObject({ status: 413 });
    expect(s3.requestCount).toBe(0);
  });

  it("aborts a stalled S3 response body at the strict request deadline", async () => {
    const shared = new Map<string, TransitFileRecord>();
    const s3 = new MemoryS3();
    const service = createService(scopeA, shared, s3, undefined, 1024, 5);
    const upload = await service.create(new File(["stalled"], "stalled.bin"));
    s3.stallReads = true;
    await expect(service.read(upload.fileId)).rejects.toMatchObject({ name: "TimeoutError" });
  });
});

function createService(
  requestScope: Readonly<SaasRequestScope>,
  shared: Map<string, TransitFileRecord>,
  s3: MemoryS3,
  metadata = new ScopedMemoryMetadata(requestScope, shared),
  maxBytes = 1024,
  requestTimeoutMs = 1_000,
): SeaweedFsTransitFileService {
  return new SeaweedFsTransitFileService({
    client: s3 as unknown as S3Client,
    bucket: "transit",
    metadata,
    scope: requestScope,
    publicOrigin: "https://connector.internal",
    ttlSeconds: 60,
    maxBytes,
    requestTimeoutMs,
  });
}

class ScopedMemoryMetadata implements TransitFileMetadataStore {
  failDelete = false;
  private readonly requestScope: Readonly<SaasRequestScope>;
  private readonly shared: Map<string, TransitFileRecord>;
  private readonly events: string[];

  constructor(requestScope: Readonly<SaasRequestScope>, shared: Map<string, TransitFileRecord>, events: string[] = []) {
    this.requestScope = requestScope;
    this.shared = shared;
    this.events = events;
  }

  async create(record: TransitFileRecord): Promise<void> {
    this.shared.set(this.key(record.id), { ...record });
  }

  async get(id: string): Promise<TransitFileRecord | undefined> {
    const record = this.shared.get(this.key(id));
    return record ? { ...record } : undefined;
  }

  async setStatus(id: string, expected: TransitFileStatus, status: TransitFileStatus): Promise<boolean> {
    const key = this.key(id);
    const record = this.shared.get(key);
    if (!record || record.status !== expected) return false;
    this.events.push(`metadata:${status}`);
    this.shared.set(key, { ...record, status });
    return true;
  }

  async markReconcile(id: string): Promise<boolean> {
    const key = this.key(id);
    const record = this.shared.get(key);
    if (!record) return false;
    this.shared.set(key, { ...record, status: "reconcile" });
    return true;
  }

  async delete(id: string): Promise<boolean> {
    if (this.failDelete) throw new Error("metadata unavailable");
    this.events.push("metadata:delete");
    return this.shared.delete(this.key(id));
  }

  async listExpired(limit: number): Promise<TransitFileRecord[]> {
    const prefix = `${this.requestScope.tenantId}\0${this.requestScope.workspaceId}\0${this.requestScope.subjectUserId}\0`;
    return [...this.shared.entries()]
      .filter(([key, record]) => key.startsWith(prefix) && Date.parse(record.expiresAt) <= Date.now())
      .slice(0, limit)
      .map(([, record]) => ({ ...record }));
  }

  private key(id: string): string {
    return `${this.requestScope.tenantId}\0${this.requestScope.workspaceId}\0${this.requestScope.subjectUserId}\0${id}`;
  }
}

class MemoryS3 {
  failDelete = false;
  deleteNotFound = false;
  stallReads = false;
  requestCount = 0;
  readonly abortSignals: AbortSignal[] = [];
  private readonly objects = new Map<string, Uint8Array>();
  private readonly events: string[];

  constructor(events: string[] = []) {
    this.events = events;
  }

  async send(
    command: { constructor: { name: string }; input: Record<string, unknown> },
    options?: { abortSignal?: AbortSignal },
  ) {
    this.requestCount += 1;
    if (options?.abortSignal) this.abortSignals.push(options.abortSignal);
    const key = String(command.input.Key);
    if (command.constructor.name === "PutObjectCommand") {
      this.objects.set(key, command.input.Body as Uint8Array);
      return {};
    }
    if (command.constructor.name === "GetObjectCommand") {
      const bytes = this.objects.get(key);
      if (!bytes) throw Object.assign(new Error("missing"), { name: "NoSuchKey" });
      if (this.stallReads) {
        return {
          ContentLength: bytes.byteLength,
          Body: {
            [Symbol.asyncIterator]() {
              return {
                next() {
                  return Promise.withResolvers<IteratorResult<Uint8Array>>().promise;
                },
              };
            },
          },
        };
      }
      return {
        ContentLength: bytes.byteLength,
        Body: {
          async *[Symbol.asyncIterator]() {
            yield bytes;
          },
        },
      };
    }
    if (command.constructor.name === "DeleteObjectCommand") {
      this.events.push("s3:delete");
      if (this.failDelete) throw new Error("s3 unavailable");
      if (this.deleteNotFound) throw Object.assign(new Error("missing"), { name: "NoSuchKey" });
      this.objects.delete(key);
      return {};
    }
    throw new Error("Unexpected S3 command");
  }

  keys(): string[] {
    return [...this.objects.keys()];
  }
}

function scope(tenantId: string, workspaceId: string, subjectUserId: string): Readonly<SaasRequestScope> {
  return Object.freeze({
    tenantId,
    workspaceId,
    actorUserId: subjectUserId,
    subjectUserId,
    workspaceRole: "member" as const,
    purpose: "action:execute" as const,
    permissions: Object.freeze(["action:execute"]) as unknown as string[],
  });
}
