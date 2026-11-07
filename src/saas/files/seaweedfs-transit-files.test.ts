import type { SaasRequestScope } from "../contracts.ts";
import type {
  TransitFileMetadataStore,
  TransitFileRecord,
  TransitFileStatus,
} from "../storage/postgres-transit-file-store.ts";
import type { S3Client } from "@aws-sdk/client-s3";

import { describe, expect, it, vi } from "vitest";
import { withRequestProcessing } from "../../core/cancellation.ts";
import { readTransitFileInput } from "../../providers/provider-files.ts";
import { SeaweedFsTransitFileService } from "./seaweedfs-transit-files.ts";

const scopeA = scope("tenant-a", "workspace-a", "user@example.com");
const scopeB = scope("tenant-b", "workspace-a", "other@example.com");

describe("SeaweedFsTransitFileService", () => {
  it("round-trips a native File's Unicode name, MIME and bytes through read and download", async () => {
    const shared = new Map<string, TransitFileRecord>();
    const s3 = new MemoryS3();
    const service = createService(scopeA, shared, s3, undefined, 4);
    const file = new File([new Uint8Array([0, 127, 128, 255])], "résumé-文.bin", {
      type: "application/octet-stream",
    });
    const upload = await service.create(file);
    expect(upload).toMatchObject({ name: "résumé-文.bin", mimeType: "application/octet-stream", sizeBytes: 4 });
    const read = await readTransitFileInput({ fileId: upload.fileId }, { transitFiles: service });
    expect(read.file).toBeInstanceOf(File);
    expect(read.file.name).toBe("résumé-文.bin");
    expect(read.file.type).toBe("application/octet-stream");
    expect(read.file.size).toBe(4);
    expect(new Uint8Array(await read.file.arrayBuffer())).toEqual(new Uint8Array([0, 127, 128, 255]));
    const response = await service.response(upload.fileId);
    expect(response.headers.get("content-length")).toBe("4");
    expect(response.headers.get("content-type")).toBe("application/octet-stream");
    expect(response.headers.get("content-disposition")).toBe(
      "attachment; filename=\"r_sum_-_.bin\"; filename*=UTF-8''r%C3%A9sum%C3%A9-%E6%96%87.bin",
    );
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(new Uint8Array([0, 127, 128, 255]));
  });

  it("preserves MIME parameters used by native File consumers", async () => {
    const service = createService(scopeA, new Map(), new MemoryS3());
    const upload = await service.create(new File(["abc"], "data.txt", { type: "text/plain;charset=utf-8" }));
    expect((await service.read(upload.fileId)).file.type).toBe("text/plain;charset=utf-8");
    expect((await service.response(upload.fileId)).headers.get("content-type")).toBe("text/plain;charset=utf-8");
  });

  it("uses the real file UUID for historical metadata without a recorded name", async () => {
    const shared = new Map<string, TransitFileRecord>();
    const metadata = new ScopedMemoryMetadata(scopeA, shared);
    const service = createService(scopeA, shared, new MemoryS3(), metadata);
    const upload = await service.create(new File(["abc"], "not-recorded.txt"));
    const record = (await metadata.get(upload.fileId))!;
    delete record.name;
    await metadata.create(record);
    expect((await service.read(upload.fileId)).file.name).toBe(upload.fileId);
  });

  it.each([
    { bytes: [1, 2, 3, 4, 5], status: 413 },
    { bytes: [1, 2, 3], status: undefined },
    { bytes: [4, 3, 2, 1], status: undefined },
  ])("rejects unknown-length corrupt bytes before download delivery: $bytes", async ({ bytes, status }) => {
    const shared = new Map<string, TransitFileRecord>();
    const s3 = new MemoryS3();
    const service = createService(scopeA, shared, s3, undefined, 4);
    const upload = await service.create(new File([new Uint8Array([1, 2, 3, 4])], "bounded.bin"));
    s3.readBytes = new Uint8Array(bytes);
    s3.omitContentLength = true;
    if (status) await expect(service.response(upload.fileId)).rejects.toMatchObject({ status });
    else await expect(service.response(upload.fileId)).rejects.toThrow(/does not match safe metadata/);
    expect(s3.closedReads).toBe(1);
  });

  it("captures root cancellation before native file materialization and S3 dispatch", async () => {
    const controller = new AbortController();
    const shared = new Map<string, TransitFileRecord>();
    const s3 = new MemoryS3();
    const service = withRequestProcessing(
      { requestSignal: controller.signal, processingDeadlineMs: Date.now() + 60_000 },
      () => createService(scopeA, shared, s3),
    );
    controller.abort();
    await expect(service.create(new File(["abc"], "cancelled.bin"))).rejects.toMatchObject({ name: "AbortError" });
    expect(shared.size).toBe(0);
    expect(s3.requestCount).toBe(0);
  });

  it("rejects expired captured root authority even without an abort signal", async () => {
    const shared = new Map<string, TransitFileRecord>();
    const s3 = new MemoryS3();
    const service = withRequestProcessing({ processingDeadlineMs: Date.now() - 1 }, () =>
      createService(scopeA, shared, s3),
    );
    await expect(service.create(new File(["abc"], "expired.bin"))).rejects.toMatchObject({ name: "TimeoutError" });
    expect(shared.size).toBe(0);
    expect(s3.requestCount).toBe(0);
  });

  it("checks the root clock while synchronous response chunks cannot run abort timers", async () => {
    const shared = new Map<string, TransitFileRecord>();
    const s3 = new MemoryS3();
    const upload = await createService(scopeA, shared, s3).create(new File(["abc"], "expired.bin"));
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    try {
      const service = withRequestProcessing({ processingDeadlineMs: now + 100 }, () =>
        createService(scopeA, shared, s3),
      );
      s3.onRead = () => clock.mockReturnValue(now + 101);
      await expect(service.response(upload.fileId)).rejects.toMatchObject({ name: "TimeoutError" });
      expect(s3.closedReads).toBe(1);
    } finally {
      clock.mockRestore();
    }
  });

  it("rejects a NUL filename before PostgreSQL metadata or object dispatch", async () => {
    const shared = new Map<string, TransitFileRecord>();
    const s3 = new MemoryS3();
    const service = createService(scopeA, shared, s3);
    await expect(service.create(new File(["abc"], "invalid\0name.bin"))).rejects.toMatchObject({ status: 400 });
    expect(shared.size).toBe(0);
    expect(s3.requestCount).toBe(0);
  });

  it("does not publish an uncertain S3 write that resolves after root cancellation", async () => {
    const controller = new AbortController();
    const shared = new Map<string, TransitFileRecord>();
    const s3 = new MemoryS3();
    const started = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    s3.afterPut = () => {
      started.resolve();
      return release.promise;
    };
    const service = withRequestProcessing(
      { requestSignal: controller.signal, processingDeadlineMs: Date.now() + 60_000 },
      () => createService(scopeA, shared, s3),
    );
    const pending = service.create(new File(["abc"], "cancelled.bin"));
    await started.promise;
    controller.abort();
    await expect(pending).rejects.toMatchObject({
      code: "transit_file_reconciliation_required",
      stage: "object_write",
    });
    release.resolve();
    await Promise.resolve();
    expect([...shared.values()]).toMatchObject([{ status: "pending" }]);
    expect(s3.keys()).toHaveLength(1);
  });

  it("bounds a stalled response by the captured root signal and closes the body", async () => {
    const shared = new Map<string, TransitFileRecord>();
    const s3 = new MemoryS3();
    const upload = await createService(scopeA, shared, s3).create(new File(["abc"], "stalled.bin"));
    const controller = new AbortController();
    const started = Promise.withResolvers<void>();
    s3.stallReads = true;
    s3.onRead = () => started.resolve();
    const service = withRequestProcessing(
      { requestSignal: controller.signal, processingDeadlineMs: Date.now() + 60_000 },
      () => createService(scopeA, shared, s3),
    );
    const pending = service.response(upload.fileId);
    await started.promise;
    controller.abort();
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
    expect(s3.closedReads).toBe(1);
  });

  it("uses opaque scoped keys without user filenames or subject emails", async () => {
    const shared = new Map<string, TransitFileRecord>();
    const s3 = new MemoryS3();
    const service = createService(scopeA, shared, s3);
    const upload = await service.create(new File(["safe bytes"], "finance-user@example.com.csv", { type: "text/csv" }));

    const objectKey = s3.keys()[0];
    expect(objectKey).toMatch(/^tenant-a\/workspace-a\/[0-9a-f-]{36}$/);
    expect(objectKey).not.toContain("finance-user@example.com.csv");
    expect(objectKey).not.toContain(scopeA.subjectUserId);
    expect(upload.name).toBe("finance-user@example.com.csv");
    expect(s3.abortSignals.every((signal) => signal instanceof AbortSignal)).toBe(true);
  });

  it.each([
    scopeB,
    scope("tenant-a", "workspace-b", scopeA.subjectUserId),
    scope("tenant-a", "workspace-a", "other@example.com"),
  ])("denies foreign tenant/workspace/user reads and deletes before S3: %j", async (foreignScope) => {
    const shared = new Map<string, TransitFileRecord>();
    const s3 = new MemoryS3();
    const owner = createService(scopeA, shared, s3);
    const foreign = createService(foreignScope, shared, s3);
    const upload = await owner.create(new File(["owner only"], "private.txt", { type: "text/plain" }));
    const requestsBefore = s3.requestCount;

    await expect(foreign.read(upload.fileId)).rejects.toMatchObject({ status: 404 });
    await expect(foreign.delete(upload.fileId)).resolves.toBe(false);
    expect(s3.requestCount).toBe(requestsBefore);
    await expect(owner.read(upload.fileId)).resolves.toMatchObject({ sizeBytes: 10, name: "private.txt" });
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
    expect((await metadata.get(upload.fileId))?.name).toBe("secret-name.txt");
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
  readBytes?: Uint8Array;
  omitContentLength = false;
  closedReads = 0;
  afterPut?: () => Promise<void>;
  onRead?: () => void;
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
      await this.afterPut?.();
      return {};
    }
    if (command.constructor.name === "GetObjectCommand") {
      const bytes = this.readBytes ?? this.objects.get(key);
      if (!bytes) throw Object.assign(new Error("missing"), { name: "NoSuchKey" });
      const close = () => {
        this.closedReads += 1;
      };
      const onRead = this.onRead;
      if (this.stallReads) {
        return {
          ContentLength: this.omitContentLength ? undefined : bytes.byteLength,
          Body: {
            destroy: close,
            [Symbol.asyncIterator]() {
              return {
                next() {
                  onRead?.();
                  return Promise.withResolvers<IteratorResult<Uint8Array>>().promise;
                },
              };
            },
          },
        };
      }
      return {
        ContentLength: this.omitContentLength ? undefined : bytes.byteLength,
        Body: {
          async *[Symbol.asyncIterator]() {
            try {
              onRead?.();
              yield bytes.subarray(0, 2);
              yield bytes.subarray(2);
            } finally {
              close();
            }
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
    purpose: "action:execute:v2" as const,
    permissions: Object.freeze(["action:execute:v2"]) as unknown as string[],
  });
}
