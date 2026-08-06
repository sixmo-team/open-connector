import type { SaasConfig } from "../config.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { TransitFileMetadataStore, TransitFileRecord } from "../storage/postgres-transit-file-store.ts";
import type { ITransitFileService, TransitFileRead, TransitFileUpload } from "./transit-file-store.ts";

import { DeleteObjectCommand, GetObjectCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { createHash, randomUUID } from "node:crypto";
import { createTransitFileResponse, TransitFileError } from "./transit-file-store.ts";

export interface SeaweedFsTransitFileOptions {
  client: S3Client;
  bucket: string;
  metadata: TransitFileMetadataStore;
  scope: Readonly<SaasRequestScope>;
  publicOrigin: string;
  ttlSeconds: number;
  maxBytes: number;
  requestTimeoutMs: number;
  cleanupLimit?: number;
}

export class TransitFileReconciliationError extends Error {
  readonly code = "transit_file_reconciliation_required";
  readonly stage: "object_write" | "metadata_publish" | "object_delete" | "metadata_delete";
  readonly markerWritten: boolean;

  constructor(
    stage: "object_write" | "metadata_publish" | "object_delete" | "metadata_delete",
    markerWritten: boolean,
  ) {
    super("Transit file operation requires reconciliation");
    this.stage = stage;
    this.markerWritten = markerWritten;
    this.name = "TransitFileReconciliationError";
  }
}

/** Create an S3 client for the already-required SeaweedFS configuration. */
export function createSeaweedFsS3Client(
  config: Pick<SaasConfig, "seaweedFsEndpoint" | "seaweedFsAccessKeyId" | "seaweedFsSecretAccessKey">,
): S3Client {
  return new S3Client({
    endpoint: config.seaweedFsEndpoint,
    region: "us-east-1",
    forcePathStyle: true,
    credentials: {
      accessKeyId: config.seaweedFsAccessKeyId,
      secretAccessKey: config.seaweedFsSecretAccessKey,
    },
  });
}

/** Scoped S3-compatible transit files with PostgreSQL metadata as the authorization boundary. */
export class SeaweedFsTransitFileService implements ITransitFileService {
  readonly maxBytes: number;
  private readonly cleanupLimit: number;
  private readonly ttlMs: number;
  private readonly options: SeaweedFsTransitFileOptions;

  constructor(options: SeaweedFsTransitFileOptions) {
    const permissions = Object.freeze([...options.scope.permissions]) as unknown as string[];
    this.options = {
      ...options,
      scope: Object.freeze({ ...options.scope, permissions }),
    };
    this.maxBytes = positiveInteger(options.maxBytes, "maximum bytes");
    this.ttlMs = positiveInteger(positiveInteger(options.ttlSeconds, "TTL seconds") * 1_000, "TTL milliseconds");
    const requestTimeoutMs = positiveInteger(options.requestTimeoutMs, "request timeout");
    if (requestTimeoutMs > 300_000) throw new Error("Transit file request timeout cannot exceed 300000 milliseconds");
    this.cleanupLimit = positiveInteger(options.cleanupLimit ?? 100, "cleanup limit");
    if (!options.bucket) throw new Error("A SeaweedFS bucket is required");
    new URL(options.publicOrigin);
  }

  async create(file: File): Promise<TransitFileUpload> {
    this.assertFileSize(file.size);
    const bytes = new Uint8Array(await file.arrayBuffer());
    this.assertFileSize(bytes.byteLength);
    const fileId = randomUUID();
    const objectKey = [
      encodeURIComponent(this.options.scope.tenantId),
      encodeURIComponent(this.options.scope.workspaceId),
      fileId,
    ].join("/");
    const mimeType = safeContentType(file.type);
    const record: TransitFileRecord = {
      id: fileId,
      objectKey,
      contentType: mimeType,
      byteSize: bytes.byteLength,
      contentSha256: createHash("sha256").update(bytes).digest("hex"),
      status: "pending",
      expiresAt: new Date(Date.now() + this.ttlMs).toISOString(),
    };
    await this.options.metadata.create(record);

    try {
      await this.options.client.send(
        new PutObjectCommand({
          Bucket: this.options.bucket,
          Key: objectKey,
          Body: bytes,
          ContentLength: bytes.byteLength,
          ContentType: mimeType,
        }),
        { abortSignal: AbortSignal.timeout(this.options.requestTimeoutMs) },
      );
    } catch {
      const markerWritten = await this.markReconcile(fileId);
      throw new TransitFileReconciliationError("object_write", markerWritten);
    }

    if (!(await this.options.metadata.setStatus(fileId, "pending", "available"))) {
      const markerWritten = await this.markReconcile(fileId);
      throw new TransitFileReconciliationError("metadata_publish", markerWritten);
    }

    return {
      fileId,
      downloadUrl: new URL(`/internal/saas/files/${fileId}`, this.options.publicOrigin).href,
      sizeBytes: bytes.byteLength,
      name: "file",
      mimeType,
    };
  }

  async read(fileId: string): Promise<TransitFileRead> {
    assertFileId(fileId);
    const record = await this.options.metadata.get(fileId);
    const expiresAt = record ? Date.parse(record.expiresAt) : Number.NaN;
    if (!record || record.status !== "available" || !Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
      throw new TransitFileError(404, "transit_file_not_found", "Transit file not found.");
    }
    this.assertFileSize(record.byteSize);

    const signal = AbortSignal.timeout(this.options.requestTimeoutMs);
    let output;
    try {
      output = await this.options.client.send(
        new GetObjectCommand({ Bucket: this.options.bucket, Key: record.objectKey }),
        { abortSignal: signal },
      );
    } catch (error) {
      if (isNotFound(error)) throw new TransitFileError(404, "transit_file_not_found", "Transit file not found.");
      throw error;
    }
    if (!output.Body) throw new TransitFileError(404, "transit_file_not_found", "Transit file not found.");
    if (output.ContentLength !== undefined) this.assertFileSize(output.ContentLength);
    const bytes = await readBodyBounded(output.Body, this.maxBytes, signal);
    if (bytes.byteLength !== record.byteSize) throw new Error("Transit file size does not match safe metadata");
    if (record.contentSha256 && createHash("sha256").update(bytes).digest("hex") !== record.contentSha256) {
      throw new Error("Transit file digest does not match safe metadata");
    }
    const mimeType = safeContentType(record.contentType);
    return {
      file: new File([Uint8Array.from(bytes)], "file", { type: mimeType }),
      sizeBytes: bytes.byteLength,
      name: "file",
      mimeType,
    };
  }

  async response(fileId: string): Promise<Response> {
    return createTransitFileResponse(await this.read(fileId));
  }

  async delete(fileId: string, preserveMetadata = false): Promise<boolean> {
    assertFileId(fileId);
    const record = await this.options.metadata.get(fileId);
    if (!record) return false;
    if (record.status !== "deleting") await this.options.metadata.setStatus(fileId, record.status, "deleting");

    try {
      await this.options.client.send(new DeleteObjectCommand({ Bucket: this.options.bucket, Key: record.objectKey }), {
        abortSignal: AbortSignal.timeout(this.options.requestTimeoutMs),
      });
    } catch (error) {
      if (!isNotFound(error)) {
        const markerWritten = await this.markReconcile(fileId);
        throw new TransitFileReconciliationError("object_delete", markerWritten);
      }
    }
    if (preserveMetadata) return true;

    try {
      return await this.options.metadata.delete(fileId);
    } catch {
      const markerWritten = await this.markReconcile(fileId);
      throw new TransitFileReconciliationError("metadata_delete", markerWritten);
    }
  }

  async cleanupExpired(): Promise<void> {
    const records = await this.options.metadata.listExpired(this.cleanupLimit);
    for (const record of records) await this.delete(record.id);
  }

  private assertFileSize(size: number): void {
    if (!Number.isSafeInteger(size) || size < 0 || size > this.maxBytes) {
      throw new TransitFileError(413, "transit_file_too_large", `Transit file exceeds ${this.maxBytes} bytes.`);
    }
  }

  private async markReconcile(fileId: string): Promise<boolean> {
    try {
      return await this.options.metadata.markReconcile(fileId);
    } catch {
      return false;
    }
  }
}

async function readBodyBounded(body: unknown, maxBytes: number, signal: AbortSignal): Promise<Uint8Array> {
  if (!body || typeof body !== "object" || !(Symbol.asyncIterator in body)) {
    throw new Error("SeaweedFS returned an unsupported response body");
  }
  const iterator = (body as AsyncIterable<Uint8Array>)[Symbol.asyncIterator]();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const result = await nextChunk(iterator, signal);
    if (result.done) break;
    const bytes = Uint8Array.from(result.value);
    total += bytes.byteLength;
    if (total > maxBytes) {
      await iterator.return?.();
      throw new TransitFileError(413, "transit_file_too_large", `Transit file exceeds ${maxBytes} bytes.`);
    }
    chunks.push(bytes);
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

async function nextChunk(
  iterator: AsyncIterator<Uint8Array>,
  signal: AbortSignal,
): Promise<IteratorResult<Uint8Array>> {
  signal.throwIfAborted();
  const aborted = Promise.withResolvers<never>();
  const onAbort = () => aborted.reject(signal.reason);
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    return await Promise.race([iterator.next(), aborted.promise]);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

function assertFileId(fileId: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(fileId)) {
    throw new TransitFileError(404, "transit_file_not_found", "Transit file not found.");
  }
}

function safeContentType(value: string | undefined): string {
  return value && /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/i.test(value)
    ? value
    : "application/octet-stream";
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`Transit file ${name} must be a positive integer`);
  return value;
}

function isNotFound(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const candidate = error as { name?: unknown; $metadata?: { httpStatusCode?: unknown } };
  return candidate.name === "NoSuchKey" || candidate.$metadata?.httpStatusCode === 404;
}
