import type { TransitFileRead, TransitFileUpload } from "../../core/types.ts";
import type { SaasConfig } from "../config.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { TransitFileMetadataStore, TransitFileRecord } from "../storage/postgres-transit-file-store.ts";
import type { ITransitFileService } from "./transit-file-store.ts";

import { DeleteObjectCommand, GetObjectCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { createHash, randomUUID } from "node:crypto";
import { MIMEType } from "node:util";
import {
  captureRequestProcessing,
  getRequestSignal,
  remainingProcessingMs,
  waitForSignal,
} from "../../core/cancellation.ts";
import { transitFileRead, transitFileResponse, TransitFileError } from "./transit-file-store.ts";

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
    requestChecksumCalculation: "WHEN_REQUIRED",
    responseChecksumValidation: "WHEN_REQUIRED",
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
      scope: captureRequestProcessing(Object.freeze({ ...options.scope, permissions })),
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
    const signal = this.requestSignal();
    this.assertFileSize(file.size);
    if (file.name.includes("\0"))
      throw new TransitFileError(400, "invalid_file_name", "File names cannot contain NUL.");
    const bytes = new Uint8Array(await waitForSignal(file.arrayBuffer(), signal));
    signal.throwIfAborted();
    this.assertFileSize(bytes.byteLength);
    if (bytes.byteLength !== file.size) throw new Error("Transit file size changed during upload");
    const fileId = randomUUID();
    const objectKey = [
      encodeURIComponent(this.options.scope.tenantId),
      encodeURIComponent(this.options.scope.workspaceId),
      fileId,
    ].join("/");
    const mimeType = safeContentType(file.type);
    const name = file.name.toWellFormed();
    const record: TransitFileRecord = {
      id: fileId,
      objectKey,
      name,
      contentType: mimeType,
      byteSize: bytes.byteLength,
      contentSha256: createHash("sha256").update(bytes).digest("hex"),
      status: "pending",
      expiresAt: new Date(Date.now() + this.ttlMs).toISOString(),
    };
    signal.throwIfAborted();
    remainingProcessingMs(this.options.scope);
    await waitForSignal(this.options.metadata.create(record), signal);

    try {
      signal.throwIfAborted();
      remainingProcessingMs(this.options.scope);
      await waitForSignal(
        this.options.client.send(
          new PutObjectCommand({
            Bucket: this.options.bucket,
            Key: objectKey,
            Body: bytes,
            ContentLength: bytes.byteLength,
            ContentType: mimeType,
          }),
          { abortSignal: signal },
        ),
        signal,
      );
    } catch {
      const markerWritten = await this.markReconcile(fileId);
      throw new TransitFileReconciliationError("object_write", markerWritten);
    }

    try {
      signal.throwIfAborted();
      remainingProcessingMs(this.options.scope);
      if (!(await waitForSignal(this.options.metadata.setStatus(fileId, "pending", "available"), signal))) {
        throw new Error("Transit file metadata publication failed");
      }
      signal.throwIfAborted();
      remainingProcessingMs(this.options.scope);
    } catch {
      const markerWritten = await this.markReconcile(fileId);
      throw new TransitFileReconciliationError("metadata_publish", markerWritten);
    }

    return {
      fileId,
      downloadUrl: new URL(`/internal/saas/files/${fileId}`, this.options.publicOrigin).href,
      sizeBytes: bytes.byteLength,
      name,
      mimeType,
    };
  }

  async read(fileId: string): Promise<TransitFileRead> {
    const signal = this.requestSignal();
    const deadlineMs =
      Date.now() +
      Math.min(
        this.options.requestTimeoutMs,
        remainingProcessingMs(this.options.scope) ?? this.options.requestTimeoutMs,
      );
    assertFileId(fileId);
    const record = await waitForSignal(this.options.metadata.get(fileId), signal);
    signal.throwIfAborted();
    const expiresAt = record ? Date.parse(record.expiresAt) : Number.NaN;
    if (!record || record.status !== "available" || !Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
      throw new TransitFileError(404, "transit_file_not_found", "Transit file not found.");
    }
    this.assertFileSize(record.byteSize);

    let output;
    try {
      signal.throwIfAborted();
      remainingProcessingMs(this.options.scope);
      output = await waitForSignal(
        this.options.client.send(new GetObjectCommand({ Bucket: this.options.bucket, Key: record.objectKey }), {
          abortSignal: signal,
        }),
        signal,
        (late) => closeBody(late.Body),
      );
    } catch (error) {
      if (isNotFound(error)) throw new TransitFileError(404, "transit_file_not_found", "Transit file not found.");
      throw error;
    }
    if (!output.Body) throw new TransitFileError(404, "transit_file_not_found", "Transit file not found.");
    try {
      signal.throwIfAborted();
      if (output.ContentLength !== undefined) {
        this.assertFileSize(output.ContentLength);
        if (output.ContentLength !== record.byteSize) throw new Error("Transit file size does not match safe metadata");
      }
      const bytes = await readBodyBounded(output.Body, record.byteSize, signal, deadlineMs);
      if (bytes.byteLength !== record.byteSize) throw new Error("Transit file size does not match safe metadata");
      if (record.contentSha256 && createHash("sha256").update(bytes).digest("hex") !== record.contentSha256) {
        throw new Error("Transit file digest does not match safe metadata");
      }
      signal.throwIfAborted();
      remainingProcessingMs(this.options.scope);
      const read = transitFileRead(bytes, {
        sizeBytes: bytes.byteLength,
        name: record.name ?? record.id,
        mimeType: safeContentType(record.contentType),
      });
      signal.throwIfAborted();
      remainingProcessingMs(this.options.scope);
      return read;
    } catch (error) {
      closeBody(output.Body);
      throw error;
    }
  }

  async response(fileId: string): Promise<Response> {
    const read = await this.read(fileId);
    remainingProcessingMs(this.options.scope);
    return transitFileResponse(read.file, read);
  }

  async delete(fileId: string, preserveMetadata = false): Promise<boolean> {
    const signal = this.requestSignal();
    assertFileId(fileId);
    const record = await waitForSignal(this.options.metadata.get(fileId), signal);
    signal.throwIfAborted();
    if (!record) return false;
    if (record.status !== "deleting") {
      remainingProcessingMs(this.options.scope);
      if (!(await waitForSignal(this.options.metadata.setStatus(fileId, record.status, "deleting"), signal)))
        return false;
    }

    try {
      signal.throwIfAborted();
      remainingProcessingMs(this.options.scope);
      await waitForSignal(
        this.options.client.send(new DeleteObjectCommand({ Bucket: this.options.bucket, Key: record.objectKey }), {
          abortSignal: signal,
        }),
        signal,
      );
    } catch (error) {
      if (!isNotFound(error)) {
        const markerWritten = await this.markReconcile(fileId);
        throw new TransitFileReconciliationError("object_delete", markerWritten);
      }
    }

    try {
      signal.throwIfAborted();
      remainingProcessingMs(this.options.scope);
      if (preserveMetadata) return true;
      const deleted = await waitForSignal(this.options.metadata.delete(fileId), signal);
      signal.throwIfAborted();
      remainingProcessingMs(this.options.scope);
      return deleted;
    } catch {
      const markerWritten = await this.markReconcile(fileId);
      throw new TransitFileReconciliationError("metadata_delete", markerWritten);
    }
  }

  async cleanupExpired(): Promise<void> {
    const signal = this.requestSignal();
    const records = await waitForSignal(this.options.metadata.listExpired(this.cleanupLimit), signal);
    for (const record of records) {
      signal.throwIfAborted();
      await this.delete(record.id);
    }
  }

  private requestSignal(): AbortSignal {
    const remaining = remainingProcessingMs(this.options.scope);
    const timeout = AbortSignal.timeout(
      Math.min(this.options.requestTimeoutMs, remaining ?? this.options.requestTimeoutMs),
    );
    const root = getRequestSignal(this.options.scope);
    return root ? AbortSignal.any([root, timeout]) : timeout;
  }

  private assertFileSize(size: number): void {
    if (!Number.isSafeInteger(size) || size < 0 || size > this.maxBytes) {
      throw new TransitFileError(413, "transit_file_too_large", `Transit file exceeds ${this.maxBytes} bytes.`);
    }
  }

  private async markReconcile(fileId: string): Promise<boolean> {
    try {
      const signal = this.requestSignal();
      return await waitForSignal(this.options.metadata.markReconcile(fileId), signal);
    } catch {
      return false;
    }
  }
}

async function readBodyBounded(
  body: unknown,
  expectedBytes: number,
  signal: AbortSignal,
  deadlineMs: number,
): Promise<Uint8Array<ArrayBuffer>> {
  if (!body || typeof body !== "object" || !(Symbol.asyncIterator in body)) {
    throw new Error("SeaweedFS returned an unsupported response body");
  }
  const iterator = (body as AsyncIterable<Uint8Array>)[Symbol.asyncIterator]();
  const output = new Uint8Array(expectedBytes);
  let total = 0;
  try {
    for (;;) {
      signal.throwIfAborted();
      if (Date.now() >= deadlineMs) throw new DOMException("Transit file request deadline expired", "TimeoutError");
      const result = await waitForSignal(Promise.resolve(iterator.next()), signal);
      signal.throwIfAborted();
      if (Date.now() >= deadlineMs) throw new DOMException("Transit file request deadline expired", "TimeoutError");
      if (result.done) break;
      if (!(result.value instanceof Uint8Array)) throw new Error("SeaweedFS returned a non-byte response chunk");
      const bytes = result.value;
      total += bytes.byteLength;
      if (total > expectedBytes) {
        throw new TransitFileError(413, "transit_file_too_large", `Transit file exceeds ${expectedBytes} bytes.`);
      }
      output.set(bytes, total - bytes.byteLength);
    }
  } catch (error) {
    // A stalled iterator's return() can itself wait forever; never extend the hard deadline for it.
    try {
      void Promise.resolve(iterator.return?.()).catch(() => {});
    } catch {}
    throw error;
  }
  return output.subarray(0, total);
}

function closeBody(body: unknown): void {
  try {
    (body as { destroy?: () => void } | undefined)?.destroy?.();
  } catch {}
}

function assertFileId(fileId: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(fileId)) {
    throw new TransitFileError(404, "transit_file_not_found", "Transit file not found.");
  }
}

function safeContentType(value: string | undefined): string {
  if (value && !/[^\u0020-\u007e]/.test(value)) {
    try {
      new MIMEType(value);
      return value;
    } catch {}
  }
  return "application/octet-stream";
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
