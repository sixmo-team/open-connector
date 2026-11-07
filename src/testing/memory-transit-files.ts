import type { TransitFileRead, TransitFileStore, TransitFileStream, TransitFileUpload } from "../core/types.ts";
import { randomUUID } from "node:crypto";
import { assertFileSize, transitFileResponse } from "../saas/files/transit-file-store.ts";

/** Test-only byte sink for provider contracts; production uses scoped PostgreSQL/S3 storage. */
export class MemoryTransitFiles implements TransitFileStore {
  readonly files: Map<string, File> = new Map();
  pendingBytes = 0;
  readonly maxBytes: number;
  private readonly publicOrigin: string;

  constructor(options: { maxBytes: number; publicOrigin: string }) {
    this.maxBytes = options.maxBytes;
    this.publicOrigin = options.publicOrigin;
  }

  async create(file: File): Promise<TransitFileUpload> {
    assertFileSize(file.size, this.maxBytes);
    return this.publish(file);
  }

  async createFromStream(input: TransitFileStream): Promise<TransitFileUpload> {
    const reader = input.body.getReader();
    const chunks: Uint8Array<ArrayBuffer>[] = [];
    const abort = () => { void reader.cancel(input.signal?.reason).catch(() => undefined); };
    input.signal?.addEventListener("abort", abort, { once: true });
    try {
      input.signal?.throwIfAborted();
      for (;;) {
        const { value, done } = await reader.read();
        input.signal?.throwIfAborted();
        if (done) break;
        this.pendingBytes += value.byteLength;
        assertFileSize(this.pendingBytes, this.maxBytes);
        chunks.push(new Uint8Array(value));
      }
      return this.publish(new File(chunks, input.name, { type: input.mimeType }));
    } catch (error) {
      await reader.cancel(error).catch(() => undefined);
      throw error;
    } finally {
      this.pendingBytes = 0;
      input.signal?.removeEventListener("abort", abort);
      reader.releaseLock();
    }
  }

  async read(fileId: string): Promise<TransitFileRead> {
    const file = this.files.get(fileId);
    if (!file) throw new Error("Missing test file");
    return { file, name: file.name, mimeType: file.type, sizeBytes: file.size };
  }
  async response(fileId: string): Promise<Response> {
    const { file, ...info } = await this.read(fileId);
    return transitFileResponse(file.stream(), info);
  }

  async delete(fileId: string): Promise<boolean> { return this.files.delete(fileId); }

  private publish(file: File): TransitFileUpload {
    const fileId = randomUUID();
    this.files.set(fileId, file);
    return { fileId, downloadUrl: `${this.publicOrigin}/files/${fileId}`, sizeBytes: file.size, name: file.name, mimeType: file.type };
  }
}
