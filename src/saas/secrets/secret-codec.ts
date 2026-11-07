import type { RequestProcessingContext } from "../../core/cancellation.ts";

import { randomUUID } from "node:crypto";
import {
  assertProcessingActive,
  getRequestProcessing,
  getRequestSignal,
  withRequestProcessing,
} from "../../core/cancellation.ts";
import { OpenBaoClient, OpenBaoError } from "./openbao-client.ts";

export interface NativeSecretScope extends RequestProcessingContext {
  tenantId: string;
  workspaceId: string;
}
/** Preserve verified identity while bounding post-side-effect reconciliation independently of caller cancellation. */
export async function withSecretCleanup<T extends NativeSecretScope, R>(
  scope: Readonly<T>,
  work: (cleanupScope: Readonly<T>) => Promise<R>,
): Promise<R> {
  const processingDeadlineMs = Math.min(
    scope.processingDeadlineMs ?? Infinity,
    getRequestProcessing()?.processingDeadlineMs ?? Infinity,
    Date.now() + 5000,
  );
  const remaining = processingDeadlineMs - Date.now();
  if (!Number.isSafeInteger(processingDeadlineMs) || remaining <= 0)
    throw new DOMException("Connector request deadline expired", "TimeoutError");
  const cleanupScope = Object.freeze({ ...scope, requestSignal: AbortSignal.timeout(remaining), processingDeadlineMs });
  return withRequestProcessing(cleanupScope, () => work(cleanupScope));
}

export interface ISecretCodec {
  readonly encrypted: boolean;
  encode(plaintext: string): Promise<string>;
  decode(stored: string): Promise<string>;
  delete(stored: string): Promise<boolean>;
}
/** Immutable secret envelopes: SQL stores the opaque KV reference, never the payload. */
export class OpenBaoSecretCodec implements ISecretCodec {
  readonly encrypted = true;
  private readonly prefix: string;
  private readonly client: OpenBaoClient;
  private readonly scope: Readonly<NativeSecretScope>;
  constructor(client: OpenBaoClient, scope: Readonly<NativeSecretScope>) {
    this.client = client;
    this.scope = scope;
    for (const value of [scope.tenantId, scope.workspaceId]) {
      if (!/^[A-Za-z0-9_-]{1,255}$/.test(value)) throw new TypeError("Invalid secret scope");
    }
    this.prefix = `client-secrets/data/tenants/${scope.tenantId}/workspaces/${scope.workspaceId}/integrations/oauth-sessions/`;
  }
  async encode(plaintext: string): Promise<string> {
    assertProcessingActive(this.scope);
    const path = `${this.prefix}${randomUUID()}`;
    await this.client.write(path, { payload: plaintext }, 0, this.scope.requestSignal);
    return path;
  }
  async decode(stored: string): Promise<string> {
    this.assertReference(stored);
    assertProcessingActive(this.scope);
    const { data } = await this.client.read(stored, undefined, this.scope.requestSignal);
    if (typeof data.payload !== "string") throw new Error("Invalid secret envelope");
    return data.payload;
  }
  async delete(stored: string): Promise<boolean> {
    this.assertReference(stored);
    const context = getRequestProcessing() ?? this.scope;
    assertProcessingActive(context);
    try {
      const signal = getRequestSignal(context);
      await this.client.read(stored, undefined, signal);
      await this.client.delete(stored, signal);
      return true;
    } catch (error) {
      if (!(error instanceof OpenBaoError) || error.code !== "OPENBAO_NOT_FOUND") throw error;
      return false;
    }
  }
  private assertReference(stored: string): void {
    if (!stored.startsWith(this.prefix) || !/^[a-f0-9-]{36}$/.test(stored.slice(this.prefix.length)))
      throw new Error("Secret reference is outside the verified scope");
  }
}
