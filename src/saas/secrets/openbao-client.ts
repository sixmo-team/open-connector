import { Buffer } from "node:buffer";
import { randomUUID } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { getRequestSignal, remainingProcessingMs } from "../../core/cancellation.ts";

export type OpenBaoErrorCode =
  | "OPENBAO_UNAUTHORIZED"
  | "OPENBAO_FORBIDDEN"
  | "OPENBAO_NOT_FOUND"
  | "OPENBAO_CONFLICT"
  | "OPENBAO_UNAVAILABLE"
  | "OPENBAO_INVALID_RESPONSE"
  | "OPENBAO_RESPONSE_TOO_LARGE"
  | "OPENBAO_REQUEST_TOO_LARGE"
  | "OPENBAO_REQUEST_FAILED";

export interface OpenBaoClientOptions {
  address: string;
  token: string;
  fetchFn?: typeof fetch;
  requestTimeoutMs?: number;
  maxRequestBytes?: number;
  maxResponseBytes?: number;
}

export interface OpenBaoTokenFileOptions extends Omit<OpenBaoClientOptions, "token"> {
  tokenFile: string;
}

export interface OpenBaoReadResult<T extends Record<string, unknown>> {
  data: T;
  revision: number;
}

export interface OpenBaoCapabilityProbeResult {
  checkedPaths: readonly string[];
}

const DEFAULT_REQUEST_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_REQUEST_BYTES = 262_144;
const DEFAULT_MAX_RESPONSE_BYTES = 1_048_576;
const MAX_TOKEN_BYTES = 16_384;
const PATH_SEGMENT = "[A-Za-z0-9_-]{1,255}";
const CONNECTION_DATA_PATH = new RegExp(
  `^client-secrets/data/tenants/${PATH_SEGMENT}/workspaces/${PATH_SEGMENT}/integrations/(?:connections|oauth-sessions)/${PATH_SEGMENT}$`,
);
const APPLICATION_DATA_PATH = new RegExp(`^service-secrets/data/integration-provider-applications/${PATH_SEGMENT}$`);

/** Safe OpenBao failure containing no request or response bodies. */
export class OpenBaoError extends Error {
  readonly code: OpenBaoErrorCode;
  readonly status: number | undefined;
  readonly path: string;

  constructor(code: OpenBaoErrorCode, path: string, status?: number) {
    super(
      status === undefined
        ? `OpenBao request failed (${code})`
        : `OpenBao request failed with HTTP ${status} (${code})`,
    );
    this.name = "OpenBaoError";
    this.code = code;
    this.path = path;
    this.status = status;
  }
}

/** Minimal KV v2 client with bounded response reads and redacted failures. */
export class OpenBaoClient {
  private readonly address: string;
  private readonly token: string;
  private readonly fetchFn: typeof fetch;
  private readonly requestTimeoutMs: number;
  private readonly maxRequestBytes: number;
  private readonly maxResponseBytes: number;

  constructor(options: OpenBaoClientOptions) {
    const address = validateAddress(options.address);
    const token = options.token.trim();
    if (!token) throw new Error("OpenBao token is missing");

    this.address = address;
    this.token = token;
    this.fetchFn = options.fetchFn ?? fetch;
    this.requestTimeoutMs = positiveInteger(options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS, "request timeout");
    this.maxRequestBytes = positiveInteger(options.maxRequestBytes ?? DEFAULT_MAX_REQUEST_BYTES, "request size limit");
    this.maxResponseBytes = positiveInteger(
      options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
      "response size limit",
    );
  }

  static async fromTokenFile(options: OpenBaoTokenFileOptions): Promise<OpenBaoClient> {
    const tokenFile = options.tokenFile.trim();
    if (!tokenFile) throw new Error("OpenBao token file is missing");
    const details = await stat(tokenFile);
    if (!details.isFile() || details.size === 0 || details.size > MAX_TOKEN_BYTES) {
      throw new Error("OpenBao token file is invalid");
    }
    const token = (await readFile(tokenFile, "utf8")).trim();
    return new OpenBaoClient({ ...options, token });
  }

  async read<T extends Record<string, unknown>>(
    path: string,
    revision?: number,
    signal?: AbortSignal,
  ): Promise<OpenBaoReadResult<T>> {
    const normalizedPath = normalizeDataPath(path);
    if (revision !== undefined && (!Number.isSafeInteger(revision) || revision <= 0)) {
      throw new TypeError("OpenBao revision must be a positive integer");
    }
    const requestPath = revision === undefined ? normalizedPath : `${normalizedPath}?version=${revision}`;
    const response = await this.request(requestPath, { method: "GET", signal });
    const body = await this.readJson(response, normalizedPath);
    const outer = jsonObject(body, "data", normalizedPath);
    const data = jsonObject(outer, "data", normalizedPath) as T;
    const metadata = jsonObject(outer, "metadata", normalizedPath);
    return { data, revision: positiveRevision(metadata.version, normalizedPath) };
  }

  async list(path: string): Promise<string[]> {
    if (path !== "service-secrets/metadata/integration-provider-applications") {
      throw new TypeError("OpenBao KV v2 metadata path is outside the integration allowlist");
    }
    const response = await this.request(`${path}?list=true`, { method: "GET" });
    const body = await this.readJson(response, path);
    const outer = jsonObject(body, "data", path);
    if (!Array.isArray(outer.keys) || outer.keys.some((key) => typeof key !== "string")) {
      throw new OpenBaoError("OPENBAO_INVALID_RESPONSE", path);
    }
    return outer.keys as string[];
  }

  async write(path: string, data: Record<string, unknown>, cas: number, signal?: AbortSignal): Promise<number> {
    const normalizedPath = normalizeDataPath(path);
    if (!Number.isSafeInteger(cas) || cas < 0) throw new TypeError("OpenBao CAS must be a non-negative integer");
    let response: Response;
    try {
      response = await this.request(normalizedPath, {
        method: "POST",
        signal,
        body: JSON.stringify({ data, options: { cas } }),
      });
    } catch (error) {
      if (error instanceof OpenBaoError && error.status === 400) {
        throw new OpenBaoError("OPENBAO_CONFLICT", normalizedPath, error.status);
      }
      throw error;
    }
    const body = await this.readJson(response, normalizedPath);
    const outer = jsonObject(body, "data", normalizedPath);
    return positiveRevision(outer.version, normalizedPath);
  }

  /** Permanently remove all KV versions so ephemeral and revoked secrets cannot be recovered. */
  async delete(path: string, signal?: AbortSignal): Promise<void> {
    const normalizedPath = normalizeDataPath(path);
    const metadataPath = normalizedPath.replace("/data/", "/metadata/");
    await this.request(metadataPath, { method: "DELETE", signal });
  }

  /** Prove exact least-privilege capabilities, then exercise each allowed namespace. */
  async probeCapabilities(): Promise<OpenBaoCapabilityProbeResult> {
    const suffix = randomUUID();
    const paths = [
      `client-secrets/data/tenants/_probe/workspaces/_probe/integrations/connections/${suffix}`,
      `client-secrets/data/tenants/_probe/workspaces/_probe/integrations/oauth-sessions/${suffix}`,
      `service-secrets/data/integration-provider-applications/_probe-${suffix}`,
    ];
    const metadataPaths = paths.map((path) => path.replace("/data/", "/metadata/"));
    const applicationsParent = "service-secrets/metadata/integration-provider-applications";
    const forbiddenPaths = [
      "sys/policies/acl",
      `client-secrets/data/tenants/_probe/workspaces/_probe/integrations/unrelated/${suffix}`,
      `service-secrets/data/unrelated/${suffix}`,
    ];
    const capabilityPath = "sys/capabilities-self";

    const health = await this.request("sys/health?standbyok=true&perfstandbyok=true", { method: "GET" });
    await this.discardBody(health, "sys/health");
    const capabilityResponse = await this.request(capabilityPath, {
      method: "POST",
      body: JSON.stringify({ paths: [...paths, ...metadataPaths, applicationsParent, ...forbiddenPaths] }),
    });
    const capabilityBody = await this.readJson(capabilityResponse, capabilityPath);
    const capabilities = isJsonObject(capabilityBody.data) ? capabilityBody.data : capabilityBody;
    for (const path of paths) assertExactCapabilities(capabilities, path, ["create", "read", "update"], capabilityPath);
    for (const path of metadataPaths) assertExactCapabilities(capabilities, path, ["delete"], capabilityPath);
    assertExactCapabilities(capabilities, applicationsParent, ["list"], capabilityPath);
    for (const path of forbiddenPaths) assertExactCapabilities(capabilities, path, ["deny"], capabilityPath);

    for (const path of paths) {
      const revision = await this.write(path, { probe: true }, 0);
      if (revision !== 1 || (await this.read(path, revision)).revision !== revision) {
        throw new OpenBaoError("OPENBAO_INVALID_RESPONSE", path);
      }
      await this.delete(path);
      try {
        await this.read(path);
        throw new OpenBaoError("OPENBAO_INVALID_RESPONSE", path);
      } catch (error) {
        if (!(error instanceof OpenBaoError) || error.code !== "OPENBAO_NOT_FOUND") throw error;
      }
    }

    return { checkedPaths: Object.freeze([...paths, ...metadataPaths, applicationsParent, ...forbiddenPaths]) };
  }

  private async request(path: string, init: RequestInit): Promise<Response> {
    const requestSignal = init.signal ?? getRequestSignal();
    const remaining = remainingProcessingMs({ requestSignal });
    const timeout = AbortSignal.timeout(Math.min(this.requestTimeoutMs, remaining ?? this.requestTimeoutMs));
    if (typeof init.body === "string" && Buffer.byteLength(init.body) > this.maxRequestBytes) {
      throw new OpenBaoError("OPENBAO_REQUEST_TOO_LARGE", path);
    }
    try {
      const response = await this.fetchFn(`${this.address}/v1/${path}`, {
        ...init,
        signal: requestSignal ? AbortSignal.any([requestSignal, timeout]) : timeout,
        headers: {
          "Content-Type": "application/json",
          "X-Vault-Token": this.token,
          ...init.headers,
        },
      });
      if (!response.ok) throw new OpenBaoError(statusCode(response.status), path, response.status);
      return response;
    } catch (error) {
      if (error instanceof OpenBaoError) throw error;
      throw new OpenBaoError("OPENBAO_UNAVAILABLE", path);
    }
  }

  private async readJson(response: Response, path: string): Promise<Record<string, unknown>> {
    const bytes = await this.readBytes(response, path);
    try {
      const value: unknown = JSON.parse(new TextDecoder().decode(bytes));
      if (!isJsonObject(value)) throw new Error();
      return value;
    } catch {
      throw new OpenBaoError("OPENBAO_INVALID_RESPONSE", path, response.status);
    }
  }

  private async discardBody(response: Response, path: string): Promise<void> {
    await this.readBytes(response, path);
  }

  private async readBytes(response: Response, path: string): Promise<Uint8Array> {
    const declaredLength = Number(response.headers.get("content-length"));
    if (Number.isFinite(declaredLength) && declaredLength > this.maxResponseBytes) {
      throw new OpenBaoError("OPENBAO_RESPONSE_TOO_LARGE", path, response.status);
    }
    if (!response.body) return new Uint8Array();

    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > this.maxResponseBytes) {
          await reader.cancel();
          throw new OpenBaoError("OPENBAO_RESPONSE_TOO_LARGE", path, response.status);
        }
        chunks.push(value);
      }
    } catch (error) {
      if (error instanceof OpenBaoError) throw error;
      throw new OpenBaoError("OPENBAO_UNAVAILABLE", path, response.status);
    }

    const result = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return result;
  }
}

function validateAddress(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("OpenBao address must be an absolute HTTPS URL");
  }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    throw new Error("OpenBao address must be an absolute HTTPS URL without credentials, query, or fragment");
  }
  url.pathname = url.pathname.replace(/\/+$/, "");
  return url.toString().replace(/\/$/, "");
}

function normalizeDataPath(path: string): string {
  const normalized = path.replace(/^\/+|\/+$/g, "");
  if (path !== normalized || (!CONNECTION_DATA_PATH.test(normalized) && !APPLICATION_DATA_PATH.test(normalized))) {
    throw new TypeError("OpenBao KV v2 data path is outside the integration allowlist");
  }
  return normalized;
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`OpenBao ${name} must be a positive integer`);
  return value;
}

function positiveRevision(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new OpenBaoError("OPENBAO_INVALID_RESPONSE", path);
  }
  return value as number;
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function jsonObject(value: unknown, key: string, path: string): Record<string, unknown> {
  if (!isJsonObject(value) || !isJsonObject(value[key])) {
    throw new OpenBaoError("OPENBAO_INVALID_RESPONSE", path);
  }
  return value[key];
}

function statusCode(status: number): OpenBaoErrorCode {
  if (status === 401) return "OPENBAO_UNAUTHORIZED";
  if (status === 403) return "OPENBAO_FORBIDDEN";
  if (status === 404) return "OPENBAO_NOT_FOUND";
  if (status === 409 || status === 412) return "OPENBAO_CONFLICT";
  if (status >= 500) return "OPENBAO_UNAVAILABLE";
  return "OPENBAO_REQUEST_FAILED";
}

function assertExactCapabilities(
  response: Record<string, unknown>,
  path: string,
  expected: string[],
  responsePath: string,
): void {
  const capabilities = response[path];
  if (
    !Array.isArray(capabilities) ||
    capabilities.some((capability) => typeof capability !== "string") ||
    capabilities.length !== expected.length ||
    expected.some((capability) => !capabilities.includes(capability))
  ) {
    throw new OpenBaoError("OPENBAO_FORBIDDEN", responsePath);
  }
}
