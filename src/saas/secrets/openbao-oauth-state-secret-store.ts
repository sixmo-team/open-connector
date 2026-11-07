import type { OAuthAuthorizationState } from "../../oauth/oauth-flow-service.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type { OpenBaoReadResult } from "./openbao-client.ts";
import type { OpenBaoSecretReference } from "./openbao-connection-store.ts";

import { assertProcessingActive } from "../../core/cancellation.ts";
import { OpenBaoClient, OpenBaoError } from "./openbao-client.ts";
import { withSecretCleanup } from "./secret-codec.ts";

export interface OpenBaoOAuthStateSecret {
  pkceCodeVerifier?: string;
  authorizationState?: OAuthAuthorizationState;
}

interface StoredOAuthStateSecret extends OpenBaoOAuthStateSecret {
  expiresAt: string;
  revision: number;
  consumed: false;
}

/** Stores only an optional PKCE verifier and atomically consumes it once with KV v2 CAS. */
export class OpenBaoOAuthStateSecretStore {
  private readonly client: OpenBaoClient;

  constructor(client: OpenBaoClient) {
    this.client = client;
  }

  async put(
    scope: Readonly<SaasRequestScope>,
    oauthSessionId: string,
    pkceCodeVerifier: string | undefined,
    expiresAt: string,
    authorizationState?: OAuthAuthorizationState,
  ): Promise<OpenBaoSecretReference> {
    const path = oauthStatePath(scope, oauthSessionId);
    const record: StoredOAuthStateSecret = {
      authorizationState,
      ...(pkceCodeVerifier === undefined
        ? {}
        : { pkceCodeVerifier: requiredString(pkceCodeVerifier, "pkceCodeVerifier") }),
      expiresAt: validTimestamp(expiresAt, path),
      revision: 1,
      consumed: false,
    };
    assertProcessingActive(scope);
    const secretRevision = await this.client.write(path, { ...record }, 0, scope.requestSignal);
    if (secretRevision !== 1) throw invalid(path);
    return { secretRef: path, secretRevision };
  }

  async take(scope: Readonly<SaasRequestScope>, oauthSessionId: string): Promise<OpenBaoOAuthStateSecret | undefined> {
    const path = oauthStatePath(scope, oauthSessionId);
    let current: OpenBaoReadResult<Record<string, unknown>>;
    try {
      assertProcessingActive(scope);
      current = await this.client.read<Record<string, unknown>>(path, undefined, scope.requestSignal);
    } catch (error) {
      if (error instanceof OpenBaoError && error.code === "OPENBAO_NOT_FOUND") return undefined;
      throw error;
    }

    if (current.data.consumed !== false) {
      await withSecretCleanup(scope, () => this.client.delete(path));
      return undefined;
    }
    const stored = parseRecord(current.data, current.revision, path);
    try {
      assertProcessingActive(scope);
      const claimedRevision = await this.client.write(
        path,
        { consumed: true, expiresAt: stored.expiresAt, revision: current.revision + 1 },
        current.revision,
        scope.requestSignal,
      );
      if (claimedRevision !== current.revision + 1) throw invalid(path);
    } catch (error) {
      if (error instanceof OpenBaoError && error.code === "OPENBAO_CONFLICT") return undefined;
      throw error;
    }

    await withSecretCleanup(scope, () => this.client.delete(path));
    if (Date.now() >= Date.parse(stored.expiresAt)) return undefined;
    return { pkceCodeVerifier: stored.pkceCodeVerifier, authorizationState: stored.authorizationState };
  }

  async delete(scope: Readonly<SaasRequestScope>, oauthSessionId: string): Promise<void> {
    assertProcessingActive(scope);
    try {
      await this.client.delete(oauthStatePath(scope, oauthSessionId));
    } catch (error) {
      if (!(error instanceof OpenBaoError) || error.code !== "OPENBAO_NOT_FOUND") throw error;
    }
  }
}

function oauthStatePath(scope: Readonly<SaasRequestScope>, oauthSessionId: string): string {
  return `client-secrets/data/tenants/${segment(scope.tenantId, "tenantId")}/workspaces/${segment(scope.workspaceId, "workspaceId")}/integrations/oauth-sessions/${segment(oauthSessionId, "oauthSessionId")}`;
}

function parseRecord(data: Record<string, unknown>, revision: number, path: string): StoredOAuthStateSecret {
  if (data.revision !== revision || data.consumed !== false) throw invalid(path);
  const record: StoredOAuthStateSecret = {
    expiresAt: validTimestamp(data.expiresAt, path),
    revision,
    consumed: false,
    authorizationState: data.authorizationState as OAuthAuthorizationState | undefined,
  };
  if (data.pkceCodeVerifier !== undefined) {
    record.pkceCodeVerifier = storedString(data.pkceCodeVerifier, path);
  }
  return record;
}

function segment(value: string, name: string): string {
  if (!/^[A-Za-z0-9_-]{1,255}$/.test(value)) {
    throw new TypeError(`${name} contains invalid path characters`);
  }
  return value;
}

function requiredString(value: string, name: string): string {
  const normalized = value.trim();
  if (!normalized) throw new TypeError(`${name} must not be empty`);
  return normalized;
}

function storedString(value: unknown, path: string): string {
  if (typeof value !== "string" || !value) throw invalid(path);
  return value;
}

function validTimestamp(value: unknown, path: string): string {
  const timestamp = storedString(value, path);
  if (!Number.isFinite(Date.parse(timestamp))) throw invalid(path);
  return timestamp;
}

function invalid(path: string): OpenBaoError {
  return new OpenBaoError("OPENBAO_INVALID_RESPONSE", path);
}
