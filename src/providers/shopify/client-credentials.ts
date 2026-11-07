import type { CredentialCacheOwner } from "../../core/types.ts";

import { sha256Hex } from "../../core/aws-sigv4.ts";
import {
  assertProcessingActive,
  getRequestSignal,
  remainingProcessingMs,
  waitForSignal,
} from "../../core/cancellation.ts";
import { optionalNumber, requiredString, requiredRawString } from "../../core/cast.ts";
import {
  defaultProviderRequestTimeoutMs,
  ProviderRequestError,
  requiredInputString,
  requiredResponseRecord,
  providerResponseError,
  runProviderRequest,
} from "../provider-runtime.ts";
import { requestShopifyJson } from "./client.ts";
import { normalizeShopDomain } from "./shop-domain.ts";

interface ShopifyClientCredentialsToken {
  accessToken: string;
  providerScopes: string[];
  shopDomain: string;
  expiresAt: number;
}

interface ShopifyClientCredentialsTokenOptions {
  owner?: Readonly<CredentialCacheOwner>;
  signal?: AbortSignal;
  forceRefresh?: boolean;
}

interface ShopifyTokenCacheEntry {
  token?: ShopifyClientCredentialsToken;
  pending: WeakMap<AbortSignal, Promise<ShopifyClientCredentialsToken>>;
}

type ShopifyClientCredentialsTokenSource = (
  values: Record<string, string>,
  fetcher: typeof fetch,
  options: ShopifyClientCredentialsTokenOptions,
) => Promise<ShopifyClientCredentialsToken>;

export function createShopifyClientCredentialsTokenSource(): ShopifyClientCredentialsTokenSource {
  const tokens = new Map<string, ShopifyTokenCacheEntry>();

  return async function getToken(values, fetcher, options): Promise<ShopifyClientCredentialsToken> {
    const remaining = remainingProcessingMs();
    const rootSignal = getRequestSignal();
    options.signal?.throwIfAborted();
    const owner = options.owner;
    if (
      !owner ||
      [owner.tenantId, owner.workspaceId, owner.credentialOwnerId, owner.connectionId].some(
        (value) => typeof value !== "string" || !value,
      )
    ) {
      throw new ProviderRequestError(401, "Shopify client credentials require a verified credential owner");
    }
    const shopDomain = normalizeShopDomain(values.shopDomain);
    const clientId = requiredInputString(values.clientId, "clientId");
    const clientSecret = requiredInputString(values.clientSecret, "clientSecret");
    const key = sha256Hex(
      JSON.stringify([
        owner.tenantId,
        owner.workspaceId,
        owner.credentialOwnerId,
        owner.connectionId,
        shopDomain,
        clientId,
        clientSecret,
      ]),
    );
    if (options.forceRefresh) tokens.delete(key);
    let entry = tokens.get(key);
    if (entry?.token && entry.token.expiresAt > Date.now()) return entry.token;
    if (!entry) {
      entry = { pending: new WeakMap() };
      tokens.set(key, entry);
      if (tokens.size > 256) {
        const oldest = tokens.keys().next().value;
        if (oldest !== undefined) tokens.delete(oldest);
      }
    }
    entry.token = undefined;
    // ponytail: single-flight only within one processing root; concurrent roots mint separately.
    // Completed tokens share only this verified owner partition; add coordination if provider limits demand it.
    const existing = rootSignal ? entry.pending.get(rootSignal) : undefined;
    if (existing) return waitForSignal(existing, options.signal);

    const requestedAt = Date.now();
    const current = entry;
    const pending: Promise<ShopifyClientCredentialsToken> = runProviderRequest(
      {
        label: "Shopify",
        signal: rootSignal ?? options.signal,
        timeoutMs: remaining === undefined ? undefined : Math.min(remaining, defaultProviderRequestTimeoutMs),
      },
      async (signal) => {
        const { payload } = await waitForSignal(
          requestShopifyJson(
            shopDomain,
            "",
            `https://${shopDomain}/admin/oauth/access_token`,
            {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "client_credentials",
                client_id: clientId,
                client_secret: clientSecret,
              }).toString(),
              signal,
            },
            fetcher,
          ),
          signal,
        );
        signal.throwIfAborted();
        assertProcessingActive();
        const token = requiredResponseRecord(payload, "Shopify client credentials token response");
        const expiresIn = optionalNumber(token.expires_in);
        if (expiresIn === undefined || !Number.isFinite(expiresIn) || expiresIn <= 0) {
          throw new ProviderRequestError(
            502,
            "Shopify client credentials token is missing a valid expires_in",
            undefined,
            "provider_error",
          );
        }
        const result: ShopifyClientCredentialsToken = {
          accessToken: requiredString(token.access_token, "access_token", providerResponseError),
          providerScopes: [
            ...new Set(
              requiredRawString(token.scope, "scope", providerResponseError)
                .split(",")
                .map((scope) => scope.trim())
                .filter(Boolean),
            ),
          ],
          shopDomain,
          expiresAt: requestedAt + Math.max(0, expiresIn * 1000 - 60_000),
        };
        if (tokens.get(key) === current) current.token = result;
        return result;
      },
    ).finally(() => {
      if (rootSignal && current.pending.get(rootSignal) === pending) current.pending.delete(rootSignal);
    });
    if (rootSignal) current.pending.set(rootSignal, pending);
    return waitForSignal(pending, options.signal);
  };
}
