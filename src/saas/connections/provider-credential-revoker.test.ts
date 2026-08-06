import type { ResolvedCredential } from "../../core/types.ts";
import type { ProviderCredentialRevocationDefinition } from "./provider-credential-revoker.ts";

import { describe, expect, it, vi } from "vitest";
import { ProviderSaasCredentialRevoker } from "./provider-credential-revoker.ts";

const oauthCredential: Extract<ResolvedCredential, { authType: "oauth2" }> = {
  authType: "oauth2",
  accessToken: "access-secret",
  refreshToken: "refresh-secret",
  tokenType: "Bearer",
  profile: { accountId: "account-1", displayName: "Account", grantedScopes: [] },
  metadata: {},
};
const signal = new AbortController().signal;

function request(service: string, credential: ResolvedCredential = oauthCredential) {
  return { service, credential, signal };
}

describe("ProviderSaasCredentialRevoker", () => {
  it("uses Google's declared form shape and accepts an already-invalid refresh token", async () => {
    const fetchFn = vi.fn<typeof fetch>(async () => new Response('{"error":"invalid_token"}', { status: 400 }));
    const revoker = new ProviderSaasCredentialRevoker({ fetchFn, lookup: null });

    await expect(
      revoker.revoke(request("gmail", { ...oauthCredential, refreshToken: "refresh secret&value" })),
    ).resolves.toBe("revoked");
    const [url, init] = fetchFn.mock.calls[0]!;
    expect(url).toBe("https://oauth2.googleapis.com/revoke");
    expect(init).toMatchObject({ method: "POST", redirect: "error", body: "token=refresh+secret%26value" });
    expect(new Headers(init?.headers).get("content-type")).toBe("application/x-www-form-urlencoded");
    expect(new Headers(init?.headers).has("authorization")).toBe(false);
    expect(String(init?.body)).not.toContain("access-secret");
    await expect(revoker.revoke(request("googledrive", { ...oauthCredential, refreshToken: undefined }))).resolves.toBe(
      "revoked",
    );
    expect(fetchFn.mock.calls[1]?.[1]?.body).toBe("token=access-secret");
  });

  it("revokes Slack bot and separately stored user grants", async () => {
    const fetchFn = vi.fn<typeof fetch>(async () => new Response('{"ok":true}', { status: 200 }));
    const revoker = new ProviderSaasCredentialRevoker({ fetchFn, lookup: null });
    const credential = {
      ...oauthCredential,
      providerSecret: { userGrant: { accessToken: "user-access-secret" } },
    };

    await expect(revoker.revoke(request("slack", credential))).resolves.toBe("revoked");
    expect(fetchFn).toHaveBeenCalledTimes(2);
    expect(fetchFn.mock.calls.map(([url, init]) => [url, init?.body])).toEqual([
      ["https://slack.com/api/auth.revoke", "token=access-secret"],
      ["https://slack.com/api/auth.revoke", "token=user-access-secret"],
    ]);
    for (const [, init] of fetchFn.mock.calls) {
      expect(init).toMatchObject({ method: "POST", redirect: "error" });
      expect(new Headers(init?.headers).get("content-type")).toBe("application/x-www-form-urlencoded");
      expect(String(init?.body)).not.toContain("refresh-secret");
    }
  });

  it("revokes identical Slack bot and user tokens only once", async () => {
    const fetchFn = vi.fn<typeof fetch>(
      async () => new Response('{"ok":false,"error":"token_revoked"}', { status: 200 }),
    );
    const revoker = new ProviderSaasCredentialRevoker({ fetchFn, lookup: null });
    const credential = {
      ...oauthCredential,
      providerSecret: { userGrant: { accessToken: oauthCredential.accessToken } },
    };

    await expect(revoker.revoke(request("slack", credential))).resolves.toBe("revoked");
    expect(fetchFn).toHaveBeenCalledOnce();
  });

  it("reports partial Slack revocation failure only as a safe unresolved outcome", async () => {
    const userToken = "user-access-secret";
    const fetchFn = vi
      .fn<typeof fetch>()
      .mockRejectedValueOnce(new Error(`provider rejected ${oauthCredential.accessToken} and ${userToken}`))
      .mockResolvedValueOnce(new Response('{"ok":true}', { status: 200 }));
    const revoker = new ProviderSaasCredentialRevoker({ fetchFn, lookup: null });
    const credential = {
      ...oauthCredential,
      providerSecret: { userGrant: { accessToken: userToken } },
    };

    const outcome = await revoker.revoke(request("slack", credential));

    expect(fetchFn).toHaveBeenCalledTimes(2);
    expect(outcome).toBe("failed");
    expect(JSON.stringify({ outcome })).not.toContain(oauthCredential.accessToken);
    expect(JSON.stringify({ outcome })).not.toContain(userToken);
  });

  it("uses Dropbox's bearer plus JSON-null shape", async () => {
    const fetchFn = vi.fn<typeof fetch>(async () => new Response("null", { status: 200 }));
    const revoker = new ProviderSaasCredentialRevoker({ fetchFn, lookup: null });

    await expect(revoker.revoke(request("dropbox"))).resolves.toBe("revoked");
    const [url, init] = fetchFn.mock.calls[0]!;
    expect(url).toBe("https://api.dropboxapi.com/2/auth/token/revoke");
    expect(init?.body).toBe("null");
    expect(new Headers(init?.headers).get("authorization")).toBe("Bearer access-secret");
    expect(new Headers(init?.headers).get("content-type")).toBe("application/json");
  });

  it("returns unsupported without egress for undeclared providers, API keys, and custom credentials", async () => {
    const fetchFn = vi.fn(async () => new Response(null, { status: 200 }));
    const revoker = new ProviderSaasCredentialRevoker({ fetchFn, lookup: null });
    const profile = oauthCredential.profile;

    await expect(revoker.revoke(request("not-reviewed"))).resolves.toBe("unsupported");
    await expect(
      revoker.revoke(
        request("gmail", {
          authType: "api_key",
          apiKey: "secret",
          values: { apiKey: "secret" },
          profile,
          metadata: {},
        }),
      ),
    ).resolves.toBe("unsupported");
    await expect(
      revoker.revoke(
        request("gmail", { authType: "custom_credential", values: { secret: "secret" }, profile, metadata: {} }),
      ),
    ).resolves.toBe("unsupported");
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it.each([
    ["malformed JSON", async () => new Response("not-json", { status: 200 })],
    ["redirect", async () => new Response(null, { status: 302, headers: { location: "https://example.com/steal" } })],
    ["oversized response", async () => new Response("x", { status: 200, headers: { "content-length": "4097" } })],
  ])("fails closed on %s", async (_case, fetchFn) => {
    const revoker = new ProviderSaasCredentialRevoker({
      fetchFn: vi.fn(fetchFn),
      lookup: null,
      maxResponseBytes: 4_096,
    });
    await expect(revoker.revoke(request("slack"))).resolves.toBe("failed");
  });
  it("fails closed before egress when the selected token exceeds the request bound", async () => {
    const fetchFn = vi.fn(async () => new Response(null, { status: 200 }));
    const revoker = new ProviderSaasCredentialRevoker({ fetchFn, lookup: null, maxRequestBytes: 4 });
    await expect(revoker.revoke(request("gmail"))).resolves.toBe("failed");
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("fails closed on deadline expiry", async () => {
    const fetchFn = vi.fn(
      async (_url: string | URL | Request, init?: RequestInit) =>
        await new Promise<Response>((_resolve, reject) => {
          const rejectAborted = () => reject(new DOMException("aborted", "AbortError"));
          if (init?.signal?.aborted) rejectAborted();
          else init?.signal?.addEventListener("abort", rejectAborted, { once: true });
        }),
    );
    const revoker = new ProviderSaasCredentialRevoker({ fetchFn, lookup: null, timeoutMs: 1 });
    await expect(revoker.revoke(request("gmail"))).resolves.toBe("failed");
  });

  it("rejects a reviewed definition targeting a private address before transport", async () => {
    const privateDefinition: ProviderCredentialRevocationDefinition = {
      service: "private-provider",
      endpoint: "https://127.0.0.1/revoke",
      method: "POST",
      contentType: "application/x-www-form-urlencoded",
      tokenKind: "access_token",
      auth: { type: "body", field: "token" },
      response: { successStatus: 200, body: "empty" },
    };
    const fetchFn = vi.fn(async () => new Response(null, { status: 200 }));
    const revoker = new ProviderSaasCredentialRevoker({ definitions: [privateDefinition], fetchFn });

    await expect(revoker.revoke(request("private-provider"))).resolves.toBe("failed");
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("retries an uncertain failure without changing or exposing the credential", async () => {
    const fetchFn = vi
      .fn()
      .mockResolvedValueOnce(new Response('{"ok":false,"error":"temporarily_unavailable"}', { status: 200 }))
      .mockResolvedValueOnce(new Response('{"ok":true}', { status: 200 }));
    const revoker = new ProviderSaasCredentialRevoker({ fetchFn, lookup: null });

    await expect(revoker.revoke(request("slack"))).resolves.toBe("failed");
    await expect(revoker.revoke(request("slack"))).resolves.toBe("revoked");
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });
});
