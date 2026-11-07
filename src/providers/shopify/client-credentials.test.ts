import { afterEach, describe, expect, it, vi } from "vitest";
import { withRequestProcessing } from "../../core/cancellation.ts";
import { createShopifyClientCredentialsTokenSource } from "./client-credentials.ts";

const owner = {
  tenantId: "tenant-a",
  workspaceId: "workspace-a",
  credentialOwnerId: "credential-owner-a",
  connectionId: "local-connection-a",
};
const values = { shopDomain: "https://STORE.myshopify.com/", clientId: "client", clientSecret: "secret" };
const tokenResponse = (accessToken: string, expiresIn = 120) =>
  Response.json({
    access_token: accessToken,
    scope: "read_products, write_orders,read_products",
    expires_in: expiresIn,
  });

afterEach(() => vi.restoreAllMocks());

describe("Shopify scoped client credentials tokens", () => {
  it("reuses a valid owner token and preserves Shopify's normalized host and form", async () => {
    const getToken = createShopifyClientCredentialsTokenSource();
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    const fetcher: typeof fetch = async (url, init) => {
      requests.push({ url: String(url), init });
      return tokenResponse(`token-${requests.length}`);
    };
    const first = await getToken(values, fetcher, { owner });
    const second = await getToken({ ...values, shopDomain: "store.myshopify.com" }, fetcher, { owner: { ...owner } });
    expect(first.accessToken).toBe("token-1");
    expect(second.accessToken).toBe("token-1");
    expect(first.providerScopes).toEqual(["read_products", "write_orders"]);
    expect(requests).toHaveLength(1);
    expect(requests[0]?.url).toBe("https://store.myshopify.com/admin/oauth/access_token");
    expect(requests[0]?.init?.method).toBe("POST");
    expect(new Headers(requests[0]?.init?.headers).get("content-type")).toBe("application/x-www-form-urlencoded");
    expect(Object.fromEntries(new URLSearchParams(String(requests[0]?.init?.body)))).toEqual({
      grant_type: "client_credentials",
      client_id: "client",
      client_secret: "secret",
    });
  });

  it.each(["tenantId", "workspaceId", "credentialOwnerId", "connectionId"] as const)(
    "does not reuse identical provider credentials across a different %s",
    async (field) => {
      const getToken = createShopifyClientCredentialsTokenSource();
      let requests = 0;
      const fetcher: typeof fetch = async () => tokenResponse(`token-${++requests}`);
      expect((await getToken(values, fetcher, { owner })).accessToken).toBe("token-1");
      expect((await getToken(values, fetcher, { owner: { ...owner, [field]: "other" } })).accessToken).toBe("token-2");
      expect((await getToken(values, fetcher, { owner })).accessToken).toBe("token-1");
    },
  );

  it("evicts failed mints and safety-expired tokens, and replaces forced refreshes", async () => {
    const getToken = createShopifyClientCredentialsTokenSource();
    const clock = vi.spyOn(Date, "now").mockReturnValue(1_000_000);
    let requests = 0;
    const fetcher: typeof fetch = async () => {
      requests++;
      return requests === 1 || requests === 5
        ? Response.json({ error: "temporary" }, { status: 503 })
        : tokenResponse(`token-${requests}`);
    };
    await expect(getToken(values, fetcher, { owner })).rejects.toMatchObject({ status: 503 });
    expect((await getToken(values, fetcher, { owner })).accessToken).toBe("token-2");
    clock.mockReturnValue(1_059_999);
    expect((await getToken(values, fetcher, { owner })).accessToken).toBe("token-2");
    clock.mockReturnValue(1_060_000);
    expect((await getToken(values, fetcher, { owner })).accessToken).toBe("token-3");
    expect((await getToken(values, fetcher, { owner, forceRefresh: true })).accessToken).toBe("token-4");
    await expect(getToken(values, fetcher, { owner, forceRefresh: true })).rejects.toMatchObject({ status: 503 });
    expect((await getToken(values, fetcher, { owner })).accessToken).toBe("token-6");
    expect((await getToken(values, fetcher, { owner })).accessToken).toBe("token-6");
  });

  it.each([
    { expires_in: 0, scope: "read_products" },
    { expires_in: -1, scope: "read_products" },
    { expires_in: "invalid", scope: "read_products" },
    { expires_in: 120, scope: null },
  ])("does not retain invalid token responses %#", async (fields) => {
    const getToken = createShopifyClientCredentialsTokenSource();
    let requests = 0;
    const fetcher: typeof fetch = async () =>
      ++requests === 1 ? Response.json({ access_token: "unusable", ...fields }) : tokenResponse("valid");
    await expect(getToken(values, fetcher, { owner })).rejects.toMatchObject({ status: 502 });
    expect((await getToken(values, fetcher, { owner })).accessToken).toBe("valid");
  });

  it("shares a pending mint only inside one processing root without letting a cancelled caller abort its sibling", async () => {
    const getToken = createShopifyClientCredentialsTokenSource();
    const root = new AbortController();
    const cancelled = new AbortController();
    const live = new AbortController();
    const started = Promise.withResolvers<void>();
    const gate = Promise.withResolvers<Response>();
    let requests = 0;
    let mintSignal: AbortSignal | null | undefined;
    const fetcher: typeof fetch = async (_url, init) => {
      requests++;
      mintSignal = init?.signal;
      started.resolve();
      return (await gate.promise).clone();
    };
    await withRequestProcessing(
      { requestSignal: root.signal, processingDeadlineMs: Date.now() + 120_000 },
      async () => {
        const first = getToken(values, fetcher, { owner, signal: cancelled.signal });
        const firstOutcome = first.then(
          () => "resolved",
          () => "cancelled",
        );
        await started.promise;
        const second = getToken(values, fetcher, { owner, signal: live.signal });
        cancelled.abort(new DOMException("Caller left", "AbortError"));
        gate.resolve(tokenResponse("live-token"));
        expect(await firstOutcome).toBe("cancelled");
        expect((await second).accessToken).toBe("live-token");
        expect(mintSignal?.aborted).toBe(false);
        expect(requests).toBe(1);
      },
    );
  });

  it("does not share pending work across processing roots or cache a cancelled root's late token", async () => {
    const getToken = createShopifyClientCredentialsTokenSource();
    const roots = [new AbortController(), new AbortController()];
    const gates = [Promise.withResolvers<Response>(), Promise.withResolvers<Response>()];
    let requests = 0;
    const fetcher: typeof fetch = async () => gates[requests++]!.promise;
    const first = withRequestProcessing(
      { requestSignal: roots[0]!.signal, processingDeadlineMs: Date.now() + 120_000 },
      () => getToken(values, fetcher, { owner }),
    ).then(
      () => "resolved",
      () => "cancelled",
    );
    const second = withRequestProcessing(
      { requestSignal: roots[1]!.signal, processingDeadlineMs: Date.now() + 120_000 },
      () => getToken(values, fetcher, { owner }),
    );
    roots[0]!.abort(new DOMException("Root ended", "AbortError"));
    gates[1]!.resolve(tokenResponse("live-root"));
    expect((await second).accessToken).toBe("live-root");
    gates[0]!.resolve(tokenResponse("late-cancelled-root"));
    expect(await first).toBe("cancelled");
    expect((await getToken(values, fetcher, { owner })).accessToken).toBe("live-root");
    expect(requests).toBe(2);
  });

  it("does not let a superseded slow mint overwrite a forced refresh", async () => {
    const getToken = createShopifyClientCredentialsTokenSource();
    const root = new AbortController();
    const gate = Promise.withResolvers<Response>();
    let requests = 0;
    const fetcher: typeof fetch = async () => (++requests === 1 ? gate.promise : tokenResponse("forced"));
    await withRequestProcessing(
      { requestSignal: root.signal, processingDeadlineMs: Date.now() + 120_000 },
      async () => {
        const original = getToken(values, fetcher, { owner });
        expect((await getToken(values, fetcher, { owner, forceRefresh: true })).accessToken).toBe("forced");
        gate.resolve(tokenResponse("superseded"));
        await original;
        expect((await getToken(values, fetcher, { owner })).accessToken).toBe("forced");
        expect(requests).toBe(2);
      },
    );
  });

  it("does not reuse completed tokens after processing authority expires", async () => {
    const getToken = createShopifyClientCredentialsTokenSource();
    let requests = 0;
    const fetcher: typeof fetch = async () => {
      requests++;
      return tokenResponse("cached");
    };
    await getToken(values, fetcher, { owner });
    await expect(
      withRequestProcessing({ processingDeadlineMs: Date.now() - 1 }, () => getToken(values, fetcher, { owner })),
    ).rejects.toMatchObject({ name: "TimeoutError" });
    expect(requests).toBe(1);
  });

  it("bounds completed owner entries rather than retaining every credential ever seen", async () => {
    const getToken = createShopifyClientCredentialsTokenSource();
    let requests = 0;
    const fetcher: typeof fetch = async () => tokenResponse(`token-${++requests}`);
    for (let index = 0; index < 257; index++) {
      await getToken(values, fetcher, { owner: { ...owner, connectionId: `connection-${index}` } });
    }
    expect((await getToken(values, fetcher, { owner: { ...owner, connectionId: "connection-0" } })).accessToken).toBe(
      "token-258",
    );
  });
});
