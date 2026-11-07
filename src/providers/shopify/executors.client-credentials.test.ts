import type { CredentialValidatorOptions, ExecutionContext } from "../../core/types.ts";

import { afterEach, describe, expect, it, vi } from "vitest";
import { withRequestProcessing } from "../../core/cancellation.ts";
import { createProviderFetch } from "../provider-runtime.ts";
import { credentialValidators, executors, proxy } from "./executors.ts";

const owner = {
  tenantId: "tenant-a",
  workspaceId: "workspace-a",
  credentialOwnerId: "owner-a",
  connectionId: "local-a",
};
const values = { shopDomain: "store.myshopify.com", clientId: "client", clientSecret: "secret" };

function context(connectionId: string, signal?: AbortSignal): ExecutionContext {
  return {
    credentialCacheOwner: { ...owner, connectionId },
    signal,
    getCredential: async () => ({
      authType: "custom_credential",
      values: { ...values, clientId: connectionId },
      profile: { accountId: "same-shop", displayName: "Store", grantedScopes: ["read_products"] },
      metadata: { tenantId: "forged", credentialOwnerId: "forged", connectionId: "forged" },
    }),
  };
}

async function invoke(path: string, execution: ExecutionContext) {
  if (path === "action") return executors["shopify.get_shop"]!({}, execution);
  if (path === "proxy")
    return proxy({ method: "POST", endpoint: "/graphql.json", body: { query: "{ shop { id } }" } }, execution);
  const options: CredentialValidatorOptions = {
    fetcher: createProviderFetch(),
    signal: execution.signal,
    credentialCacheOwner: execution.credentialCacheOwner,
  };
  try {
    const credential = await execution.getCredential("shopify");
    if (credential?.authType !== "custom_credential") throw new Error("Expected fixture credential");
    await credentialValidators.customCredential!({ values: credential.values }, options);
    return { ok: true };
  } catch {
    return { ok: false };
  }
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe.each(["action", "proxy"])("Shopify %s owner cache", (path) => {
  it("keeps identical credentials isolated by verified owner and reuses only that owner's token", async () => {
    let mints = 0;
    const businessTokens: string[] = [];
    vi.stubGlobal("fetch", async (url: URL, init?: RequestInit) => {
      if (String(url).endsWith("/admin/oauth/access_token")) {
        mints++;
        return Response.json({ access_token: `token-${mints}`, scope: "read_products", expires_in: 120 });
      }
      businessTokens.push(new Headers(init?.headers).get("x-shopify-access-token") ?? "missing");
      return Response.json({
        data: { shop: { id: "gid://shopify/Shop/1", name: "Store", myshopifyDomain: values.shopDomain } },
      });
    });
    const first = context(`${path}-first`);
    const second = context(`${path}-first`);
    second.credentialCacheOwner = { ...second.credentialCacheOwner!, credentialOwnerId: "owner-b" };
    expect(await invoke(path, first)).toMatchObject({ ok: true });
    expect(await invoke(path, second)).toMatchObject({ ok: true });
    expect(await invoke(path, first)).toMatchObject({ ok: true });
    expect(businessTokens).toEqual(["token-1", "token-2", "token-1"]);
    expect(mints).toBe(2);
  });
});

describe.each(["action", "proxy", "validator"])("Shopify %s token cancellation", (path) => {
  it.each(["request", "body"])("stops a slow token %s at root cancellation before business dispatch", async (stage) => {
    const root = new AbortController();
    const started = Promise.withResolvers<void>();
    const gate = Promise.withResolvers<void>();
    let businessDispatches = 0;
    vi.stubGlobal("fetch", async (url: URL) => {
      if (!String(url).endsWith("/admin/oauth/access_token")) {
        businessDispatches++;
        return Response.json({
          data: { shop: { id: "gid://shopify/Shop/1", name: "Store", myshopifyDomain: values.shopDomain } },
        });
      }
      const response = Response.json({ access_token: "late-token", scope: "read_products", expires_in: 120 });
      if (stage === "request") {
        started.resolve();
        await gate.promise;
      } else {
        const text = response.text.bind(response);
        response.text = async () => {
          started.resolve();
          await gate.promise;
          return text();
        };
      }
      return response;
    });
    const pending = withRequestProcessing(
      { requestSignal: root.signal, processingDeadlineMs: Date.now() + 120_000 },
      () => invoke(path, context(`${path}-root-${stage}`)),
    );
    await started.promise;
    root.abort(new DOMException("Root ended", "AbortError"));
    const turn = Promise.withResolvers<void>();
    setImmediate(turn.resolve);
    const settledBeforeRelease = await Promise.race([pending.then(() => true), turn.promise.then(() => false)]);
    gate.resolve();
    expect(await pending).toMatchObject({ ok: false });
    expect(settledBeforeRelease).toBe(true);
    expect(businessDispatches).toBe(0);
  });

  it("propagates a caller's cancellation into an unshared mint", async () => {
    const caller = new AbortController();
    const started = Promise.withResolvers<void>();
    const gate = Promise.withResolvers<void>();
    let mintSignal: AbortSignal | null | undefined;
    let businessDispatches = 0;
    vi.stubGlobal("fetch", async (url: URL, init?: RequestInit) => {
      if (!String(url).endsWith("/admin/oauth/access_token")) {
        businessDispatches++;
        return Response.json({
          data: { shop: { id: "gid://shopify/Shop/1", name: "Store", myshopifyDomain: values.shopDomain } },
        });
      }
      mintSignal = init?.signal;
      started.resolve();
      await gate.promise;
      return Response.json({ access_token: "late-token", scope: "read_products", expires_in: 120 });
    });
    const pending = invoke(path, context(`${path}-caller`, caller.signal));
    await started.promise;
    caller.abort(new DOMException("Caller left", "AbortError"));
    const wasAborted = mintSignal?.aborted;
    gate.resolve();
    expect(await pending).toMatchObject({ ok: false });
    expect(wasAborted).toBe(true);
    expect(businessDispatches).toBe(0);
  });

  it("fails closed without runtime owner identity despite credential metadata", async () => {
    let requests = 0;
    vi.stubGlobal("fetch", async () => {
      requests++;
      return Response.json({
        access_token: "unscoped",
        scope: "read_products",
        expires_in: 120,
        data: { shop: { id: "1" } },
      });
    });
    const unscoped = context(`${path}-missing-owner`);
    delete unscoped.credentialCacheOwner;
    expect(await invoke(path, unscoped)).toMatchObject({ ok: false });
    expect(requests).toBe(0);
  });
});
