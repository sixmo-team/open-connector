import type { CredentialValidators, ProviderExecutors, ProviderProxyExecutor } from "../../core/types.ts";
import type { ApiKeyProviderContext } from "../provider-runtime.ts";

import { defineApiKeyProviderExecutors, defineProviderProxy } from "../provider-runtime.ts";
import { linkfoxActions } from "./actions.ts";
import { executeLinkfoxAction, linkfoxApiBaseUrl, validateLinkfoxCredential } from "./runtime.ts";

const service = "linkfox";
const handlers: Record<string, (input: Record<string, unknown>, context: ApiKeyProviderContext) => Promise<unknown>> =
  {};
for (const action of linkfoxActions) {
  handlers[action.name] = (input, context) =>
    executeLinkfoxAction(action.name, input, context.apiKey, context.fetcher, context.signal);
}

export const executors: ProviderExecutors = defineApiKeyProviderExecutors(service, handlers, {
  skipDnsValidation: true,
});

export const proxy: ProviderProxyExecutor = defineProviderProxy({
  service,
  baseUrl: linkfoxApiBaseUrl,
  auth: { type: "api_key_header", name: "Authorization" },
  skipDnsValidation: true,
});

export const credentialValidators: CredentialValidators = {
  async apiKey(input, { fetcher, signal }) {
    return validateLinkfoxCredential(input.apiKey, fetcher, signal);
  },
};
