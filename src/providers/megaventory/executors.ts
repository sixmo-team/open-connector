import type { CredentialValidators, ProviderExecutors } from "../../core/types.ts";

import { defineApiKeyProviderExecutors } from "../provider-runtime.ts";
import { megaventoryActionHandlers, validateMegaventoryCredential } from "./runtime.ts";
const service = "megaventory";
export const executors: ProviderExecutors = defineApiKeyProviderExecutors(service, megaventoryActionHandlers, {
  skipDnsValidation: true,
});
export const credentialValidators: CredentialValidators = {
  apiKey(input, { fetcher, signal }) {
    return validateMegaventoryCredential(input.apiKey, fetcher, signal);
  },
};
