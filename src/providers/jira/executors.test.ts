import type { ResolvedCredential } from "../../core/types.ts";

import { describe, expect, it } from "vitest";
import { credentialValidators } from "./executors.ts";

const credential: Extract<ResolvedCredential, { authType: "oauth2" }> = {
  authType: "oauth2",
  accessToken: "jira-token",
  tokenType: "Bearer",
  profile: { accountId: "oauth2", displayName: "OAuth Credential", grantedScopes: [] },
  metadata: {},
};

describe("Jira OAuth credential validation", () => {
  it.each([
    { name: "no resource", resources: [] },
    { name: "a resource without Jira access", resources: [{ id: "cloud-123", url: "https://docs.atlassian.net", scopes: ["read:me"] }] },
  ])("does not manufacture a connected account for $name", async ({ resources }) => {
    await expect(credentialValidators.oauth2!(credential, {
      fetcher: async () => Response.json(resources),
    })).rejects.toMatchObject({ status: 403 });
  });

  it("preserves the verified Jira site identity and granted permissions", async () => {
    const result = await credentialValidators.oauth2!(credential, {
      fetcher: async () => Response.json([{ id: "cloud-123", name: "Actual Jira site", url: "https://work.atlassian.net", scopes: ["read:jira-work"] }]),
    });
    expect(result).toMatchObject({ profile: { accountId: "jira:cloud-123", displayName: "Actual Jira site" }, metadata: { cloudId: "cloud-123", siteUrl: "https://work.atlassian.net" } });
  });

  it("rejects malformed accessible-resource responses", async () => {
    await expect(
      credentialValidators.oauth2!(credential, { fetcher: async () => Response.json({}) }),
    ).rejects.toMatchObject({ status: 502, message: "jira accessible-resources response must be an array" });
  });

  it("rejects malformed accessible-resource entries", async () => {
    await expect(
      credentialValidators.oauth2!(credential, { fetcher: async () => Response.json([{}]) }),
    ).rejects.toMatchObject({ status: 502, message: "missing jira accessible resource id" });
  });
});
