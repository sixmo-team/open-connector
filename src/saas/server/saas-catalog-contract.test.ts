import type { JsonSchema, ProviderDefinition } from "../../core/types.ts";
import type { CatalogServicePrincipal, OAuthClientConfigReadiness } from "../contracts.ts";
import type { SaasConnectServerOptions } from "./saas-connect-server.ts";

import { describe, expect, it, vi } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import { ProviderLoader } from "../../providers/provider-loader.ts";
import { SaasConnectServer } from "./saas-connect-server.ts";

function catalogApp(inputSchema: JsonSchema) {
  const provider: ProviderDefinition = {
    service: "public_example",
    displayName: "Public Example",
    categories: ["Developer Tools"],
    authTypes: ["no_auth"],
    auth: [{ type: "no_auth" }],
    actions: [
      {
        id: "public_example.read",
        service: "public_example",
        name: "read",
        description: "Read public data.",
        operationType: "read",
        requiredScopes: [],
        providerPermissions: [],
        inputSchema,
        outputSchema: { type: "object" },
      },
    ],
  };
  const principal: CatalogServicePrincipal = {
    subjectKind: "service",
    subject: "open-connector-catalog",
    purpose: "catalog:read",
    permissions: ["catalog:read"],
  };
  return new SaasConnectServer({
    catalog: createCatalogStore([provider], { executableActionIds: ["public_example.read"] }),
    providerLoader: new ProviderLoader({}),
    verifyJwt: async () => principal,
    readiness: async () => ({
      postgres: true,
      openBao: true,
      jwks: true,
      seaweedFs: true,
      providerRegistry: true,
      catalogFingerprint: true,
    }),
  }).createApp();
}

describe("private catalog consumer contract", () => {
  it("serves complete schemas and changes the catalog identity when a schema changes", async () => {
    const firstSchema = { type: "object", properties: { query: { type: "string" } }, required: ["query"] };
    const secondSchema = { type: "object", properties: { query: { type: "number" } }, required: ["query"] };
    const firstResponse = await catalogApp(firstSchema).request("/internal/saas/catalog/actions?limit=1");
    const secondResponse = await catalogApp(secondSchema).request("/internal/saas/catalog/actions?limit=1");
    const first = await firstResponse.json();
    const second = await secondResponse.json();
    expect(first.items[0].inputSchema).toEqual(firstSchema);
    expect(second.items[0].inputSchema).toEqual(secondSchema);
    expect(first.catalogFingerprint).not.toBe(second.catalogFingerprint);
  });

  it("advertises public provider connection readiness so the product can offer a real connection", async () => {
    const response = await catalogApp({ type: "object" }).request("/internal/saas/catalog/providers");
    const providers = await response.json();
    expect(providers[0].connectionMethods).toContainEqual({ type: "no_auth", fields: [], status: "operational" });
  });

  it("recovers current OAuth readiness without restart or changing the immutable catalog identity", async () => {
    let now = 10_000;
    const clock = vi.spyOn(Date, "now").mockImplementation(() => now);
    let current = new Map<string, OAuthClientConfigReadiness>([
      ["mail_example", { status: "unavailable", reasonCode: "oauth_client_config_missing" }],
    ]);
    const provider: ProviderDefinition = {
      service: "mail_example",
      displayName: "Mail",
      categories: ["Developer Tools"],
      authTypes: ["oauth2"],
      auth: [
        {
          type: "oauth2",
          authorizationUrl: "https://mail.example/authorize",
          tokenUrl: "https://mail.example/token",
          scopes: ["read"],
          tokenEndpointAuthMethod: "client_secret_post",
        },
      ],
      actions: [],
    };
    const options: SaasConnectServerOptions & {
      refreshOAuthClientReadiness: () => Promise<ReadonlyMap<string, OAuthClientConfigReadiness>>;
    } = {
      catalog: createCatalogStore([provider]),
      providerLoader: new ProviderLoader({}),
      verifyJwt: async () => ({
        subjectKind: "service",
        subject: "catalog-review",
        purpose: "catalog:read",
        permissions: ["catalog:read"],
      }),
      readiness: async () => ({
        postgres: true,
        openBao: true,
        jwks: true,
        seaweedFs: true,
        providerRegistry: true,
        catalogFingerprint: true,
      }),
      oauthClientReadiness: current,
      refreshOAuthClientReadiness: async () => current,
    };
    try {
      const app = new SaasConnectServer(options).createApp();
      const before = await (await app.request("/internal/saas/catalog/actions")).json();
      expect(
        (await (await app.request("/internal/saas/catalog/providers")).json())[0].connectionMethods[0].status,
      ).toBe("unavailable");
      current = new Map([["mail_example", { status: "operational" }]]);
      now += 6000;
      expect((await (await app.request("/internal/saas/catalog/providers")).json())[0].connectionMethods[0]).toEqual({
        type: "oauth2",
        fields: [],
        status: "operational",
      });
      const after = await (await app.request("/internal/saas/catalog/actions")).json();
      expect(after.catalogFingerprint).toBe(before.catalogFingerprint);
    } finally {
      clock.mockRestore();
    }
  });
});
