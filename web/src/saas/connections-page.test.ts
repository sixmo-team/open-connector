import type { SafeAdminConnection } from "./admin-model";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { AdminConnectionsPage } from "./connections-page";

vi.mock("@embra/i18n/react", () => ({
  useTranslate() {
    return (key: string) => key;
  },
}));

describe("AdminConnectionsPage", () => {
  it("renders only the safe connection model", () => {
    const connection = {
      providerName: "GitHub",
      accountName: "octo-admin",
      accountEmail: "octo@example.com",
      ownerName: "Ada Lovelace",
      visibility: "workspace",
      status: "active",
      authType: "oauth2",
      lastVerifiedAt: "2026-08-04T12:00:00.000Z",
      calls: 42,
      inputBytes: 120,
      outputBytes: 340,
      durationMs: 900,
      id: "conn-internal-47",
      connectorAlias: "production-root",
      secretRef: "secret://tenant/workspace/connection",
      token: "never-render-this-token",
      openBaoPath: "kv/data/integrations/github",
      rawPayload: { access_token: "raw-provider-token" },
    } satisfies SafeAdminConnection & Record<string, unknown>;

    const markup = renderToStaticMarkup(createElement(AdminConnectionsPage, { connections: [connection] }));

    expect(markup).toContain("GitHub");
    expect(markup).toContain("octo-admin");
    expect(markup).toContain("octo@example.com");
    expect(markup).toContain("Ada Lovelace");
    expect(markup).toContain("42");
    expect(markup).not.toContain("conn-internal-47");
    expect(markup).not.toContain("production-root");
    expect(markup).not.toContain("secret://");
    expect(markup).not.toContain("never-render-this-token");
    expect(markup).not.toContain("kv/data");
    expect(markup).not.toContain("raw-provider-token");
  });
});
