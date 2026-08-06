import { beforeEach, describe, expect, it, vi } from "vitest";
import { getAdminScopes, loadAdminData, putAdminActionGrant } from "./admin-api";

const scope = { tenantId: "tenant A", workspaceId: "workspace/A", subjectId: "user@example.com" };

function responseFor(url: string, method: string): Response {
  const headers = { "Content-Type": "application/json", "x-csrf-token": "csrf-from-bff" };
  if (url === "/internal/integration-admin/scopes") {
    return new Response(
      JSON.stringify({
        actor: { actorUserId: "admin-1", subject: "system-admin", displayName: "System administrator", email: null },
        scopes: [],
      }),
      { status: 200, headers },
    );
  }
  if (method === "PUT") return new Response(JSON.stringify({ grant: { enabled: true } }), { status: 200, headers });
  if (url.includes("/overview?")) {
    return new Response(
      JSON.stringify({
        target: {},
        overview: {
          connections: { total: 0, active: 0 },
          providers: { total: 0, active: 0 },
          actions: { total: 0, enabled: 0 },
          runs: {
            total: 0,
            succeeded: 0,
            failed: 0,
            inputBytes: 0,
            outputBytes: 0,
            durationMs: 0,
            p50DurationMs: 0,
            p95DurationMs: 0,
          },
        },
      }),
      { status: 200, headers },
    );
  }
  const resource = ["providers", "actions", "connections", "runs"].find((item) => url.includes(`/${item}?`));
  return new Response(JSON.stringify({ target: {}, [resource!]: [] }), { status: 200, headers });
}

describe("integration administration API boundary", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("uses only the fixed same-origin BFF routes", async () => {
    const fetcher = vi.fn(async (input: string | URL | Request, init?: RequestInit) =>
      responseFor(String(input), init?.method ?? "GET"),
    ) as unknown as typeof fetch;

    await getAdminScopes(fetcher);
    await loadAdminData(scope, fetcher);
    await putAdminActionGrant("github.create/issue", scope, true, "inherit", fetcher);

    const calls = (fetcher as unknown as ReturnType<typeof vi.fn>).mock.calls as [string, RequestInit][];
    const urls = calls.map(([url]) => url);
    expect(urls).toHaveLength(7);
    expect(urls[0]).toBe("/internal/integration-admin/scopes");
    expect(
      urls
        .slice(1, 6)
        .map((url) => url.split("?")[0])
        .sort(),
    ).toEqual(
      ["actions", "connections", "overview", "providers", "runs"].map(
        (resource) => `/internal/integration-admin/${resource}`,
      ),
    );
    expect(urls[6]).toContain("/internal/integration-admin/action-grants/github.create%2Fissue?");
    expect(urls.every((url) => url.startsWith("/internal/integration-admin/"))).toBe(true);
    expect(urls.every((url) => !/^https?:/.test(url))).toBe(true);
    expect(urls.join(" ")).not.toMatch(/\/(?:api|v1|mcp)(?:\/|\?|$)|runtime-token|execute|proxy/i);

    for (const [, init] of calls) {
      expect(init.credentials).toBe("same-origin");
      expect(init.mode).toBe("same-origin");
      expect(init.redirect).toBe("error");
    }
    expect(calls[6][1].headers).toMatchObject({ "x-csrf-token": "csrf-from-bff" });
    expect(calls[6][1].body).toBe(JSON.stringify({ enabled: true, approvalOverride: "inherit" }));
  });
});
