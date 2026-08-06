import { afterEach, describe, expect, it, vi } from "vitest";
import { AdminApiError, loadAdminData } from "./admin-api";
import { changeAdminScope } from "./scope-selector";

function scopedResponse(url: string): Response {
  const headers = { "Content-Type": "application/json" };
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

afterEach(() => {
  Reflect.deleteProperty(globalThis, "localStorage");
});

describe("administration scope selection", () => {
  it("clears dependent selections and refetches every scoped page", async () => {
    const original = { tenantId: "tenant-a", workspaceId: "workspace-a", subjectId: "subject-a" };
    expect(changeAdminScope(original, "tenantId", "tenant-b")).toEqual({
      tenantId: "tenant-b",
      workspaceId: "",
      subjectId: "",
    });
    expect(changeAdminScope(original, "workspaceId", "workspace-b")).toEqual({
      tenantId: "tenant-a",
      workspaceId: "workspace-b",
      subjectId: "",
    });

    const next = { tenantId: "tenant-b", workspaceId: "workspace-b", subjectId: "subject-b" };
    const fetcher = vi.fn(async (input: string | URL | Request) =>
      scopedResponse(String(input)),
    ) as unknown as typeof fetch;
    await loadAdminData(next, fetcher);

    const urls = (fetcher as unknown as ReturnType<typeof vi.fn>).mock.calls.map(([url]) => String(url));
    expect(urls).toHaveLength(5);
    expect(urls.map((url) => url.split("?")[0]).sort()).toEqual(
      ["actions", "connections", "overview", "providers", "runs"].map(
        (resource) => `/internal/integration-admin/${resource}`,
      ),
    );
    for (const url of urls) {
      const query = new URLSearchParams(url.split("?")[1]);
      expect(Object.fromEntries(query)).toEqual({
        tenantId: "tenant-b",
        workspaceId: "workspace-b",
        subjectUserId: "subject-b",
      });
    }
  });

  it("does not persist a scope rejected by the BFF", async () => {
    const setItem = vi.fn();
    Object.defineProperty(globalThis, "localStorage", { configurable: true, value: { setItem } });
    const fetcher = vi.fn(async () => new Response(null, { status: 403 })) as unknown as typeof fetch;

    await expect(
      loadAdminData({ tenantId: "revoked", workspaceId: "revoked", subjectId: "revoked" }, fetcher),
    ).rejects.toBeInstanceOf(AdminApiError);
    expect(setItem).not.toHaveBeenCalled();
  });
});
