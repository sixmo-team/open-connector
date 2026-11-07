import { describe, expect, it, vi } from "vitest";
import { getAdminScopes, putAdminActionGrants } from "./admin-api";

const scope = { tenantId: "tenant-a", workspaceId: "workspace-a", subjectId: "user-a" };

describe("administration permissions", () => {
  it("rejects empty or oversized atomic batches and missing operator reasons before writing", async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({ actor: { displayName: "Operator", email: null }, scopes: [] }), {
      headers: { "Content-Type": "application/json", "x-csrf-token": "csrf" },
    })) as unknown as typeof fetch;
    await getAdminScopes(fetcher);
    for (const [ids, reason, category] of [[[], "review", "Invalid action batch"], [["a"], "   ", "Invalid reason"], [["a"], "x".repeat(501), "Invalid reason"], [Array.from({ length: 5001 }, (_, i) => String(i)), "review", "Invalid action batch"]] as [string[], string, string][]) {
      await expect(putAdminActionGrants(ids, scope, null, reason, fetcher)).rejects.toThrow(category);
    }
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});
