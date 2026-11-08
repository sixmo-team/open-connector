import { expect, it } from "vitest";
import { createOomolConsoleMemberDirectory } from "./member-directory.ts";
import { defaultEndpoints } from "./request.ts";
import { executeOomolConsoleAction } from "./runtime.ts";
const deps = { endpoints: defaultEndpoints, memberDirectory: createOomolConsoleMemberDirectory(defaultEndpoints) };
it("uses the caller API key for registry bindings without private identity headers", async () => {
  const calls: { url: string; init: RequestInit | undefined }[] = [];
  const fetcher: typeof fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return Response.json({ ok: true });
  };
  const context = { apiKey: "public-api-key", teamId: "team/one", fetcher };
  for (const name of ["add_skill_package_to_team", "remove_skill_package_from_team"] as const)
    await expect(
      executeOomolConsoleAction(name, { packageName: "@org/skill" }, context, fetcher, deps),
    ).resolves.toMatchObject({ success: true, teamId: "team/one" });
  expect(calls.map((c) => c.init?.method)).toEqual(["PUT", "DELETE"]);
  for (const c of calls) {
    expect(c.url).toBe("https://registry.oomol.com/-/oomol/packages/@org/skill/orgs/team%2Fone");
    const headers = new Headers(c.init?.headers);
    expect(headers.get("authorization")).toBe("Bearer public-api-key");
    expect(headers.has("x-oomol-user-id")).toBe(false);
  }
});
it("reads execution records through the public apps route with the selected team", async () => {
  const fetcher: typeof fetch = async (url, init) => {
    expect(String(url)).toBe("https://connector.oomol.com/v1/apps/by-id/app%2Fone/executions");
    expect(new Headers(init?.headers).get("x-oo-team-id")).toBe("team-one");
    return Response.json({ success: true, data: { data: [], nextCursor: "next-page" } });
  };
  await expect(
    executeOomolConsoleAction(
      "list_connection_executions",
      { appId: "app/one" },
      { apiKey: "key", teamId: "team-one", fetcher },
      fetcher,
      deps,
    ),
  ).resolves.toEqual({ data: [], nextCursor: "next-page" });
});

it("rejects billing requests without a team before making any network request", async () => {
  let calls = 0;
  const fetcher: typeof fetch = async () => {
    calls++;
    return Response.json({});
  };
  for (const name of ["get_billing_summary", "get_usage_breakdown"] as const) {
    await expect(executeOomolConsoleAction(name, {}, { apiKey: "key", fetcher }, fetcher, deps)).rejects.toThrow();
  }
  expect(calls).toBe(0);
});

it("resolves member names through the current credential instead of reusing another caller's summary", async () => {
  const userId = crypto.randomUUID();
  const firstKey = crypto.randomUUID();
  const secondKey = crypto.randomUUID();
  const firstTeam = crypto.randomUUID();
  const secondTeam = crypto.randomUUID();
  let firstSummaryAllowed = true;
  const fetcher: typeof fetch = async (url, init) => {
    const address = new URL(String(url));
    const authorization = new Headers(init?.headers).get("authorization");
    if (authorization !== `Bearer ${firstKey}` && authorization !== `Bearer ${secondKey}`) {
      return new Response(null, { status: 401 });
    }
    const first = authorization === `Bearer ${firstKey}`;
    if (address.pathname === `/v1/teams/${first ? firstTeam : secondTeam}/members`) {
      return Response.json({ members: [{ user_id: userId, user_type: "user", role: "member" }] });
    }
    if (address.pathname === "/v1/users/summaries" && address.searchParams.get("user_ids") === userId) {
      if (first && !firstSummaryAllowed) return new Response(null, { status: 403 });
      return Response.json({
        [userId]: { nickname: first ? "First credential profile" : "Second credential profile" },
      });
    }
    throw new Error("Unexpected member-directory request");
  };
  const list = (apiKey: string, teamId: string) =>
    executeOomolConsoleAction("list_members", {}, { apiKey, teamId, fetcher }, fetcher, deps);

  await expect(list(firstKey, firstTeam)).resolves.toMatchObject({
    members: [{ userId, name: "First credential profile" }],
  });
  await expect(list(secondKey, secondTeam)).resolves.toMatchObject({
    members: [{ userId, name: "Second credential profile" }],
  });
  firstSummaryAllowed = false;
  await expect(list(firstKey, firstTeam)).resolves.toEqual(
    expect.objectContaining({ members: [expect.not.objectContaining({ name: expect.any(String) })] }),
  );
});
