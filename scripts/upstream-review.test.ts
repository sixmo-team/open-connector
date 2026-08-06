import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { analyzeUpstreamChanges, formatUpstreamReview, validateCandidateRevision } from "./upstream-review.ts";

const temporaryDirectories: string[] = [];

const baselineCatalog = JSON.stringify({
  service: "changed",
  actions: [{ id: "changed.read", inputSchema: { type: "object" }, outputSchema: { type: "string" } }],
});
const candidateCatalog = JSON.stringify({
  service: "changed",
  actions: [
    {
      id: "changed.read",
      inputSchema: { properties: { id: { type: "string" } }, type: "object" },
      outputSchema: { type: "string" },
    },
  ],
});

interface Fixture {
  base: string;
  candidate: string;
  directory: string;
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("analyzeUpstreamChanges", () => {
  it("deterministically classifies upstream changes without changing the worktree", async () => {
    const fixture = await createClassificationFixture();
    const statusBefore = git(fixture.directory, ["status", "--porcelain"]);

    const first = analyzeUpstreamChanges(fixture.base, fixture.candidate, fixture.directory);
    const second = analyzeUpstreamChanges(fixture.base, fixture.candidate, fixture.directory);

    expect(second).toEqual(first);
    expect(git(fixture.directory, ["status", "--porcelain"])).toBe(statusBefore);
    expect(first.providerOnlyChanges).toEqual(["src/providers/example/actions.ts"]);
    expect(first.sensitiveChanges).toEqual([
      { path: "src/oauth/oauth-flow-service.ts", kinds: ["OAuth"] },
      { path: "src/server/actions/action-runner.ts", kinds: ["runtime", "action-runner"] },
      { path: "src/server/api/auth.ts", kinds: ["runtime", "auth"] },
      { path: "src/server/storage/runtime-store.ts", kinds: ["runtime", "store"] },
    ]);
    expect(first.catalogAdditions).toEqual(["catalog/apps/added.json"]);
    expect(first.catalogRemovals).toEqual(["catalog/apps/removed.json"]);
    expect(first.catalogSchemaFingerprints.map(({ path }) => path)).toEqual([
      "catalog/apps/added.json",
      "catalog/apps/changed.json",
      "catalog/apps/removed.json",
    ]);
    expect(first.catalogSchemaFingerprints[0]).toMatchObject({ base: null });
    expect(first.catalogSchemaFingerprints[1]?.base).not.toBe(first.catalogSchemaFingerprints[1]?.candidate);
    expect(first.catalogSchemaFingerprints[2]).toMatchObject({ candidate: null });
    expect(first.saasConflictRiskFiles).toEqual([
      "catalog/apps/added.json",
      "catalog/apps/changed.json",
      "catalog/apps/removed.json",
      "src/oauth/oauth-flow-service.ts",
      "src/server/actions/action-runner.ts",
      "src/server/api/auth.ts",
      "src/server/storage/runtime-store.ts",
      "web/src/shared-ui.tsx",
    ]);
    expect(first.requiredFocusedTestCommands).toEqual([
      "npm run generate:catalog",
      "npm run verify:generated",
      "npm test -- src/providers",
      "npm test -- src/core src/saas",
      "npm test -- src/saas/storage",
      "npm test -- src/saas/auth src/saas/server",
      "npm test -- src/oauth src/saas/oauth",
      "npm test -- src/saas/actions",
      "npm test -- src/saas",
    ]);

    const report = formatUpstreamReview(first);
    for (const heading of [
      "Provider-only changes",
      "Runtime/store/auth/OAuth/action-runner changes",
      "Generated catalog additions",
      "Generated catalog removals",
      "Generated catalog schema fingerprints",
      "SaaS conflict-risk files",
      "Required focused test commands",
    ]) {
      expect(report).toContain(heading);
    }
  });

  it("rejects revisions and repository paths that could be interpreted as commands or paths", async () => {
    for (const candidate of ["HEAD", "../candidate", "a".repeat(39), `${"a".repeat(40)};touch /tmp/pwned`]) {
      expect(() => validateCandidateRevision(candidate)).toThrow("40-character lowercase Git SHA");
    }

    const directory = await createRepository();
    await writePath(directory, "src/unsafe\tpath.ts", "unsafe\n");
    commit(directory, "unsafe path");
    const candidate = git(directory, ["rev-parse", "HEAD"]).trim();
    const base = git(directory, ["rev-parse", "HEAD^"]).trim();

    expect(() => analyzeUpstreamChanges(base, candidate, directory)).toThrow("unsafe repository path");
  });
});

async function createClassificationFixture(): Promise<Fixture> {
  const directory = await createRepository();
  const baselineFiles: Record<string, string> = {
    "catalog/apps/changed.json": baselineCatalog,
    "catalog/apps/removed.json": JSON.stringify({ service: "removed", actions: [] }),
    "src/oauth/oauth-flow-service.ts": "export const oauth = 1;\n",
    "src/providers/example/actions.ts": "export const action = 1;\n",
    "src/server/actions/action-runner.ts": "export const runner = 1;\n",
    "src/server/api/auth.ts": "export const auth = 1;\n",
    "src/server/storage/runtime-store.ts": "export const store = 1;\n",
    "web/src/shared-ui.tsx": "export const ui = 1;\n",
  };
  for (const [path, contents] of Object.entries(baselineFiles)) await writePath(directory, path, contents);
  commit(directory, "baseline files");
  const base = git(directory, ["rev-parse", "HEAD"]).trim();

  await writePath(directory, "catalog/apps/added.json", JSON.stringify({ service: "added", actions: [] }));
  await writePath(directory, "catalog/apps/changed.json", candidateCatalog);
  await rm(join(directory, "catalog/apps/removed.json"));
  for (const path of Object.keys(baselineFiles).filter((path) => !path.startsWith("catalog/"))) {
    await writePath(directory, path, "export const changed = 2;\n");
  }
  commit(directory, "candidate changes");
  return { base, candidate: git(directory, ["rev-parse", "HEAD"]).trim(), directory };
}

async function createRepository(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "open-connector-review-"));
  temporaryDirectories.push(directory);
  git(directory, ["init", "--quiet"]);
  await writePath(directory, "README", "fixture\n");
  commit(directory, "initial");
  return directory;
}

async function writePath(directory: string, path: string, contents: string): Promise<void> {
  const target = join(directory, path);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, contents);
}

function commit(directory: string, message: string): void {
  git(directory, ["add", "--all", "--"]);
  git(directory, [
    "-c",
    "user.name=Upstream Review Test",
    "-c",
    "user.email=upstream-review@example.invalid",
    "commit",
    "--quiet",
    "-m",
    message,
  ]);
}

function git(directory: string, args: string[]): string {
  return execFileSync("git", args, { cwd: directory, encoding: "utf8" });
}
