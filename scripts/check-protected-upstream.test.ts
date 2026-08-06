import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { findCutoverViolations, findProtectedUpstreamViolations } from "./check-protected-upstream.ts";

const temporaryDirectories: string[] = [];

const requiredFiles: Record<string, string> = {
  "src/saas/index.ts": "export {};\n",
  "web/saas.html": "<!doctype html>\n",
  "web/vite.config.ts": "export default {};\n",
  "docker/Dockerfile": 'CMD ["node", "src/saas/index.ts"]\n',
  "scripts/saas-migrate.ts": "export {};\n",
  "src/providers/registry.generated.ts": "export {};\n",
  "catalog/apps/example.json": "{}\n",
  "package.json": JSON.stringify({
    scripts: {
      start: "node src/saas/index.ts",
      dev: "node --watch src/saas/index.ts",
      migrate: "node scripts/saas-migrate.ts",
    },
  }),
};

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("single-runtime cutover guard", () => {
  it("accepts the sole SaaS runtime layout", async () => {
    const directory = await fixture();
    expect(findCutoverViolations(directory)).toEqual([]);
  });

  it("rejects restored legacy runtimes and entrypoints", async () => {
    const directory = await fixture();
    await writePath(directory, "src/server/index.ts", "export {};\n");
    const packageJson = JSON.parse(requiredFiles["package.json"] ?? "{}") as { scripts: Record<string, string> };
    packageJson.scripts.start = "node src/server/index.ts";
    await writePath(directory, "package.json", JSON.stringify(packageJson));

    expect(findCutoverViolations(directory).join("\n")).toMatch(/src\/server|package start/);
  });

  it("protects reusable core/provider code but permits cutover files", async () => {
    const directory = await fixture();
    await writePath(directory, "src/core/example.ts", "baseline\n");
    await writePath(directory, "scripts/tool.ts", "baseline\n");
    git(directory, ["init", "--quiet"]);
    commit(directory, "baseline");
    const base = git(directory, ["rev-parse", "HEAD"]).trim();

    await writePath(directory, "src/core/example.ts", "changed\n");
    await writePath(directory, "scripts/tool.ts", "changed\n");
    commit(directory, "changes");

    const violations = findProtectedUpstreamViolations(base, directory).join("\n");
    expect(violations).toContain("src/core/example.ts");
    expect(violations).not.toContain("scripts/tool.ts");
  });
});

async function fixture(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "open-connector-cutover-"));
  temporaryDirectories.push(directory);
  await Promise.all(Object.entries(requiredFiles).map(([path, contents]) => writePath(directory, path, contents)));
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
    "user.name=Cutover Guard Test",
    "-c",
    "user.email=cutover-guard@example.invalid",
    "commit",
    "--quiet",
    "-m",
    message,
  ]);
}

function git(directory: string, args: string[]): string {
  return execFileSync("git", args, { cwd: directory, encoding: "utf8" });
}
