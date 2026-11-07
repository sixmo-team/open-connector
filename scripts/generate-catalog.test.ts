import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "vitest";

test("check rejects stale ignored catalog and executable contracts without writing", async () => {
  const root = await mkdtemp(join(tmpdir(), "connector-generation-"));
  const run = (...args: string[]) =>
    spawnSync(process.execPath, ["scripts/generate-catalog.ts", ...args], {
      cwd: root,
      encoding: "utf8",
    });
  try {
    await mkdir(join(root, "src/providers"), { recursive: true });
    // A single real provider exercises the production renderer without copying the whole provider tree.
    for (const path of [
      "src/core",
      "src/catalog-index.ts",
      "src/catalog-localization",
      "src/providers/17track",
      "scripts",
      "package.json",
    ]) {
      await cp(path, join(root, path), { recursive: true });
    }
    // This fixture publishes only one provider, so its translation catalog must have the same scope.
    await writeFile(
      join(root, "src/catalog-localization/zh-CN.ts"),
      "export const zhCN = { categories: {}, providers: {} };\n",
    );
    await symlink(join(process.cwd(), "node_modules"), join(root, "node_modules"), "dir");
    const generated = run();
    assert.equal(generated.status, 0, generated.stderr);
    const fresh = run("--check");
    assert.equal(fresh.status, 0, fresh.stderr);
    const mutations: Record<string, (original: string) => string> = {
      "catalog/apps/17track.json": (original) => JSON.stringify({ ...JSON.parse(original), auth: [], triggers: [] }),
      "catalog/apps-index.json": (original) => JSON.stringify({ ...JSON.parse(original), providers: [] }),
      "src/providers/registry.generated.ts": (original) =>
        original.replace("./17track/executors.ts", "./missing/executors.ts"),
      "src/providers/action-contracts.generated.ts": () =>
        'export interface ProviderActionNames { "17track": never; }\n',
    };
    for (const [path, mutate] of Object.entries(mutations)) {
      const file = join(root, path);
      const original = await readFile(file, "utf8");
      const stale = mutate(original);
      assert.notEqual(stale, original);
      await writeFile(file, stale);
      const checked = run("--check");
      assert.notEqual(checked.status, 0, `accepted stale ${path}`);
      assert.equal(await readFile(file, "utf8"), stale, `check wrote ${path}`);
      await writeFile(file, original);
    }
    const extra = join(root, "catalog/apps/unexpected.json");
    await writeFile(extra, "{}\n");
    assert.notEqual(run("--check").status, 0, "accepted extra catalog app");
    assert.equal(await readFile(extra, "utf8"), "{}\n");
    await rm(extra);
    const registry = join(root, "src/providers/registry.generated.ts");
    await rm(registry);
    assert.notEqual(run("--check").status, 0, "accepted missing registry");
    await assert.rejects(readFile(registry), { code: "ENOENT" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}, 30_000);
