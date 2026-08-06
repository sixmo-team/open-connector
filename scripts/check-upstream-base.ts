import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const APPROVED_UPSTREAM_BASE = "bf94ce83e70a62df34140d2b1c7687eda7b49f82";

const lowercaseShaPattern = /^[0-9a-f]{40}$/;

export function validateUpstreamBase(value: string): boolean {
  const base = value.trim();
  return lowercaseShaPattern.test(base) && base === APPROVED_UPSTREAM_BASE;
}

export function readUpstreamBase(rootDir = process.cwd()): string {
  const base = readFileSync(resolve(rootDir, ".upstream-base"), "utf8").trim();

  if (!lowercaseShaPattern.test(base)) {
    throw new Error(".upstream-base must contain one 40-character lowercase Git SHA");
  }
  if (base !== APPROVED_UPSTREAM_BASE) {
    throw new Error(
      `.upstream-base contains unreviewed revision ${base}; expected approved revision ${APPROVED_UPSTREAM_BASE}`,
    );
  }

  return base;
}

export function checkUpstreamBase(rootDir = process.cwd()): string {
  const base = readUpstreamBase(rootDir);
  const result = spawnSync("git", ["merge-base", "--is-ancestor", base, "HEAD"], {
    cwd: rootDir,
    encoding: "utf8",
  });

  if (result.error) {
    throw new Error(`could not run git merge-base: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const detail = result.stderr.trim();
    throw new Error(
      result.status === 1
        ? `approved upstream revision ${base} is not an ancestor of HEAD`
        : `git merge-base failed${detail ? `: ${detail}` : ` with exit code ${result.status}`}`,
    );
  }

  return base;
}

function main(): void {
  try {
    const base = checkUpstreamBase();
    console.log(`Upstream baseline is approved and reachable: ${base}`);
  } catch (error) {
    console.error(`Upstream baseline check failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}

const entryPath = process.argv[1];
if (entryPath && import.meta.url === pathToFileURL(resolve(entryPath)).href) {
  main();
}
