import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { readUpstreamBase } from "./check-upstream-base.ts";
import {
  forbiddenRuntimeMarkers,
  forbiddenRuntimePaths as forbiddenPaths,
  requiredRuntimePaths as requiredPaths,
} from "./legacy-runtime-denylist.ts";

const protectedPrefixes = ["src/core/", "src/oauth/", "src/providers/"] as const;
const generatedRegistry = "src/providers/registry.generated.ts";

export function findProtectedUpstreamViolations(base: string, rootDir = process.cwd()): string[] {
  const fields = splitNull(runGit(["diff", "--name-status", "--find-renames", "-z", base, "--"], rootDir));
  const violations: string[] = [];

  for (let index = 0; index < fields.length;) {
    const status = fields[index++];
    const oldPath = fields[index++];
    if (!status || !oldPath) throw new Error("git diff returned an incomplete name-status record");
    const newPath = status[0] === "R" || status[0] === "C" ? fields[index++] : undefined;
    if ((newPath && isProtectedPath(newPath)) || isProtectedPath(oldPath)) {
      violations.push(newPath ? `${status} ${oldPath} -> ${newPath}` : `${status} ${oldPath}`);
    }
  }

  return violations;
}

export function findCutoverViolations(rootDir = process.cwd()): string[] {
  const violations: string[] = [];
  for (const path of requiredPaths) {
    if (!existsSync(resolve(rootDir, path))) violations.push(`missing required path: ${path}`);
  }
  for (const path of forbiddenPaths) {
    if (existsSync(resolve(rootDir, path))) violations.push(`legacy path still exists: ${path}`);
  }

  const packagePath = resolve(rootDir, "package.json");
  if (existsSync(packagePath)) {
    const scripts =
      (JSON.parse(readFileSync(packagePath, "utf8")) as { scripts?: Record<string, string> }).scripts ?? {};
    if (scripts.start !== "node --experimental-transform-types src/saas/index.ts")
      violations.push("package start is not the SaaS runtime");
    if (scripts.dev !== "node --experimental-transform-types --watch src/saas/index.ts")
      violations.push("package dev is not the SaaS runtime");
    if (scripts.migrate !== "node --experimental-transform-types scripts/saas-migrate.ts")
      violations.push("package migrate is not the SaaS migrator");
    const scriptText = JSON.stringify(scripts);
    for (const marker of forbiddenRuntimeMarkers) {
      if (scriptText.includes(marker)) violations.push(`legacy package script marker: ${marker}`);
    }
  }

  const dockerPath = resolve(rootDir, "docker/Dockerfile");
  if (existsSync(dockerPath)) {
    const dockerfile = readFileSync(dockerPath, "utf8");
    if (!dockerfile.includes('CMD ["node", "--experimental-transform-types", "src/saas/index.ts"]'))
      violations.push("Dockerfile does not start the SaaS runtime");
    for (const marker of [
      "src/server/",
      "Dockerfile.saas",
      "wrangler",
      "SQLite",
      "/app/data",
      "OPEN_CONNECTOR_ADMIN_TOKEN",
    ]) {
      if (dockerfile.includes(marker)) violations.push(`legacy Dockerfile marker: ${marker}`);
    }
  }

  const legacyRoot = resolve(rootDir, "src/server");
  for (const file of sourceFiles(resolve(rootDir, "src"))) {
    const source = readFileSync(file, "utf8");
    for (const match of source.matchAll(/(?:from\s+|import\s*(?:\(\s*)?)["']([^"']+)["']/g)) {
      const specifier = match[1];
      if (!specifier?.startsWith(".")) continue;
      const target = resolve(file, "..", specifier);
      if (target === legacyRoot || target.startsWith(`${legacyRoot}/`)) {
        violations.push(`Native import resolves into legacy runtime: ${relative(rootDir, file)} -> ${specifier}`);
      }
    }
  }

  return violations;
}

export function checkProtectedUpstream(rootDir = process.cwd()): void {
  const violations = [
    ...findProtectedUpstreamViolations(readUpstreamBase(rootDir), rootDir),
    ...findCutoverViolations(rootDir),
  ];
  if (violations.length) {
    throw new Error(["single-runtime cutover invariant failed:", ...violations.map((item) => `- ${item}`)].join("\n"));
  }
}

function isProtectedPath(path: string): boolean {
  return path !== generatedRegistry && protectedPrefixes.some((prefix) => path.startsWith(prefix));
}

function sourceFiles(path: string): string[] {
  if (!existsSync(path)) return [];
  if (!statSync(path).isDirectory()) return path.endsWith(".ts") || path.endsWith(".tsx") ? [path] : [];
  return readdirSync(path).flatMap((name) => sourceFiles(resolve(path, name)));
}

function splitNull(value: string): string[] {
  const fields = value.split("\0");
  if (fields.at(-1) === "") fields.pop();
  return fields;
}

function runGit(args: string[], cwd: string): string {
  const result = spawnSync("git", args, { cwd, encoding: "utf8" });
  if (result.error) throw new Error(`could not run git ${args[0]}: ${result.error.message}`);
  if (result.status !== 0) throw new Error(`git ${args[0]} failed: ${result.stderr.trim()}`);
  return result.stdout;
}

function main(): void {
  try {
    checkProtectedUpstream();
    console.log("Single-runtime cutover and protected upstream invariants pass");
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}

const entryPath = process.argv[1];
if (entryPath && import.meta.url === pathToFileURL(resolve(entryPath)).href) main();
