import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { basename, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { readUpstreamBase } from "./check-upstream-base.ts";

const fullShaPattern = /^[0-9a-f]{40}$/;
const catalogPrefix = "catalog/apps/";

export type SensitiveChangeKind = "runtime" | "store" | "auth" | "OAuth" | "action-runner";

export interface SensitiveUpstreamChange {
  path: string;
  kinds: SensitiveChangeKind[];
}

export interface CatalogSchemaFingerprint {
  path: string;
  base: string | null;
  candidate: string | null;
}

export interface UpstreamReview {
  base: string;
  candidate: string;
  providerOnlyChanges: string[];
  sensitiveChanges: SensitiveUpstreamChange[];
  catalogAdditions: string[];
  catalogRemovals: string[];
  catalogSchemaFingerprints: CatalogSchemaFingerprint[];
  catalogCapabilityFingerprints: CatalogSchemaFingerprint[];
  sourceFingerprints: CatalogSchemaFingerprint[];
  catalogInputs: UpstreamCatalogInputs | null;
  saasConflictRiskFiles: string[];
  requiredFocusedTestCommands: string[];
}

export interface UpstreamCatalogInputs {
  baseCatalogDir: string;
  candidateCatalogDir: string;
}

export function validateCandidateRevision(value: string): string {
  if (!fullShaPattern.test(value)) {
    throw new Error("candidate revision must be one 40-character lowercase Git SHA");
  }
  return value;
}

export function analyzeUpstreamChanges(
  baseInput: string,
  candidateInput: string,
  rootDir = process.cwd(),
  catalogInputs?: UpstreamCatalogInputs,
): UpstreamReview {
  const base = validateCandidateRevision(baseInput);
  const candidate = validateCandidateRevision(candidateInput);
  assertLocalCommit(base, "baseline", rootDir);
  assertLocalCommit(candidate, "candidate", rootDir);
  assertAncestor(base, candidate, rootDir);
  const sourceFingerprints = readSourceFingerprints(base, candidate, rootDir);
  const changedPaths = sourceFingerprints.map(({ path }) => path);
  const providerOnlyChanges = changedPaths.filter(isProviderImplementationPath);
  const sensitiveChanges = changedPaths.flatMap((path) => {
    const kinds = classifySensitiveChange(path);
    return kinds.length === 0 ? [] : [{ path, kinds }];
  });
  const inputs = catalogInputs
    ? {
        baseCatalogDir: resolve(rootDir, catalogInputs.baseCatalogDir),
        candidateCatalogDir: resolve(rootDir, catalogInputs.candidateCatalogDir),
      }
    : null;
  const baseCatalogPaths = inputs ? listGeneratedCatalogPaths(inputs.baseCatalogDir) : listCatalogPaths(base, rootDir);
  const candidateCatalogPaths = inputs
    ? listGeneratedCatalogPaths(inputs.candidateCatalogDir)
    : listCatalogPaths(candidate, rootDir);
  if (
    !inputs &&
    (baseCatalogPaths.length === 0 || candidateCatalogPaths.length === 0) &&
    changedPaths.some(isCatalogProducerPath)
  ) {
    throw new Error(
      "Catalog-producing source changed without tracked catalogs; provide both actual generated catalog snapshots",
    );
  }
  const baseCatalogSet = new Set(baseCatalogPaths);
  const candidateCatalogSet = new Set(candidateCatalogPaths);
  const catalogAdditions = candidateCatalogPaths.filter((path) => !baseCatalogSet.has(path));
  const catalogRemovals = baseCatalogPaths.filter((path) => !candidateCatalogSet.has(path));
  const comparedPaths = inputs
    ? [...new Set([...baseCatalogPaths, ...candidateCatalogPaths])].sort()
    : changedPaths.filter(
        (path) => path.startsWith(catalogPrefix) && (baseCatalogSet.has(path) || candidateCatalogSet.has(path)),
      );
  const catalogSchemaFingerprints: CatalogSchemaFingerprint[] = [];
  const catalogCapabilityFingerprints: CatalogSchemaFingerprint[] = [];
  for (const path of comparedPaths) {
    const before = baseCatalogSet.has(path)
      ? fingerprintCatalog(
          inputs
            ? readFileSync(resolve(inputs.baseCatalogDir, basename(path)), "utf8")
            : readRevisionFile(base, path, rootDir),
          path,
        )
      : null;
    const after = candidateCatalogSet.has(path)
      ? fingerprintCatalog(
          inputs
            ? readFileSync(resolve(inputs.candidateCatalogDir, basename(path)), "utf8")
            : readRevisionFile(candidate, path, rootDir),
          path,
        )
      : null;
    if (before?.capabilities === after?.capabilities) continue;
    catalogSchemaFingerprints.push({ path, base: before?.schemas ?? null, candidate: after?.schemas ?? null });
    catalogCapabilityFingerprints.push({
      path,
      base: before?.capabilities ?? null,
      candidate: after?.capabilities ?? null,
    });
  }
  const sensitivePaths = new Set(sensitiveChanges.map(({ path }) => path));
  const saasConflictRiskFiles = changedPaths.filter((path) => isSaasConflictRisk(path, sensitivePaths));
  return {
    base,
    candidate,
    providerOnlyChanges,
    sensitiveChanges,
    catalogAdditions,
    catalogRemovals,
    catalogSchemaFingerprints,
    catalogCapabilityFingerprints,
    sourceFingerprints,
    catalogInputs: inputs,
    saasConflictRiskFiles,
    requiredFocusedTestCommands: focusedTestCommands({
      providerOnlyChanges,
      sensitiveChanges,
      catalogSchemaFingerprints,
      sourceFingerprints,
      saasConflictRiskFiles,
    }),
  };
}

export function createUpstreamReview(
  candidate: string,
  rootDir = process.cwd(),
  catalogInputs?: UpstreamCatalogInputs,
): UpstreamReview {
  return analyzeUpstreamChanges(readUpstreamBase(rootDir), candidate, rootDir, catalogInputs);
}

export function formatUpstreamReview(review: UpstreamReview): string {
  return [
    "Upstream review",
    `Base: ${review.base}`,
    `Candidate: ${review.candidate}`,
    `Catalog inputs: ${review.catalogInputs ? JSON.stringify(review.catalogInputs) : "tracked revision files"}`,
    "",
    formatList("Provider-only changes", review.providerOnlyChanges),
    "",
    formatList(
      "Runtime/store/auth/OAuth/action-runner changes",
      review.sensitiveChanges.map(({ path, kinds }) => `[${kinds.join(", ")}] ${path}`),
    ),
    "",
    formatList("Generated catalog additions", review.catalogAdditions),
    "",
    formatList("Generated catalog removals", review.catalogRemovals),
    "",
    formatList(
      "Generated catalog schema fingerprints",
      review.catalogSchemaFingerprints.map(
        ({ path, base, candidate }) => `${path}: base=${base ?? "absent"} candidate=${candidate ?? "absent"}`,
      ),
    ),
    "",
    formatList(
      "Complete provider capabilities (authentication, scopes, permissions, triggers and action contracts)",
      review.catalogCapabilityFingerprints.map(
        ({ path, base, candidate }) => `${path}: base=${base ?? "absent"} candidate=${candidate ?? "absent"}`,
      ),
    ),
    "",
    formatList(
      "Exact changed source modes and Git blobs (including generator/index/executor coverage)",
      review.sourceFingerprints.map(
        ({ path, base, candidate }) => `${path}: base=${base ?? "absent"} candidate=${candidate ?? "absent"}`,
      ),
    ),
    "",
    formatList("SaaS conflict-risk files", review.saasConflictRiskFiles),
    "",
    formatList(
      "Required focused test commands",
      review.requiredFocusedTestCommands.map((command) => `\`${command}\``),
    ),
  ].join("\n");
}

function classifySensitiveChange(path: string): SensitiveChangeKind[] {
  const kinds: SensitiveChangeKind[] = [];
  if (
    path.startsWith("src/server/") ||
    path.startsWith("src/saas/") ||
    path.startsWith("src/catalog-") ||
    path.startsWith("src/core/") ||
    path === "src/catalog-store.ts" ||
    path === "src/connection-service.ts" ||
    path === "src/providers/provider-loader.ts"
  ) {
    kinds.push("runtime");
  }
  if (/(?:^|[-/])(store|storage|database)(?:[-/.]|$)/i.test(path)) kinds.push("store");
  const isOAuth = /(?:^|[-/])oauth2?(?:[-/.]|$)/i.test(path);
  if (/(?:^|[-/])auth(?:entication)?(?:[-/.]|$)/i.test(path) && !isOAuth) kinds.push("auth");
  if (isOAuth) kinds.push("OAuth");
  if (/(?:^|[-/])action-runner(?:[-/.]|$)/i.test(path) || path === "src/core/execution.ts") {
    kinds.push("action-runner");
  }
  return kinds;
}

function isProviderImplementationPath(path: string): boolean {
  const parts = path.split("/");
  return parts[0] === "src" && parts[1] === "providers" && parts.length > 3;
}

function isCatalogProducerPath(path: string): boolean {
  return (
    !path.endsWith(".test.ts") &&
    (path.startsWith("src/providers/") ||
      path.startsWith("src/catalog-") ||
      /^scripts\/(?:generate-|provider-source|ensure-generated)/.test(path))
  );
}

function isSaasConflictRisk(path: string, sensitivePaths: ReadonlySet<string>): boolean {
  return (
    sensitivePaths.has(path) ||
    path.startsWith(catalogPrefix) ||
    path.startsWith("src/saas/") ||
    path.startsWith("web/") ||
    path.startsWith("docker/") ||
    path.startsWith("scripts/") ||
    path === "package.json" ||
    path === "package-lock.json" ||
    path === "src/providers/registry.generated.ts"
  );
}

function focusedTestCommands(
  review: Pick<
    UpstreamReview,
    | "providerOnlyChanges"
    | "sensitiveChanges"
    | "catalogSchemaFingerprints"
    | "sourceFingerprints"
    | "saasConflictRiskFiles"
  >,
): string[] {
  const commands = new Set<string>();
  const kinds = new Set(review.sensitiveChanges.flatMap(({ kinds }) => kinds));
  if (
    review.providerOnlyChanges.length > 0 ||
    review.catalogSchemaFingerprints.length > 0 ||
    review.sourceFingerprints.some(({ path }) => isCatalogProducerPath(path))
  ) {
    commands.add("npm run generate:catalog");
    commands.add("npm run verify:generated");
    commands.add("npm test -- src/providers");
  }
  if (kinds.has("runtime")) commands.add("npm test -- src/core src/saas");
  if (kinds.has("store")) commands.add("npm test -- src/saas/storage");
  if (kinds.has("auth")) commands.add("npm test -- src/saas/auth src/saas/server");
  if (kinds.has("OAuth")) commands.add("npm test -- src/oauth src/saas/oauth");
  if (kinds.has("action-runner")) commands.add("npm test -- src/saas/actions");
  if (review.saasConflictRiskFiles.length > 0) commands.add("npm test -- src/saas");
  return [...commands];
}

function listCatalogPaths(revision: string, cwd: string): string[] {
  return splitNull(runGit(["ls-tree", "-r", "--name-only", "-z", revision, "--", catalogPrefix], cwd))
    .map(validateRepoPath)
    .filter((path) => path.endsWith(".json"));
}

function fingerprintCatalog(contents: string, path: string): { schemas: string; capabilities: string } {
  let value: unknown;
  try {
    value = JSON.parse(contents);
  } catch (error) {
    throw new Error(
      `could not parse generated catalog ${path}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!isRecord(value) || !Array.isArray(value.actions) || value.service !== basename(path, ".json")) {
    throw new Error(`generated catalog ${path} must identify its provider and contain an actions array`);
  }
  const schemas = value.actions.map((action, index) => {
    if (!isRecord(action) || typeof action.id !== "string" || action.id.length === 0)
      throw new Error(`generated catalog ${path} action ${index} must identify its action`);
    return { id: action.id, inputSchema: action.inputSchema ?? null, outputSchema: action.outputSchema ?? null };
  });
  return {
    schemas: `sha256:${createHash("sha256").update(canonicalJson(schemas)).digest("hex")}`,
    capabilities: `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`,
  };
}

function listGeneratedCatalogPaths(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true })
    .map((entry) => {
      if (!entry.isFile() || !entry.name.endsWith(".json"))
        throw new Error(`Generated catalog snapshot contains a non-JSON file: ${entry.name}`);
      return validateRepoPath(`${catalogPrefix}${entry.name}`);
    })
    .sort();
}

function readSourceFingerprints(base: string, candidate: string, rootDir: string): CatalogSchemaFingerprint[] {
  const fields = splitNull(
    runGit(["diff", "--raw", "--no-abbrev", "--no-renames", "-z", base, candidate, "--"], rootDir),
  );
  const zeroObject = "0".repeat(40);
  const changes: CatalogSchemaFingerprint[] = [];
  for (let index = 0; index < fields.length; index += 2) {
    const header = /^:([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) [A-Z](?:\d+)?$/.exec(fields[index]!);
    if (!header || fields[index + 1] === undefined) throw new Error("Invalid raw source change record");
    changes.push({
      path: validateRepoPath(fields[index + 1]!),
      base: header[3] === zeroObject ? null : `git:${header[1]}:${header[3]}`,
      candidate: header[4] === zeroObject ? null : `git:${header[2]}:${header[4]}`,
    });
  }
  return changes;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return jsonScalar(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("catalog schema contains a non-finite number");
    return jsonScalar(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${jsonScalar(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  throw new Error(`catalog schema contains unsupported ${typeof value} value`);
}

function jsonScalar(value: null | boolean | string | number): string {
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new Error("catalog schema contains an unsupported value");
  return encoded;
}

function validateRepoPath(path: string): string {
  const parts = path.split("/");
  if (
    path.length === 0 ||
    path.startsWith("/") ||
    path.includes("\\") ||
    // oxlint-disable-next-line no-control-regex -- ASCII controls are invalid in repository paths.
    /[\u0000-\u001f\u007f]/.test(path) ||
    parts.some((part) => part === "" || part === "." || part === "..")
  ) {
    throw new Error(`candidate contains unsafe repository path ${JSON.stringify(path)}`);
  }
  return path;
}

function readRevisionFile(revision: string, path: string, cwd: string): string {
  return runGit(["show", `${revision}:${path}`], cwd);
}

function assertLocalCommit(revision: string, label: string, cwd: string): void {
  const type = runGit(["cat-file", "-t", revision], cwd).trim();
  if (type !== "commit") throw new Error(`${label} revision ${revision} is a ${type}, not a commit`);
}

function assertAncestor(base: string, candidate: string, cwd: string): void {
  const result = spawnSync("git", ["merge-base", "--is-ancestor", base, candidate], { cwd, encoding: "utf8" });
  if (result.error) throw new Error(`could not run git merge-base: ${result.error.message}`);
  if (result.status === 1) throw new Error(`baseline ${base} is not an ancestor of candidate ${candidate}`);
  if (result.status !== 0) {
    const detail = result.stderr.trim();
    throw new Error(`git merge-base failed${detail ? `: ${detail}` : ` with exit code ${result.status}`}`);
  }
}

function formatList(title: string, values: readonly string[]): string {
  return `${title}\n${values.length === 0 ? "- None" : values.map((value) => `- ${value}`).join("\n")}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function splitNull(value: string): string[] {
  const fields = value.split("\0");
  if (fields.at(-1) === "") fields.pop();
  return fields;
}

function runGit(args: string[], cwd: string): string {
  const result = spawnSync("git", args, { cwd, encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
  if (result.error) throw new Error(`could not run git ${args[0]}: ${result.error.message}`);
  if (result.status !== 0) {
    const detail = result.stderr.trim();
    throw new Error(`git ${args[0]} failed${detail ? `: ${detail}` : ` with exit code ${result.status}`}`);
  }
  return result.stdout;
}

function main(): void {
  try {
    const { values, positionals } = parseArgs({
      allowPositionals: true,
      options: { "base-catalog": { type: "string" }, "candidate-catalog": { type: "string" } },
    });
    const [candidate] = positionals;
    const before = values["base-catalog"];
    const after = values["candidate-catalog"];
    if (!candidate || positionals.length !== 1 || Boolean(before) !== Boolean(after)) {
      throw new Error(
        "usage: npm run upstream:review -- <candidate-sha> [--base-catalog <dir> --candidate-catalog <dir>]",
      );
    }
    console.log(
      formatUpstreamReview(
        createUpstreamReview(
          candidate,
          process.cwd(),
          before && after
            ? {
                baseCatalogDir: before,
                candidateCatalogDir: after,
              }
            : undefined,
        ),
      ),
    );
  } catch (error) {
    console.error(`Upstream review failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}

const entryPath = process.argv[1];
if (entryPath && import.meta.url === pathToFileURL(resolve(entryPath)).href) main();
