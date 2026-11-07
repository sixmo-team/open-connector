import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { z } from "zod";
import { findCutoverViolations } from "./check-protected-upstream.ts";
import {
  expectedImageCommand,
  expectedImagePort,
  expectedImageWorkingDirectory,
  forbiddenImageContentMarkers,
  forbiddenRuntimeMarkers,
  forbiddenRuntimePaths,
} from "./legacy-runtime-denylist.ts";

const dockerConfigSchema = z.object({
  Entrypoint: z.array(z.string()).nullable().optional(),
  Cmd: z.array(z.string()).nullable().optional(),
  User: z.string().optional(),
  WorkingDir: z.string().optional(),
  Env: z.array(z.string()).optional(),
  ExposedPorts: z.record(z.string(), z.object({})).optional(),
  Healthcheck: z.object({ Test: z.array(z.string()).optional() }).optional(),
});
const dockerImageInspectSchema = z.array(z.object({ Config: dockerConfigSchema })).min(1);
const imagePackageSchema = z.object({ scripts: z.record(z.string(), z.string()).optional() });

type DockerImageConfig = z.infer<typeof dockerConfigSchema>;

export interface RuntimeImageSnapshot {
  config: DockerImageConfig;
  paths: readonly string[];
  packageJson: string;
  executableText: readonly [path: string, content: string][];
}

export function findRuntimeImageViolations(snapshot: RuntimeImageSnapshot): string[] {
  const violations: string[] = [];
  const { config } = snapshot;
  if (JSON.stringify(config.Cmd ?? []) !== JSON.stringify(expectedImageCommand)) {
    violations.push(`image command must be ${expectedImageCommand.join(" ")}`);
  }
  if (config.Entrypoint?.length && JSON.stringify(config.Entrypoint) !== JSON.stringify(["docker-entrypoint.sh"])) {
    violations.push("image must not override the SaaS command with a custom entrypoint");
  }
  if (!config.User || config.User === "0" || config.User === "root") violations.push("image user must be non-root");
  if (config.WorkingDir !== expectedImageWorkingDirectory) {
    violations.push(`image working directory must be ${expectedImageWorkingDirectory}`);
  }
  const ports = Object.keys(config.ExposedPorts ?? {});
  if (ports.length !== 1 || ports[0] !== expectedImagePort)
    violations.push(`image must expose only ${expectedImagePort}`);
  if (!(config.Healthcheck?.Test ?? []).join(" ").includes("/ready"))
    violations.push("image healthcheck must probe /ready");

  const envNames = (config.Env ?? []).map((entry) => entry.split("=", 1)[0]);
  for (const marker of forbiddenRuntimeMarkers) {
    if (envNames.includes(marker)) violations.push(`legacy image environment key: ${marker}`);
  }

  const paths = new Set(snapshot.paths.map(normalizePath));
  for (const path of ["app/package.json", "app/src/saas/index.ts", "app/dist/web-saas/saas.html", "app/catalog/apps-index.json"]) {
    if (!paths.has(path)) violations.push(`missing image runtime path: /${path}`);
  }
  for (const path of paths) {
    if (path.startsWith("app/src/") && /\.test\.[cm]?[jt]s$/.test(path))
      violations.push(`test source shipped in image: /${path}`);
  }
  for (const forbidden of forbiddenRuntimePaths) {
    const imagePath = `app/${forbidden}`;
    if ([...paths].some((path) => path === imagePath || path.startsWith(`${imagePath}/`))) {
      violations.push(`legacy image path: /${imagePath}`);
    }
  }

  let scripts: Record<string, string> = {};
  try {
    const parsedPackage = imagePackageSchema.safeParse(JSON.parse(snapshot.packageJson));
    if (!parsedPackage.success) violations.push("image package.json does not match the runtime package contract");
    else scripts = parsedPackage.data.scripts ?? {};
  } catch {
    violations.push("image package.json is invalid JSON");
  }
  if (scripts.start !== "node --experimental-transform-types src/saas/index.ts") violations.push("image package start is not the SaaS runtime");
  for (const [name, command] of Object.entries(scripts)) {
    for (const marker of forbiddenRuntimeMarkers) {
      if (command.includes(marker)) violations.push(`legacy image package script ${name}: ${marker}`);
    }
  }
  for (const [path, content] of snapshot.executableText) {
    for (const marker of forbiddenImageContentMarkers) {
      if (content.includes(marker)) violations.push(`legacy executable marker in /${normalizePath(path)}: ${marker}`);
    }
  }
  return [...new Set(violations)].sort();
}

export function verifyNoLegacyRuntime(rootDir = process.cwd(), image?: string): void {
  const sourceViolations = findCutoverViolations(rootDir);
  if (sourceViolations.length) throw new Error(formatViolations("source cutover invariant failed", sourceViolations));
  if (!image) return;

  const temporaryDirectory = mkdtempSync(join(tmpdir(), "open-connector-image-"));
  let container = "";
  try {
    const [inspection] = dockerImageInspectSchema.parse(JSON.parse(run("docker", ["image", "inspect", image])));
    if (!inspection) throw new Error(`Docker did not return config for image ${image}`);
    container = run("docker", ["create", image]).trim();
    if (!container) throw new Error(`Docker did not create a container for image ${image}`);

    const archive = join(temporaryDirectory, "rootfs.tar");
    run("docker", ["export", "--output", archive, container], false);
    const extracted = join(temporaryDirectory, "rootfs");
    mkdirSync(extracted);
    run("tar", ["-xf", archive, "-C", extracted, "app"], false);
    const appRoot = join(extracted, "app");
    const snapshot: RuntimeImageSnapshot = {
      config: inspection.Config,
      paths: walk(appRoot).map((path) => relative(extracted, path)),
      packageJson: readFileSync(join(appRoot, "package.json"), "utf8"),
      executableText: textFiles(appRoot, ["src/saas", "dist", "web"]),
    };
    const violations = findRuntimeImageViolations(snapshot);
    if (violations.length) throw new Error(formatViolations("runtime image invariant failed", violations));

    const failClosed = spawnSync("docker", ["run", "--rm", "--network", "none", image], {
      cwd: rootDir,
      encoding: "utf8",
      timeout: 15_000,
      maxBuffer: 2 * 1024 * 1024,
    });
    if (failClosed.error) throw failClosed.error;
    if (failClosed.status === 0) throw new Error("runtime image started successfully without required configuration");
  } finally {
    if (container) spawnSync("docker", ["rm", "--force", container], { stdio: "ignore" });
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

function textFiles(appRoot: string, directories: readonly string[]): Array<[string, string]> {
  const files: Array<[string, string]> = [];
  for (const directory of directories) {
    const root = join(appRoot, directory);
    for (const path of walk(root)) {
      const metadata = statSync(path);
      if (!metadata.isFile() || metadata.size > 2 * 1024 * 1024 || !/\.(?:c?js|mjs|ts|html|json)$/.test(path)) continue;
      files.push([relative(resolve(appRoot, ".."), path), readFileSync(path, "utf8")]);
    }
  }
  return files;
}

function walk(root: string): string[] {
  try {
    const result: string[] = [root];
    for (const entry of readdirSync(root, { withFileTypes: true })) {
      const path = join(root, entry.name);
      if (entry.isDirectory()) result.push(...walk(path));
      else result.push(path);
    }
    return result;
  } catch (error) {
    if (isErrnoException(error) && error.code === "ENOENT") return [];
    throw error;
  }
}

function isErrnoException(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

function run(command: string, args: string[], capture = true): string {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: capture ? "pipe" : "ignore",
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} ${args[0] ?? ""} failed with exit code ${result.status}`);
  return result.stdout ?? "";
}

function normalizePath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\//, "").replace(/^\//, "");
}

function formatViolations(title: string, violations: readonly string[]): string {
  return [title, ...violations.map((violation) => `- ${violation}`)].join("\n");
}

function main(): void {
  const imageFlag = process.argv.indexOf("--image");
  const image = imageFlag === -1 ? undefined : process.argv[imageFlag + 1];
  if (imageFlag !== -1 && !image) throw new Error("--image requires an image reference or ID");
  verifyNoLegacyRuntime(process.cwd(), image);
  process.stdout.write(image ? `Verified runtime image ${image}\n` : "Verified source runtime cutover\n");
}

const entryPath = process.argv[1];
if (entryPath && import.meta.url === pathToFileURL(resolve(entryPath)).href) main();
