import type { ProviderSource } from "./provider-source.ts";

import { readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { format } from "oxfmt";
import { loadProviderSources } from "./provider-source.ts";

const providersDir = join(process.cwd(), "src/providers");

/**
 * Generate provider registries from definitions already loaded by the caller.
 */
export async function generateProviderRegistries(providerSources: ProviderSource[], check = false): Promise<void> {
  await Promise.all([
    writeRegistry("registry.generated.ts", providerSources, check),
    writeActionContracts(providerSources, check),
  ]);
  const obsolete = join(providersDir, "registry.cloudflare.generated.ts");
  if (check) {
    if ((await readTextFile(obsolete)) !== undefined) throw new Error(`Unexpected generated artifact: ${obsolete}`);
  } else {
    await rm(obsolete, { force: true });
  }
}

if (import.meta.main) {
  await generateProviderRegistries(await loadProviderSources(), process.argv.includes("--check"));
}

function propertyName(service: string): string {
  return /^[A-Za-z_$][\w$]*$/.test(service) ? service : JSON.stringify(service);
}

async function writeRegistry(filename: string, sources: ProviderSource[], check: boolean): Promise<void> {
  const services = sources.map((source) => source.service);
  const lines = [
    'import type { ExecutorModule } from "./provider-loader.ts";',
    "",
    "/** Generated lazy imports for provider executors. Do not hand-edit. */",
    "export const executorModules: Record<string, () => Promise<ExecutorModule>> = {",
    ...services.map(
      (service) => `  ${propertyName(service)}: (): Promise<ExecutorModule> => import("./${service}/executors.ts"),`,
    ),
    "};",
  ];

  const path = join(providersDir, filename);
  const content = `${lines.join("\n")}\n`;
  await updateArtifact(path, content, check);
}

async function writeActionContracts(sources: ProviderSource[], check: boolean): Promise<void> {
  const lines = [
    "/** Generated action-name contracts for provider handlers. Do not hand-edit. */",
    "export interface ProviderActionNames {",
  ];

  for (const source of sources) {
    const names = [...new Set(source.definition.actions.map((action) => action.name))];
    if (names.length === 0) {
      lines.push(`  ${propertyName(source.service)}: never;`);
    } else if (names.length === 1) {
      lines.push(`  ${propertyName(source.service)}: ${JSON.stringify(names[0])};`);
    } else {
      lines.push(`  ${propertyName(source.service)}:`);
      lines.push(...names.map((name) => `    | ${JSON.stringify(name)}`));
      lines[lines.length - 1] += ";";
    }
  }

  lines.push("}");
  const filename = "action-contracts.generated.ts";
  const path = join(providersDir, filename);
  const result = await format(path, `${lines.join("\n")}\n`, {
    printWidth: 120,
    trailingComma: "all",
  });
  if (result.errors.length > 0) {
    throw new Error(`Failed to format generated action contracts: ${result.errors[0]!.message}`);
  }
  const content = result.code;
  await updateArtifact(path, content, check);
}

async function updateArtifact(path: string, content: string, check: boolean): Promise<void> {
  if ((await readTextFile(path)) === content) return;
  if (check) throw new Error(`Stale or missing generated artifact: ${path}`);
  const temporary = `${path}.${process.pid}.tmp`;
  try {
    await writeFile(temporary, content);
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true });
  }
}

async function readTextFile(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return undefined;
    }

    throw error;
  }
}
