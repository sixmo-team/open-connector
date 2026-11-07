import type { CatalogIndexSource } from "../src/catalog-index.ts";

import { mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { catalogIndexFileName, createCatalogIndex } from "../src/catalog-index.ts";
import { validateCatalogTranslations, untranslatedProviderServices } from "../src/catalog-localization/validation.ts";
import { sortProviders } from "../src/core/catalog.ts";
import { assertProviderId } from "../src/core/provider-id.ts";
import { generateProviderRegistries } from "./generate-provider-registry.ts";
import { loadProviderSources } from "./provider-source.ts";

const check = process.argv.includes("--check");
const outputDir = join(process.cwd(), "catalog/apps");
const catalogRootDir = join(process.cwd(), "catalog");
const tempOutputDir = join(catalogRootDir, `.apps-${process.pid}-${Date.now()}`);
// Keep the compact startup index beside apps/, not among provider JSON files.
const indexFile = join(catalogRootDir, catalogIndexFileName);
const tempIndexFile = join(catalogRootDir, `.apps-index-${process.pid}-${Date.now()}.json`);
const providerSources = await loadProviderSources();
const apps = sortProviders(providerSources.map((source) => source.definition));
validateCatalogTranslations(apps);
const contents = new Map<string, string>();
const sources: CatalogIndexSource[] = [];
for (const app of apps) {
  assertProviderId(app.service, "catalog app service");
  const file = `${app.service}.json`;
  const content = `${JSON.stringify(app, null, 2)}\n`;
  contents.set(file, content);
  sources.push({ file, bytes: Buffer.byteLength(content), provider: app });
}
const indexContent = `${JSON.stringify(createCatalogIndex(sources))}\n`;
await generateProviderRegistries(providerSources, check);

if (check) {
  const entries = await readdir(outputDir, { withFileTypes: true });
  if (entries.length !== contents.size || entries.some((entry) => !entry.isFile() || !contents.has(entry.name))) {
    throw new Error(`Unexpected or missing generated catalog apps in ${outputDir}`);
  }
  for (const [file, content] of contents) {
    await assertContent(join(outputDir, file), content);
  }
  await assertContent(indexFile, indexContent);
  console.log(`Verified ${apps.length} apps, compact index, lazy Node registry and action contracts.`);
} else {
  await mkdir(catalogRootDir, { recursive: true });
  try {
    await mkdir(tempOutputDir, { recursive: true });
    for (const [file, content] of contents) await writeFile(join(tempOutputDir, file), content);
    await writeFile(tempIndexFile, indexContent);
    // An interrupted swap must never pair the old index with new apps.
    await rm(indexFile, { force: true });
    await rm(outputDir, { recursive: true, force: true });
    await rename(tempOutputDir, outputDir);
    await rename(tempIndexFile, indexFile);
  } catch (error) {
    await rm(tempOutputDir, { recursive: true, force: true });
    await rm(tempIndexFile, { force: true });
    throw error;
  }
  console.log(
    `Generated ${apps.length} apps and ${apps.reduce((sum, app) => sum + app.actions.length, 0)} actions, and the startup index ${indexFile}.`,
  );
  console.log(
    `Chinese provider translations: ${apps.length - untranslatedProviderServices(apps).length}/${apps.length}; run node scripts/check-catalog-translations.ts for untranslated services.`,
  );
}

async function assertContent(path: string, expected: string): Promise<void> {
  if ((await readFile(path, "utf8")) !== expected) throw new Error(`Stale generated artifact: ${path}`);
}
