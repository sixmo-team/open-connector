import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import { Client, Pool } from "pg";
import {
  assertLocalConnectionIdentityBackfillComplete,
  backfillLocalConnectionIdentities,
  parseLocalConnectionIdentityMappings,
} from "../src/saas/storage/connection-identity-backfill.ts";

const MAX_MAPPING_FILE_BYTES = 1024 * 1024;
const [argument, ...extraArguments] = process.argv.slice(2);
if (!argument || extraArguments.length) {
  throw new Error("Usage: node scripts/saas-backfill-connections.ts <backend-mapping.json> | --verify");
}

const verifyOnly = argument === "--verify";
const auditConnectionString = process.env.OPEN_CONNECTOR_POSTGRES_MIGRATOR_URL;
const runtimeConnectionString = process.env.OPEN_CONNECTOR_POSTGRES_URL;
if (!auditConnectionString || (!verifyOnly && !runtimeConnectionString)) {
  throw new Error(
    "OPEN_CONNECTOR_POSTGRES_MIGRATOR_URL is required; backfill also requires OPEN_CONNECTOR_POSTGRES_URL",
  );
}

const auditor = new Client({ connectionString: auditConnectionString });
let runtimePool: Pool | undefined;
try {
  await auditor.connect();
  if (verifyOnly) {
    await assertLocalConnectionIdentityBackfillComplete(auditor);
    console.log("Connection identity readiness passed: zero null identities remain.");
  } else {
    const filePath = resolve(argument);
    const file = await stat(filePath);
    if (!file.isFile() || file.size > MAX_MAPPING_FILE_BYTES) {
      throw new Error(`Mapping must be a file no larger than ${MAX_MAPPING_FILE_BYTES} bytes`);
    }
    const mappings = parseLocalConnectionIdentityMappings(JSON.parse(await readFile(filePath, "utf8")));
    runtimePool = new Pool({ connectionString: runtimeConnectionString });
    const updated = await backfillLocalConnectionIdentities(runtimePool, auditor, mappings);
    console.log(`Backfilled ${updated} connection identities; run --verify after all batches.`);
  }
} finally {
  await Promise.allSettled([runtimePool?.end(), auditor.end()]);
}
