import { migratePostgres } from "../src/saas/storage/postgres-migrator.ts";

const migratorConnectionString = process.env.OPEN_CONNECTOR_POSTGRES_MIGRATOR_URL;
const runtimeConnectionString = process.env.OPEN_CONNECTOR_POSTGRES_URL;
if (!migratorConnectionString || !runtimeConnectionString) {
  throw new Error("OPEN_CONNECTOR_POSTGRES_MIGRATOR_URL and OPEN_CONNECTOR_POSTGRES_URL are required");
}

const applied = await migratePostgres({ migratorConnectionString, runtimeConnectionString });
console.log(applied.length ? `Applied SaaS migrations: ${applied.join(", ")}` : "SaaS schema is current.");
