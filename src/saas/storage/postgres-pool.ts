import type { PoolConfig } from "pg";

import { Pool } from "pg";

/** Create the unprivileged pool used by the SaaS request runtime. */
export function createPostgresPool(
  connectionString: string | undefined = process.env.OPEN_CONNECTOR_POSTGRES_URL,
  options: Omit<PoolConfig, "connectionString"> = {},
): Pool {
  if (!connectionString) {
    throw new Error("OPEN_CONNECTOR_POSTGRES_URL is required");
  }

  return new Pool({ ...options, connectionString });
}
