-- Expand phase: prior images do not know local_connection_id and must remain
-- able to insert and update rows until the authoritative backfill is complete.
ALTER TABLE integration_runtime.connections
  ALTER COLUMN local_connection_id DROP NOT NULL;
