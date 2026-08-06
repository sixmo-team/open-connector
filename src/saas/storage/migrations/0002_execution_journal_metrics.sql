ALTER TABLE integration_runtime.run_intents
  ADD COLUMN provider_request_count bigint
    CHECK (provider_request_count IS NULL OR provider_request_count >= 0);
