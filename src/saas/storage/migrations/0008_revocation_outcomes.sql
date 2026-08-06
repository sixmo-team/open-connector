ALTER TABLE integration_runtime.connection_revocation_receipts
  ADD COLUMN outcome text NOT NULL DEFAULT 'revoked'
  CHECK (outcome IN ('revoked', 'unsupported'));

ALTER TABLE integration_runtime.connection_revocation_receipts
  ALTER COLUMN outcome DROP DEFAULT;

UPDATE integration_runtime.connections
SET safe_metadata = jsonb_set(safe_metadata, '{providerRevocationOutcome}', '"revoked"'::jsonb, true)
WHERE status = 'revoked'
  AND NOT (safe_metadata ? 'providerRevocationOutcome');

UPDATE integration_runtime.connections
SET safe_metadata = CASE
  WHEN safe_metadata->>'lifecycleProviderRevoked' = 'true'
    THEN jsonb_set(
      safe_metadata - 'lifecycleProviderRevoked',
      '{lifecycleProviderRevocationOutcome}',
      '"revoked"'::jsonb,
      true
    )
  ELSE safe_metadata - 'lifecycleProviderRevoked'
END
WHERE safe_metadata ? 'lifecycleProviderRevoked';
