-- Execution-profile SERVICE operations carry a real tenant/workspace target, not a fake customer.
-- These policies grant no credential or customer-data mutation authority to the service principal.
DO $migration$
DECLARE
  target_matches constant text := $target$
    current_setting('integration.principal_kind', true) = 'service'
    AND current_setting('integration.policy_target_kind', true) IN ('tenant','workspace')
    AND tenant_id = NULLIF(current_setting('integration.policy_tenant_id', true),'')
    AND (current_setting('integration.policy_target_kind', true) = 'tenant'
      OR workspace_id = NULLIF(current_setting('integration.policy_workspace_id', true),''))
  $target$;
  name text;
BEGIN
  FOREACH name IN ARRAY ARRAY[
    'connections','oauth_states','run_intents','idempotency_records','refresh_leases','transit_files',
    'connection_revocation_receipts','connection_retirements','connection_requests','saas_cleanup',
    'trigger_subscriptions','trigger_source_applications','trigger_secret_cleanup','trigger_execution_leases'
  ] LOOP
    EXECUTE format('CREATE POLICY native_lifecycle_inventory ON integration_runtime.%I FOR SELECT USING ((%s) AND current_setting(''integration.purpose'',true) IN (''lifecycle:subjects'',''lifecycle:configuration:purge''))',name,target_matches);
  END LOOP;
  FOREACH name IN ARRAY ARRAY['managed_projects','oauth_sources'] LOOP
    EXECUTE format('CREATE POLICY native_configuration_read ON integration_runtime.%I FOR SELECT USING ((%s) AND current_setting(''integration.purpose'',true) IN (''lifecycle:configuration:read'',''lifecycle:configuration:purge''))',name,target_matches);
    EXECUTE format('CREATE POLICY native_configuration_delete ON integration_runtime.%I FOR DELETE USING ((%s) AND current_setting(''integration.purpose'',true) = ''lifecycle:configuration:purge'')',name,target_matches);
  END LOOP;
END $migration$;
