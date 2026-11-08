-- Technical configuration is workspace-owned. A real historical customer creator remains unchanged;
-- operator-created rows have no customer creator and never impersonate an owner/admin.
ALTER TABLE integration_runtime.managed_projects ALTER COLUMN subject_user_id DROP NOT NULL;
ALTER TABLE integration_runtime.oauth_sources ALTER COLUMN subject_user_id DROP NOT NULL;

DO $migration$
DECLARE
  target_matches constant text := $target$
    current_setting('integration.principal_kind',true) = 'policy_control'
    AND current_setting('integration.purpose',true) IN ('configuration:read','configuration:write')
    AND current_setting('integration.policy_target_kind',true) = 'workspace'
    AND NULLIF(current_setting('integration.operator_subject',true),'') IS NOT NULL
    AND COALESCE(current_setting('integration.tenant_id',true),'') = ''
    AND COALESCE(current_setting('integration.workspace_id',true),'') = ''
    AND COALESCE(current_setting('integration.subject_user_id',true),'') = ''
    AND COALESCE(current_setting('integration.actor_user_id',true),'') = ''
    AND COALESCE(current_setting('integration.workspace_role',true),'') = ''
    AND COALESCE(current_setting('integration.policy_user_id',true),'') = ''
    AND tenant_id = NULLIF(current_setting('integration.policy_tenant_id',true),'')
    AND workspace_id = NULLIF(current_setting('integration.policy_workspace_id',true),'')
  $target$;
  name text;
BEGIN
  FOREACH name IN ARRAY ARRAY['managed_projects','oauth_sources'] LOOP
    EXECUTE format('CREATE POLICY configuration_control_read ON integration_runtime.%I FOR SELECT USING (%s)',name,target_matches);
    EXECUTE format('CREATE POLICY configuration_control_insert ON integration_runtime.%I FOR INSERT WITH CHECK ((%s) AND current_setting(''integration.purpose'',true)=''configuration:write'' AND subject_user_id IS NULL)',name,target_matches);
    EXECUTE format('CREATE POLICY configuration_control_update ON integration_runtime.%I FOR UPDATE USING ((%s) AND current_setting(''integration.purpose'',true)=''configuration:write'') WITH CHECK ((%s) AND current_setting(''integration.purpose'',true)=''configuration:write'')',name,target_matches,target_matches);
    EXECUTE format('CREATE POLICY configuration_control_delete ON integration_runtime.%I FOR DELETE USING ((%s) AND current_setting(''integration.purpose'',true)=''configuration:write'')',name,target_matches);
  END LOOP;
  -- The definer can only inspect request existence inside this verified workspace. Runtime
  -- never acquires this owner policy or customer queue/connection SELECT authority.
  EXECUTE format('CREATE POLICY configuration_dependency_owner_guard ON integration_runtime.connection_requests FOR SELECT TO CURRENT_USER USING (%s)',target_matches);
END $migration$;

CREATE FUNCTION integration_runtime.configuration_workspace_state(target_tenant text,target_workspace text)
  RETURNS TABLE (pending bigint,manual bigint,paused boolean,referenced boolean)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  IF current_setting('integration.principal_kind',true) IS DISTINCT FROM 'policy_control'
    OR COALESCE(current_setting('integration.purpose',true),'') NOT IN ('configuration:read','configuration:write')
    OR current_setting('integration.policy_target_kind',true) IS DISTINCT FROM 'workspace'
    OR NULLIF(current_setting('integration.operator_subject',true),'') IS NULL
    OR target_tenant IS DISTINCT FROM NULLIF(current_setting('integration.policy_tenant_id',true),'')
    OR target_workspace IS DISTINCT FROM NULLIF(current_setting('integration.policy_workspace_id',true),'')
    OR target_tenant IS NULL OR target_workspace IS NULL
    OR COALESCE(current_setting('integration.tenant_id',true),'') <> ''
    OR COALESCE(current_setting('integration.workspace_id',true),'') <> ''
    OR COALESCE(current_setting('integration.subject_user_id',true),'') <> ''
    OR COALESCE(current_setting('integration.actor_user_id',true),'') <> ''
    OR COALESCE(current_setting('integration.workspace_role',true),'') <> ''
    OR COALESCE(current_setting('integration.policy_user_id',true),'') <> '' THEN
    RAISE EXCEPTION 'Configuration dependency target does not match verified operator workspace';
  END IF;
  RETURN QUERY SELECT
    (SELECT count(*) FROM integration_runtime.saas_cleanup c WHERE c.tenant_id=target_tenant AND c.workspace_id=target_workspace AND c.status='pending'),
    (SELECT count(*) FROM integration_runtime.saas_cleanup c WHERE c.tenant_id=target_tenant AND c.workspace_id=target_workspace AND c.status='manual'),
    COALESCE((SELECT p.cleanup_paused FROM integration_runtime.managed_projects p WHERE p.tenant_id=target_tenant AND p.workspace_id=target_workspace),false),
    EXISTS (SELECT 1 FROM integration_runtime.oauth_sources s WHERE s.tenant_id=target_tenant AND s.workspace_id=target_workspace)
    OR EXISTS (SELECT 1 FROM integration_runtime.connections c WHERE c.tenant_id=target_tenant AND c.workspace_id=target_workspace AND c.managed_project_id IS NOT NULL)
    OR EXISTS (SELECT 1 FROM integration_runtime.connection_requests r WHERE r.tenant_id=target_tenant AND r.workspace_id=target_workspace AND r.managed_project_id IS NOT NULL)
    OR EXISTS (SELECT 1 FROM integration_runtime.saas_cleanup c WHERE c.tenant_id=target_tenant AND c.workspace_id=target_workspace);
END $$;
REVOKE ALL ON FUNCTION integration_runtime.configuration_workspace_state(text,text) FROM PUBLIC;
