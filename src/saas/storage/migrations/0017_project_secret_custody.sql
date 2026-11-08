-- Reserve exact immutable KV references durably before any project-key write can dispatch.
ALTER TABLE integration_runtime.managed_projects
  ALTER COLUMN secret_ref DROP NOT NULL,
  ADD COLUMN pending_secret_ref text,
  ADD CONSTRAINT managed_project_secret_custody CHECK (
    secret_ref IS NOT NULL OR pending_secret_ref IS NOT NULL OR cardinality(retired_secret_refs)>0
  );

CREATE OR REPLACE FUNCTION integration_runtime.configuration_workspace_state(target_tenant text,target_workspace text)
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
    COALESCE((SELECT p.cleanup_paused OR p.pending_secret_ref IS NOT NULL OR p.secret_ref IS NULL FROM integration_runtime.managed_projects p WHERE p.tenant_id=target_tenant AND p.workspace_id=target_workspace),false),
    EXISTS (SELECT 1 FROM integration_runtime.oauth_sources s WHERE s.tenant_id=target_tenant AND s.workspace_id=target_workspace)
    OR EXISTS (SELECT 1 FROM integration_runtime.connections c WHERE c.tenant_id=target_tenant AND c.workspace_id=target_workspace AND c.managed_project_id IS NOT NULL)
    OR EXISTS (SELECT 1 FROM integration_runtime.connection_requests r WHERE r.tenant_id=target_tenant AND r.workspace_id=target_workspace AND r.managed_project_id IS NOT NULL)
    OR EXISTS (SELECT 1 FROM integration_runtime.saas_cleanup c WHERE c.tenant_id=target_tenant AND c.workspace_id=target_workspace)
    OR EXISTS (SELECT 1 FROM integration_runtime.managed_projects p WHERE p.tenant_id=target_tenant AND p.workspace_id=target_workspace AND p.pending_secret_ref IS NOT NULL);
END $$;
REVOKE ALL ON FUNCTION integration_runtime.configuration_workspace_state(text,text) FROM PUBLIC;
