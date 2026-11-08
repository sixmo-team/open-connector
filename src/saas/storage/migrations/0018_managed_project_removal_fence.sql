-- Runtime retains its existing DML policies. Only the inaccessible table owner can
-- lock active member-visible projects or perform the narrowly validated SERVICE transition.
CREATE POLICY managed_project_transition_owner_guard ON integration_runtime.managed_projects
  FOR UPDATE TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY managed_request_removal_owner_guard ON integration_runtime.connection_requests
  FOR SELECT TO CURRENT_USER USING (true);

CREATE FUNCTION integration_runtime.lock_active_managed_project(project uuid) RETURNS boolean
  LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
  target_tenant text;
  target_workspace text;
  admitted boolean;
BEGIN
  IF current_setting('integration.principal_kind',true) = 'user'
    AND NULLIF(current_setting('integration.tenant_id',true),'') IS NOT NULL
    AND NULLIF(current_setting('integration.workspace_id',true),'') IS NOT NULL
    AND NULLIF(current_setting('integration.subject_user_id',true),'') IS NOT NULL
    AND NULLIF(current_setting('integration.actor_user_id',true),'') IS NOT NULL
    AND NULLIF(current_setting('integration.purpose',true),'') IS NOT NULL
    AND current_setting('integration.workspace_role',true) IN ('owner','admin','member','viewer') THEN
    target_tenant := current_setting('integration.tenant_id',true);
    target_workspace := current_setting('integration.workspace_id',true);
  ELSIF current_setting('integration.principal_kind',true) = 'policy_control'
    AND current_setting('integration.purpose',true) = 'configuration:write'
    AND current_setting('integration.policy_target_kind',true) = 'workspace'
    AND NULLIF(current_setting('integration.operator_subject',true),'') IS NOT NULL
    AND NULLIF(current_setting('integration.policy_tenant_id',true),'') IS NOT NULL
    AND NULLIF(current_setting('integration.policy_workspace_id',true),'') IS NOT NULL
    AND COALESCE(current_setting('integration.tenant_id',true),'') = ''
    AND COALESCE(current_setting('integration.workspace_id',true),'') = ''
    AND COALESCE(current_setting('integration.subject_user_id',true),'') = ''
    AND COALESCE(current_setting('integration.actor_user_id',true),'') = ''
    AND COALESCE(current_setting('integration.workspace_role',true),'') = ''
    AND COALESCE(current_setting('integration.policy_user_id',true),'') = '' THEN
    target_tenant := current_setting('integration.policy_tenant_id',true);
    target_workspace := current_setting('integration.policy_workspace_id',true);
  ELSE
    RAISE EXCEPTION 'Managed project admission requires its verified workspace authority';
  END IF;
  -- FOR SHARE, not KEY SHARE: the non-key inactive UPDATE must wait for admitted publishers.
  -- A pending key rotation leaves the old active key usable.
  SELECT true INTO admitted FROM integration_runtime.managed_projects p
    WHERE p.tenant_id=target_tenant AND p.workspace_id=target_workspace AND p.id=project
      AND p.secret_ref IS NOT NULL FOR SHARE;
  RETURN COALESCE(admitted,false);
END $$;
REVOKE ALL ON FUNCTION integration_runtime.lock_active_managed_project(uuid) FROM PUBLIC;

CREATE FUNCTION integration_runtime.fence_managed_project_removal(project uuid) RETURNS boolean
  LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
  target_tenant text;
  target_workspace text;
  service_purge boolean := false;
  owned integration_runtime.managed_projects%ROWTYPE;
BEGIN
  IF current_setting('integration.principal_kind',true) = 'user'
    AND NULLIF(current_setting('integration.tenant_id',true),'') IS NOT NULL
    AND NULLIF(current_setting('integration.workspace_id',true),'') IS NOT NULL
    AND NULLIF(current_setting('integration.subject_user_id',true),'') IS NOT NULL
    AND current_setting('integration.actor_user_id',true) = current_setting('integration.subject_user_id',true)
    AND NULLIF(current_setting('integration.purpose',true),'') IS NOT NULL
    AND current_setting('integration.workspace_role',true) IN ('owner','admin') THEN
    target_tenant := current_setting('integration.tenant_id',true);
    target_workspace := current_setting('integration.workspace_id',true);
  ELSIF current_setting('integration.principal_kind',true) IN ('policy_control','service')
    AND NULLIF(current_setting('integration.operator_subject',true),'') IS NOT NULL
    AND NULLIF(current_setting('integration.policy_tenant_id',true),'') IS NOT NULL
    AND COALESCE(current_setting('integration.tenant_id',true),'') = ''
    AND COALESCE(current_setting('integration.workspace_id',true),'') = ''
    AND COALESCE(current_setting('integration.subject_user_id',true),'') = ''
    AND COALESCE(current_setting('integration.actor_user_id',true),'') = ''
    AND COALESCE(current_setting('integration.workspace_role',true),'') = ''
    AND COALESCE(current_setting('integration.policy_user_id',true),'') = '' THEN
    IF current_setting('integration.principal_kind',true) = 'policy_control'
      AND current_setting('integration.purpose',true) = 'configuration:write'
      AND current_setting('integration.policy_target_kind',true) = 'workspace'
      AND NULLIF(current_setting('integration.policy_workspace_id',true),'') IS NOT NULL THEN
      target_workspace := current_setting('integration.policy_workspace_id',true);
    ELSIF current_setting('integration.principal_kind',true) = 'service'
      AND current_setting('integration.purpose',true) = 'lifecycle:configuration:purge'
      AND current_setting('integration.policy_target_kind',true) IN ('tenant','workspace')
      AND (current_setting('integration.policy_target_kind',true) = 'tenant'
        OR NULLIF(current_setting('integration.policy_workspace_id',true),'') IS NOT NULL) THEN
      service_purge := true;
      target_workspace := CASE WHEN current_setting('integration.policy_target_kind',true) = 'workspace'
        THEN current_setting('integration.policy_workspace_id',true) ELSE NULL END;
    ELSE
      RAISE EXCEPTION 'Managed project removal requires its exact technical authority';
    END IF;
    target_tenant := current_setting('integration.policy_tenant_id',true);
  ELSE
    RAISE EXCEPTION 'Managed project removal requires its verified workspace authority';
  END IF;
  SELECT * INTO owned FROM integration_runtime.managed_projects p
    WHERE p.tenant_id=target_tenant AND (target_workspace IS NULL OR p.workspace_id=target_workspace)
      AND p.id=project FOR UPDATE;
  IF NOT FOUND OR owned.pending_secret_ref IS NOT NULL THEN RETURN false; END IF;
  -- Definer-only visibility keeps another customer's private reference a hard removal barrier.
  IF (NOT service_purge AND EXISTS (SELECT 1 FROM integration_runtime.oauth_sources s WHERE s.managed_project_id=project))
    OR EXISTS (SELECT 1 FROM integration_runtime.connections c WHERE c.managed_project_id=project)
    OR EXISTS (SELECT 1 FROM integration_runtime.connection_requests r WHERE r.managed_project_id=project)
    OR EXISTS (SELECT 1 FROM integration_runtime.saas_cleanup c WHERE c.managed_project_id=project) THEN
    RETURN false;
  END IF;
  UPDATE integration_runtime.managed_projects p
    SET retired_secret_refs=CASE WHEN p.secret_ref IS NULL THEN p.retired_secret_refs ELSE array_prepend(p.secret_ref,p.retired_secret_refs) END,
      secret_ref=NULL,cleanup_paused=true,updated_at=now()
    WHERE p.id=owned.id AND p.tenant_id=owned.tenant_id AND p.workspace_id=owned.workspace_id;
  RETURN true;
END $$;
REVOKE ALL ON FUNCTION integration_runtime.fence_managed_project_removal(uuid) FROM PUBLIC;
