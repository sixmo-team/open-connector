CREATE TABLE integration_runtime.connection_retirements (
  tenant_id text NOT NULL,
  workspace_id text NOT NULL,
  subject_user_id text NOT NULL,
  local_connection_id uuid NOT NULL,
  service text NOT NULL,
  connection_name text NOT NULL,
  generation text NOT NULL,
  PRIMARY KEY (tenant_id,workspace_id,local_connection_id,service,connection_name)
);
ALTER TABLE integration_runtime.connections
  ADD COLUMN source text NOT NULL DEFAULT 'local' CHECK (source IN ('local','saas')),
  ADD COLUMN source_reference jsonb,
  ADD COLUMN source_status text CHECK (source_status IN ('active','reauth_required')),
  ADD COLUMN source_comment text;
ALTER TABLE integration_runtime.oauth_states
  ADD COLUMN local_connection_id uuid,
  ADD COLUMN retirement_generation text;
-- Keep terminal cleanup metadata even when a connection is removed.
ALTER TABLE integration_runtime.oauth_states DROP CONSTRAINT oauth_states_tenant_id_workspace_id_connection_id_fkey;
CREATE TABLE integration_runtime.connection_requests (
  id uuid PRIMARY KEY,
  tenant_id text NOT NULL,
  workspace_id text NOT NULL,
  subject_user_id text NOT NULL,
  local_connection_id uuid NOT NULL,
  oauth_session_id uuid NOT NULL,
  service text NOT NULL,
  connection_name text NOT NULL,
  retirement_generation text NOT NULL,
  state_hash text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('local','saas')),
  phase text NOT NULL CHECK (phase IN ('pending','processing','completed')),
  status text NOT NULL CHECK (status IN ('initiated','connected','failed','expired')),
  secret_ref text NOT NULL,
  retired_secret_refs text[] NOT NULL DEFAULT '{}',
  candidate_ref text,
  app_id uuid,
  error_code text,
  error_message text,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  managed_project_id uuid,
  provider_config_id text,
  external_user_id text,
  remote_request_id text,
  remote_account_id text,
  saas_phase text CHECK (saas_phase IN ('creating','pending','candidate')),
  lease_id uuid,
  lease_until timestamptz,
  next_poll_at bigint NOT NULL DEFAULT 0,
  poll_attempts integer NOT NULL DEFAULT 0,
  UNIQUE (tenant_id,workspace_id,state_hash)
);
CREATE INDEX connection_requests_owner_idx ON integration_runtime.connection_requests (tenant_id,workspace_id,subject_user_id,id);
CREATE TABLE integration_runtime.managed_projects (
  id uuid PRIMARY KEY,
  tenant_id text NOT NULL,
  workspace_id text NOT NULL,
  subject_user_id text NOT NULL,
  project_id text NOT NULL,
  base_url text NOT NULL,
  secret_ref text NOT NULL,
  retired_secret_refs text[] NOT NULL DEFAULT '{}',
  cleanup_paused boolean NOT NULL DEFAULT false,
  UNIQUE (tenant_id,workspace_id)
);
CREATE TABLE integration_runtime.oauth_sources (
  tenant_id text NOT NULL,
  workspace_id text NOT NULL,
  subject_user_id text NOT NULL,
  service text NOT NULL,
  managed_project_id uuid NOT NULL,
  provider_config_id text NOT NULL,
  PRIMARY KEY (tenant_id,workspace_id,service)
);
CREATE TABLE integration_runtime.saas_cleanup (
  id text NOT NULL,
  tenant_id text NOT NULL,
  workspace_id text NOT NULL,
  subject_user_id text NOT NULL,
  managed_project_id uuid NOT NULL,
  provider_config_id text NOT NULL,
  external_user_id text NOT NULL,
  remote_request_id text,
  remote_account_id text,
  service text,
  request_expires_at timestamptz,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','manual')),
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at bigint NOT NULL DEFAULT 0,
  error_code text,
  lease_id uuid,
  lease_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,workspace_id,subject_user_id,id)
);
ALTER TABLE integration_runtime.connection_retirements ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.connection_retirements FORCE ROW LEVEL SECURITY;
-- Generations belong to immutable workspace/local lineage, not its mutable owner.
CREATE POLICY retirement_scope ON integration_runtime.connection_retirements FOR ALL
  USING (tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),'')
    AND subject_user_id=NULLIF(current_setting('integration.subject_user_id',true),''))
  WITH CHECK (tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),'')
    AND subject_user_id=NULLIF(current_setting('integration.subject_user_id',true),''));
-- Only the actual migration/table owner can bridge OLD/NEW marker ownership in the trigger.
-- Runtime cannot assume that role; ordinary retirement visibility remains exact-owner.
CREATE POLICY retirement_trigger_owner_access ON integration_runtime.connection_retirements FOR ALL TO CURRENT_USER
  USING (tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),''))
  WITH CHECK (tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),''));
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['connection_requests','managed_projects','oauth_sources','saas_cleanup'] LOOP
    EXECUTE format('ALTER TABLE integration_runtime.%I ENABLE ROW LEVEL SECURITY',t);
    EXECUTE format('ALTER TABLE integration_runtime.%I FORCE ROW LEVEL SECURITY',t);
    EXECUTE format('CREATE POLICY exact_owner ON integration_runtime.%I FOR ALL USING (tenant_id=NULLIF(current_setting(''integration.tenant_id'',true),'''') AND workspace_id=NULLIF(current_setting(''integration.workspace_id'',true),'''') AND subject_user_id=NULLIF(current_setting(''integration.subject_user_id'',true),'''')) WITH CHECK (tenant_id=NULLIF(current_setting(''integration.tenant_id'',true),'''') AND workspace_id=NULLIF(current_setting(''integration.workspace_id'',true),'''') AND subject_user_id=NULLIF(current_setting(''integration.subject_user_id'',true),''''))',t);
  END LOOP;
END $$;
CREATE FUNCTION integration_runtime.retire_connection_authorizations() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cleanup_reference record;
BEGIN
  IF OLD.tenant_id IS DISTINCT FROM NULLIF(current_setting('integration.tenant_id',true),'')
    OR OLD.workspace_id IS DISTINCT FROM NULLIF(current_setting('integration.workspace_id',true),'')
    OR OLD.subject_user_id IS DISTINCT FROM NULLIF(current_setting('integration.subject_user_id',true),'') THEN
    RAISE EXCEPTION 'Connection retirement target does not match verified scope';
  END IF;
  -- Only a pre-contract row may acquire its previously missing local identity.
  IF TG_OP='UPDATE' AND (
    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
    OR NEW.id IS DISTINCT FROM OLD.id OR (OLD.local_connection_id IS NOT NULL AND NEW.local_connection_id IS DISTINCT FROM OLD.local_connection_id)
    OR NEW.service IS DISTINCT FROM OLD.service OR NEW.connection_name IS DISTINCT FROM OLD.connection_name
  ) THEN
    RAISE EXCEPTION 'Connection retirement lineage is immutable';
  END IF;
  IF TG_OP='UPDATE' AND NEW.subject_user_id IS DISTINCT FROM OLD.subject_user_id AND (
    OLD.visibility<>'workspace' OR NEW.visibility<>'workspace'
    OR COALESCE(NULLIF(current_setting('integration.workspace_role',true),''),'') NOT IN ('owner','admin')
  ) THEN
    RAISE EXCEPTION 'Connection retirement ownership transfer is not authorized';
  END IF;
  IF OLD.local_connection_id IS NOT NULL AND (TG_OP='DELETE' OR OLD.subject_user_id IS DISTINCT FROM NEW.subject_user_id
    OR OLD.visibility IS DISTINCT FROM NEW.visibility
    OR (OLD.status='active' AND NEW.status<>'active')) THEN
    FOR cleanup_reference IN
      SELECT managed_project_id,remote_account_id FROM integration_runtime.connection_requests
      WHERE tenant_id=OLD.tenant_id AND workspace_id=OLD.workspace_id AND subject_user_id=OLD.subject_user_id
        AND local_connection_id=OLD.local_connection_id AND kind='saas' AND phase<>'completed'
        AND remote_account_id IS NOT NULL
      ORDER BY managed_project_id,remote_account_id FOR UPDATE
    LOOP
      PERFORM integration_runtime.retire_managed_account(cleanup_reference.managed_project_id,cleanup_reference.remote_account_id);
    END LOOP;
    INSERT INTO integration_runtime.saas_cleanup
      (id,tenant_id,workspace_id,subject_user_id,managed_project_id,provider_config_id,external_user_id,remote_request_id,remote_account_id,service,request_expires_at,status)
      SELECT 'request:'||id,tenant_id,workspace_id,subject_user_id,managed_project_id,provider_config_id,external_user_id,
        remote_request_id,remote_account_id,service,expires_at,
        CASE WHEN remote_request_id IS NULL AND remote_account_id IS NULL THEN 'manual' ELSE 'pending' END
      FROM integration_runtime.connection_requests
      WHERE tenant_id=OLD.tenant_id AND workspace_id=OLD.workspace_id AND subject_user_id=OLD.subject_user_id
        AND local_connection_id=OLD.local_connection_id AND kind='saas' AND phase<>'completed'
      ON CONFLICT DO NOTHING;
    INSERT INTO integration_runtime.connection_retirements
      (tenant_id,workspace_id,local_connection_id,service,connection_name,generation,subject_user_id)
      VALUES (OLD.tenant_id,OLD.workspace_id,OLD.local_connection_id,OLD.service,OLD.connection_name,gen_random_uuid()::text,
        CASE WHEN TG_OP='DELETE' THEN OLD.subject_user_id ELSE NEW.subject_user_id END)
      ON CONFLICT (tenant_id,workspace_id,local_connection_id,service,connection_name)
      DO UPDATE SET generation=EXCLUDED.generation,subject_user_id=EXCLUDED.subject_user_id;
    UPDATE integration_runtime.oauth_states SET status='failed',updated_at=now()
      WHERE tenant_id=OLD.tenant_id AND workspace_id=OLD.workspace_id AND subject_user_id=OLD.subject_user_id
        AND local_connection_id=OLD.local_connection_id AND status IN ('pending','reserved');
    UPDATE integration_runtime.connection_requests SET status='failed',phase='completed',lease_id=NULL,lease_until=NULL,
      error_code='connection_retired',updated_at=now()
      WHERE tenant_id=OLD.tenant_id AND workspace_id=OLD.workspace_id AND subject_user_id=OLD.subject_user_id
        AND local_connection_id=OLD.local_connection_id AND phase<>'completed';
  END IF;
  IF TG_OP='DELETE' THEN
    IF OLD.source='saas' THEN
      PERFORM integration_runtime.retire_managed_account(
        (OLD.source_reference->>'managedProjectId')::uuid,OLD.source_reference->>'connectedAccountId');
      INSERT INTO integration_runtime.saas_cleanup
        (id,tenant_id,workspace_id,subject_user_id,managed_project_id,provider_config_id,external_user_id,remote_account_id,service)
        VALUES ('account:'||(OLD.source_reference->>'managedProjectId')||':'||(OLD.source_reference->>'connectedAccountId'),OLD.tenant_id,OLD.workspace_id,OLD.subject_user_id,
          (OLD.source_reference->>'managedProjectId')::uuid,OLD.source_reference->>'providerConfigId',
          OLD.source_reference->>'externalUserId',OLD.source_reference->>'connectedAccountId',OLD.service)
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN OLD;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER retire_connection_authorizations BEFORE UPDATE OR DELETE ON integration_runtime.connections
  FOR EACH ROW EXECUTE FUNCTION integration_runtime.retire_connection_authorizations();
REVOKE ALL ON FUNCTION integration_runtime.retire_connection_authorizations() FROM PUBLIC;

-- Project keys and default source selection are workspace technical configuration.
DROP POLICY exact_owner ON integration_runtime.managed_projects;
DROP POLICY exact_owner ON integration_runtime.oauth_sources;
CREATE POLICY project_scope ON integration_runtime.managed_projects FOR ALL
  USING (tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),''))
  WITH CHECK (tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),''));
CREATE POLICY source_scope ON integration_runtime.oauth_sources FOR ALL
  USING (tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),''))
  WITH CHECK (tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),''));

ALTER TABLE integration_runtime.managed_projects ADD UNIQUE (tenant_id,workspace_id,id);
ALTER TABLE integration_runtime.connections ADD COLUMN managed_project_id uuid
  GENERATED ALWAYS AS ((source_reference->>'managedProjectId')::uuid) STORED;
ALTER TABLE integration_runtime.connections ADD FOREIGN KEY (tenant_id,workspace_id,managed_project_id)
  REFERENCES integration_runtime.managed_projects (tenant_id,workspace_id,id) ON DELETE RESTRICT;
ALTER TABLE integration_runtime.connection_requests ADD FOREIGN KEY (tenant_id,workspace_id,managed_project_id)
  REFERENCES integration_runtime.managed_projects (tenant_id,workspace_id,id) ON DELETE RESTRICT;
ALTER TABLE integration_runtime.oauth_sources ADD FOREIGN KEY (tenant_id,workspace_id,managed_project_id)
  REFERENCES integration_runtime.managed_projects (tenant_id,workspace_id,id) ON DELETE RESTRICT;
ALTER TABLE integration_runtime.saas_cleanup ADD FOREIGN KEY (tenant_id,workspace_id,managed_project_id)
  REFERENCES integration_runtime.managed_projects (tenant_id,workspace_id,id) ON DELETE RESTRICT;

ALTER TABLE integration_runtime.managed_projects ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE integration_runtime.oauth_sources ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();

-- This is a cleanup-ordering fact, not a second copy of live connection ownership.
CREATE SEQUENCE integration_runtime.managed_account_fence_seq AS bigint;
REVOKE ALL ON SEQUENCE integration_runtime.managed_account_fence_seq FROM PUBLIC;
ALTER TABLE integration_runtime.connection_requests ADD COLUMN account_fence_revision bigint NOT NULL
  DEFAULT nextval('integration_runtime.managed_account_fence_seq'::regclass);
CREATE TABLE integration_runtime.managed_account_retirements (
  -- Physical protective metadata survives customer/project deletion; it carries no customer identity.
  resource_key text PRIMARY KEY,
  fence_revision bigint NOT NULL
);
ALTER TABLE integration_runtime.managed_account_retirements ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.managed_account_retirements FORCE ROW LEVEL SECURITY;
CREATE POLICY managed_account_retirement_owner_guard ON integration_runtime.managed_account_retirements FOR ALL TO CURRENT_USER
  USING (true) WITH CHECK (true);

-- Only the real table owner can inspect private references for these boolean guards.
-- Runtime receives function EXECUTE, never that role or broader customer-row SELECT.
CREATE POLICY managed_reference_owner_guard ON integration_runtime.connections FOR SELECT TO CURRENT_USER
  USING (source='saas');
CREATE POLICY managed_cleanup_owner_guard ON integration_runtime.saas_cleanup FOR SELECT TO CURRENT_USER
  USING (true);
CREATE POLICY managed_project_owner_guard ON integration_runtime.managed_projects FOR SELECT TO CURRENT_USER
  USING (true);

CREATE FUNCTION integration_runtime.lock_managed_account(project uuid,account text) RETURNS void
  LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE resource_key text;
BEGIN
  SELECT jsonb_build_array('managed-account',p.base_url,p.project_id,account)::text INTO resource_key
  FROM integration_runtime.managed_projects p
  WHERE p.tenant_id=NULLIF(current_setting('integration.tenant_id',true),'')
    AND p.workspace_id=NULLIF(current_setting('integration.workspace_id',true),'') AND p.id=project;
  IF resource_key IS NULL OR account IS NULL OR account='' THEN
    RAISE EXCEPTION 'Managed account resource does not match verified workspace configuration';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(resource_key,0));
END $$;

CREATE FUNCTION integration_runtime.retire_managed_account(project uuid,account text) RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  PERFORM integration_runtime.lock_managed_account(project,account);
  INSERT INTO integration_runtime.managed_account_retirements (resource_key,fence_revision)
    SELECT encode(sha256(convert_to(jsonb_build_array('managed-account',p.base_url,p.project_id,account)::text,'UTF8')),'hex'),
      nextval('integration_runtime.managed_account_fence_seq'::regclass)
    FROM integration_runtime.managed_projects p
    WHERE p.tenant_id=NULLIF(current_setting('integration.tenant_id',true),'')
      AND p.workspace_id=NULLIF(current_setting('integration.workspace_id',true),'') AND p.id=project
    ON CONFLICT (resource_key) DO UPDATE SET fence_revision=EXCLUDED.fence_revision;
END $$;

CREATE FUNCTION integration_runtime.is_managed_account_referenced(project uuid,account text) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM integration_runtime.managed_projects own
    JOIN integration_runtime.managed_projects peer ON peer.base_url=own.base_url AND peer.project_id=own.project_id
    JOIN integration_runtime.connections c ON c.tenant_id=peer.tenant_id AND c.workspace_id=peer.workspace_id AND c.managed_project_id=peer.id
    WHERE own.tenant_id=NULLIF(current_setting('integration.tenant_id',true),'')
      AND own.workspace_id=NULLIF(current_setting('integration.workspace_id',true),'') AND own.id=project
      AND c.source='saas' AND c.source_reference->>'connectedAccountId'=account)
$$;

CREATE FUNCTION integration_runtime.is_managed_account_cleanup_pending(project uuid,account text) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM integration_runtime.managed_projects own
    JOIN integration_runtime.managed_projects peer ON peer.base_url=own.base_url AND peer.project_id=own.project_id
    JOIN integration_runtime.saas_cleanup c ON c.tenant_id=peer.tenant_id AND c.workspace_id=peer.workspace_id AND c.managed_project_id=peer.id
    WHERE own.tenant_id=NULLIF(current_setting('integration.tenant_id',true),'')
      AND own.workspace_id=NULLIF(current_setting('integration.workspace_id',true),'') AND own.id=project
      AND c.remote_account_id=account)
$$;

CREATE FUNCTION integration_runtime.is_managed_account_retired(project uuid,account text,revision bigint) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM integration_runtime.managed_projects p
    JOIN integration_runtime.managed_account_retirements r ON
      r.resource_key=encode(sha256(convert_to(jsonb_build_array('managed-account',p.base_url,p.project_id,account)::text,'UTF8')),'hex')
    WHERE p.tenant_id=NULLIF(current_setting('integration.tenant_id',true),'')
      AND p.workspace_id=NULLIF(current_setting('integration.workspace_id',true),'') AND p.id=project
      AND r.fence_revision>=revision)
$$;
REVOKE ALL ON FUNCTION integration_runtime.lock_managed_account(uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION integration_runtime.retire_managed_account(uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION integration_runtime.is_managed_account_referenced(uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION integration_runtime.is_managed_account_cleanup_pending(uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION integration_runtime.is_managed_account_retired(uuid,text,bigint) FROM PUBLIC;
