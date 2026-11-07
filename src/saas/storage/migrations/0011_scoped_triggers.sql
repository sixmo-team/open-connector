ALTER TABLE integration_runtime.connections ADD COLUMN trigger_cleanup_fenced boolean NOT NULL DEFAULT false;
CREATE TABLE integration_runtime.trigger_subscriptions (
  tenant_id text NOT NULL, workspace_id text NOT NULL, subject_user_id text NOT NULL, actor_user_id text NOT NULL,
  credential_owner_id text NOT NULL, id text NOT NULL, owner_id text NOT NULL,
  mode text NOT NULL CHECK (mode IN ('webhook','resource','resource-set')), service text NOT NULL, trigger_id text NOT NULL,
  connection_id uuid NOT NULL, local_connection_id uuid NOT NULL, account_binding jsonb NOT NULL, request_key text NOT NULL,
  status text NOT NULL CHECK (status IN ('active','deleting','deleted','abandoned')), revision bigint NOT NULL DEFAULT 1 CHECK (revision BETWEEN 1 AND 9007199254740991),
  secret_ref text NOT NULL, retired_secret_refs text[] NOT NULL DEFAULT '{}', reconcile_at bigint NOT NULL, lease_id text, lease_until timestamptz,
  PRIMARY KEY (tenant_id,workspace_id,id)
);
CREATE TABLE integration_runtime.trigger_source_applications (
  tenant_id text NOT NULL, workspace_id text NOT NULL, subject_user_id text NOT NULL, actor_user_id text NOT NULL,
  credential_owner_id text NOT NULL, namespace text NOT NULL, owner_id text NOT NULL, id text NOT NULL, service text NOT NULL, trigger_id text NOT NULL,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision BETWEEN 1 AND 9007199254740991), secret_ref text NOT NULL, retired_secret_refs text[] NOT NULL DEFAULT '{}',
  bindings jsonb NOT NULL CHECK (jsonb_typeof(bindings)='array'), retired boolean NOT NULL DEFAULT false,
  PRIMARY KEY (tenant_id,workspace_id,id)
);
CREATE TABLE integration_runtime.trigger_secret_cleanup (
  tenant_id text NOT NULL, workspace_id text NOT NULL, subject_user_id text NOT NULL, secret_ref text NOT NULL,
  PRIMARY KEY (tenant_id,workspace_id,subject_user_id,secret_ref)
);
CREATE TABLE integration_runtime.trigger_execution_leases (
  id uuid PRIMARY KEY,tenant_id text NOT NULL,workspace_id text NOT NULL,subject_user_id text NOT NULL,credential_owner_id text NOT NULL,
  connection_id uuid NOT NULL,local_connection_id uuid NOT NULL,service text NOT NULL,capability_id text NOT NULL,account_binding jsonb NOT NULL,
  created_at timestamptz NOT NULL,lease_until timestamptz NOT NULL,
  CHECK (lease_until>created_at AND lease_until<=created_at+interval '120 seconds')
);
CREATE INDEX trigger_execution_connection_idx ON integration_runtime.trigger_execution_leases (tenant_id,workspace_id,connection_id,lease_until);
ALTER TABLE integration_runtime.trigger_execution_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.trigger_execution_leases FORCE ROW LEVEL SECURITY;
REVOKE ALL ON integration_runtime.trigger_execution_leases FROM PUBLIC;
CREATE POLICY trigger_execution_read ON integration_runtime.trigger_execution_leases FOR SELECT USING (
  tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),'')
  AND ((subject_user_id=NULLIF(current_setting('integration.actor_user_id',true),'') AND credential_owner_id=NULLIF(current_setting('integration.subject_user_id',true),''))
    OR (current_setting('integration.purpose',true) IN ('lifecycle:read','lifecycle:delete') AND subject_user_id=NULLIF(current_setting('integration.subject_user_id',true),''))
    OR (current_setting('integration.purpose',true)='lifecycle:delete' AND credential_owner_id=NULLIF(current_setting('integration.subject_user_id',true),''))));
CREATE POLICY trigger_execution_insert ON integration_runtime.trigger_execution_leases FOR INSERT WITH CHECK (
  tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),'')
  AND subject_user_id=NULLIF(current_setting('integration.actor_user_id',true),'') AND credential_owner_id=NULLIF(current_setting('integration.subject_user_id',true),'')
  AND current_setting('integration.purpose',true)='action:execute:v2');
CREATE POLICY trigger_execution_delete ON integration_runtime.trigger_execution_leases FOR DELETE USING (
  tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),'')
  AND ((current_setting('integration.purpose',true)='action:execute:v2' AND subject_user_id=NULLIF(current_setting('integration.actor_user_id',true),'') AND credential_owner_id=NULLIF(current_setting('integration.subject_user_id',true),''))
    OR (current_setting('integration.purpose',true)='lifecycle:delete' AND subject_user_id=NULLIF(current_setting('integration.subject_user_id',true),'') AND lease_until<=clock_timestamp())));
CREATE POLICY trigger_execution_internal_read ON integration_runtime.trigger_execution_leases FOR SELECT TO CURRENT_USER
  USING (tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),''));
CREATE INDEX trigger_subscriptions_connection_idx ON integration_runtime.trigger_subscriptions (tenant_id,workspace_id,connection_id) WHERE status<>'deleted';
CREATE INDEX trigger_subscription_secret_idx ON integration_runtime.trigger_subscriptions (tenant_id,workspace_id,secret_ref);
CREATE INDEX trigger_source_secret_idx ON integration_runtime.trigger_source_applications (tenant_id,workspace_id,secret_ref);
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['trigger_subscriptions','trigger_source_applications','trigger_secret_cleanup'] LOOP
    EXECUTE format('ALTER TABLE integration_runtime.%I ENABLE ROW LEVEL SECURITY',t);
    EXECUTE format('ALTER TABLE integration_runtime.%I FORCE ROW LEVEL SECURITY',t);
    EXECUTE format('REVOKE ALL ON integration_runtime.%I FROM PUBLIC',t);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['trigger_subscriptions','trigger_source_applications'] LOOP
    EXECUTE format('CREATE POLICY trigger_actor_data ON integration_runtime.%I FOR ALL USING (
      tenant_id=NULLIF(current_setting(''integration.tenant_id'',true),'''') AND workspace_id=NULLIF(current_setting(''integration.workspace_id'',true),'''')
      AND ((subject_user_id=NULLIF(current_setting(''integration.actor_user_id'',true),'''') AND actor_user_id=subject_user_id AND credential_owner_id=NULLIF(current_setting(''integration.subject_user_id'',true),''''))
        OR (current_setting(''integration.purpose'',true) IN (''lifecycle:read'',''lifecycle:delete'') AND subject_user_id=NULLIF(current_setting(''integration.subject_user_id'',true),''''))))
      WITH CHECK (tenant_id=NULLIF(current_setting(''integration.tenant_id'',true),'''') AND workspace_id=NULLIF(current_setting(''integration.workspace_id'',true),'''')
      AND ((subject_user_id=NULLIF(current_setting(''integration.actor_user_id'',true),'''') AND actor_user_id=subject_user_id AND credential_owner_id=NULLIF(current_setting(''integration.subject_user_id'',true),''''))
        OR (current_setting(''integration.purpose'',true)=''lifecycle:delete'' AND subject_user_id=NULLIF(current_setting(''integration.subject_user_id'',true),''''))))',t);
    EXECUTE format('CREATE POLICY trigger_internal_owner_read ON integration_runtime.%I FOR SELECT TO CURRENT_USER USING (tenant_id=NULLIF(current_setting(''integration.tenant_id'',true),'''') AND workspace_id=NULLIF(current_setting(''integration.workspace_id'',true),''''))',t);
  END LOOP;
END $$;
CREATE POLICY trigger_secret_actor ON integration_runtime.trigger_secret_cleanup FOR ALL
  USING (tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),'')
    AND subject_user_id=CASE WHEN current_setting('integration.purpose',true) IN ('lifecycle:read','lifecycle:delete') THEN NULLIF(current_setting('integration.subject_user_id',true),'') ELSE NULLIF(current_setting('integration.actor_user_id',true),'') END)
  WITH CHECK (tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),'')
    AND subject_user_id=CASE WHEN current_setting('integration.purpose',true)='lifecycle:delete' THEN NULLIF(current_setting('integration.subject_user_id',true),'') ELSE NULLIF(current_setting('integration.actor_user_id',true),'') END);
CREATE POLICY trigger_cleanup_connection_owner_read ON integration_runtime.connections FOR SELECT TO CURRENT_USER
  USING (tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),''));
CREATE FUNCTION integration_runtime.can_cleanup_trigger_connection(connection_id uuid) RETURNS boolean
  LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT current_setting('integration.purpose',true)='lifecycle:delete' AND EXISTS (
    SELECT 1 FROM integration_runtime.connections c WHERE c.id=$1
      AND c.tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND c.workspace_id=NULLIF(current_setting('integration.workspace_id',true),'')
      AND (c.subject_user_id=NULLIF(current_setting('integration.subject_user_id',true),'') OR EXISTS (
        SELECT 1 FROM integration_runtime.trigger_subscriptions s WHERE s.tenant_id=c.tenant_id AND s.workspace_id=c.workspace_id
          AND s.connection_id=c.id AND s.local_connection_id=c.local_connection_id AND s.credential_owner_id=c.subject_user_id
          AND s.subject_user_id=NULLIF(current_setting('integration.subject_user_id',true),'') AND s.mode<>'resource-set' AND s.status<>'deleted')))
$$;
CREATE FUNCTION integration_runtime.trigger_cleanup_connection(connection_id uuid) RETURNS SETOF integration_runtime.connections
  LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT c.* FROM integration_runtime.connections c WHERE c.id=$1
    AND c.tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND c.workspace_id=NULLIF(current_setting('integration.workspace_id',true),'')
    AND integration_runtime.can_cleanup_trigger_connection(c.id)
$$;
REVOKE ALL ON FUNCTION integration_runtime.can_cleanup_trigger_connection(uuid),integration_runtime.trigger_cleanup_connection(uuid) FROM PUBLIC;
CREATE FUNCTION integration_runtime.is_trigger_secret_referenced(secret_ref text) RETURNS boolean
  LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM integration_runtime.trigger_subscriptions s WHERE s.tenant_id=NULLIF(current_setting('integration.tenant_id',true),'')
    AND s.workspace_id=NULLIF(current_setting('integration.workspace_id',true),'') AND s.secret_ref=$1)
    OR EXISTS (SELECT 1 FROM integration_runtime.trigger_source_applications a WHERE a.tenant_id=NULLIF(current_setting('integration.tenant_id',true),'')
      AND a.workspace_id=NULLIF(current_setting('integration.workspace_id',true),'') AND a.secret_ref=$1)
$$;
REVOKE ALL ON FUNCTION integration_runtime.is_trigger_secret_referenced(text) FROM PUBLIC;
-- No actor is fabricated for maintenance. Only a proven stored relationship permits internal cleanup.
DO $$ DECLARE access text := $policy$
  tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),'')
  AND current_setting('integration.purpose',true)='lifecycle:delete'
  AND (subject_user_id=NULLIF(current_setting('integration.subject_user_id',true),'') OR credential_owner_id=NULLIF(current_setting('integration.subject_user_id',true),'')
    OR (mode='resource-set' AND CASE WHEN current_user::regrole=(SELECT relowner FROM pg_catalog.pg_class WHERE oid='integration_runtime.trigger_subscriptions'::regclass)
      THEN false ELSE integration_runtime.can_cleanup_trigger_connection(connection_id) END))
$policy$; BEGIN
  EXECUTE 'CREATE POLICY trigger_internal_cleanup_read ON integration_runtime.trigger_subscriptions FOR SELECT USING ('||access||')';
  EXECUTE 'CREATE POLICY trigger_internal_cleanup_update ON integration_runtime.trigger_subscriptions FOR UPDATE USING ('||access||') WITH CHECK ('||access||')';
END $$;
CREATE POLICY source_internal_cleanup_read ON integration_runtime.trigger_source_applications FOR SELECT USING (
  tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),'')
  AND current_setting('integration.purpose',true)='lifecycle:delete' AND credential_owner_id=NULLIF(current_setting('integration.subject_user_id',true),''));
CREATE POLICY source_internal_cleanup_update ON integration_runtime.trigger_source_applications FOR UPDATE USING (
  tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),'')
  AND current_setting('integration.purpose',true)='lifecycle:delete' AND credential_owner_id=NULLIF(current_setting('integration.subject_user_id',true),''))
  WITH CHECK (tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),'')
    AND current_setting('integration.purpose',true)='lifecycle:delete' AND credential_owner_id=NULLIF(current_setting('integration.subject_user_id',true),'') AND retired AND bindings='[]');
DO $$ DECLARE access text := $policy$
  mode='resource-set' AND subject_user_id=credential_owner_id
  AND tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),'')
  AND ((credential_owner_id=NULLIF(current_setting('integration.subject_user_id',true),'') AND EXISTS (
    SELECT 1 FROM integration_runtime.connections c WHERE c.id=trigger_subscriptions.connection_id AND c.tenant_id=trigger_subscriptions.tenant_id
      AND c.workspace_id=trigger_subscriptions.workspace_id AND c.subject_user_id=trigger_subscriptions.credential_owner_id AND c.status='active' AND NOT c.trigger_cleanup_fenced
      AND (c.source='local' OR c.source_status='active') AND (c.subject_user_id=NULLIF(current_setting('integration.actor_user_id',true),'') OR c.visibility='workspace')))
    OR CASE WHEN current_user::regrole=(SELECT relowner FROM pg_catalog.pg_class WHERE oid='integration_runtime.trigger_subscriptions'::regclass)
      THEN false ELSE integration_runtime.can_cleanup_trigger_connection(connection_id) END)
$policy$; BEGIN
  EXECUTE 'CREATE POLICY scoped_resource_set_read ON integration_runtime.trigger_subscriptions FOR SELECT USING ('||access||')';
  EXECUTE 'CREATE POLICY scoped_resource_set_update ON integration_runtime.trigger_subscriptions FOR UPDATE USING ('||access||') WITH CHECK ('||access||')';
  EXECUTE 'CREATE POLICY scoped_resource_set_insert ON integration_runtime.trigger_subscriptions FOR INSERT WITH CHECK ('||access||')';
END $$;
CREATE FUNCTION integration_runtime.check_trigger_state_bindings() RETURNS trigger
  LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE bindings jsonb; binding jsonb; connection integration_runtime.connections%ROWTYPE; expected jsonb;
BEGIN
  IF NEW.owner_id::jsonb IS DISTINCT FROM jsonb_build_array(NEW.tenant_id,NEW.workspace_id,NEW.credential_owner_id,NEW.actor_user_id)
    OR NEW.trigger_id NOT LIKE NEW.service||'.%' THEN RAISE EXCEPTION 'Trigger namespace does not match its actual owner and provider'; END IF;
  IF TG_OP='UPDATE' AND (NEW.tenant_id,NEW.workspace_id,NEW.subject_user_id,NEW.actor_user_id,NEW.credential_owner_id,NEW.id,NEW.owner_id,NEW.service,NEW.trigger_id)
    IS DISTINCT FROM (OLD.tenant_id,OLD.workspace_id,OLD.subject_user_id,OLD.actor_user_id,OLD.credential_owner_id,OLD.id,OLD.owner_id,OLD.service,OLD.trigger_id) THEN
    RAISE EXCEPTION 'Trigger data and credential ownership are immutable'; END IF;
  IF TG_TABLE_NAME='trigger_subscriptions' THEN
    IF NEW.subject_user_id IS DISTINCT FROM (CASE WHEN NEW.mode='resource-set' THEN NEW.credential_owner_id ELSE NEW.actor_user_id END) THEN
      RAISE EXCEPTION 'Trigger data owner is invalid'; END IF;
    IF TG_OP='UPDATE' AND (NEW.connection_id,NEW.local_connection_id,NEW.account_binding,NEW.request_key,NEW.mode)
      IS DISTINCT FROM (OLD.connection_id,OLD.local_connection_id,OLD.account_binding,OLD.request_key,OLD.mode) THEN
      RAISE EXCEPTION 'Trigger subscription lineage is immutable'; END IF;
    IF NEW.status='deleted' THEN RETURN NEW; END IF;
    IF TG_OP='UPDATE' AND NEW.lease_id IS NULL AND NEW.lease_until IS NULL AND
      (NEW.secret_ref,NEW.revision,NEW.status,NEW.reconcile_at) IS NOT DISTINCT FROM (OLD.secret_ref,OLD.revision,OLD.status,OLD.reconcile_at) THEN RETURN NEW; END IF;
    bindings=jsonb_build_array(jsonb_build_object('connectionId',NEW.connection_id,'localConnectionId',NEW.local_connection_id,'account',NEW.account_binding));
  ELSE
    IF NEW.subject_user_id IS DISTINCT FROM NEW.actor_user_id OR NEW.namespace::jsonb->>0 IS DISTINCT FROM NEW.owner_id OR NEW.namespace::jsonb->>2 IS DISTINCT FROM NEW.trigger_id THEN
      RAISE EXCEPTION 'Source data owner and namespace are invalid'; END IF;
    IF TG_OP='UPDATE' AND (NEW.namespace IS DISTINCT FROM OLD.namespace OR (OLD.retired AND NOT NEW.retired)) THEN
      RAISE EXCEPTION 'Source application namespace and retirement are immutable'; END IF;
    IF NEW.retired AND current_setting('integration.purpose',true)<>'lifecycle:delete' THEN RAISE EXCEPTION 'Source retirement requires exact lifecycle authority'; END IF;
    IF TG_OP='UPDATE' AND current_setting('integration.purpose',true)='lifecycle:delete'
      AND NEW.subject_user_id IS DISTINCT FROM NULLIF(current_setting('integration.subject_user_id',true),'')
      AND (to_jsonb(NEW)-ARRAY['bindings','retired']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['bindings','retired']) THEN
      RAISE EXCEPTION 'Credential-owner cleanup may only retire another actor Source metadata';
    END IF;
    bindings=NEW.bindings;
  END IF;
  FOR binding IN SELECT value FROM jsonb_array_elements(bindings) LOOP
    IF current_setting('integration.purpose',true)='lifecycle:delete' THEN
      SELECT * INTO connection FROM integration_runtime.trigger_cleanup_connection((binding->>'connectionId')::uuid);
    ELSE
      SELECT * INTO connection FROM integration_runtime.connections c WHERE c.tenant_id=NEW.tenant_id AND c.workspace_id=NEW.workspace_id
        AND c.subject_user_id=NEW.credential_owner_id AND c.id=(binding->>'connectionId')::uuid FOR SHARE;
    END IF;
    IF NOT FOUND OR connection.subject_user_id IS DISTINCT FROM NEW.credential_owner_id OR connection.local_connection_id::text IS DISTINCT FROM binding->>'localConnectionId' OR connection.service<>NEW.service
      OR (current_setting('integration.purpose',true)<>'lifecycle:delete' AND (connection.status<>'active' OR connection.trigger_cleanup_fenced OR (connection.source='saas' AND connection.source_status IS DISTINCT FROM 'active')
        OR (current_setting('integration.actor_user_id',true)<>connection.subject_user_id AND connection.visibility<>'workspace'))) THEN
      RAISE EXCEPTION 'Trigger state requires the current exact scoped connection'; END IF;
    IF connection.source='local' THEN
      IF NULLIF(connection.provider_account_id,'') IS NULL THEN RAISE EXCEPTION 'Trigger account identity is unverified'; END IF;
      expected=jsonb_build_object('source','local','providerAccountId',connection.provider_account_id);
    ELSE
      IF NULLIF(connection.source_reference->>'managedProjectId','') IS NULL OR NULLIF(connection.source_reference->>'providerConfigId','') IS NULL
        OR NULLIF(connection.source_reference->>'externalUserId','') IS NULL OR NULLIF(connection.source_reference->>'connectedAccountId','') IS NULL THEN RAISE EXCEPTION 'Trigger managed account identity is unverified'; END IF;
      expected=jsonb_build_object('source','saas','managedProjectId',connection.source_reference->>'managedProjectId','providerConfigId',connection.source_reference->>'providerConfigId',
        'externalUserId',connection.source_reference->>'externalUserId','connectedAccountId',connection.source_reference->>'connectedAccountId');
    END IF;
    IF binding->'account' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Trigger account binding changed'; END IF;
  END LOOP;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION integration_runtime.check_trigger_state_bindings() FROM PUBLIC;
CREATE TRIGGER check_trigger_subscription_bindings BEFORE INSERT OR UPDATE ON integration_runtime.trigger_subscriptions FOR EACH ROW EXECUTE FUNCTION integration_runtime.check_trigger_state_bindings();
CREATE TRIGGER check_trigger_source_bindings BEFORE INSERT OR UPDATE ON integration_runtime.trigger_source_applications FOR EACH ROW EXECUTE FUNCTION integration_runtime.check_trigger_state_bindings();
CREATE FUNCTION integration_runtime.check_trigger_execution_lease() RETURNS trigger
  LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE connection integration_runtime.connections%ROWTYPE; expected jsonb;
BEGIN
  SELECT * INTO connection FROM integration_runtime.connections c WHERE c.tenant_id=NEW.tenant_id AND c.workspace_id=NEW.workspace_id
    AND c.id=NEW.connection_id AND c.subject_user_id=NEW.credential_owner_id FOR SHARE;
  IF NOT FOUND OR connection.local_connection_id IS DISTINCT FROM NEW.local_connection_id OR connection.service<>NEW.service OR connection.status<>'active'
    OR connection.trigger_cleanup_fenced OR (connection.source='saas' AND connection.source_status IS DISTINCT FROM 'active')
    OR (NEW.subject_user_id<>connection.subject_user_id AND connection.visibility<>'workspace')
    OR NEW.created_at>clock_timestamp() OR NEW.lease_until<=clock_timestamp()
    OR left(NEW.capability_id,length(NEW.service)+9) IS DISTINCT FROM 'trigger:'||NEW.service||'.' THEN
    RAISE EXCEPTION 'Trigger execution admission does not match the active scoped connection';
  END IF;
  IF connection.source='local' THEN
    IF NULLIF(connection.provider_account_id,'') IS NULL THEN
      expected=jsonb_build_object('source','local','unverified',true,'secretRevision',connection.secret_revision::text,'authType',connection.auth_type);
    ELSE expected=jsonb_build_object('source','local','providerAccountId',connection.provider_account_id); END IF;
  ELSE
    IF NULLIF(connection.source_reference->>'managedProjectId','') IS NULL OR NULLIF(connection.source_reference->>'providerConfigId','') IS NULL
      OR NULLIF(connection.source_reference->>'externalUserId','') IS NULL OR NULLIF(connection.source_reference->>'connectedAccountId','') IS NULL THEN
      RAISE EXCEPTION 'Trigger execution managed identity is unverified'; END IF;
    expected=jsonb_build_object('source','saas','managedProjectId',connection.source_reference->>'managedProjectId','providerConfigId',connection.source_reference->>'providerConfigId',
      'externalUserId',connection.source_reference->>'externalUserId','connectedAccountId',connection.source_reference->>'connectedAccountId');
  END IF;
  IF NEW.account_binding IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Trigger execution account lineage changed'; END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION integration_runtime.check_trigger_execution_lease() FROM PUBLIC;
CREATE TRIGGER check_trigger_execution_lease BEFORE INSERT ON integration_runtime.trigger_execution_leases FOR EACH ROW EXECUTE FUNCTION integration_runtime.check_trigger_execution_lease();
CREATE FUNCTION integration_runtime.guard_trigger_bound_connection() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE bound boolean; persistent_bound boolean; replacement jsonb;
BEGIN
  IF OLD.tenant_id IS DISTINCT FROM NULLIF(current_setting('integration.tenant_id',true),'') OR OLD.workspace_id IS DISTINCT FROM NULLIF(current_setting('integration.workspace_id',true),'') THEN
    RAISE EXCEPTION 'Trigger connection target does not match verified scope'; END IF;
  SELECT EXISTS (SELECT 1 FROM integration_runtime.trigger_subscriptions s WHERE s.tenant_id=OLD.tenant_id AND s.workspace_id=OLD.workspace_id AND s.connection_id=OLD.id AND s.status<>'deleted')
    OR EXISTS (SELECT 1 FROM integration_runtime.trigger_source_applications a,jsonb_array_elements(a.bindings) b WHERE a.tenant_id=OLD.tenant_id AND a.workspace_id=OLD.workspace_id AND b->>'connectionId'=OLD.id::text) INTO persistent_bound;
  SELECT persistent_bound OR EXISTS (SELECT 1 FROM integration_runtime.trigger_execution_leases e WHERE e.tenant_id=OLD.tenant_id AND e.workspace_id=OLD.workspace_id AND e.connection_id=OLD.id AND e.lease_until>clock_timestamp()) INTO bound;
  IF NOT bound THEN
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    -- A separately authorized transfer/unshare after complete teardown establishes new visibility.
    IF NEW.subject_user_id IS DISTINCT FROM OLD.subject_user_id OR NEW.visibility IS DISTINCT FROM OLD.visibility THEN
      NEW.trigger_cleanup_fenced=false;
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Remove active Trigger subscriptions and Sources before deleting this connection'; END IF;
  IF NEW.status='revoked' OR NEW.safe_metadata->>'reconciliation'='provider_revocation_pending' THEN
    RAISE EXCEPTION 'Remove active Trigger subscriptions and Sources before revoking this connection'; END IF;
  IF NEW.subject_user_id IS DISTINCT FROM OLD.subject_user_id OR NEW.visibility IS DISTINCT FROM OLD.visibility OR NEW.local_connection_id IS DISTINCT FROM OLD.local_connection_id OR NEW.source IS DISTINCT FROM OLD.source THEN
    RAISE EXCEPTION 'Remove active Trigger subscriptions and Sources before changing connection ownership, visibility or source'; END IF;
  IF NEW.source='local' THEN
    IF NULLIF(NEW.provider_account_id,'') IS NULL THEN replacement=NULL; ELSE replacement=jsonb_build_object('source','local','providerAccountId',NEW.provider_account_id); END IF;
  ELSE
    IF NULLIF(NEW.source_reference->>'managedProjectId','') IS NULL OR NULLIF(NEW.source_reference->>'providerConfigId','') IS NULL OR NULLIF(NEW.source_reference->>'externalUserId','') IS NULL OR NULLIF(NEW.source_reference->>'connectedAccountId','') IS NULL THEN replacement=NULL;
    ELSE replacement=jsonb_build_object('source','saas','managedProjectId',NEW.source_reference->>'managedProjectId','providerConfigId',NEW.source_reference->>'providerConfigId','externalUserId',NEW.source_reference->>'externalUserId','connectedAccountId',NEW.source_reference->>'connectedAccountId'); END IF;
  END IF;
  IF (persistent_bound AND replacement IS NULL) OR EXISTS (SELECT 1 FROM integration_runtime.trigger_subscriptions s WHERE s.tenant_id=OLD.tenant_id AND s.workspace_id=OLD.workspace_id AND s.connection_id=OLD.id AND s.status<>'deleted' AND s.account_binding IS DISTINCT FROM replacement)
    OR EXISTS (SELECT 1 FROM integration_runtime.trigger_source_applications a,jsonb_array_elements(a.bindings) b WHERE a.tenant_id=OLD.tenant_id AND a.workspace_id=OLD.workspace_id AND b->>'connectionId'=OLD.id::text AND b->'account' IS DISTINCT FROM replacement)
    OR EXISTS (SELECT 1 FROM integration_runtime.trigger_execution_leases e WHERE e.tenant_id=OLD.tenant_id AND e.workspace_id=OLD.workspace_id AND e.connection_id=OLD.id AND e.lease_until>clock_timestamp()
      AND ((e.account_binding->>'unverified'='true' AND (NEW.source<>'local' OR e.account_binding->>'secretRevision' IS DISTINCT FROM NEW.secret_revision::text OR e.account_binding->>'authType' IS DISTINCT FROM NEW.auth_type))
        OR (e.account_binding->>'unverified' IS DISTINCT FROM 'true' AND e.account_binding IS DISTINCT FROM replacement))) THEN
    RAISE EXCEPTION 'Remove active Trigger subscriptions and Sources before replacing the verified provider account'; END IF;
  -- A truthful status-only reconnect_required transition and same-account token/consent renewal remain allowed.
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION integration_runtime.guard_trigger_bound_connection() FROM PUBLIC;
CREATE TRIGGER guard_trigger_bound_connection BEFORE UPDATE OR DELETE ON integration_runtime.connections FOR EACH ROW EXECUTE FUNCTION integration_runtime.guard_trigger_bound_connection();
