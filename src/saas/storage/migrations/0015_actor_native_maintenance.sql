-- Maintenance reads current OO permission only; execution admission keeps its existing purpose gate.
CREATE POLICY action_defaults_maintenance_read ON integration_runtime.action_defaults FOR SELECT USING (
  current_setting('integration.principal_kind',true)='user' AND current_setting('integration.purpose',true)='maintenance:run'
  AND current_setting('integration.actor_user_id',true)=current_setting('integration.subject_user_id',true));
CREATE POLICY action_grants_maintenance_read ON integration_runtime.action_grants FOR SELECT USING (
  current_setting('integration.principal_kind',true)='user' AND current_setting('integration.purpose',true)='maintenance:run'
  AND current_setting('integration.actor_user_id',true)=current_setting('integration.subject_user_id',true)
  AND tenant_id::text=lower(current_setting('integration.tenant_id',true))
  AND workspace_id::text=lower(current_setting('integration.workspace_id',true))
  AND user_id::text=lower(current_setting('integration.actor_user_id',true)));

-- A customer maintenance pass can reach only its own persisted consumers, not every actor of its credential.
CREATE OR REPLACE FUNCTION integration_runtime.can_cleanup_trigger_connection(connection_id uuid) RETURNS boolean
  LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT current_setting('integration.purpose',true) IN ('lifecycle:delete','maintenance:run') AND EXISTS (
    SELECT 1 FROM integration_runtime.connections c WHERE c.id=$1
      AND c.tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND c.workspace_id=NULLIF(current_setting('integration.workspace_id',true),'')
      AND ((current_setting('integration.purpose',true)='lifecycle:delete' AND c.subject_user_id=NULLIF(current_setting('integration.subject_user_id',true),'')) OR EXISTS (
        SELECT 1 FROM integration_runtime.trigger_subscriptions s WHERE s.tenant_id=c.tenant_id AND s.workspace_id=c.workspace_id
          AND s.connection_id=c.id AND s.local_connection_id=c.local_connection_id AND s.credential_owner_id=c.subject_user_id
          AND s.subject_user_id=NULLIF(current_setting('integration.subject_user_id',true),'') AND s.actor_user_id=s.subject_user_id
          AND s.mode<>'resource-set' AND s.status<>'deleted'
          AND (current_setting('integration.purpose',true)='lifecycle:delete' OR current_setting('integration.actor_user_id',true)=s.subject_user_id))))
$$;
DO $$ DECLARE access text := $policy$
  tenant_id=NULLIF(current_setting('integration.tenant_id',true),'') AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),'')
  AND current_setting('integration.purpose',true)='maintenance:run'
  AND current_setting('integration.actor_user_id',true)=current_setting('integration.subject_user_id',true)
  AND ((mode<>'resource-set' AND subject_user_id=NULLIF(current_setting('integration.actor_user_id',true),'') AND actor_user_id=subject_user_id)
    OR (mode='resource-set' AND CASE WHEN current_user::regrole=(SELECT relowner FROM pg_catalog.pg_class WHERE oid='integration_runtime.trigger_subscriptions'::regclass)
      THEN false ELSE integration_runtime.can_cleanup_trigger_connection(connection_id) END))
$policy$; BEGIN
  EXECUTE 'CREATE POLICY trigger_actor_maintenance_read ON integration_runtime.trigger_subscriptions FOR SELECT USING ('||access||')';
  EXECUTE 'CREATE POLICY trigger_actor_maintenance_update ON integration_runtime.trigger_subscriptions FOR UPDATE USING ('||access||') WITH CHECK ('||access||')';
END $$;

-- Original account/actor binding remains mandatory even after current permission or visibility is revoked.
CREATE OR REPLACE FUNCTION integration_runtime.check_trigger_state_bindings() RETURNS trigger
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
    IF current_setting('integration.purpose',true) IN ('lifecycle:delete','maintenance:run') THEN
      SELECT * INTO connection FROM integration_runtime.trigger_cleanup_connection((binding->>'connectionId')::uuid);
    ELSE
      SELECT * INTO connection FROM integration_runtime.connections c WHERE c.tenant_id=NEW.tenant_id AND c.workspace_id=NEW.workspace_id
        AND c.subject_user_id=NEW.credential_owner_id AND c.id=(binding->>'connectionId')::uuid FOR SHARE;
    END IF;
    IF NOT FOUND OR connection.subject_user_id IS DISTINCT FROM NEW.credential_owner_id OR connection.local_connection_id::text IS DISTINCT FROM binding->>'localConnectionId' OR connection.service<>NEW.service
      OR (current_setting('integration.purpose',true) NOT IN ('lifecycle:delete','maintenance:run') AND (connection.status<>'active' OR connection.trigger_cleanup_fenced OR (connection.source='saas' AND connection.source_status IS DISTINCT FROM 'active')
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
