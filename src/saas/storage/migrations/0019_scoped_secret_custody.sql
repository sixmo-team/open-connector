-- Old rows have neither actual actor/credential lineage nor authoritative original-write outcomes.
-- Fail closed: an operator must reconcile every old exact reference before this cutover can run.
LOCK TABLE integration_runtime.trigger_secret_cleanup IN ACCESS EXCLUSIVE MODE;
ALTER TABLE integration_runtime.trigger_secret_cleanup NO FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM integration_runtime.trigger_secret_cleanup) THEN
    RAISE EXCEPTION 'Secret custody cutover requires reconciliation of every trigger_secret_cleanup row before migration; original write outcomes and actual actor/credential lineage are unknown';
  END IF;
END $$;

-- Terminal request fencing commits before external secret deletion and cannot be reclaimed.
ALTER TABLE integration_runtime.connection_requests DROP CONSTRAINT connection_requests_phase_check;
ALTER TABLE integration_runtime.connection_requests ADD CONSTRAINT connection_requests_phase_check
  CHECK (phase IN ('pending','processing','completed','purging'));

CREATE TABLE integration_runtime.secret_custody (
  tenant_id text NOT NULL CHECK (tenant_id<>''),
  workspace_id text NOT NULL CHECK (workspace_id<>''),
  secret_ref text NOT NULL CHECK (secret_ref<>''),
  subject_user_id text NOT NULL CHECK (subject_user_id<>''),
  actor_user_id text NOT NULL CHECK (actor_user_id<>''),
  credential_owner_id text NOT NULL CHECK (credential_owner_id<>''),
  kind text NOT NULL CHECK (kind IN ('trigger-subscription','trigger-source','connection-request','connection-candidate')),
  target_id text NOT NULL CHECK (target_id<>''),
  identity jsonb NOT NULL CHECK (jsonb_typeof(identity)='object' AND identity<>'{}'::jsonb),
  connection_id uuid,
  state text NOT NULL CHECK (state IN ('pending','deleting')),
  PRIMARY KEY (tenant_id,workspace_id,secret_ref),
  CHECK (kind NOT IN ('connection-request','connection-candidate') OR subject_user_id=credential_owner_id),
  CHECK (kind<>'trigger-subscription' OR (connection_id IS NOT NULL AND identity ? 'mode' AND identity->>'mode' IN ('webhook','resource','resource-set'))),
  CHECK (kind NOT IN ('trigger-subscription','trigger-source') OR
    (identity->>'actorUserId' IS NOT NULL AND (state='deleting' OR identity->>'actorUserId'=actor_user_id) AND
      subject_user_id=CASE WHEN kind='trigger-subscription' AND identity->>'mode'='resource-set'
        THEN credential_owner_id ELSE COALESCE(identity->>'ownerActorUserId',identity->>'actorUserId') END))
);
CREATE INDEX secret_custody_owner_idx ON integration_runtime.secret_custody (tenant_id,workspace_id,subject_user_id,kind,state);
CREATE INDEX secret_custody_actor_idx ON integration_runtime.secret_custody (tenant_id,workspace_id,actor_user_id,kind,state);
CREATE INDEX secret_custody_credential_idx ON integration_runtime.secret_custody (tenant_id,workspace_id,credential_owner_id,kind,state);
ALTER TABLE integration_runtime.secret_custody ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.secret_custody FORCE ROW LEVEL SECURITY;
REVOKE ALL ON integration_runtime.secret_custody FROM PUBLIC;

-- Native actor/credential separation, exact lifecycle relations, and existing shared-resource cleanup proof.
DO $$ DECLARE
  scope_match text := $scope$
    current_setting('integration.principal_kind',true)='user'
    AND tenant_id=NULLIF(current_setting('integration.tenant_id',true),'')
    AND workspace_id=NULLIF(current_setting('integration.workspace_id',true),'')
  $scope$;
  access text := $access$
    ((current_setting('integration.purpose',true) NOT IN ('lifecycle:read','lifecycle:delete','maintenance:run')
      AND actor_user_id=NULLIF(current_setting('integration.actor_user_id',true),'')
      AND credential_owner_id=NULLIF(current_setting('integration.subject_user_id',true),''))
    OR (state='deleting' AND kind='trigger-subscription' AND identity->>'mode'='resource-set'
      AND current_setting('integration.purpose',true) NOT IN ('lifecycle:read','lifecycle:delete','maintenance:run')
      AND credential_owner_id=NULLIF(current_setting('integration.subject_user_id',true),'')
      AND EXISTS (SELECT 1 FROM integration_runtime.connections c
        WHERE c.id=secret_custody.connection_id AND c.tenant_id=secret_custody.tenant_id
          AND c.workspace_id=secret_custody.workspace_id AND c.subject_user_id=secret_custody.credential_owner_id
          AND c.status='active' AND NOT c.trigger_cleanup_fenced AND (c.source='local' OR c.source_status='active')
          AND (c.subject_user_id=NULLIF(current_setting('integration.actor_user_id',true),'') OR c.visibility='workspace')))
    OR (current_setting('integration.purpose',true) IN ('lifecycle:read','lifecycle:delete')
      AND (subject_user_id=NULLIF(current_setting('integration.subject_user_id',true),'')
        OR actor_user_id=NULLIF(current_setting('integration.subject_user_id',true),'')
        OR (kind IN ('trigger-subscription','trigger-source')
          AND COALESCE(identity->>'ownerActorUserId',identity->>'actorUserId')=NULLIF(current_setting('integration.subject_user_id',true),''))
        OR credential_owner_id=NULLIF(current_setting('integration.subject_user_id',true),'')))
    OR (current_setting('integration.purpose',true)='maintenance:run'
      AND current_setting('integration.actor_user_id',true)=current_setting('integration.subject_user_id',true)
      AND (actor_user_id=NULLIF(current_setting('integration.actor_user_id',true),'')
        OR subject_user_id=NULLIF(current_setting('integration.actor_user_id',true),'')
        OR (kind='trigger-subscription' AND identity->>'mode'='resource-set'
          AND integration_runtime.can_cleanup_trigger_connection(connection_id)))))
  $access$;
  mutation text;
BEGIN
  mutation := '('||scope_match||') AND ('||access||') AND current_setting(''integration.purpose'',true)<>''lifecycle:read''';
  EXECUTE 'CREATE POLICY custody_customer_read ON integration_runtime.secret_custody FOR SELECT USING (('||scope_match||') AND ('||access||'))';
  EXECUTE 'CREATE POLICY custody_customer_insert ON integration_runtime.secret_custody FOR INSERT WITH CHECK ('||mutation||' AND actor_user_id=NULLIF(current_setting(''integration.actor_user_id'',true),'''') AND (
    state<>''pending'' OR kind<>''trigger-subscription'' OR identity->>''mode''<>''resource-set''
    OR current_setting(''integration.purpose'',true) IN (''lifecycle:delete'',''maintenance:run'')
    OR EXISTS (SELECT 1 FROM integration_runtime.connections c
      WHERE c.id=secret_custody.connection_id AND c.tenant_id=secret_custody.tenant_id
        AND c.workspace_id=secret_custody.workspace_id AND c.subject_user_id=secret_custody.credential_owner_id
        AND c.status=''active'' AND NOT c.trigger_cleanup_fenced AND (c.source=''local'' OR c.source_status=''active'')
        AND (c.subject_user_id=NULLIF(current_setting(''integration.actor_user_id'',true),'''') OR c.visibility=''workspace''))))';
  EXECUTE 'CREATE POLICY custody_customer_update ON integration_runtime.secret_custody FOR UPDATE USING ('||mutation||') WITH CHECK ('||mutation||')';
  EXECUTE 'CREATE POLICY custody_customer_delete ON integration_runtime.secret_custody FOR DELETE USING ('||mutation||')';
END $$;

-- SERVICE has inventory/configuration-purge SELECT only. Never row locks or customer mutation.
CREATE POLICY native_lifecycle_inventory ON integration_runtime.secret_custody FOR SELECT USING (
  current_setting('integration.principal_kind',true)='service'
  AND current_setting('integration.purpose',true) IN ('lifecycle:subjects','lifecycle:configuration:purge')
  AND current_setting('integration.policy_target_kind',true) IN ('tenant','workspace')
  AND tenant_id=NULLIF(current_setting('integration.policy_tenant_id',true),'')
  AND (current_setting('integration.policy_target_kind',true)='tenant'
    OR workspace_id=NULLIF(current_setting('integration.policy_workspace_id',true),'')));

CREATE FUNCTION integration_runtime.check_secret_custody_immutable() RETURNS trigger
  LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  IF (to_jsonb(NEW)-'state') IS DISTINCT FROM (to_jsonb(OLD)-'state')
    OR (OLD.state='deleting' AND NEW.state<>'deleting') THEN
    RAISE EXCEPTION 'Exact secret custody lineage is immutable and deleting cannot become pending';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION integration_runtime.check_secret_custody_immutable() FROM PUBLIC;
CREATE TRIGGER secret_custody_immutable BEFORE UPDATE ON integration_runtime.secret_custody
  FOR EACH ROW EXECUTE FUNCTION integration_runtime.check_secret_custody_immutable();

DROP TABLE integration_runtime.trigger_secret_cleanup;
DROP FUNCTION integration_runtime.is_trigger_secret_referenced(text);

-- Retirement cannot reopen a request whose private payload already crossed its terminal fence.
CREATE OR REPLACE FUNCTION integration_runtime.retire_connection_authorizations() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cleanup_reference record;
BEGIN
  IF OLD.tenant_id IS DISTINCT FROM NULLIF(current_setting('integration.tenant_id',true),'')
    OR OLD.workspace_id IS DISTINCT FROM NULLIF(current_setting('integration.workspace_id',true),'')
    OR OLD.subject_user_id IS DISTINCT FROM NULLIF(current_setting('integration.subject_user_id',true),'') THEN
    RAISE EXCEPTION 'Connection retirement target does not match verified scope';
  END IF;
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
        AND local_connection_id=OLD.local_connection_id AND kind='saas' AND phase IN ('pending','processing')
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
        AND local_connection_id=OLD.local_connection_id AND kind='saas' AND phase IN ('pending','processing')
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
        AND local_connection_id=OLD.local_connection_id AND phase IN ('pending','processing');
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
REVOKE ALL ON FUNCTION integration_runtime.retire_connection_authorizations() FROM PUBLIC;
