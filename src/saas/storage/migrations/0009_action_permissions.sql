CREATE TABLE integration_runtime.action_defaults (
  action_id text PRIMARY KEY CHECK (action_id <> '' AND action_id NOT LIKE '%*%'),
  enabled boolean NOT NULL,
  created_by_subject text NOT NULL CHECK (btrim(created_by_subject) <> ''),
  updated_by_subject text NOT NULL CHECK (btrim(updated_by_subject) <> ''),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE integration_runtime.action_grants (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  user_id uuid NOT NULL,
  action_id text NOT NULL CHECK (action_id <> '' AND action_id NOT LIKE '%*%'),
  enabled boolean NOT NULL,
  created_by_subject text NOT NULL CHECK (btrim(created_by_subject) <> ''),
  updated_by_subject text NOT NULL CHECK (btrim(updated_by_subject) <> ''),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, workspace_id, user_id, action_id)
);
CREATE TABLE integration_runtime.action_policy_audit (
  id uuid PRIMARY KEY,
  target_kind text NOT NULL CHECK (target_kind IN ('platform', 'user')),
  tenant_id uuid,
  workspace_id uuid,
  user_id uuid,
  operator_subject text NOT NULL CHECK (btrim(operator_subject) <> ''),
  action_ids text[] NOT NULL CHECK (cardinality(action_ids) BETWEEN 1 AND 5000),
  enabled boolean,
  reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500 AND btrim(reason) <> ''),
  request_id text NOT NULL CHECK (btrim(request_id) <> ''),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((target_kind = 'platform' AND tenant_id IS NULL AND workspace_id IS NULL AND user_id IS NULL AND enabled IS NOT NULL)
    OR (target_kind = 'user' AND tenant_id IS NOT NULL AND workspace_id IS NOT NULL AND user_id IS NOT NULL))
);
CREATE INDEX action_policy_audit_user ON integration_runtime.action_policy_audit (tenant_id, workspace_id, user_id, id) WHERE target_kind = 'user';

-- Session settings are populated only from the verified native principal, never request body scope.
CREATE FUNCTION integration_runtime.policy_control_matches(kind text, tenant uuid, workspace uuid, subject uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT current_setting('integration.principal_kind', true) = 'policy_control'
    AND current_setting('integration.policy_target_kind', true) = kind
    AND (kind = 'platform' OR (
      tenant::text = lower(current_setting('integration.policy_tenant_id', true))
      AND workspace::text = lower(current_setting('integration.policy_workspace_id', true))
      AND subject::text = lower(current_setting('integration.policy_user_id', true))))
$$;
CREATE FUNCTION integration_runtime.policy_service_matches(tenant uuid, workspace uuid, subject uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT current_setting('integration.principal_kind', true) = 'service'
    AND tenant::text = lower(current_setting('integration.policy_tenant_id', true))
    AND (current_setting('integration.policy_target_kind', true) = 'tenant' OR (
      workspace::text = lower(current_setting('integration.policy_workspace_id', true))
      AND (current_setting('integration.policy_target_kind', true) = 'workspace' OR (
        current_setting('integration.policy_target_kind', true) = 'user'
        AND subject::text = lower(current_setting('integration.policy_user_id', true))))))
$$;
CREATE FUNCTION integration_runtime.policy_actor_matches(tenant uuid, workspace uuid, subject uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT current_setting('integration.principal_kind', true) = 'user'
    AND current_setting('integration.purpose', true) IN ('action:search', 'action:execute:v2')
    AND tenant::text = lower(current_setting('integration.tenant_id', true))
    AND workspace::text = lower(current_setting('integration.workspace_id', true))
    AND subject::text = lower(current_setting('integration.actor_user_id', true))
    AND (current_setting('integration.purpose', true) <> 'action:search'
      OR current_setting('integration.actor_user_id', true) = current_setting('integration.subject_user_id', true))
$$;
CREATE FUNCTION integration_runtime.policy_lifecycle_matches(tenant uuid, workspace uuid, subject uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT current_setting('integration.principal_kind', true) = 'user'
    AND current_setting('integration.purpose', true) IN ('lifecycle:read', 'lifecycle:delete')
    AND tenant::text = lower(current_setting('integration.tenant_id', true))
    AND workspace::text = lower(current_setting('integration.workspace_id', true))
    AND subject::text = lower(current_setting('integration.subject_user_id', true))
$$;

ALTER TABLE integration_runtime.action_defaults ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.action_defaults FORCE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.action_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.action_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.action_policy_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.action_policy_audit FORCE ROW LEVEL SECURITY;
REVOKE ALL ON integration_runtime.action_defaults, integration_runtime.action_grants, integration_runtime.action_policy_audit FROM PUBLIC;

CREATE POLICY action_defaults_read ON integration_runtime.action_defaults FOR SELECT USING (
  (current_setting('integration.principal_kind', true) = 'user'
    AND current_setting('integration.purpose', true) IN ('action:search', 'action:execute:v2')
    AND (current_setting('integration.purpose', true) <> 'action:search'
      OR current_setting('integration.actor_user_id', true) = current_setting('integration.subject_user_id', true)))
  OR (current_setting('integration.principal_kind', true) = 'policy_control'
    AND current_setting('integration.purpose', true) IN ('action-policy:read', 'action-policy:write')
    AND current_setting('integration.policy_target_kind', true) IN ('platform', 'user'))
);
CREATE POLICY action_defaults_insert ON integration_runtime.action_defaults FOR INSERT WITH CHECK (
  integration_runtime.policy_control_matches('platform', NULL, NULL, NULL)
  AND current_setting('integration.purpose', true) = 'action-policy:write'
);
CREATE POLICY action_defaults_update ON integration_runtime.action_defaults FOR UPDATE USING (
  integration_runtime.policy_control_matches('platform', NULL, NULL, NULL)
  AND current_setting('integration.purpose', true) = 'action-policy:write'
) WITH CHECK (
  integration_runtime.policy_control_matches('platform', NULL, NULL, NULL)
  AND current_setting('integration.purpose', true) = 'action-policy:write'
);
CREATE POLICY action_grants_read ON integration_runtime.action_grants FOR SELECT USING (
  integration_runtime.policy_actor_matches(tenant_id, workspace_id, user_id)
  OR integration_runtime.policy_lifecycle_matches(tenant_id, workspace_id, user_id)
  OR (integration_runtime.policy_control_matches('user', tenant_id, workspace_id, user_id)
    AND current_setting('integration.purpose', true) IN ('action-policy:read', 'action-policy:write'))
  OR (integration_runtime.policy_service_matches(tenant_id, workspace_id, user_id)
    AND current_setting('integration.purpose', true) IN ('action-policy:subjects', 'action-policy:purge'))
);
CREATE POLICY action_grants_insert ON integration_runtime.action_grants FOR INSERT WITH CHECK (
  integration_runtime.policy_control_matches('user', tenant_id, workspace_id, user_id)
  AND current_setting('integration.purpose', true) = 'action-policy:write'
);
CREATE POLICY action_grants_update ON integration_runtime.action_grants FOR UPDATE USING (
  integration_runtime.policy_control_matches('user', tenant_id, workspace_id, user_id)
  AND current_setting('integration.purpose', true) = 'action-policy:write'
) WITH CHECK (
  integration_runtime.policy_control_matches('user', tenant_id, workspace_id, user_id)
  AND current_setting('integration.purpose', true) = 'action-policy:write'
);
CREATE POLICY action_grants_delete ON integration_runtime.action_grants FOR DELETE USING (
  (integration_runtime.policy_control_matches('user', tenant_id, workspace_id, user_id)
    AND current_setting('integration.purpose', true) = 'action-policy:write')
  OR (integration_runtime.policy_service_matches(tenant_id, workspace_id, user_id)
    AND current_setting('integration.purpose', true) = 'action-policy:purge')
);
CREATE POLICY action_policy_audit_read ON integration_runtime.action_policy_audit FOR SELECT USING (
  (integration_runtime.policy_control_matches(target_kind, tenant_id, workspace_id, user_id)
    AND current_setting('integration.purpose', true) IN ('action-policy:read', 'action-policy:write'))
  OR (target_kind = 'user' AND (
    integration_runtime.policy_lifecycle_matches(tenant_id, workspace_id, user_id)
    OR (integration_runtime.policy_service_matches(tenant_id, workspace_id, user_id)
      AND current_setting('integration.purpose', true) IN ('action-policy:subjects', 'action-policy:purge'))))
);
CREATE POLICY action_policy_audit_insert ON integration_runtime.action_policy_audit FOR INSERT WITH CHECK (
  integration_runtime.policy_control_matches(target_kind, tenant_id, workspace_id, user_id)
  AND current_setting('integration.purpose', true) = 'action-policy:write'
  AND operator_subject = current_setting('integration.operator_subject', true)
);
CREATE POLICY action_policy_audit_delete ON integration_runtime.action_policy_audit FOR DELETE USING (
  target_kind = 'user' AND integration_runtime.policy_service_matches(tenant_id, workspace_id, user_id)
  AND current_setting('integration.purpose', true) = 'action-policy:purge'
);
