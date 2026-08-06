ALTER TABLE integration_runtime.connections
  ADD COLUMN local_connection_id uuid NOT NULL;

ALTER TABLE integration_runtime.connections
  DROP CONSTRAINT connections_tenant_id_workspace_id_service_connection_name_key;

CREATE UNIQUE INDEX connections_scope_local_connection_idx
  ON integration_runtime.connections (tenant_id, workspace_id, local_connection_id);

CREATE UNIQUE INDEX connections_user_alias_idx
  ON integration_runtime.connections (
    tenant_id, workspace_id, subject_user_id, service, connection_name
  )
  WHERE visibility = 'user';

CREATE UNIQUE INDEX connections_workspace_alias_idx
  ON integration_runtime.connections (tenant_id, workspace_id, service, connection_name)
  WHERE visibility = 'workspace';

DROP POLICY connections_update ON integration_runtime.connections;
CREATE POLICY connections_update ON integration_runtime.connections
  FOR UPDATE USING (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
  ) WITH CHECK (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND (
      subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
      OR (
        visibility = 'workspace'
        AND NULLIF(current_setting('integration.workspace_role', true), '') IN ('owner', 'admin')
      )
    )
  );
