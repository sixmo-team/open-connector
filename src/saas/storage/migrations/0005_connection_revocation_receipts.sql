CREATE TABLE integration_runtime.connection_revocation_receipts (
  tenant_id text NOT NULL CHECK (tenant_id <> ''),
  workspace_id text NOT NULL CHECK (workspace_id <> ''),
  subject_user_id text NOT NULL CHECK (subject_user_id <> ''),
  local_connection_id uuid NOT NULL,
  connector_connection_id uuid NOT NULL,
  completed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, workspace_id, subject_user_id, local_connection_id, connector_connection_id)
);

ALTER TABLE integration_runtime.connection_revocation_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.connection_revocation_receipts FORCE ROW LEVEL SECURITY;

CREATE POLICY connection_revocation_receipts_select
  ON integration_runtime.connection_revocation_receipts
  FOR SELECT
  USING (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
  );

CREATE POLICY connection_revocation_receipts_insert
  ON integration_runtime.connection_revocation_receipts
  FOR INSERT
  WITH CHECK (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
  );
