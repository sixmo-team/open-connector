CREATE POLICY connection_revocation_receipts_delete
  ON integration_runtime.connection_revocation_receipts
  FOR DELETE
  USING (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
  );
