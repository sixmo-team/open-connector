-- Ordinary transit data belongs to the actor, not the owner of a shared credential.
-- Lifecycle operations retain the exact signed subject target without rewriting execution scope.
ALTER POLICY transit_files_subject_access ON integration_runtime.transit_files
  USING (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND subject_user_id = CASE
      WHEN current_setting('integration.purpose', true) IN ('lifecycle:read', 'lifecycle:delete')
        THEN NULLIF(current_setting('integration.subject_user_id', true), '')
      ELSE NULLIF(current_setting('integration.actor_user_id', true), '')
    END
  ) WITH CHECK (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND subject_user_id = CASE
      WHEN current_setting('integration.purpose', true) IN ('lifecycle:read', 'lifecycle:delete')
        THEN NULLIF(current_setting('integration.subject_user_id', true), '')
      ELSE NULLIF(current_setting('integration.actor_user_id', true), '')
    END
  );

-- Expired executions are lifecycle-owned by both their actor and credential owner.
-- Ordinary execution completion still requires the original actor/credential-owner pair.
ALTER POLICY trigger_execution_delete ON integration_runtime.trigger_execution_leases
  USING (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND (
      (
        current_setting('integration.purpose', true) = 'action:execute:v2'
        AND subject_user_id = NULLIF(current_setting('integration.actor_user_id', true), '')
        AND credential_owner_id = NULLIF(current_setting('integration.subject_user_id', true), '')
      )
      OR (
        current_setting('integration.purpose', true) = 'lifecycle:delete'
        AND (
          subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
          OR credential_owner_id = NULLIF(current_setting('integration.subject_user_id', true), '')
        )
        AND lease_until <= clock_timestamp()
      )
    )
  );
