CREATE SCHEMA IF NOT EXISTS integration_runtime;
REVOKE ALL ON SCHEMA integration_runtime FROM PUBLIC;

CREATE TABLE integration_runtime.connections (
  id uuid PRIMARY KEY,
  tenant_id text NOT NULL CHECK (tenant_id <> ''),
  workspace_id text NOT NULL CHECK (workspace_id <> ''),
  subject_user_id text NOT NULL CHECK (subject_user_id <> ''),
  visibility text NOT NULL DEFAULT 'user' CHECK (visibility IN ('user', 'workspace')),
  service text NOT NULL CHECK (service <> ''),
  connection_name text NOT NULL CHECK (connection_name <> ''),
  auth_type text NOT NULL CHECK (auth_type <> ''),
  revision text NOT NULL CHECK (revision <> ''),
  secret_ref text NOT NULL CHECK (secret_ref <> ''),
  secret_revision bigint NOT NULL DEFAULT 0 CHECK (secret_revision >= 0),
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'active', 'expired', 'revoked', 'failed', 'reconnect_required')),
  credential_profile jsonb CHECK (
    credential_profile IS NULL OR jsonb_typeof(credential_profile) = 'object'
  ),
  auth_metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(auth_metadata) = 'object'),
  display_name text,
  provider_account_id text,
  granted_scopes jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(granted_scopes) = 'array'),
  safe_metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(safe_metadata) = 'object'),
  last_verified_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, id, subject_user_id, visibility),
  UNIQUE (tenant_id, workspace_id, service, connection_name)
);

CREATE TABLE integration_runtime.oauth_states (
  id uuid PRIMARY KEY,
  tenant_id text NOT NULL CHECK (tenant_id <> ''),
  workspace_id text NOT NULL CHECK (workspace_id <> ''),
  subject_user_id text NOT NULL CHECK (subject_user_id <> ''),
  connection_id uuid,
  service text NOT NULL CHECK (service <> ''),
  connection_name text,
  state_hash text NOT NULL CHECK (state_hash <> ''),
  secret_ref text NOT NULL CHECK (secret_ref <> ''),
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'reserved', 'completed', 'failed', 'expired')),
  return_target text,
  callback_result_fingerprint text,
  reservation_expires_at timestamptz,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, workspace_id, state_hash),
  FOREIGN KEY (tenant_id, workspace_id, connection_id)
    REFERENCES integration_runtime.connections (tenant_id, workspace_id, id) ON DELETE CASCADE
);

CREATE TABLE integration_runtime.run_intents (
  id uuid PRIMARY KEY,
  tenant_id text NOT NULL CHECK (tenant_id <> ''),
  workspace_id text NOT NULL CHECK (workspace_id <> ''),
  actor_user_id text NOT NULL CHECK (actor_user_id <> ''),
  subject_user_id text NOT NULL CHECK (subject_user_id <> ''),
  connection_id uuid,
  service text NOT NULL CHECK (service <> ''),
  action_id text NOT NULL CHECK (action_id <> ''),
  caller text NOT NULL CHECK (caller IN ('http', 'mcp', 'web')),
  request_hash text,
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'unknown')),
  ok boolean,
  provider_execution_id text,
  runtime_token_id text,
  connection_profile jsonb CHECK (
    connection_profile IS NULL OR jsonb_typeof(connection_profile) = 'object'
  ),
  policy jsonb CHECK (policy IS NULL OR jsonb_typeof(policy) = 'object'),
  input_bytes bigint CHECK (input_bytes IS NULL OR input_bytes >= 0),
  output_bytes bigint CHECK (output_bytes IS NULL OR output_bytes >= 0),
  duration_ms bigint CHECK (duration_ms IS NULL OR duration_ms >= 0),
  safe_error_code text,
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id, connection_id)
    REFERENCES integration_runtime.connections (tenant_id, workspace_id, id) ON DELETE RESTRICT
);

CREATE TABLE integration_runtime.idempotency_records (
  id uuid PRIMARY KEY,
  tenant_id text NOT NULL CHECK (tenant_id <> ''),
  workspace_id text NOT NULL CHECK (workspace_id <> ''),
  subject_user_id text NOT NULL CHECK (subject_user_id <> ''),
  connection_id uuid,
  action_id text,
  key_hash text NOT NULL CHECK (key_hash <> ''),
  request_hash text NOT NULL CHECK (request_hash <> ''),
  claim_id text NOT NULL CHECK (claim_id <> ''),
  status text NOT NULL DEFAULT 'in_progress'
    CHECK (status IN ('in_progress', 'completed', 'reserved', 'succeeded', 'failed')),
  response jsonb CHECK (response IS NULL OR jsonb_typeof(response) = 'object'),
  result_fingerprint text,
  safe_error_code text,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, workspace_id, subject_user_id, key_hash),
  FOREIGN KEY (tenant_id, workspace_id, connection_id)
    REFERENCES integration_runtime.connections (tenant_id, workspace_id, id) ON DELETE RESTRICT
);

CREATE TABLE integration_runtime.refresh_leases (
  tenant_id text NOT NULL CHECK (tenant_id <> ''),
  workspace_id text NOT NULL CHECK (workspace_id <> ''),
  subject_user_id text NOT NULL CHECK (subject_user_id <> ''),
  visibility text NOT NULL CHECK (visibility IN ('user', 'workspace')),
  connection_id uuid PRIMARY KEY,
  lease_holder text NOT NULL CHECK (lease_holder <> ''),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id, connection_id, subject_user_id, visibility)
    REFERENCES integration_runtime.connections
      (tenant_id, workspace_id, id, subject_user_id, visibility)
    ON DELETE CASCADE
);

CREATE TABLE integration_runtime.transit_files (
  id uuid PRIMARY KEY,
  tenant_id text NOT NULL CHECK (tenant_id <> ''),
  workspace_id text NOT NULL CHECK (workspace_id <> ''),
  subject_user_id text NOT NULL CHECK (subject_user_id <> ''),
  object_key text NOT NULL CHECK (object_key <> ''),
  content_type text,
  byte_size bigint NOT NULL CHECK (byte_size >= 0),
  content_sha256 text,
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'available', 'deleting', 'reconcile')),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, workspace_id, object_key)
);

CREATE INDEX connections_scope_subject_idx
  ON integration_runtime.connections (tenant_id, workspace_id, subject_user_id);
CREATE INDEX oauth_states_scope_subject_idx
  ON integration_runtime.oauth_states (tenant_id, workspace_id, subject_user_id);
CREATE INDEX oauth_states_expiry_idx
  ON integration_runtime.oauth_states (tenant_id, workspace_id, expires_at);
CREATE INDEX run_intents_scope_subject_created_idx
  ON integration_runtime.run_intents (tenant_id, workspace_id, subject_user_id, created_at DESC);
CREATE INDEX idempotency_records_expiry_idx
  ON integration_runtime.idempotency_records (tenant_id, workspace_id, expires_at);
CREATE INDEX refresh_leases_expiry_idx
  ON integration_runtime.refresh_leases (tenant_id, workspace_id, expires_at);
CREATE INDEX transit_files_scope_subject_idx
  ON integration_runtime.transit_files (tenant_id, workspace_id, subject_user_id);
CREATE INDEX transit_files_expiry_idx
  ON integration_runtime.transit_files (tenant_id, workspace_id, expires_at);

ALTER TABLE integration_runtime.connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.connections FORCE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.oauth_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.oauth_states FORCE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.run_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.run_intents FORCE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.idempotency_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.idempotency_records FORCE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.refresh_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.refresh_leases FORCE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.transit_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_runtime.transit_files FORCE ROW LEVEL SECURITY;

CREATE POLICY connections_select ON integration_runtime.connections
  FOR SELECT USING (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND (
      visibility = 'workspace'
      OR subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
    )
  );
CREATE POLICY connections_insert ON integration_runtime.connections
  FOR INSERT WITH CHECK (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
  );
CREATE POLICY connections_update ON integration_runtime.connections
  FOR UPDATE USING (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
  ) WITH CHECK (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
  );
CREATE POLICY connections_delete ON integration_runtime.connections
  FOR DELETE USING (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
  );

CREATE POLICY oauth_states_subject_access ON integration_runtime.oauth_states
  FOR ALL USING (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
  ) WITH CHECK (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
  );
CREATE POLICY run_intents_subject_access ON integration_runtime.run_intents
  FOR ALL USING (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
  ) WITH CHECK (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
  );
CREATE POLICY idempotency_records_subject_access ON integration_runtime.idempotency_records
  FOR ALL USING (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
  ) WITH CHECK (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
  );
CREATE POLICY refresh_leases_visible_access ON integration_runtime.refresh_leases
  FOR ALL USING (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND (
      visibility = 'workspace'
      OR subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
    )
  ) WITH CHECK (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND (
      visibility = 'workspace'
      OR subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
    )
  );
CREATE POLICY transit_files_subject_access ON integration_runtime.transit_files
  FOR ALL USING (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
  ) WITH CHECK (
    tenant_id = NULLIF(current_setting('integration.tenant_id', true), '')
    AND workspace_id = NULLIF(current_setting('integration.workspace_id', true), '')
    AND subject_user_id = NULLIF(current_setting('integration.subject_user_id', true), '')
  );

REVOKE ALL ON
  integration_runtime.connections,
  integration_runtime.oauth_states,
  integration_runtime.run_intents,
  integration_runtime.idempotency_records,
  integration_runtime.refresh_leases,
  integration_runtime.transit_files
FROM PUBLIC;
