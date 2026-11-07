# OpenConnector SaaS deployment

This is an operator runbook, not an execution record. Every command below is a required deployment step; record its output and approval in the change ticket. Do not treat this document as evidence that a backup, restore drill, snapshot, migration, or deployment has run.

## Production boundary

Use `../ai-backend-marketing-agent/docker-compose.yml` with these invariants:

- `open-connector` has no published port. It joins the internal `integration-control` network and the connector-only `connector-egress` bridge.
- `integration-admin` listens on `0.0.0.0:4400` in its container but is published only as `127.0.0.1:4400:4400` and has no reverse-proxy, ngrok, or public hostname route.
- The API joins `integration-control` only to call OpenConnector. Ngrok does not join any OpenConnector network and the public API has no `/integration-console` or `/internal/integration-admin` route.
- Both services use registry references ending in `@sha256:<64 hex characters>`, run as UID/GID 1000, have read-only roots, bounded tmpfs, `no-new-privileges`, all capabilities dropped, PID/CPU/memory limits, and health checks. Do not mount a data or credential volume.
- The connector receives a dedicated renewable least-privilege OpenBao token only through the read-only `/run/secrets/open_connector_openbao_token` Compose secret. Never put that token in an environment variable, image, or persistent volume. A root token or a token that can reach forbidden OpenBao paths fails startup.
- OpenBao must be an external production service: initialized, unsealed, healthy, non-dev, and available over verified TLS. The new SaaS services neither depend on nor use the Compose `openbao`/`openbao-init` development services. Their `server -dev` and root-token behavior remains available only for the pre-existing local stack.
- `integration-admin` has no egress network. The deployment-only `INTEGRATION_ADMIN_AUTH_JWKS_URL` populates both process verifier URLs (`AUTH_JWKS_URL` and `INTERNAL_AUTH_JWKS_URL`) with the same uncredentialed backend API endpoint over `integration-control`; admin readiness fails when it is absent, unreachable, redirected, or has no usable key.
- Use distinct PostgreSQL migrator/owner and runtime roles. The connector receives only `OPEN_CONNECTOR_POSTGRES_URL`; keep `OPEN_CONNECTOR_POSTGRES_MIGRATOR_URL` in the migration job. The runtime role must not own the schema, bypass RLS, inherit an owner, create roles, or be superuser.
- Use a dedicated SeaweedFS bucket and bucket-scoped access key. The connector must not use a local transit-file directory.
- Do not configure wildcard action or proxy grants. New canaries start with action grants disabled.
- Resolve `proxy-addr` to `2.0.8` or a later patched release in `package-lock.json` ([GHSA-jqcg-44mw-7w3h](https://github.com/advisories/GHSA-jqcg-44mw-7w3h)); the MCP SDK brings it transitively through Express. Rebuild the shared connector/migration image after lockfile changes: updating host `node_modules` alone does not patch a deployed container.

Set every variable listed in the Compose file. In particular, the backend requires:

```text
OPEN_CONNECTOR_INTERNAL_URL
OPEN_CONNECTOR_JWT_ISSUER
OPEN_CONNECTOR_JWT_AUDIENCE=open-connector-saas
OPEN_CONNECTOR_JWT_ACTIVE_KID
OPEN_CONNECTOR_CONSOLE_STATIC_URL
INTEGRATION_ADMIN_LISTEN_HOST=0.0.0.0
INTEGRATION_ADMIN_PORT=4400
INTEGRATION_ADMIN_AUTH_JWKS_URL
```

The connector requires:

```text
OPEN_CONNECTOR_POSTGRES_URL
OPEN_CONNECTOR_JWKS_URL
OPEN_CONNECTOR_JWKS_BEARER_TOKEN_FILE=/run/secrets/open_connector_jwks_bearer_token
OPEN_CONNECTOR_OAUTH_CALLBACK_ORIGIN=https://api.example.com/integrations
OPEN_CONNECTOR_JWT_ISSUER
OPEN_CONNECTOR_JWT_AUDIENCE=open-connector-saas
OPEN_CONNECTOR_OPENBAO_ADDR
OPEN_CONNECTOR_OPENBAO_TOKEN_FILE=/run/secrets/open_connector_openbao_token
OPEN_CONNECTOR_SEAWEEDFS_ENDPOINT
OPEN_CONNECTOR_SEAWEEDFS_BUCKET
```

The current runtime additionally requires the active JWT key ID, a short-lived internal-service bearer token supplied only through the read-only JWKS token secret, and dedicated SeaweedFS access key ID/secret shown in `.env.example`.

The deployment operator must renew the finite JWKS bootstrap credential before its `exp` and recreate only `open-connector` with the same Compose files after atomic secret replacement. Updating the host file alone does not reload its mounted inode or the verifier's captured credential. Keep UID/GID `1000`, mode `0400`, the approved service privileges and issuer/audience; never log token values.

Every `/ready` request forces a fresh authenticated JOSE key reload and resolves the configured usable EdDSA key, bounded to three seconds. Cached keys cannot hide a rejected bootstrap credential: that state returns 503 while `/health` remains process-only. Readiness does not renew credentials; expiry monitoring and rotation remain deployment operations.

Start production by naming its service set explicitly. `open-connector` waits for the same-image `open-connector-migrate` job to complete successfully:

```bash
docker compose up -d postgres seaweedfs seaweedfs-audit omniroute api ngrok open-connector integration-admin
```

Do not use an unqualified `docker compose up` for production and do not add `openbao` or `openbao-init` to that service list. `OPEN_CONNECTOR_OPENBAO_ADDR` and the backend production `OPENBAO_ADDR` must resolve to the external TLS service. The rendered boundary check rejects the local Compose OpenBao hostname, plaintext HTTP, and the wrong token-file path.

Managed-account cleanup deletes the exact project/provider/external-user/account tuple. A `404` for this delete means already absent, including a retry after remote deletion but a failed local commit. It does not make request discovery, account reads, rejected keys or mismatched responses successful. Unverifiable tasks remain pending/manual; finish native cleanup before removing project configuration.

Managed connections use `secret_revision=0` to denote the absence of a local credential version. Lifecycle cleanup must not read that marker as a vault version; positive local versions still use the normal exact-owner secret path. The separate managed-account cleanup remains mandatory.

## Pre-deployment evidence

1. Record the current backend and connector image digests as `PRIOR_BACKEND_IMAGE` and `PRIOR_CONNECTOR_IMAGE`. Resolve the candidate tags to digests before putting them in Compose; never deploy a tag alone.
2. Render and inspect the effective model:

   ```bash
   docker compose config --format json > compose.rendered.json
   npm run stack:check
   ```

   `stack:check` must confirm zero connector publications, exactly the loopback admin publication, the exact private-network membership, connector-only egress, immutable new images, and no admin route on API/ngrok.

3. Verify the host firewall rejects inbound TCP 4400 and the server's public address refuses 3000, 4400, and every connector port. Run these checks from a separate external host, not from the server itself.
4. Verify connector `/ready` through the API/backend container on `integration-control`. Readiness must prove the PostgreSQL migration ledger and forced RLS boundary, OpenBao health and least-privilege capabilities, authenticated JWKS availability, the dedicated SeaweedFS bucket, generated provider registry, and expected catalog fingerprint. `/health` proves only that the process is alive.

## Backup and migration gate

No migration starts until both restore drills below have succeeded and their evidence is attached.

### PostgreSQL

Follow the existing backend procedure in `../ai-backend-marketing-agent/infra/postgres/backup-restore.md` to create a consistent backup and restore it into an isolated verification database. Run that document's integrity and application verification checks against the restored database. Record the backup identifier, checksum, restore target, timestamps, and verifier output.

Create a separate empty shadow database with separate migrator and runtime roles matching production privileges. Point only the migration job at it, then run:

```bash
OPEN_CONNECTOR_POSTGRES_MIGRATOR_URL="$SHADOW_MIGRATOR_URL" \
OPEN_CONNECTOR_POSTGRES_URL="$SHADOW_RUNTIME_URL" \
npm run migrate
```

`migrate` acquires the connector migration advisory lock and applies each migration transactionally. A failure blocks the deployment; do not manually skip a migration ledger entry.

Start the **prior connector image digest** against the migrated shadow database, the non-production OpenBao test namespace, the test JWKS endpoint, and the test SeaweedFS bucket. Require its readiness and the existing catalog/OAuth/read-only action checks to pass. This proves backward compatibility before production migration. Stop and remove this shadow instance after retaining its logs.

Only after that check passes, let Compose run the production migration with `docker compose run --rm open-connector-migrate`. Do not run two migration jobs concurrently.

### OpenBao

For integrated Raft storage, authenticate with an authorized snapshot operator token and take a snapshot before migration or policy changes:

```bash
bao operator raft snapshot save openbao-pre-connector.snap
sha256sum openbao-pre-connector.snap
bao operator raft snapshot inspect openbao-pre-connector.snap
```

Copy the snapshot and checksum to the approved backup location. Restore it into an isolated OpenBao recovery cluster and verify that the cluster unseals, the connector mounts exist, representative encrypted values decrypt, and the production connector policy still denies forbidden paths. Never use `snapshot restore -force` against the live cluster as a verification shortcut; use it only in the isolated restore drill according to the OpenBao recovery procedure.

If OpenBao uses external storage, do not run the Raft commands. Use that storage backend's documented consistent snapshot and isolated restore procedure, and record the same checksum, restore, decrypt, and denied-capability evidence.

## Canary and rollout

1. Deploy exactly one connector canary using the candidate immutable digest. Keep every action grant disabled.
2. Wait for readiness, then compare its generated provider registry and catalog fingerprint with the approved build artifact.
3. Through the backend/internal network, validate catalog reads, complete a test OAuth connection, and run a read-only Gmail list operation in an isolated test tenant/account. Confirm audit records contain the verified tenant, actor, subject, connection, and canary identity.
4. Enable the approved canary grants only after those checks pass. Observe readiness, error rate, audit delivery, PostgreSQL/OpenBao/SeaweedFS latency, OAuth refresh, and tenant-scope denials for the full canary window.
5. Roll out one immutable instance at a time. Stop on any readiness failure, catalog drift, cross-scope result, unexpected OpenBao capability, or action without its approval/grant.

## Management access

Create a dedicated SSH group for system administrators and apply these server-side restrictions to it:

```text
AuthenticationMethods publickey
AllowTcpForwarding local
PermitOpen 127.0.0.1:4400
GatewayPorts no
AllowAgentForwarding no
X11Forwarding no
PermitTTY no
```

Keep the host firewall closed for 4400. Administrators use only:

```bash
ssh -N -L 127.0.0.1:8443:127.0.0.1:4400 <system-admin>@<server>
```

Open `http://127.0.0.1:8443/integration-console`. Audit the SSH login and the backend-verified administrator actor/subject for every management request. Do not add an ngrok, load-balancer, ingress, or reverse-proxy route for the console or admin API.

## Rollback

Rollback means restoring `PRIOR_BACKEND_IMAGE` and `PRIOR_CONNECTOR_IMAGE` in Compose and redeploying those exact digests. Disable canary/action grants first, preserve logs and audit records, and wait for prior-image readiness before removing the failed candidate.

Do not reverse the connector database migrations during an application rollback: this plan's migrations are additive and backward-compatible, with no drop, rename, or type narrowing, and the prior-image shadow check proved that contract. Restore PostgreSQL or OpenBao only for confirmed data corruption or disaster recovery, under the applicable restore procedure and incident approval. Re-run `stack:check`, internal readiness, external port-refusal checks, catalog/OAuth/read-only Gmail checks, and audit verification after rollback.
