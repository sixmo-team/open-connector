# Native Multi-Tenant Integration Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the OpenConnector fork into a private, horizontally scalable integration data plane for `ai-backend-marketing-agent` without changing existing OpenConnector behavior, with complete tenant/workspace/user isolation, OpenBao-backed credentials, native mobile connection flows, Mastra tool execution, and a system-administrator console reachable only through an SSH tunnel.

**Architecture:** `ai-backend-marketing-agent` remains the only control plane and source of truth for identity, membership, roles, billing, approvals, connection ownership, action grants, audit, and lifecycle. The OpenConnector fork remains a separate internal container and becomes a scoped data plane: it verifies short-lived backend-issued JWTs, binds every request to tenant/workspace/subject-user context, stores runtime metadata in a dedicated PostgreSQL schema protected by forced RLS, stores credentials only in OpenBao, and executes existing provider actions. `ai-marketing-agent-user-mobile` remains the only end-user UI. The adapted OOMOL console is served by a separate backend management container whose host port is published only on server loopback, is absent from the public API/reverse proxy, and is reachable only through SSH local port forwarding plus system-administrator authentication.

**Tech Stack:** Node.js 22+, TypeScript, Hono, Zod/JSON Schema, PostgreSQL 16, `pg`, OpenBao KV/Transit, SeaweedFS S3 API, Mastra, Expo 54/React Native, React/Vite, Vitest, Docker Compose, OpenTelemetry.

## Global Constraints

- Baseline OpenConnector revision is exactly `8e6d35e9c5f09116ea090e9a5ae0a3cf92fab077` (`@oomol-lab/open-connector` 1.3.4).
- The authoritative product repositories are `../ai-backend-marketing-agent` and `../ai-marketing-agent-user-mobile`; OpenConnector must adapt to their contracts, never the reverse.
- Do not rename, repurpose, or migrate existing `ad_connections`, Yandex Direct, or VK Ads code. Add generic integration modules beside them.
- Existing Yandex Direct and VK Ads adapters, approvals, reporting, and Mastra tools remain native backend paths.
- Preserve upstream local/SQLite and Cloudflare behavior. SaaS behavior must live under new `src/saas/**` modules and a separate entrypoint.
- Treat existing OpenConnector source as protected upstream code. Implement SaaS behavior only in new `src/saas/**`, `web/src/saas/**`, separate entrypoints/configs, and additive packaging files; do not modify existing `ConnectionService`, `ActionRunner`, OAuth flow, local server, Cloudflare server, dashboard entrypoint/pages, provider definitions/executors, or existing Dockerfile.
- OpenConnector must publish no host port and accept inbound traffic only from the dedicated backend integration network. The administrative container may listen on its private container interface, but Docker must publish it only as `127.0.0.1:4400`; nginx, Caddy, Traefik, ngrok, a load balancer, public firewall rule, and public DNS must not route to it.
- Do not expose connector URLs, JWTs, aliases, IDs, `/api`, `/v1`, `/mcp`, `/docs`, or provider proxy endpoints to mobile users or browsers.
- SaaS mode must disable static runtime tokens, direct MCP execution, arbitrary provider proxy, default authenticated connections, public connector OAuth callbacks, and direct browser administration.
- Production starts only the SaaS entrypoint and separate SaaS image. The preserved upstream local/Cloudflare runtimes and original console build remain available for upstream development/tests but never run beside the SaaS runtime in production.
- Every SaaS request must derive `tenant_id`, `workspace_id`, `actor_user_id`, `subject_user_id`, role, purpose, and permissions from a verified asymmetric JWT. Caller-supplied identity headers are forbidden.
- Private connections are owner-only. Workspace-shared connections are available only to authorized members of the same workspace. Only a workspace `owner` or `admin` may change connection visibility to or from `workspace`; ordinary connection ownership is insufficient.
- Unknown actions fail closed. Tenant grants may tighten policy but may never downgrade global safety or approval classification.
- Provider side effects must never begin unless execution intent and idempotency state are durably recorded.
- Credentials, access tokens, refresh tokens, PKCE verifiers, and provider client secrets must never be stored in connector PostgreSQL, backend PostgreSQL, logs, traces, mobile storage, or action payload history.
- Connector credentials live in OpenBao. PostgreSQL stores only secret references, revisions, safe metadata, hashes, and lifecycle state.
- No plaintext secret fallback is permitted in SaaS mode. Missing PostgreSQL, JWT/JWKS, OpenBao, or encryption configuration must fail startup.
- Use the existing PostgreSQL server, OpenBao, SeaweedFS, backend outbox, Mastra, and observability stack. Do not add Redis, Nango, ACI, another workflow engine, or another secrets system.
- Do not adopt or fork `oomol-lab/connector-sdk` or `oomol-lab/connector-types` initially. Use an explicit typed HTTP facade until the scoped wire contract is stable.
- Keep upstream provider directories and generated registry/catalog mechanics unchanged wherever possible so upstream provider updates merge cleanly.
- Do not add a plugin framework. New providers continue to use `src/providers/<service>/definition.ts`, `actions.ts`, `executors.ts`, `scopes.ts`, and generated registries.
- Do not push or change Git remotes during this implementation. Keep the current official OOMOL remote and pinned local baseline; fork/`origin`/`upstream` setup is a separate future operation requiring explicit approval.
- Each task must leave its affected repository passing its focused tests before commit. Run repository-wide validation only in the final task.
- Mastra integration must use the lockfile-installed `@mastra/core` 1.46.0 behavior verified by focused tests. A Mastra upgrade is a catalog/tool-selection compatibility change and must rerun Task 20 model evals before rollout.

## Confirmed Product Decisions

- The adapted OpenConnector administrative console is system-administrator-only. Tenant users and every workspace role—including workspace `owner` and `admin`—must receive 403 and must never receive console assets or BFF data.
- Administrative console access requires two independent boundaries: an SSH local port-forward to the server loopback listener and backend system-administrator authorization. Possessing tenant/workspace credentials or discovering a URL is insufficient.
- Workspace connection sharing/unsharing is restricted to workspace `owner` and `admin`. New connections default to private.
- OAuth uses only platform-managed provider applications stored in OpenBao. Tenant-supplied OAuth client IDs/secrets and BYO OAuth application UI/API are out of scope.
- OpenConnector accesses only its dedicated OpenBao integration paths directly through a least-privilege policy. Backend never forwards provider credentials in action requests.
- The complete upstream OpenConnector provider/action catalog and all provider source directories remain intact and continue to receive upstream updates; no non-Google provider or action is deleted, excluded from generated registries, or disabled inside the connector core. Initial end-user enablement is Google-only through backend-owned provider/action allowlists: `gmail`, `googlecalendar`, `googledrive`, `googledocs`, `googlesheets`, `googleslides`, `googleforms`, `googletasks`, `googlephotos`, `googleads`, `google_analytics`, `google_search_console`, `google_bigquery`, `google_routes`, `google_address_validation`, and `youtube`. Other providers remain available in the internal catalog for later activation but are hidden from end users and non-executable until explicitly enabled. Existing native Yandex Direct/VK Ads paths remain unchanged.
- **Authoritative Mastra integration decision:** Represent connector actions as real schema-bearing Mastra `Tool` instances and discover them through the lockfile-installed native `ToolSearchProcessor` with `search: { topK: 3, autoLoad: true }`, `storage: "context"`, and request-aware filtering in all `search|load|active` phases. This is the documented Mastra large-tool-catalog pattern ([ToolSearchProcessor](https://github.com/mastra-ai/mastra/blob/main/docs/src/content/en/reference/processors/tool-search-processor.mdx), [using tools](https://github.com/mastra-ai/mastra/blob/main/docs/src/content/en/docs/agents/using-tools.mdx), [request context](https://github.com/mastra-ai/mastra/blob/main/docs/src/content/en/docs/server/request-context.mdx), [agent approval](https://github.com/mastra-ai/mastra/blob/main/docs/src/content/en/docs/agents/agent-approval.mdx)) and supersedes any generic `integration.search-actions`/`integration.execute-action`, direct MCP client, custom retrieval layer, or second tool registry proposal. Reconsider only if a lockfile-pinned Mastra upgrade removes this API or measured Task 20 evals prove it insufficient.

---

## System Invariants

1. **Backend authority:** A connector row or secret cannot create access. Access exists only when the backend resolves an active local connection under verified tenant/workspace/user membership and issues a purpose-specific JWT.
2. **No confused deputy:** Connector routes reject a token whose purpose, action, connection, subject user, or canonical request hash does not exactly match the request.
3. **Two-user rule:** Two users may use the same provider and the same human alias without collisions. Their database rows, OpenBao paths, OAuth states, idempotency records, files, and run logs remain disjoint.
4. **Admin targeting:** An administrator acts as `actor_user_id` while querying a separately authorized `subject_user_id`. The connector never chooses or widens the subject.
5. **One-time OAuth:** State is random, hashed at rest, scoped, expiring, atomically reserved, and consumed exactly once. Callback response loss is recoverable without repeating provider token exchange.
6. **Audit before effect:** Backend run intent and connector run intent exist before any provider call. If either durable write fails, execution fails without contacting the provider.
7. **Safe catalog drift:** A newly merged upstream action is invisible to agents until it has source-controlled safety classification and an explicit tenant grant.
8. **No secret observability:** Run records contain action/provider identifiers, result status, duration, input/output byte counts, safe error codes, and hashes—never raw request/response bodies or credentials.
9. **Upstream compatibility:** Local Node/SQLite and Cloudflare entrypoints retain their current APIs and tests. SaaS-specific routes and storage remain isolated.
10. **Console isolation:** Only backend-authenticated system administrators may receive the administrative HTML/assets or BFF data. Tenant identity, workspace membership, and workspace `owner`/`admin` roles never grant console access.
11. **Catalog preservation:** Provider/action availability is controlled only by backend policy and UI exposure. Never delete, stub, filter out of generated registries, or modify upstream provider/action implementations merely because they are not enabled in the current rollout.
12. **Protected upstream core:** The release gate compares protected upstream files to `.upstream-base` and fails on any product-authored change. SaaS wrappers may import stable public core functions but must not patch or fork existing runtime behavior.
13. **No Internet-facing administration:** Neither OpenConnector nor its console/BFF has public ingress. Public API and ngrok/reverse-proxy surfaces contain no admin route or console asset; SSH tunneling is the only network path to the loopback management listener.
14. **Single production runtime:** The production Compose graph starts only `start:saas`; it never starts the upstream local server, Cloudflare worker, original console, or static-token runtime beside it.
15. **Real action tools:** The model never supplies a canonical `actionId`. Each dynamically discovered Mastra tool captures one exact action ID in its executor and exposes that action's actual connector input schema plus a backend-local connection ID.
16. **Discovery is not authorization:** Tool search/load/active phases filter against a request-scoped backend policy snapshot for usability, while execution independently reloads membership, connection ownership/status, grant, classification, approval, and exact request hash.
17. **Bounded native discovery:** Connector actions are absent from the initial model tool list. `search_tools` returns at most three authorized matches, auto-loads them for the next turn, stores loaded state in tenant-scoped conversation context, and remains bounded by the server step limit and connector deadlines.

## Wire Identity Contract

Backend-issued JWT claims use snake_case on the wire and are parsed into camelCase only inside the connector:

```ts
interface ConnectorIdentityClaims {
  iss: string;
  aud: "open-connector-saas";
  sub: string;
  jti: string;
  iat: number;
  nbf: number;
  exp: number;
  tenant_id: string;
  workspace_id: string;
  actor_user_id: string;
  subject_user_id: string;
  workspace_role: "owner" | "admin" | "member" | "viewer";
  purpose:
    | "catalog:read"
    | "connection:read"
    | "connection:write"
    | "oauth:start"
    | "oauth:complete"
    | "action:search"
    | "action:execute"
    | "admin:read";
  permissions: string[];
  local_connection_id?: string;
  connector_connection_id?: string;
  oauth_session_id?: string;
  action_id?: string;
  request_hash?: string;
}
```

Rules:

- Token lifetime is at most 60 seconds; OAuth completion tokens may be 120 seconds because the backend mints them only after callback state reservation.
- `action:execute` requires exact `local_connection_id`, `connector_connection_id`, `action_id`, and SHA-256 `request_hash`.
- `oauth:start` and `oauth:complete` require exact `oauth_session_id` and local connection IDs.
- `admin:read` requires backend authorization before minting and never permits writes or execution.
- Wildcard permissions are forbidden.

## Repository Map and Ownership

| Repository                          | Owns                                                                                                                                                | Must not own                                                                                  |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `../ai-backend-marketing-agent`     | Identity, membership, local connection records, grants, safety classification, approvals, billing limits, lifecycle, audit, admin BFF, JWT issuer   | Provider tokens or connector implementation details                                           |
| `../ai-marketing-agent-user-mobile` | End-user provider catalog, connection list, OAuth browser session, credential forms, reconnect/revoke                                               | Connector URL, remote aliases, admin UI, provider tokens                                      |
| `open-connector`                    | Provider catalog/executors, scoped OAuth/token refresh, OpenBao credential access, scoped runtime state, action execution, adapted operator console | Product users, tenant provisioning, billing, invitations, chat, final authorization decisions |

## Planned File Structure

### OpenConnector fork

```text
src/saas/
  index.ts
  config.ts
  contracts.ts
  auth/saas-jwt-verifier.ts
  auth/scoped-request.ts
  server/saas-connect-server.ts
  server/saas-openapi.ts
  storage/postgres-pool.ts
  storage/scoped-query.ts
  storage/postgres-runtime-database.ts
  storage/postgres-connection-store.ts
  storage/postgres-oauth-state-store.ts
  storage/postgres-run-store.ts
  storage/postgres-idempotency-store.ts
  storage/postgres-refresh-lease-store.ts
  storage/postgres-transit-file-store.ts
  storage/migrations/0001_saas_runtime.sql
  secrets/openbao-client.ts
  secrets/openbao-connection-store.ts
  secrets/openbao-oauth-client-config-store.ts
  oauth/saas-oauth-service.ts
  connections/scoped-connection-service.ts
  actions/saas-action-runner.ts
  files/seaweedfs-transit-files.ts
  telemetry/saas-metrics.ts
scripts/saas-migrate.ts
scripts/check-upstream-base.ts
.upstream-base
scripts/check-protected-upstream.ts
web/saas.html
web/vite.saas.config.ts
web/src/saas/
  main.tsx
  admin-ui.tsx
  admin-api.ts
  admin-model.ts
  i18n.ts
  locales/en.json
  locales/ru.json
```

### Backend

```text
packages/domain/src/integration.ts
packages/runtime/src/integrations/
  index.ts
  repository.ts
  service.ts
  connector-client.ts
  connector-token-service.ts
  connector-request-hash.ts
  action-classification.ts
  action-policy.ts
  action-execution-service.ts
  reconciliation-service.ts
  admin-service.ts
apps/api/src/routes/
  integrations.ts
  integration-oauth.ts
  integration-jwks.ts
apps/integration-admin/src/
  index.ts
  app.ts
  routes.ts
  static-console.ts
infra/postgres/migrations/1785801600000_add-integration-control-plane.sql
```

### Mobile

```text
src/api/integrations.ts
src/lib/integrationOAuth.ts
src/types/integrations.ts
app/settings/connections.tsx
```

---

### Task 1: Pin the Baseline and Add an Upstream Compatibility Guard

**Files:**

- Create: `.upstream-base`
- Create: `scripts/check-upstream-base.ts`
- Create: `scripts/check-upstream-base.test.ts`
- Create: `scripts/check-protected-upstream.ts`
- Create: `scripts/check-protected-upstream.test.ts`
- Modify: `package.json`
- Create: `.github/workflows/upstream-compat.yml`

**Interfaces:**

- Consumes: the existing read-only clone at the pinned official OOMOL revision; no fork URL.
- Produces: `npm run upstream:check`, `npm run upstream:protected`, and immutable recorded baseline `8e6d35e9c5f09116ea090e9a5ae0a3cf92fab077`.

- [ ] **Step 1: Verify the source baseline without changing remotes**

Run from `open-connector`:

```bash
test "$(git remote get-url origin)" = "https://github.com/oomol-lab/open-connector.git"
test "$(git rev-parse HEAD)" = "8e6d35e9c5f09116ea090e9a5ae0a3cf92fab077"
```

Expected: the current official remote and HEAD match. Do not rename/add remotes, fetch, or push.

- [ ] **Step 2: Write the failing baseline guard test**

```ts
import { describe, expect, it } from "vitest";
import { validateUpstreamBase } from "./check-upstream-base.ts";

describe("validateUpstreamBase", () => {
  it("accepts the pinned OpenConnector baseline", () => {
    expect(validateUpstreamBase("8e6d35e9c5f09116ea090e9a5ae0a3cf92fab077")).toBe(true);
  });

  it("rejects an unreviewed baseline", () => {
    expect(validateUpstreamBase("0000000000000000000000000000000000000000")).toBe(false);
  });
});
```

The same test suite must prove that the protected-source guard rejects a modified or deleted path that existed at the baseline under `src/**`, `web/**`, `docker/**`, or `scripts/**`, while allowing additive `src/saas/**`, `web/src/saas/**`, `web/saas.html`, `web/vite.saas.config.ts`, `docker/Dockerfile.saas`, `scripts/saas-migrate.ts`, and the named SaaS/upstream guard scripts.

- [ ] **Step 3: Run the test and verify failure**

Run: `npm test -- scripts/check-upstream-base.test.ts scripts/check-protected-upstream.test.ts`

Expected: FAIL because the baseline and both guard implementations do not exist.

- [ ] **Step 4: Implement the guard and CI command**

`.upstream-base` contains exactly:

```text
8e6d35e9c5f09116ea090e9a5ae0a3cf92fab077
```

`validateUpstreamBase` trims the file value, validates a 40-character lowercase SHA, compares it to the approved value, and exits non-zero when `git merge-base --is-ancestor <base> HEAD` fails. `check-protected-upstream.ts` uses `git diff --name-status <base>...HEAD` and the baseline tree to reject modification, deletion, or rename of every path that already existed under `src/**`, `web/**`, `docker/**`, or `scripts/**`; it allows only the additive paths enumerated above. Updating `.upstream-base` is allowed only after the upstream-review procedure in Task 20. Add scripts:

```json
{
  "upstream:check": "node scripts/check-upstream-base.ts",
  "upstream:protected": "node scripts/check-protected-upstream.ts",
  "saas:verify-generated": "npm run generate:registry && git diff --exit-code -- src/providers/registry.generated.ts src/providers/registry.cloudflare.generated.ts"
}
```

The workflow runs `npm ci`, `npm run upstream:check`, `npm run upstream:protected`, `npm run saas:verify-generated`, `npm test`, and `npm run build` on pull requests and manual dispatch.

- [ ] **Step 5: Verify and commit**

Run: `npm test -- scripts/check-upstream-base.test.ts scripts/check-protected-upstream.test.ts && npm run upstream:check && npm run upstream:protected`

Expected: PASS and no source changes outside the listed files.

```bash
git add .upstream-base scripts/check-upstream-base.ts scripts/check-upstream-base.test.ts scripts/check-protected-upstream.ts scripts/check-protected-upstream.test.ts package.json .github/workflows/upstream-compat.yml
git commit -m "chore: pin upstream connector baseline"
```

---

### Task 2: Define the SaaS Wire Contracts and Canonical Request Hash

**Files:**

- Create: `src/saas/contracts.ts`
- Create: `src/saas/contracts.test.ts`
- Create: `src/saas/actions/canonical-request.ts`
- Create: `src/saas/actions/canonical-request.test.ts`
- Create: `docs/contracts/saas-runtime.openapi.yaml`

**Interfaces:**

- Produces: `ConnectorIdentityClaims`, `SaasRequestScope`, `SaasPurpose`, `canonicalActionRequestHash()` and the authoritative internal HTTP contract.
- Consumes: none.

- [ ] **Step 1: Write failing claim and hash tests**

```ts
it("rejects an execute token without exact connection, action, and request hash", () => {
  expect(() => parseConnectorIdentityClaims({ ...validClaims, purpose: "action:execute" })).toThrow(
    "action:execute claims are incomplete",
  );
});

it("hashes object keys deterministically", () => {
  expect(canonicalActionRequestHash("gmail.messages_list", "c1", { b: 2, a: 1 })).toBe(
    canonicalActionRequestHash("gmail.messages_list", "c1", { a: 1, b: 2 }),
  );
});
```

- [ ] **Step 2: Verify failure**

Run: `npm test -- src/saas/contracts.test.ts src/saas/actions/canonical-request.test.ts`

Expected: FAIL because the modules do not exist.

- [ ] **Step 3: Implement exact contracts**

Use Zod schemas with `.strict()` and the wire claim names defined in this plan. Canonicalize JSON recursively by sorting object keys, preserving array order, rejecting non-finite numbers and objects deeper than the existing action input depth limit, then hash this envelope:

```ts
interface CanonicalActionEnvelope {
  actionId: string;
  connectorConnectionId: string;
  input: unknown;
}
```

The OpenAPI document defines only internal SaaS routes:

```text
GET    /internal/saas/catalog/providers
GET    /internal/saas/catalog/actions/search
GET    /internal/saas/catalog/actions
GET    /internal/saas/connections
POST   /internal/saas/connections/credentials
DELETE /internal/saas/connections/{connectionId}
POST   /internal/saas/oauth/start
POST   /internal/saas/oauth/complete
POST   /internal/saas/actions/{actionId}
GET    /internal/saas/runs
GET    /internal/saas/runs/{executionId}
```

Every operation requires bearer auth and declares its exact `purpose` value.

- [ ] **Step 4: Verify contract behavior**

Run: `npm test -- src/saas/contracts.test.ts src/saas/actions/canonical-request.test.ts`

Expected: PASS for deterministic hashing, strict claims, purpose-specific fields, expiry bounds, and wildcard permission rejection.

- [ ] **Step 5: Commit**

```bash
git add src/saas/contracts.ts src/saas/contracts.test.ts src/saas/actions/canonical-request.ts src/saas/actions/canonical-request.test.ts docs/contracts/saas-runtime.openapi.yaml
git commit -m "feat: define scoped connector wire contracts"
```

---

### Task 3: Add the Backend Generic Integration Control-Plane Schema

**Files:**

- Create: `../ai-backend-marketing-agent/infra/postgres/migrations/1785801600000_add-integration-control-plane.sql`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/db/schema/index.ts`
- Create: `../ai-backend-marketing-agent/packages/domain/src/integration.ts`
- Modify: `../ai-backend-marketing-agent/packages/domain/src/index.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/src/integrations/repository.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/src/integrations/index.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/test/integration-repository.test.ts`

**Interfaces:**

- Produces: `IntegrationConnectionRepository`, `IntegrationConnectionRecord`, `IntegrationOAuthSessionRecord`, `IntegrationActionGrant`, `IntegrationActionRun`.
- Preserves: all existing `ad_connections` tables and APIs unchanged.

- [ ] **Step 1: Write failing two-tenant repository tests**

```ts
it("does not resolve another tenant's integration connection", async () => {
  const tenantA = crypto.randomUUID();
  const tenantB = crypto.randomUUID();
  const connection = await repository.createConnection(scope(tenantA), newConnection());

  await expect(repository.getConnection(scope(tenantB), connection.id)).resolves.toBeNull();
});

it("allows identical providers and display aliases for different users", async () => {
  const first = await repository.createConnection(userScope("u1"), gmailConnection("work"));
  const second = await repository.createConnection(userScope("u2"), gmailConnection("work"));
  expect(first.id).not.toBe(second.id);
});
```

- [ ] **Step 2: Verify failure**

Run from `../ai-backend-marketing-agent`:

```bash
npm test -- packages/runtime/test/integration-repository.test.ts
```

Expected: FAIL because the schema and repository do not exist.

- [ ] **Step 3: Create the schema and domain types**

Create `app.integration_connections` with UUID primary key and these non-null ownership fields:

```text
tenant_id
workspace_id
owner_user_id
visibility: user | workspace
provider_id
connector_connection_id
connector_alias
auth_type
status: pending | active | expired | revoked | failed | reconnect_required
created_by_user_id
created_at
updated_at
```

Safe optional metadata:

```text
display_name
provider_account_id
granted_scopes jsonb
last_verified_at
revoked_at
```

Create:

- `app.integration_oauth_sessions`: local connection, state hash, status `pending|reserved|completed|failed|expired`, expiry, reservation lease, fixed return target, callback result fingerprint.
- `app.integration_action_grants`: tenant/workspace/action exact ID, enabled flag, `approval_override` limited to `inherit|always`, created/updated actor.
- `app.integration_action_runs`: actor and subject user, local connection, provider/action, connector execution ID, status, duration, input/output byte counts, request hash, idempotency hash, safe error code; no raw input/output.

Add foreign keys to existing tenant/workspace/user tables, tenant-leading indexes, and uniqueness on `(tenant_id, workspace_id, connector_connection_id)` and `(tenant_id, workspace_id, provider_id, connector_alias)`.

- [ ] **Step 4: Implement repository methods with mandatory scopes**

```ts
interface IntegrationConnectionScope {
  tenantId: string;
  workspaceId: string;
  actorUserId: string;
  subjectUserId: string;
}

interface IntegrationConnectionRepository {
  createConnection(
    scope: IntegrationConnectionScope,
    input: CreateIntegrationConnection,
  ): Promise<IntegrationConnectionRecord>;
  getConnection(scope: IntegrationConnectionScope, id: string): Promise<IntegrationConnectionRecord | null>;
  listAccessibleConnections(scope: IntegrationConnectionScope): Promise<IntegrationConnectionRecord[]>;
  reserveOAuthSessionByStateHash(
    stateHash: string,
    reservationId: string,
    now: Date,
  ): Promise<IntegrationOAuthSessionRecord | null>;
  completeOAuthSession(scope: IntegrationConnectionScope, sessionId: string, resultFingerprint: string): Promise<void>;
}
```

Every business-object SQL statement includes tenant and workspace. User-visible reads add `(owner_user_id = subject OR visibility = 'workspace')`. The sole scope-bootstrap query is the unauthenticated OAuth callback's atomic reservation by a unique 256-bit state hash; it accepts no tenant/user values, requires `pending` plus unexpired state, writes a reservation ID/lease, and returns the authoritative stored scope for immediate membership and connection revalidation.

- [ ] **Step 5: Verify migration and commit**

Run:

```bash
npm run db:migrate:up:dry-run
npm test -- packages/runtime/test/integration-repository.test.ts
npm run check
```

Expected: migration dry run succeeds; all focused tests pass.

```bash
git add infra/postgres/migrations/1785801600000_add-integration-control-plane.sql packages/runtime/src/db/schema/index.ts packages/domain/src/integration.ts packages/domain/src/index.ts packages/runtime/src/integrations/repository.ts packages/runtime/src/integrations/index.ts packages/runtime/test/integration-repository.test.ts
git commit -m "feat: add tenant-scoped integration control plane"
```

---

### Task 4: Issue Backend-Authoritative Connector JWTs and JWKS

**Files:**

- Create: `../ai-backend-marketing-agent/packages/runtime/src/integrations/connector-request-hash.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/src/integrations/connector-token-service.ts`
- Create: `../ai-backend-marketing-agent/apps/api/src/routes/integration-jwks.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/openbao/client.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/config/app-env.ts`
- Modify: `../ai-backend-marketing-agent/apps/api/src/app.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/test/connector-token-service.test.ts`
- Create: `../ai-backend-marketing-agent/apps/api/test/integration-jwks.test.ts`

**Interfaces:**

- Consumes: verified backend tenant/workspace/membership context and OpenBao.
- Produces: `ConnectorTokenService.issue(input)` and internal JWKS endpoint.

- [ ] **Step 1: Write failing claim-binding tests**

```ts
it("binds execute tokens to exact subject, connection, action, and body hash", async () => {
  const token = await service.issue({
    scope,
    purpose: "action:execute",
    permissions: ["action:execute"],
    localConnectionId,
    connectorConnectionId,
    actionId: "gmail.messages_list",
    requestHash,
  });
  const claims = await verify(token);
  expect(claims).toMatchObject({
    tenant_id: scope.tenantId,
    workspace_id: scope.workspaceId,
    actor_user_id: scope.actorUserId,
    subject_user_id: scope.subjectUserId,
    action_id: "gmail.messages_list",
    request_hash: requestHash,
  });
});
```

Also test maximum lifetime, `kid`, audience, mismatched purpose fields, and rejection of caller-supplied tenant overrides.

- [ ] **Step 2: Verify failure**

Run:

```bash
npm test -- packages/runtime/test/connector-token-service.test.ts apps/api/test/integration-jwks.test.ts
```

Expected: FAIL because issuer and route do not exist.

- [ ] **Step 3: Add OpenBao signing-key paths and issuer**

Add service-secret paths under:

```text
service-secrets/data/integration-connector/signing-keys/{kid}
```

Store Ed25519 private JWK plus status `active|verification_only`. JWKS returns public keys only. `ConnectorTokenService` uses `jose`, sets 60-second expiry by default, includes `jti`, and accepts only a fully resolved `IntegrationExecutionScope`; it never accepts raw HTTP identity headers.

- [ ] **Step 4: Register internal JWKS route**

Expose `GET /internal/integrations/.well-known/jwks.json` only on the existing internal surface. Return cache headers short enough for key rotation and include active plus verification-only public keys.

- [ ] **Step 5: Verify and commit**

Run:

```bash
npm test -- packages/runtime/test/connector-token-service.test.ts apps/api/test/integration-jwks.test.ts
npm run check
```

```bash
git add packages/runtime/src/integrations/connector-request-hash.ts packages/runtime/src/integrations/connector-token-service.ts apps/api/src/routes/integration-jwks.ts packages/runtime/src/openbao/client.ts packages/runtime/src/config/app-env.ts apps/api/src/app.ts packages/runtime/test/connector-token-service.test.ts apps/api/test/integration-jwks.test.ts
git commit -m "feat: issue scoped connector execution tokens"
```

---

### Task 5: Add a Fail-Closed SaaS Entrypoint and JWT Scope Verification

**Files:**

- Create: `src/saas/config.ts`
- Create: `src/saas/auth/saas-jwt-verifier.ts`
- Create: `src/saas/auth/scoped-request.ts`
- Create: `src/saas/server/saas-connect-server.ts`
- Create: `src/saas/index.ts`
- Create: `src/saas/auth/saas-jwt-verifier.test.ts`
- Create: `src/saas/server/saas-connect-server.test.ts`
- Modify: `package.json`
- Create: `docker/Dockerfile.saas`

**Interfaces:**

- Consumes: Task 2 wire claims and Task 4 JWKS.
- Produces: separate `npm run start:saas` entrypoint; `getSaasRequestScope(context, expectedPurpose)`.

- [ ] **Step 1: Write failing startup and authorization tests**

Test that SaaS startup rejects missing PostgreSQL URL, OpenBao address/token, JWKS URL, issuer, audience, and SeaweedFS configuration. Test that `/api`, `/v1/proxy`, `/mcp`, direct `/oauth/callback`, and static runtime-token authentication return 404 or 403 in SaaS mode.

```ts
it("rejects a valid JWT minted for the wrong purpose", async () => {
  const response = await app.request("/internal/saas/connections", {
    headers: { authorization: `Bearer ${tokenFor("action:execute")}` },
  });
  expect(response.status).toBe(403);
});
```

- [ ] **Step 2: Verify failure**

Run: `npm test -- src/saas/auth/saas-jwt-verifier.test.ts src/saas/server/saas-connect-server.test.ts`

Expected: FAIL because SaaS modules do not exist.

- [ ] **Step 3: Implement strict configuration and verification**

Use `createRemoteJWKSet`/`jwtVerify`. Require exact issuer, audience, `alg`, current `kid`, `nbf`, `exp`, purpose, permissions, and purpose-specific binding fields. Parse claims with Task 2 Zod schema. Return generic `unauthorized`/`forbidden` responses without leaking which claim failed.

- [ ] **Step 4: Build a separate route surface**

`SaasConnectServer` registers only `/health`, `/ready`, `/internal/saas/**`, and console static assets on its private container listener. It reuses the upstream catalog/provider loader/action metadata but does not instantiate local auth, runtime tokens, provider proxy, direct MCP, or public OAuth callback routes. No host or public reverse-proxy route may target this listener.

Add scripts:

```json
{
  "start:saas": "node src/saas/index.ts",
  "test:saas": "vitest run src/saas"
}
```

- [ ] **Step 5: Verify and commit**

Run: `npm test -- src/saas/auth/saas-jwt-verifier.test.ts src/saas/server/saas-connect-server.test.ts && npm run build`

```bash
git add src/saas package.json docker/Dockerfile.saas
git commit -m "feat: add fail-closed SaaS connector entrypoint"
```

---

### Task 6: Add PostgreSQL Runtime Schema with Forced RLS

**Files:**

- Create: `src/saas/storage/migrations/0001_saas_runtime.sql`
- Create: `src/saas/storage/postgres-pool.ts`
- Create: `src/saas/storage/scoped-query.ts`
- Create: `src/saas/storage/postgres-migrator.ts`
- Create: `scripts/saas-migrate.ts`
- Create: `src/saas/storage/scoped-query.test.ts`
- Modify: `package.json`

**Interfaces:**

- Produces: `withScopedClient(pool, scope, fn)` and schema `integration_runtime`.
- Consumes: `SaasRequestScope`.

- [ ] **Step 1: Write failing cross-scope RLS tests**

Using the backend development PostgreSQL instance, insert two tenants with identical provider and alias. Set scope for tenant A and assert tenant B rows cannot be selected, updated, or deleted. Repeat for two users in one workspace with private and workspace-shared visibility.

- [ ] **Step 2: Verify failure**

Run:

```bash
TEST_POSTGRES_URL="$POSTGRES_URL" npm test -- src/saas/storage/scoped-query.test.ts
```

Expected: FAIL because schema and scoped client do not exist.

- [ ] **Step 3: Create schema and policies**

Create tables:

```text
connections
oauth_states
run_intents
idempotency_records
refresh_leases
transit_files
```

All rows include `tenant_id`, `workspace_id`, and relevant `subject_user_id`/visibility. Use `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY`. Policies read scope from transaction-local settings:

```sql
current_setting('integration.tenant_id', true)
current_setting('integration.workspace_id', true)
current_setting('integration.subject_user_id', true)
```

The runtime role must not own tables and must not have `BYPASSRLS`. Migrations use a separate migrator role.

- [ ] **Step 4: Implement transaction-scoped access**

`withScopedClient` opens a transaction, calls `set_config(..., true)` using parameters, executes the callback, commits, and always rolls back on error. Never use session-level `SET` on a pooled connection.

Add `pg` and `@types/pg`, plus:

```json
{
  "saas:migrate": "node scripts/saas-migrate.ts"
}
```

- [ ] **Step 5: Verify and commit**

Run:

```bash
npm run saas:migrate
TEST_POSTGRES_URL="$POSTGRES_URL" npm test -- src/saas/storage/scoped-query.test.ts
```

```bash
git add src/saas/storage scripts/saas-migrate.ts package.json package-lock.json
git commit -m "feat: add RLS-protected connector runtime storage"
```

---

### Task 7: Bind Upstream Runtime Stores to an Immutable SaaS Scope

**Files:**

- Create: `src/saas/storage/postgres-runtime-database.ts`
- Create: `src/saas/storage/postgres-connection-store.ts`
- Create: `src/saas/storage/postgres-oauth-state-store.ts`
- Create: `src/saas/storage/postgres-run-store.ts`
- Create: `src/saas/storage/postgres-idempotency-store.ts`
- Create: `src/saas/storage/postgres-runtime-database.test.ts`
- Modify: `src/saas/server/saas-connect-server.ts`

**Interfaces:**

- Produces: `SaasRuntimeDatabaseFactory.forScope(scope)` returning upstream-compatible stores already bound to one immutable scope.
- Preserves: upstream `IConnectionStore`, `IOAuthStateStore`, `IRunLogStore`, and `IIdempotencyStore` signatures for local/Cloudflare modes.

- [ ] **Step 1: Write failing bound-store tests**

```ts
it("binds identical upstream store calls to different tenants", async () => {
  const storeA = factory.forScope(scopeA).connectionStore;
  const storeB = factory.forScope(scopeB).connectionStore;
  await storeA.set("gmail", "work", credentialA);
  await storeB.set("gmail", "work", credentialB);
  expect((await storeA.get("gmail", "work"))?.id).not.toBe((await storeB.get("gmail", "work"))?.id);
});
```

Also assert private/user and shared/workspace visibility rules and that list operations never return a global list.

- [ ] **Step 2: Verify failure**

Run: `TEST_POSTGRES_URL="$POSTGRES_URL" npm test -- src/saas/storage/postgres-runtime-database.test.ts`

Expected: FAIL because factory and stores do not exist.

- [ ] **Step 3: Implement scoped adapters**

Each adapter captures a frozen `SaasRequestScope`. Its methods call `withScopedClient`; no method accepts alternate tenant/user identifiers. Connection uniqueness is `(tenant, workspace, service, connection_name)`. Disable authenticated `default` aliases in SaaS mode; backend always supplies the opaque alias derived from local connection UUID.

- [ ] **Step 4: Instantiate per request**

The SaaS server verifies JWT first, obtains scope, then resolves a lightweight runtime bundle sharing only immutable catalog, provider loader, PostgreSQL pool, and OpenBao client. Never cache a scoped service across requests.

- [ ] **Step 5: Verify and commit**

Run: `TEST_POSTGRES_URL="$POSTGRES_URL" npm test -- src/saas/storage/postgres-runtime-database.test.ts && npm run build`

```bash
git add src/saas/storage src/saas/server/saas-connect-server.ts
git commit -m "feat: bind connector runtime stores to request scope"
```

---

### Task 8: Store Connector Credentials and OAuth Client Secrets in OpenBao

**Files:**

- Create: `src/saas/secrets/openbao-client.ts`
- Create: `src/saas/secrets/openbao-connection-store.ts`
- Create: `src/saas/secrets/openbao-oauth-client-config-store.ts`
- Create: `src/saas/secrets/openbao-oauth-state-secret-store.ts`
- Create: `src/saas/secrets/openbao-connection-store.test.ts`
- Create: `src/saas/secrets/openbao-oauth-state-secret-store.test.ts`
- Modify: `src/saas/storage/postgres-connection-store.ts`
- Modify: `src/saas/config.ts`

**Interfaces:**

- Produces: `OpenBaoConnectionSecretStore`, `OpenBaoOAuthClientConfigStore`, `OpenBaoOAuthStateSecretStore`.
- Consumes: dedicated least-privilege OpenBao token and scoped PostgreSQL metadata.

- [ ] **Step 1: Write failing no-plaintext and CAS tests**

Test that a stored OAuth credential appears in fake OpenBao under the exact scoped path while PostgreSQL contains only `secret_ref` and `secret_revision`. Assert database text does not contain access token, refresh token, API key, client secret, raw OAuth state, or PKCE verifier. Test stale revision update rejection and one-time OAuth-state secret deletion.

- [ ] **Step 2: Verify failure**

Run: `npm test -- src/saas/secrets/openbao-connection-store.test.ts src/saas/secrets/openbao-oauth-state-secret-store.test.ts`

Expected: FAIL because OpenBao stores do not exist.

- [ ] **Step 3: Implement exact secret paths and CAS**

Connection credentials:

```text
client-secrets/data/tenants/{tenantId}/workspaces/{workspaceId}/integrations/connections/{connectionId}
```

Ephemeral OAuth state secrets:

```text
client-secrets/data/tenants/{tenantId}/workspaces/{workspaceId}/integrations/oauth-sessions/{oauthSessionId}
```

Global platform OAuth applications:

```text
service-secrets/data/integration-provider-applications/{providerId}
```

Use OpenBao KV v2 CAS. Credential records include provider, auth type, value, created/updated timestamps, and revision. OAuth session secrets contain only the PKCE verifier and expire/delete after one successful `take`; PostgreSQL contains the state hash, secret reference, and expiry. OAuth client configuration is global platform configuration only; expose no tenant override. OpenConnector reads/writes only these dedicated paths directly, and backend never transports provider secrets. Never log response bodies. A failed PostgreSQL metadata write after a secret write triggers best-effort secret cleanup plus a reconciliation marker.

- [ ] **Step 4: Fail closed and apply least privilege**

SaaS startup checks OpenBao health and verifies read/write/delete only under the integration paths. A missing token, unavailable OpenBao, absent provider application secret, or unencrypted secret path fails the operation before provider execution.

- [ ] **Step 5: Verify and commit**

Run: `npm test -- src/saas/secrets/openbao-connection-store.test.ts src/saas/secrets/openbao-oauth-state-secret-store.test.ts && npm run build`

```bash
git add src/saas/secrets src/saas/storage/postgres-connection-store.ts src/saas/config.ts
git commit -m "feat: store scoped connector credentials in OpenBao"
```

---

### Task 9: Implement One-Time Scoped OAuth and Native Mobile Return

**Files:**

- Create: `src/saas/oauth/saas-oauth-service.ts`
- Create: `src/saas/oauth/saas-oauth-service.test.ts`
- Modify: `src/saas/server/saas-connect-server.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/src/integrations/service.ts`
- Create: `../ai-backend-marketing-agent/apps/api/src/routes/integration-oauth.ts`
- Create: `../ai-backend-marketing-agent/apps/api/test/integration-oauth.test.ts`

**Interfaces:**

- Produces: backend-only OAuth start/callback/reconnect flow and safe mobile redirect.
- Consumes: local connection record, scoped connector JWT, OpenBao provider application secrets.

- [ ] **Step 1: Write failing replay, expiry, mismatch, and response-loss tests**

Cover:

- tenant A callback cannot complete tenant B state;
- user A cannot complete user B private connection;
- expired state is rejected;
- a consumed state cannot exchange the code again;
- provider or connection mismatch is rejected;
- connector completion succeeds but backend response loss can be reconciled without another token exchange;
- return URL is selected from server configuration, never callback input.

- [ ] **Step 2: Verify failure in both repositories**

Run:

```bash
npm test -- src/saas/oauth/saas-oauth-service.test.ts
```

Then from backend:

```bash
npm test -- apps/api/test/integration-oauth.test.ts
```

Expected: FAIL because scoped OAuth flow does not exist.

- [ ] **Step 3: Reuse the upstream OAuth flow through SaaS-bound stores and origin**

Instantiate the existing `OAuthFlowService` unchanged with the SaaS connection store, the scoped OAuth state store, and `OAuthClientConfigService.origin` set to the backend's public callback origin. The SaaS state store writes only a state hash to PostgreSQL, keeps the PKCE verifier only in the scoped OpenBao OAuth-session secret, and binds tenant/workspace/subject/local connection/provider/expiry. This preserves the existing redirect URI calculation while keeping the connector callback private.

- [ ] **Step 4: Implement backend-owned browser flow**

Public mobile flow:

```text
POST /integrations/connections/{provider}/oauth/start
GET  /integrations/oauth/callback
```

Start creates a pending local UUID, derives an opaque connector alias from that UUID, mints `oauth:start`, calls connector, stores connector state hash, and returns `{ connectionId, authorizeUrl }`.

Callback atomically reserves backend state, mints `oauth:complete`, calls internal connector completion, activates the local connection, then redirects only to the configured Expo deep link with `{connectionId,status}`. Connector callback is not public.

- [ ] **Step 5: Verify and commit each repository**

Run focused tests in both repositories. Commit connector changes:

```bash
git add src/saas/oauth src/saas/server/saas-connect-server.ts
git commit -m "feat: add scoped one-time OAuth completion"
```

Commit backend changes:

```bash
git add packages/runtime/src/integrations/service.ts apps/api/src/routes/integration-oauth.ts apps/api/test/integration-oauth.test.ts
git commit -m "feat: bridge mobile OAuth through backend"
```

---

### Task 10: Add Generic Backend Connection APIs and Safe Catalog Forms

**Files:**

- Create: `../ai-backend-marketing-agent/packages/runtime/src/integrations/connector-client.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/service.ts`
- Create: `../ai-backend-marketing-agent/apps/api/src/routes/integrations.ts`
- Modify: `../ai-backend-marketing-agent/apps/api/src/app.ts`
- Create: `../ai-backend-marketing-agent/apps/api/test/integrations.test.ts`

**Interfaces:**

- Produces: end-user REST endpoints and `OpenConnectorClient` typed from Task 2 contract.
- Consumes: existing tenant middleware, membership checks, access limits, integration repository, connector token service.

- [ ] **Step 1: Write failing API tests**

Test that the connector's internal catalog still contains non-Google providers/actions while the end-user provider response exposes only the current Google allowlist. Also test list, details, reconnect, revoke, multiple Gmail accounts, private/shared visibility, foreign tenant 404 behavior, role checks, plan limits, and absence of remote alias/token fields. Assert only workspace `owner`/`admin` may change visibility; ordinary connection owners, members, and viewers receive 403. Assert no tenant OAuth client configuration endpoint or field exists.

- [ ] **Step 2: Verify failure**

Run: `npm test -- apps/api/test/integrations.test.ts`

Expected: FAIL because routes/client do not exist.

- [ ] **Step 3: Implement the typed internal client**

`OpenConnectorClient` methods require an already minted token and use fixed configured base URL:

```ts
interface OpenConnectorClient {
  listProviders(token: string): Promise<SafeProviderCatalog[]>;
  listActions(token: string, cursor?: string): Promise<SafeActionCatalogPage>;
  searchActions(token: string, query: string): Promise<SafeActionSummary[]>;
  putCredential(token: string, input: ConnectorCredentialInput): Promise<SafeConnectionSummary>;
  revokeConnection(token: string, connectorConnectionId: string): Promise<void>;
  executeAction(token: string, input: ConnectorActionRequest, idempotencyKey: string): Promise<ConnectorActionResult>;
}
```

No method accepts an arbitrary host or path. Apply request/response byte limits and timeouts. Redact connector error details before public responses. `listActions` is paginated, backend-only, and returns the complete action input/output schemas plus catalog fingerprint required to build the immutable Mastra registry; it is never exposed to mobile or browsers.

- [ ] **Step 4: Implement public routes**

```text
GET    /integrations/providers
GET    /integrations/connections
GET    /integrations/connections/{id}
POST   /integrations/connections/{provider}/oauth/start
POST   /integrations/connections/{provider}/credentials
POST   /integrations/connections/{id}/reconnect
DELETE /integrations/connections/{id}
PATCH  /integrations/connections/{id}/visibility
```

`GET /integrations/connections` returns normalized native Yandex/VK plus allowlisted Google connector connections with `executionKind: native|connector`; existing ad-connection routes remain unchanged. The visibility route accepts only `user|workspace`, defaults new records to `user`, and requires workspace `owner`/`admin`. OAuth forms use platform applications from OpenBao and never expose OAuth client configuration fields. Credential forms return only safe field metadata. Backend never persists submitted credential values.
When the existing backend integration feature is disabled, the new provider/connection routes expose no connector providers and every pre-existing Yandex Direct/VK Ads connection response, route, and behavior is byte-for-byte compatible. Enable connector providers only for an explicit canary tenant after Task 20 passes.

- [ ] **Step 5: Verify and commit**

Run: `npm test -- apps/api/test/integrations.test.ts && npm run check`

```bash
git add packages/runtime/src/integrations apps/api/src/routes/integrations.ts apps/api/src/app.ts apps/api/test/integrations.test.ts
git commit -m "feat: expose tenant-scoped integration connections"
```

---

### Task 11: Render Provider Connections Entirely in the Mobile App

**Files:**

- Create: `../ai-marketing-agent-user-mobile/src/types/integrations.ts`
- Create: `../ai-marketing-agent-user-mobile/src/api/integrations.ts`
- Create: `../ai-marketing-agent-user-mobile/src/lib/integrationOAuth.ts`
- Modify: `../ai-marketing-agent-user-mobile/app/settings/connections.tsx`
- Create: `../ai-marketing-agent-user-mobile/tests/api/integrations.test.ts`
- Create: `../ai-marketing-agent-user-mobile/tests/lib/integrationOAuth.test.ts`

**Interfaces:**

- Produces: native Google provider search, multiple-account list, OAuth/API-key/custom credential connection, reconnect, revoke, and owner/admin-only visibility management.
- Consumes: Task 10 backend endpoints only.

- [ ] **Step 1: Write failing API and OAuth-return tests**

Test that requests carry bearer plus `x-workspace-id`, remote connector fields are not represented in mobile types, mobile deep-link completion parses `{connectionId,status}`, two accounts of one provider render independently, and visibility controls render only when backend returns `canManageVisibility: true`.

- [ ] **Step 2: Verify failure**

Run from mobile repo:

```bash
npm exec vitest run tests/api/integrations.test.ts tests/lib/integrationOAuth.test.ts
```

Expected: FAIL because modules do not exist.

- [ ] **Step 3: Implement typed mobile API**

Use existing `apiClient` and React Query patterns. Public types include only:

```ts
interface IntegrationConnection {
  id: string;
  providerId: string;
  providerDisplayName: string;
  executionKind: "native" | "connector";
  visibility: "user" | "workspace";
  ownerUserId: string;
  displayName: string;
  status: string;
  grantedScopes: string[];
  canManageVisibility: boolean;
}
```

- [ ] **Step 4: Adapt the existing connections screen**

Reuse current cards, `WebBrowser.openAuthSessionAsync`, `Linking.createURL("oauth/connected")`, confirmation dialog, reconnect/revoke mutations, and theme. Show only the allowlisted Google ecosystem providers. Add provider search and schema-driven forms for supported API key/custom credential fields. Secret fields use password inputs and are cleared immediately after submission. Show private/workspace visibility controls only when `canManageVisibility` is true; backend remains authoritative. The screen never opens or links to the OOMOL console.

- [ ] **Step 5: Verify and commit**

Run:

```bash
npm exec vitest run tests/api/integrations.test.ts tests/lib/integrationOAuth.test.ts tests/lib/oauthReturn.test.ts
npm run lint
```

```bash
git add src/types/integrations.ts src/api/integrations.ts src/lib/integrationOAuth.ts app/settings/connections.tsx tests/api/integrations.test.ts tests/lib/integrationOAuth.test.ts
git commit -m "feat: add native multi-account integration UI"
```

---

### Task 12: Add Distributed Refresh Leases and SeaweedFS Transit Files

**Files:**

- Create: `src/saas/storage/postgres-refresh-lease-store.ts`
- Create: `src/saas/connections/scoped-connection-service.ts`
- Create: `src/saas/connections/scoped-connection-service.test.ts`
- Create: `src/saas/oauth/postgres-refresh-coordinator.ts`
- Create: `src/saas/oauth/postgres-refresh-coordinator.test.ts`
- Create: `src/saas/files/seaweedfs-transit-files.ts`
- Create: `src/saas/files/seaweedfs-transit-files.test.ts`
- Modify: `src/saas/storage/postgres-runtime-database.ts`
- Modify: `package.json`

**Interfaces:**

- Produces: SaaS-only `ScopedConnectionService` with PostgreSQL refresh coordination and a scoped S3-compatible transit file service.
- Preserves: existing `src/connection-service.ts` and its tests byte-for-byte.

- [ ] **Step 1: Write failing concurrent refresh tests**

Create two service instances sharing PostgreSQL and one expired credential. Run concurrent `getCredential`; assert one provider refresh call, one CAS update, both callers receive the same revision, and lease expiry permits recovery after a crashed holder.

- [ ] **Step 2: Write failing transit isolation tests**

Assert tenant A cannot read/delete tenant B file even with its file ID. Assert object keys include tenant/workspace/random UUID but no user filenames or emails. Assert PostgreSQL metadata is removed after successful S3 deletion and reconciliation marker remains after partial failure.

- [ ] **Step 3: Verify failures**

Run: `npm test -- src/saas/oauth/postgres-refresh-coordinator.test.ts src/saas/files/seaweedfs-transit-files.test.ts`

- [ ] **Step 4: Implement coordinators and S3 adapter**

Implement refresh coordination entirely in `src/saas/**`. `ScopedConnectionService` acquires the PostgreSQL lease for the scoped connection before delegating credential resolution to an unmodified upstream `ConnectionService`, reloads credential state under the lease, and releases it in `finally`. Serializing every credential resolution per connection is the deliberate safe first implementation; optimize to preflight expiry only after measurement. Add `@aws-sdk/client-s3` and use existing SeaweedFS endpoint/bucket credentials. Store only safe file metadata in RLS-protected PostgreSQL.

- [ ] **Step 5: Verify and commit**

Run focused SaaS tests, then run `npm test -- src/connection-service.test.ts` as an unchanged-upstream regression check.

```bash
git add src/saas/storage/postgres-refresh-lease-store.ts src/saas/connections src/saas/oauth src/saas/files src/saas/storage/postgres-runtime-database.ts package.json package-lock.json
git commit -m "feat: coordinate refresh and transit files across replicas"
```

---

### Task 13: Persist Audit Intent Before Provider Side Effects

**Files:**

- Create: `src/saas/actions/saas-action-runner.ts`
- Create: `src/saas/actions/saas-action-runner.test.ts`
- Modify: `src/saas/storage/postgres-run-store.ts`
- Modify: `src/saas/storage/postgres-idempotency-store.ts`
- Modify: `src/saas/server/saas-connect-server.ts`

**Interfaces:**

- Produces: SaaS-only `ExecutionJournal.start()`, `ExecutionJournal.complete()`, `ExecutionJournal.fail()` and audit-first execution.
- Preserves: existing `src/server/actions/action-runner.ts` and its tests byte-for-byte.

- [ ] **Step 1: Write the provider-not-called test**

```ts
it("does not call provider when durable run intent fails", async () => {
  journal.start.mockRejectedValue(new Error("postgres unavailable"));
  const result = await runner.run(request);
  expect(providerExecutor).not.toHaveBeenCalled();
  expect(result.ok).toBe(false);
});
```

Also test exact request-hash claim/body match, tenant-partitioned idempotency, replay result, conflict, safe error redaction, and byte metrics.

- [ ] **Step 2: Verify failure**

Run: `npm test -- src/saas/actions/saas-action-runner.test.ts`

Expected: FAIL because the isolated SaaS runner does not exist.

- [ ] **Step 3: Implement a separate SaaS execution boundary**

Use the existing pure `core/execution.ts` provider execution function, catalog, provider loader, and the SaaS scoped connection facade. Do not call or modify the upstream HTTP/MCP `ActionRunner`. Before provider execution:

1. verify action ID and connection provider;
2. recompute canonical request hash and compare token claim;
3. claim scoped idempotency key;
4. durably insert run intent;
5. only then call provider executor.

After execution, persist status, duration, byte counts, safe error code, and provider request count when available. No raw input/output storage.

- [ ] **Step 4: Ensure recovery semantics**

If provider succeeds but completion persistence fails, return a retryable reconciliation error while retaining the in-progress run and idempotency claim. A retry must read the existing record rather than repeat a known completed provider effect; non-idempotent actions remain blocked for operator reconciliation when completion is unknown.

- [ ] **Step 5: Verify and commit**

Run focused tests and `npm run build`.

```bash
git add src/saas/actions src/saas/storage/postgres-run-store.ts src/saas/storage/postgres-idempotency-store.ts src/saas/server/saas-connect-server.ts
git commit -m "feat: journal connector actions before side effects"
```

---

### Task 14: Classify Actions and Enforce Tenant Grants in the Backend

**Files:**

- Create: `../ai-backend-marketing-agent/packages/runtime/src/integrations/action-classification.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/src/integrations/action-policy.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/test/integration-action-policy.test.ts`
- Create: `../ai-backend-marketing-agent/scripts/check-integration-catalog-drift.ts`
- Modify: `../ai-backend-marketing-agent/package.json`

**Interfaces:**

- Produces: `IntegrationActionClassification`, `IntegrationActionPolicy.evaluate()` and catalog drift check.
- Consumes: connector catalog plus tenant grants.

- [ ] **Step 1: Write failing fail-closed policy tests**

```ts
it("denies an unclassified upstream action", () => {
  expect(policy.evaluate(scope, { id: "gmail.new_upstream_action" })).toEqual({
    allowed: false,
    reason: "ACTION_UNCLASSIFIED",
  });
});

it("does not allow a tenant grant to remove global approval", () => {
  expect(policy.evaluate(scope, destructiveAction, { approvalOverride: "inherit" }).requiresApproval).toBe(true);
});
```

- [ ] **Step 2: Verify failure**

Run: `npm test -- packages/runtime/test/integration-action-policy.test.ts`

- [ ] **Step 3: Implement source-controlled classifications**

Each enabled action has exact metadata:

```ts
interface IntegrationActionClassification {
  actionId: string;
  providerId: string;
  risk: "read" | "write" | "destructive" | "access_change";
  requiresApproval: boolean;
  idempotency: "safe" | "keyed" | "unsafe";
  minimumRole: "viewer" | "member" | "admin" | "owner";
  maxInputBytes: number;
  maxOutputBytes: number;
}
```

Create classifications only for actions belonging to the confirmed Google rollout IDs: `gmail`, `googlecalendar`, `googledrive`, `googledocs`, `googlesheets`, `googleslides`, `googleforms`, `googletasks`, `googlephotos`, `googleads`, `google_analytics`, `google_search_console`, `google_bigquery`, `google_routes`, `google_address_validation`, and `youtube`. This is a backend policy allowlist only: do not delete or alter non-Google provider/action source, catalog records, executors, schemas, or generated registries. Non-Google actions remain present in the internal catalog and become available later by adding classifications, grants, and frontend exposure. Until then they are hidden from end users and denied at execution. Unknown Google actions remain visible only to system operators and cannot execute until classified.

- [ ] **Step 4: Add drift command**

`integration:catalog:check` fetches the complete catalog through the internal client in CI/test environment, compares exact action IDs to classifications, and reports added/removed/changed schema fingerprints. Missing classification is an execution denial, not a reason to remove an action from the connector catalog. The command never rewrites registries or auto-enables actions.

- [ ] **Step 5: Verify and commit**

Run:

```bash
npm test -- packages/runtime/test/integration-action-policy.test.ts
npm run integration:catalog:check
npm run check
```

```bash
git add packages/runtime/src/integrations/action-classification.ts packages/runtime/src/integrations/action-policy.ts packages/runtime/test/integration-action-policy.test.ts scripts/check-integration-catalog-drift.ts package.json
git commit -m "feat: enforce classified integration actions"
```

---

### Task 15: Register Real Connector Actions Through Native Mastra Tool Search

**Files:**

- Create: `../ai-backend-marketing-agent/packages/runtime/src/integrations/action-execution-service.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/src/integrations/action-tool-registry.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/src/integrations/tool-search-processor.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/mastra/agents/request-context.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/mastra/agents/subagents.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/test/integration-action-tool-registry.test.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/test/integration-tool-search.test.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/test/integration-action-execution.test.ts`

**Interfaces:**

- Produces: one real Mastra `Tool` per classified connector action, a native `ToolSearchProcessor`, and request-scoped connected-service instructions.
- Consumes: complete connector action schemas, catalog fingerprint, backend scope, safe local connection summaries, action policy, approval service, connector client/token service, and audit/run repositories.
- Preserves: the existing static tool registry and all native Yandex Direct/VK Ads agents, tools, and workflows unchanged.

- [ ] **Step 1: Write failing registry and discovery tests**

Cover:

- every classified action becomes a stable `integration.<canonical-action-id>` Mastra tool whose input contains only `{ localConnectionId, input }`;
- the canonical action ID is captured by the tool executor and is never accepted as model input;
- the nested `input` schema is the connector action's real JSON Schema, not `Record<string, unknown>`;
- duplicate IDs, malformed schemas, missing classifications, and catalog fingerprint drift fail startup/readiness;
- `ToolSearchProcessor` search, load, and active phases return only tools present in the request's O(1) `integrationAllowedToolIds` map;
- a tool loaded earlier in the thread disappears immediately after connection revocation, grant removal, membership loss, or feature disablement;
- search results and dynamic instructions contain safe local connection IDs/display labels only, never connector aliases, connector connection IDs, tokens, or credentials;
- multiple accessible accounts remain distinct and require explicit `localConnectionId`; no default account is guessed;
- native Yandex/VK tools remain registered and unchanged;
- when the connector feature is disabled, no connector action processor or connector action tool is attached.

- [ ] **Step 2: Write failing execution and approval tests**

Cover provider/action mismatch, inaccessible local connection, role/plan denial, missing approval, payload drift, exact request hash, durable backend run intent, body-bound connector JWT, idempotency key, result redaction, connector timeout classification, and approval resume after process restart. Assert that the wrapper re-reads connection ownership, status, grant, and classification immediately before every execution; discovery state is never authorization.

- [ ] **Step 3: Verify failure**

Run:

```bash
npm test -- packages/runtime/test/integration-action-tool-registry.test.ts packages/runtime/test/integration-tool-search.test.ts packages/runtime/test/integration-action-execution.test.ts
```

- [ ] **Step 4: Build the immutable action registry**

At backend startup, fetch the complete paginated action catalog and fingerprint through the fixed internal connector client. Validate every enabled action and construct a Mastra tool with `createTool()`:

```ts
createTool({
  id: `integration.${action.id}`,
  description: searchableDescription(action, provider),
  inputSchema: {
    type: "object",
    additionalProperties: false,
    required: ["localConnectionId", "input"],
    properties: {
      localConnectionId: {
        type: "string",
        format: "uuid",
        description: "Backend-local connection ID from the current request context.",
      },
      input: action.inputSchema,
    },
  },
  requireApproval: classification.requiresApproval,
  execute: (args, context) => actionExecutionService.execute(action.id, args.localConnectionId, args.input, context),
});
```

The tool closure owns the exact canonical action ID. Tool output uses a common safe execution envelope and nests the redacted provider result under the connector action's output schema. Mastra performs provider-safe tool-name formatting; add a registry test for stable name mapping and collisions across every enabled action. Cache this immutable registry by catalog fingerprint. Connector catalog unavailability or fingerprint mismatch makes connector integration unready and fail-closed; it does not affect native tools.

- [ ] **Step 5: Configure native dynamic discovery**

Attach one installed-version `ToolSearchProcessor` to `generationSpecialistAgent`:

```ts
new ToolSearchProcessor({
  tools: connectorActionTools,
  search: { topK: 3, minScore: 0, autoLoad: true },
  storage: "context",
  filter: ({ toolName, requestContext }) => requestContext?.get("integrationAllowedToolIds")?.[toolName] === true,
});
```

`storage: "context"` is mandatory: loaded state is derived from tenant-scoped conversation messages, survives process replacement, and avoids replica-local or anonymous shared state. `autoLoad: true` gives the bounded `search_tools -> real action` flow and does not expose `load_tool`. Do not create `integration.search-actions`, `integration.execute-action`, a generic action-ID tool, a direct MCP client, or a second vector/tool-search subsystem.

Before every agent run, backend-authoritative middleware resolves current membership, active accessible connections, provider/action classifications, tenant grants, and feature state. It writes a JSON-serializable `Record<toolId, true>` to `integrationAllowedToolIds` and adds a compact safe instruction block listing connected provider names, `localConnectionId`, display label, owner/visibility, and reconnect state. Instructions require a concise English capability query for `search_tools`, even for a Russian request; critical launch actions also receive curated Russian/English aliases in their descriptions. If multiple accounts match, the agent asks the user once rather than guessing.

Keep native tools always available. Connector actions exist only behind `search_tools` and are injected on the next model turn. Preserve the existing server-wide `maxSteps: 10` so connector rollout cannot regress native Yandex/VK workflows; the normal connector path must finish in at most three steps (`search_tools`, real action, final response). Add a 60-second end-to-end agent deadline and propagate its `AbortSignal` through model and connector calls. Integration instructions permit at most one refined search after an empty result. The request filter must remain a pure O(1) lookup over the precomputed map—no database, OpenBao, connector, or network I/O. Connector calls retain their narrower explicit deadline/byte limits. Search selection, termination, and latency are gated in Task 20 before canary enablement.

- [ ] **Step 6: Implement audit-first execution**

Execution always reloads connection and grant under current scope, applies existing sensitive-operation/approval services, writes backend run intent, mints an exact-action/body-bound JWT, calls the connector, and stores safe metrics. Mastra `requireApproval` provides the native suspend/resume UX; the existing backend exact-payload approval record remains authoritative and is revalidated after resume and before side effects.

- [ ] **Step 7: Verify and commit**

Run focused tests plus existing tool checks:

```bash
npm test -- packages/runtime/test/integration-action-tool-registry.test.ts packages/runtime/test/integration-tool-search.test.ts packages/runtime/test/integration-action-execution.test.ts packages/runtime/test/tool-registry.test.ts packages/runtime/test/provider-write-approval.test.ts
npm run check
```

```bash
git add packages/runtime/src/integrations packages/runtime/src/mastra/agents/request-context.ts packages/runtime/src/mastra/agents/subagents.ts packages/runtime/test/integration-action-tool-registry.test.ts packages/runtime/test/integration-tool-search.test.ts packages/runtime/test/integration-action-execution.test.ts
git commit -m "feat: add native scoped integration tool search"
```

---

### Task 16: Add Lifecycle Reconciliation, Outbox, Purge, and Export

**Files:**

- Create: `../ai-backend-marketing-agent/packages/runtime/src/integrations/reconciliation-service.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/test/integration-reconciliation.test.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/service.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/outbox/service.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/material-governance/service.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/billing/export-service.ts`
- Create: `../ai-backend-marketing-agent/apps/api/src/routes/integration-internal-events.ts`

**Interfaces:**

- Produces: restart-safe connection lifecycle events and tenant/user connection cleanup/export.
- Consumes: existing outbox and governance patterns.

- [ ] **Step 1: Write failing partial-failure tests**

Test:

- connector OAuth completed while backend activation response was lost;
- backend revoke committed while OpenBao deletion failed;
- tenant closure blocks new actions before purge;
- user removal revokes private connections but preserves eligible workspace-shared connections after explicit ownership transfer;
- export includes metadata and audit totals but no credentials.

- [ ] **Step 2: Verify failure**

Run: `npm test -- packages/runtime/test/integration-reconciliation.test.ts`

- [ ] **Step 3: Implement idempotent lifecycle events**

Use backend outbox event types:

```text
integration.connection.pending
integration.connection.activated
integration.connection.revoke_requested
integration.connection.revoked
integration.connection.reconciliation_required
integration.tenant.purge_requested
```

Each handler is tenant-scoped, idempotent, and records correlation/local/connector IDs. Connector never publishes identity decisions directly to clients.

- [ ] **Step 4: Implement export and purge ordering**

Order: block execution → revoke provider credential → delete OpenBao secret → delete connector runtime metadata/files → retain required audit metadata → mark local connection revoked/purged. Export safe connection metadata, grants, counts, and run summaries only.

- [ ] **Step 5: Verify and commit**

Run focused tests and existing outbox/governance tests.

```bash
git add packages/runtime/src/integrations packages/runtime/src/outbox/service.ts packages/runtime/src/material-governance/service.ts packages/runtime/src/billing/export-service.ts apps/api/src/routes/integration-internal-events.ts packages/runtime/test/integration-reconciliation.test.ts
git commit -m "feat: reconcile integration connection lifecycle"
```

---

### Task 17: Add an Audited Backend Admin BFF

**Files:**

- Create: `../ai-backend-marketing-agent/apps/integration-admin/src/index.ts`
- Create: `../ai-backend-marketing-agent/apps/integration-admin/src/app.ts`
- Create: `../ai-backend-marketing-agent/apps/integration-admin/src/routes.ts`
- Create: `../ai-backend-marketing-agent/apps/integration-admin/src/static-console.ts`
- Create: `../ai-backend-marketing-agent/apps/integration-admin/test/admin-access.test.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/src/integrations/admin-service.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/config/app-env.ts`
- Modify: `../ai-backend-marketing-agent/package.json`

**Interfaces:**

- Produces: a dedicated loopback management listener containing the admin BFF and allowlisted static console proxy.
- Consumes: existing system-administrator/internal authentication, audit repository, and integration repositories.
- Preserves: public `apps/api/src/app.ts`; it registers no admin BFF or console route.

- [ ] **Step 1: Write failing admin-scope tests**

Cover:

- an authenticated system administrator may select tenant/workspace/subject user only through existing internal authorization;
- workspace `owner`, `admin`, `member`, `viewer`, and ordinary tenant users all receive 403 from every management endpoint and console asset route;
- an unauthenticated request receives 401 without revealing tenant or console metadata;
- the public API returns 404 for `/internal/integration-admin/**` and `/integration-console/**`;
- deployment configuration rejects any host publication except `127.0.0.1:4400`; the app itself may listen on its private container interface;
- actor and subject remain distinct in every audit event;
- admin reads never include secret refs, connector aliases, raw inputs/outputs, or execution tokens;
- direct execution endpoints do not exist on the management listener;
- authentication uses only the existing short-lived backend identity and system-administrator authorization; no static admin token, OpenConnector runtime token, or tenant credential is accepted.

- [ ] **Step 2: Verify failure**

Run: `npm test -- apps/integration-admin/test/admin-access.test.ts apps/api/test/internal-routes-auth.test.ts`

- [ ] **Step 3: Implement BFF endpoints**

```text
GET /internal/integration-admin/scopes
GET /internal/integration-admin/overview
GET /internal/integration-admin/providers
GET /internal/integration-admin/actions
GET /internal/integration-admin/connections
GET /internal/integration-admin/runs
PUT /internal/integration-admin/action-grants/{actionId}
```

Every endpoint is protected by the existing system-administrator middleware before target parameters are parsed; workspace membership roles never grant console access. Target scopes are then reauthorized by backend. Stats derive from backend `integration_action_runs`; connector run logs are used only for reconciliation/debug comparison.

- [ ] **Step 4: Serve console assets only from the loopback management listener**

The dedicated management app proxies only `/integration-console` and fingerprinted asset GETs from the connector's private static origin after system-administrator authorization. The public API app is not modified. Reject connector API, OAuth, `/v1`, `/api`, `/mcp`, `/docs`, arbitrary proxy paths, and non-GET asset requests. Add `Content-Security-Policy: default-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'`, `Cache-Control: no-store` for the HTML shell, CSRF protection for grant mutations, and no third-party assets or telemetry.

- [ ] **Step 5: Verify and commit**

Run focused management-app tests plus existing public internal-route tests.

```bash
git add apps/integration-admin packages/runtime/src/integrations/admin-service.ts packages/runtime/src/config/app-env.ts package.json
git commit -m "feat: add SSH-only integration admin service"
```

---

### Task 18: Adapt the Existing OOMOL Console for Multi-Tenant Administration

**Files:**

- Modify: `package.json`
- Create: `web/saas.html`
- Create: `web/vite.saas.config.ts`
- Create: `web/src/saas/main.tsx`
- Create: `web/src/saas/i18n.ts`
- Create: `web/src/saas/locales/en.json`
- Create: `web/src/saas/locales/ru.json`
- Create: `web/src/saas/admin-api.ts`
- Create: `web/src/saas/admin-model.ts`
- Create: `web/src/saas/admin-ui.tsx`
- Create: `web/src/saas/scope-selector.tsx`
- Create: `web/src/saas/overview-page.tsx`
- Create: `web/src/saas/providers-page.tsx`
- Create: `web/src/saas/actions-page.tsx`
- Create: `web/src/saas/connections-page.tsx`
- Create: `web/src/saas/runs-page.tsx`
- Create: `web/src/saas/admin-api.test.ts`
- Create: `web/src/saas/scope-selector.test.tsx`
- Create: `web/src/saas/connections-page.test.tsx`

The existing `web/index.html`, `web/vite.config.ts`, `web/src/main.tsx`, local `api.ts`, `model.ts`, `ui.tsx`, provider/action/run/access pages, locales, runtime-token UI, and their tests remain byte-for-byte unchanged.

**Interfaces:**

- Produces: system-administrator-only backend-BFF console with tenant/workspace/user selector, safe connection metadata, grants, run statistics, duration, and volume.
- Consumes: Task 17 BFF only.

- [ ] **Step 1: Write failing browser-boundary tests**

Mock `fetch` and assert every API request targets `/internal/integration-admin/**`; reject connector `/api`, `/v1`, `/mcp`, token management, or arbitrary execution calls. Assert scope changes refetch all pages and do not persist unauthorized scopes. Backend tests must prove that tenant/workspace users cannot receive the HTML shell or any console asset.

- [ ] **Step 2: Verify failure**

Run: `npm test -- web/src/saas/admin-api.test.ts web/src/saas/scope-selector.test.tsx web/src/saas/connections-page.test.tsx`

- [ ] **Step 3: Add scope selector and safe models**

Selector hierarchy:

```text
tenant → workspace → subject user
```

Options come only from BFF. Display actor context separately. Scope query parameters are opaque IDs and are reauthorized server-side.

- [ ] **Step 4: Reuse OOMOL presentation through a separate build entry**

`web/saas.html` loads only `web/src/saas/main.tsx`; `web/vite.saas.config.ts` writes a separate `dist/web-saas` build. Do not add a mode branch to the existing entrypoint or Vite config. The SaaS app imports existing theme, typography, styles, logo, `ProviderIcon`, `Badge`, `Card`, tables, charts, and navigation components rather than creating a second design system. Its API base is same-origin and therefore resolves only to the SSH-tunneled management listener.

- Overview: connections, active providers, calls, success/failure, input/output bytes, duration percentiles.
- Providers: catalog availability and enabled connection counts.
- Actions: global classification plus tenant grant; there is no runtime-token or execute UI.
- Connections: provider, safe account metadata, owner, visibility, status, last verification, call totals.
- Runs: exact actor/subject/provider/action/local connection, status, duration, byte volume, redacted error code.
- Never display raw provider payloads, tokens, OpenBao paths, connector aliases, or an execute button.
- With identical safe fixtures, the SaaS build must preserve the original OOMOL console's typography, colors, spacing, icons, tables, charts, and navigation structure; only the scope selector and removal of runtime-token/execute controls may differ.

- [ ] **Step 5: Verify and commit**

Run:

```bash
npm test -- web/src web/src/saas
npm run build:web
npm run build:web:saas
```

Launch the original console and the SaaS build locally with the same safe fixture at a fixed 1440×900 viewport. Capture the overview, providers, actions, connections, and runs pages and review them side by side before commit; a visual/layout regression fails the task.

```bash
git add web/saas.html web/vite.saas.config.ts web/src/saas package.json
git commit -m "feat: adapt connector console for tenant administration"
```

---

### Task 19: Deploy the Scoped Connector Beside the Existing Backend Stack

**Files:**

- Modify: `../ai-backend-marketing-agent/docker-compose.yml`
- Modify: `../ai-backend-marketing-agent/.env.example`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/config/app-env.ts`
- Modify: `../ai-backend-marketing-agent/scripts/check-local-stack.ts`
- Modify: `docker/Dockerfile.saas`
- Create: `docs/saas-deployment.md`
- Create: `src/saas/config.test.ts`

**Interfaces:**

- Produces: a private `open-connector` service using existing production PostgreSQL, OpenBao, and SeaweedFS, plus a loopback-only management service.
- Consumes: immutable fork image tag/digest and all prior runtime components; production OpenBao must not run in dev mode or expose a root token.

- [ ] **Step 1: Write failing configuration tests**

Assert production SaaS config rejects SQLite, plaintext secrets, absent JWKS, absent OpenBao, absent PostgreSQL, local transit files, wildcard action/proxy permissions, and any connector host-port publication. Backend deployment tests reject a management bind other than loopback, any public API/reverse-proxy/ngrok route to admin paths, and any Compose network shared directly between ngrok and OpenConnector.

- [ ] **Step 2: Verify failure**

Run: `npm test -- src/saas/config.test.ts`

- [ ] **Step 3: Add deployment configuration**

Compose starts only the OpenConnector SaaS entrypoint, with no `ports`, on a dedicated `integration-control` network shared only with backend, PostgreSQL, OpenBao, SeaweedFS, and the management app, plus a connector-only egress bridge for provider HTTPS. The public API joins `integration-control` only to call connector; ngrok/public reverse proxy does not. Add `integration-admin`, listening on its private container interface but published only as `127.0.0.1:4400:4400`, never a public hostname or proxy route. Both new containers run as non-root with read-only root filesystem, `no-new-privileges`, `cap_drop: [ALL]`, bounded tmpfs, resource limits, health/readiness, and immutable image references. Mount no persistent credential volume. Use a dedicated renewable least-privilege OpenBao token from a read-only secret file, separate PostgreSQL runtime/migrator roles, TLS to OpenBao, and a dedicated SeaweedFS bucket. Production preflight rejects OpenBao `-dev`, root tokens, plaintext transport, and unsealed/unhealthy status.

Required backend variables:

```text
OPEN_CONNECTOR_INTERNAL_URL
OPEN_CONNECTOR_JWT_ISSUER
OPEN_CONNECTOR_JWT_AUDIENCE=open-connector-saas
OPEN_CONNECTOR_JWT_ACTIVE_KID
OPEN_CONNECTOR_CONSOLE_STATIC_URL
INTEGRATION_ADMIN_LISTEN_HOST=0.0.0.0
INTEGRATION_ADMIN_PORT=4400
```

Required connector variables:

```text
OPEN_CONNECTOR_MODE=saas
OPEN_CONNECTOR_POSTGRES_URL
OPEN_CONNECTOR_JWKS_URL
OPEN_CONNECTOR_JWT_ISSUER
OPEN_CONNECTOR_JWT_AUDIENCE=open-connector-saas
OPEN_CONNECTOR_OPENBAO_ADDR
OPEN_CONNECTOR_OPENBAO_TOKEN_FILE=/run/secrets/open_connector_openbao_token
OPEN_CONNECTOR_SEAWEEDFS_ENDPOINT
OPEN_CONNECTOR_SEAWEEDFS_BUCKET
```

- [ ] **Step 4: Add readiness checks**

Readiness verifies PostgreSQL schema version/RLS, OpenBao permissions, JWKS availability, SeaweedFS bucket, provider registry generation, and catalog fingerprint. Health remains process-only. `stack:check` inspects the rendered Compose model and fails unless connector has zero published ports, admin publishes only `127.0.0.1:4400`, ngrok shares no connector network, and public API contains no admin/console routes.
Migration deployment takes a verified PostgreSQL backup first, acquires a migration advisory lock, applies each additive migration transactionally to a shadow database, runs the prior image against the migrated schema, and only then updates the canary. OpenBao integrated-storage deployments take and verify a Raft snapshot; external-storage deployments use that store's documented snapshot procedure.

- [ ] **Step 5: Smoke test and commit each repository**

Run backend stack and checks:

```bash
npm run stack:up
npm run stack:check
```

Run connector readiness through the backend container/internal network. Verify that the server's public address refuses ports 3000/4400 and all connector ports. Configure a dedicated SSH group with key-only authentication, `AllowTcpForwarding local`, `PermitOpen 127.0.0.1:4400`, `GatewayPorts no`, `AllowAgentForwarding no`, `X11Forwarding no`, and `PermitTTY no`; keep the host firewall closed for 4400. Open the dashboard only through `ssh -N -L 127.0.0.1:8443:127.0.0.1:4400 <system-admin>@<server>` and browse `http://127.0.0.1:8443/integration-console`. Audit both SSH login and backend admin actor/subject. Before migration, run the existing PostgreSQL backup and restore-verification commands plus the applicable OpenBao snapshot/restore drill. Deploy one connector canary with action grants disabled, validate catalog/OAuth/read-only Gmail, then enable grants. Rollback means restoring the previous immutable images; all migrations in this plan are additive and backward-compatible, with no drop/rename/type narrowing.

---

### Task 20: Add Upstream-Update Gates and Full Security Verification

**Files:**

- Create: `src/saas/security/multitenant.integration.test.ts`
- Create: `src/saas/security/oauth.integration.test.ts`
- Create: `src/saas/security/execution-token.integration.test.ts`
- Create: `src/saas/security/openbao.integration.test.ts`
- Create: `scripts/upstream-review.ts`
- Modify: `scripts/check-protected-upstream.ts`
- Modify: `.github/workflows/upstream-compat.yml`
- Create: `../ai-backend-marketing-agent/apps/api/test/integration-e2e.test.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/test/integration-tool-selection.eval.ts`
- Create: `../ai-marketing-agent-user-mobile/tests/e2e/integration-connections.spec.ts`

**Interfaces:**

- Produces: release gates for upstream merges, end-to-end isolation, and model-driven tool-selection quality.
- Consumes: completed implementation.

- [ ] **Step 1: Build the two-tenant/two-user security fixture**

Create tenants A/B, two users in tenant A, separate workspaces, identical Gmail aliases, private and workspace-shared connections, action grants, and admin actor/subject pairs. Use real PostgreSQL RLS, fake provider HTTP endpoints, test OpenBao, and SeaweedFS.

- [ ] **Step 2: Prove isolation and callback security**

Tests must fail if any of these are possible:

- cross-tenant or cross-workspace connection read/execute/delete;
- private connection use by another user;
- unauthorized admin subject selection;
- OAuth replay, expiry, provider/connection mismatch, or open redirect;
- connector token purpose/action/connection/body-hash mismatch;
- idempotency collision across tenants;
- refresh duplication across replicas;
- cross-tenant transit-file access;
- plaintext credential/token occurrence in PostgreSQL/logs/traces;
- direct proxy/MCP/static-token/public-callback use in SaaS mode;
- public API or ngrok exposure of admin BFF/console paths;
- any host-published OpenConnector port or non-loopback admin bind;
- management access without an SSH tunnel and system-administrator authentication;
- any dashboard request to a third-party origin or connector execution endpoint;
- any product-authored change to protected upstream core/dashboard/provider/Dockerfile paths.

- [ ] **Step 3: Prove lifecycle and metrics**

Test callback response loss recovery, revoke partial failure, tenant purge, user removal, export without secrets, audit-before-effect, redacted errors, duration and byte statistics, catalog drift fail-closed behavior, backup/restore evidence, canary enablement, and rollback to the prior images without schema rollback.

- [ ] **Step 4: Gate native tool discovery with real model evals**

Run `runEvals` against the production model configuration and the actual immutable action registry, `ToolSearchProcessor`, request context, and approval bridge. The fixed release corpus contains Russian and English paraphrases for every enabled launch action, provider/action near-neighbors, no-tool requests, disconnected providers, revoked connections, two-account ambiguity, and read/write/destructive cases. Assertions inspect the trajectory, not answer prose:

- the expected action is returned within `search_tools` top 3 and is the only connector action called;
- Russian requests produce concise English search terms, with no more than one refined search;
- a loaded action cannot survive an active-phase scope change;
- one account is selected only when exactly one accessible candidate exists; multiple candidates produce one clarification and no action call;
- no-tool and disconnected-provider cases execute no connector action;
- write/destructive actions suspend once and cannot execute before exact-payload approval;
- fixed-corpus critical-action recall is 100%, wrong mutating calls are zero, cross-scope calls are zero, and every run terminates within the configured step/deadline bounds.

Record model ID, catalog fingerprint, prompt/instruction fingerprint, per-case tool trajectory, token use, turns, duration, and pass/fail. A model, prompt, catalog, classification, or Mastra upgrade invalidates the evidence and reruns this gate. Run a no-side-effect shadow evaluation on canary tenant traffic before enabling execution. Do not add embeddings or another discovery service unless this native BM25 flow fails the measured corpus and the failure cannot be fixed by action descriptions or curated aliases.

Benchmark the exact enabled production catalog on production-equivalent hardware, not a synthetic count alone. Record registry build time, incremental heap per replica, and local `searchTools()` p50/p95 with dense and sparse tenant grants at 300, 1,000, and 5,000 actions. Canary enablement requires local search p95 below 50 ms at 5,000 actions, registry build below 2 seconds, incremental registry heap below 256 MiB, normal successful trajectories no longer than three steps, and every stalled model/provider request aborted by the 60-second end-to-end deadline. Exceeding a bound blocks rollout; it does not trigger a second search system automatically.

- [ ] **Step 5: Add upstream review automation**

`upstream-review.ts` compares `.upstream-base` to a fetched candidate revision and reports:

```text
provider-only changes
runtime/store/auth/OAuth/action-runner changes
generated catalog additions/removals/schema fingerprints
SaaS conflict-risk files
required focused test commands
```

`upstream:protected` independently fails while any baseline-existing source/dashboard/provider/Dockerfile/script path differs from `.upstream-base`. It never auto-merges or auto-enables actions. After a reviewed upstream merge and passing compatibility tests, update `.upstream-base` to the reviewed merge commit in the same commit as regenerated registries and evidence; this makes upstream changes the new protected baseline without permitting product-authored patches.

- [ ] **Step 6: Run final validation and smoke test**

OpenConnector:

```bash
npm run fix-check
npm test
npm run build
npm run build:web
npm run build:web:saas
npm run upstream:check
npm run upstream:protected
npm run saas:verify-generated
```

Backend:

```bash
npm run check
npm test
npm run lint
npm run format:check
npm run db:migrate:up:dry-run
npm exec vitest run packages/runtime/test/integration-tool-selection.eval.ts
npm run stack:check
```

Mobile:

```bash
npm exec vitest run
npm run lint
npm run export:web
npm run test:e2e -- tests/e2e/integration-connections.spec.ts
```

Smoke scenario:

1. Tenant A/user A connects Gmail through mobile OAuth.
2. Tenant A/user B cannot see the private connection.
3. A workspace owner/admin shares it to the workspace; user B can search permitted read actions.
4. Tenant B never sees or executes it.
5. Mastra exposes `search_tools`, finds the exact real Gmail action, injects its connector JSON Schema on the next turn, and executes the approved read action without any generic action-ID tool.
6. With two Gmail accounts, Mastra asks once which safe local account to use and executes neither until selected; a write action then suspends for exact-payload approval.
7. A system administrator first establishes `ssh -N -L 127.0.0.1:8443:127.0.0.1:4400 <system-admin>@<server>`, opens the loopback console, switches among authorized target users, and sees safe call counts/bytes/duration; the public host port is closed and every tenant/workspace role receives 403.
8. Revocation removes OpenBao credential and blocks subsequent execution.
9. Native Yandex Direct and VK Ads flows still pass their existing tests.

- [ ] **Step 7: Commit final gates in each repository**

Commit OpenConnector security and upstream gates, backend E2E tests, and mobile E2E test separately with focused messages.

---

## Definition of Done

- Mobile users connect, list, search, reconnect, and revoke integrations without seeing OOMOL UI or connector identifiers; only workspace `owner`/`admin` can share or unshare a connection.
- Connector exposure is disabled by default through the existing backend feature mechanism and enabled first for one canary tenant; disabled mode preserves all existing native routes, tools, connections, and workflows.
- Multiple accounts of the same provider work for the same user and across users without alias collisions.
- Backend remains the only authority for tenant/workspace/user identity, roles, plan limits, grants, approvals, and lifecycle.
- Connector independently enforces the backend-issued scope through JWT binding, forced PostgreSQL RLS, scoped OpenBao paths, and exact-action request hashes.
- No route allows browsers, mobile clients, or Mastra to call connector MCP, proxy, admin, OAuth callback, or raw execution APIs directly.
- Provider actions cannot begin before durable backend and connector intent/idempotency records exist.
- Generic credentials exist only in OpenBao; PostgreSQL/logs/traces/mobile contain no secret material.
- Connector replicas share PostgreSQL/OpenBao/SeaweedFS and coordinate refresh without duplicate provider refresh calls.
- Admin console reuses OOMOL presentation and navigation, calls only the loopback management BFF, is reachable only through an SSH local port-forward, is accessible only to authenticated system administrators, supports administrator-selected tenant/workspace/user targets, and displays safe provider/action/run statistics and byte volume. All tenant and workspace roles receive 403.
- OpenConnector has no published host port and production starts only its SaaS entrypoint. The management container is published only on server loopback, is absent from public API/ngrok/reverse-proxy routing, and the console is usable only through SSH local port forwarding plus system-administrator authorization.
- The full upstream provider/action catalog remains intact. Initial end-user exposure and execution are limited by backend policy to the confirmed Google ecosystem IDs; non-Google providers stay in the internal catalog for later activation and are never deleted merely because they are currently disabled.
- Mastra uses the installed native `ToolSearchProcessor` with `autoLoad: true`, `storage: "context"`, request-scoped search/load/active filtering, and one real schema-bearing tool per classified action. No custom generic search/execute tool, direct MCP client, or second discovery subsystem exists.
- The production-model tool-selection corpus passes for both Russian and English: 100% fixed-corpus critical-action recall, zero wrong mutating calls, zero cross-scope calls, correct two-account clarification, and bounded turns/deadlines.
- Existing Yandex Direct/VK Ads, ad-connections, approvals, billing, chat, and Mastra tests remain green.
- Upstream provider updates merge without modifying SaaS modules, and new actions remain disabled until classified and granted.

## Self-Review Checklist

- **Spec coverage:** backend authority, mobile-only user UI, full tenant/user/workspace isolation, multiple accounts, OAuth/API-key connections, Mastra discovery/execution, approvals, admin statistics/scope switching, OpenBao, PostgreSQL, SeaweedFS, horizontal replicas, purge/export, and upstream sync each map to explicit tasks.
- **Security boundary:** actor and subject are distinct; all execution is body-bound; no global database bypass role, global list, default authenticated connection, direct MCP, provider proxy, or static runtime token remains in SaaS mode.
- **No duplicate platform:** no ACI/Nango/Redis/workflow engine/second identity system is introduced.
- **Upstream safety:** existing OpenConnector core, OAuth, local/Cloudflare servers, dashboard entrypoint/pages/locales, provider implementations, generated-registry rules, and Dockerfile remain unchanged. All product behavior lives in additive SaaS wrappers, a separate web entry/build, and a separate SaaS image; CI rejects protected-file drift.
- **Type consistency:** `tenantId`, `workspaceId`, `actorUserId`, `subjectUserId`, `localConnectionId`, `connectorConnectionId`, `actionId`, and `requestHash` are stable across all tasks and map to snake_case only in JWT claims.
- **No hidden secrets:** DTOs, tests, admin pages, and run records use safe metadata only.

## Execution Handoff

Plan implementation may begin from the pinned local clone without configuring a fork. Do not change remotes or push; fork setup remains a separately approved future operation.

Recommended execution mode: **superpowers:subagent-driven-development**, one fresh implementation agent per task with two-stage review. Use **superpowers:executing-plans** only if all three repositories must be changed serially in one controlled session.
