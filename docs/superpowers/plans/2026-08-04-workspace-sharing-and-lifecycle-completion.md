# Workspace Sharing and Lifecycle Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans`. Execute tasks in order. Do not start the full-provider or single-runtime cutover plans until this plan passes its final gate.

**Актуальная рамка (2026-11-06):** [Границы сервисов](../specs/2026-11-06-service-boundaries-and-upstream-sync-design.md) и [будущее обновление main → multitenant](2026-11-06-upstream-main-multitenant-sync.md). Этот документ описывает историческую последовательность доработки; перед новым исполнением проверить фактическое состояние, не повторять завершённые переходы по старым флажкам. Разрешения функций принадлежат OpenConnector по отдельному плану, человеческое согласие и бизнес-доступ — бекенду ИИ-маркетолога.

**Goal:** Make private/workspace connection visibility authoritative in both databases, make ownership transfer reachable, implement the connector run APIs, and make user/workspace/tenant export and deletion complete across the backend PostgreSQL database, OpenConnector PostgreSQL database, OpenBao, and SeaweedFS.

**Prerequisite:** `2026-08-04-native-multitenant-integration-runtime.md` has been implemented. This follow-up supersedes its incomplete visibility and lifecycle behavior; it does not weaken JWT, RLS, OpenBao, or backend-authorization invariants.

**Repositories:**

- `open-connector` owns credential/runtime state, runtime audit, exact-scope execution/export/purge and, after the planned permission cutover, its own function permissions.
- `../ai-backend-marketing-agent` owns identity, membership/business access, local connection mapping, its own audit and aggregation/orchestration of export and lifecycle; it does not read the connector database directly.
- `../ai-marketing-agent-user-mobile` remains the end-user UI; its existing visibility controls must work without a connector URL or connector ID becoming a trust input.

## Non-negotiable invariants

1. The backend row and connector row have the same `visibility` before a connection returns to `active`.
2. Every visibility transition blocks new execution before the first cross-service write. A crash leaves the connection blocked and retryable, never partially active.
3. Only a current workspace `owner` or `admin` may share or unshare. Backend membership is reloaded on every mutation and execution.
4. A workspace connection retains one owner. Workspace members may execute it, but only the backend selects the owner as `subject_user_id` when minting the connector execution token.
5. The mobile connection ID is always a backend-local UUID. The backend resolves the connector ID under tenant/workspace scope; callers never authorize by supplying a connector ID.
6. Lifecycle cleanup uses exact user scopes. Tenant and workspace cleanup fan out over backend-authoritative scopes; no runtime database role receives `BYPASSRLS`, table ownership, wildcard tenant access, or a global list route.
7. Export contains only safe metadata and redacted run summaries. Credentials, provider responses, request bodies, OAuth state, tokens, secret references, and OpenBao versions never leave the connector.
8. Entity deletion is not acknowledged until connector secrets/files/state are removed or a durable reconciliation record blocks final deletion.
9. Every destructive endpoint is idempotent and bound to a short-lived purpose-specific JWT plus a canonical request hash.
10. `connection_revocation_receipts` and every new runtime table are included in the startup RLS/ownership/schema probe.

## New wire contract

Add these private routes to `docs/contracts/saas-runtime.openapi.yaml`:

```text
PATCH /internal/saas/connections/{connectorConnectionId}/visibility
GET   /internal/saas/runs
GET   /internal/saas/runs/{executionId}
GET   /internal/saas/lifecycle/export
POST  /internal/saas/lifecycle/purge
```

- Visibility body: `{ "visibility": "user" | "workspace" }`.
- `connection:write` JWT binds `local_connection_id`, `connector_connection_id`, `subject_user_id`, and `request_hash` for the visibility operation.
- Run routes use `admin:read`; the backend mints a token for one selected subject and exact tenant/workspace.
- Lifecycle routes use new `lifecycle:read` and `lifecycle:delete` purposes. They always represent exactly one tenant/workspace/subject scope.
- Purge body: `{ "correlationId": "uuid" }`; its hash is bound into the JWT. A repeated purge after all scoped rows are absent returns the same successful result.

The backend exposes tenant-safe product routes only. It resolves every local connection, target user, workspace, and role before calling the connector.

---

### Task 1: Extend the scoped wire contract before behavior

**Files:**

- Modify: `src/saas/contracts.ts`
- Modify: `src/saas/contracts.test.ts`
- Modify: `src/saas/actions/canonical-request.ts`
- Modify: `docs/contracts/saas-runtime.openapi.yaml`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/connector-token-service.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/test/connector-token-service.test.ts`

- [ ] **Step 1: Add failing contract tests**

Cover exact purpose/permission matching, required connection bindings for visibility, required `correlationId` and request hash for purge, rejection of wildcard permissions, and rejection of lifecycle tokens with missing tenant/workspace/subject claims.

- [ ] **Step 2: Add `lifecycle:read` and `lifecycle:delete`**

Keep all existing snake-case JWT claims. Do not add caller-controlled identity headers or a broad lifecycle scope. Add a canonical operation hash helper only if the existing canonical request helper cannot express the new fixed route body without a fake connector action.

- [ ] **Step 3: Update OpenAPI and backend token typing**

Document exact methods, schemas, status codes, pagination limits, and purpose values. No public connector callback or lifecycle URL is added.

- [ ] **Step 4: Verify**

Run:

```bash
npm test -- src/saas/contracts.test.ts src/saas/actions/canonical-request.test.ts
cd ../ai-backend-marketing-agent && npx vitest run packages/runtime/test/connector-token-service.test.ts --maxWorkers=1
```

Expected: all purpose, binding, expiry, and hash tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/saas/contracts.ts src/saas/contracts.test.ts src/saas/actions/canonical-request.ts docs/contracts/saas-runtime.openapi.yaml
git commit -m "feat: define sharing and lifecycle contracts"
```

Commit backend files separately in the backend repository.

---

### Task 2: Make connector visibility an atomic scoped mutation

**Files:**

- Modify: `src/saas/storage/postgres-runtime-database.ts`
- Modify: `src/saas/storage/postgres-connection-store.ts`
- Modify: `src/saas/storage/postgres-runtime-database.test.ts`
- Modify: `src/saas/storage/scoped-query.test.ts`
- Modify: `src/saas/server/saas-connect-server.ts`
- Modify: `src/saas/server/saas-connect-server.test.ts`

- [ ] **Step 1: Write failing store tests**

Prove all of the following against PostgreSQL with forced RLS:

- the owner can change `user -> workspace` only with an owner/admin role;
- another workspace member cannot mutate the row even though the row becomes visible after sharing;
- another tenant or workspace receives no row and changes nothing;
- `workspace -> user` immediately removes the row from another member's list and execution lookup;
- a repeated request with the same target visibility is idempotent;
- local and connector connection IDs must both match.

- [ ] **Step 2: Add `updateVisibilityById` to `SaasRuntimeConnectionStore`**

The SQL must include tenant, workspace, current owner (`subject_user_id`), connector ID, local ID, and active status. The method checks `workspaceRole` before opening the transaction. Do not implement this through an unscoped admin pool.

- [ ] **Step 3: Implement the route**

Add `PATCH /internal/saas/connections/:connectionId/visibility`. Validate exact JSON keys, exact JWT bindings, role, request hash, and IDs before calling the store. Return `404` for an inaccessible row, `403` for binding/role mismatch, and the safe connection summary on success.

- [ ] **Step 4: Verify**

```bash
npm test -- src/saas/server/saas-connect-server.test.ts src/saas/storage/postgres-runtime-database.test.ts src/saas/storage/scoped-query.test.ts
```

Expected: the new private-to-workspace path is reachable and every cross-tenant/workspace/owner probe changes zero rows.

- [ ] **Step 5: Commit**

```bash
git add src/saas/storage/postgres-runtime-database.ts src/saas/storage/postgres-connection-store.ts src/saas/storage/postgres-runtime-database.test.ts src/saas/storage/scoped-query.test.ts src/saas/server/saas-connect-server.ts src/saas/server/saas-connect-server.test.ts
git commit -m "feat: synchronize scoped connection visibility"
```

---

### Task 3: Make backend visibility transitions crash-safe

**Files:**

- Create: `../ai-backend-marketing-agent/infra/postgres/migrations/<timestamp>_add-integration-visibility-reconciliation.sql`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/db/schema/index.ts`
- Modify: `../ai-backend-marketing-agent/packages/domain/src/integration.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/repository.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/connector-client.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/service.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/test/integration-repository.test.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/test/provider-integration-service.test.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/test/integration-connector-client.test.ts`

- [ ] **Step 1: Add failing transition tests**

Cover success, connector timeout before change, connector success followed by backend failure, retry after either failure, concurrent opposite requests, an admin operating on a shared connection owned by another user, and execution rejection while a transition is pending.

- [ ] **Step 2: Persist one pending target on the connection row**

Add nullable `pending_visibility` and `visibility_correlation_id`. Repository operations are:

1. `beginVisibilityChange`: compare-and-set `active -> reconnect_required`, persist target/correlation, and return the authoritative owner and connector ID.
2. Connector mutation with a token whose `subject_user_id` is that owner.
3. `completeVisibilityChange`: set `visibility = pending_visibility`, clear pending fields, and restore `active` only when correlation and IDs match.
4. Failure leaves `reconnect_required` and pending fields intact for retry; it never restores execution optimistically.

Do not add a second workflow engine or distributed transaction.

- [ ] **Step 3: Add `OpenConnectorClient.updateConnectionVisibility`**

Validate the safe response and require returned connector ID, local ID, and target visibility to match. Retry only transport/invalid-response uncertainty with the same idempotent request; do not retry authorization or validation failures.

- [ ] **Step 4: Replace the local-only update**

`IntegrationOperationService.updateVisibility` reloads membership, resolves the connection under tenant/workspace scope, begins the blocked transition, calls the connector as the connection owner, then completes locally. Record requested/completed/reconciliation-required lifecycle events without credentials or connector payloads.

- [ ] **Step 5: Verify**

```bash
cd ../ai-backend-marketing-agent
npx vitest run packages/runtime/test/integration-repository.test.ts packages/runtime/test/provider-integration-service.test.ts packages/runtime/test/integration-connector-client.test.ts --maxWorkers=1
npx tsc --noEmit
```

Expected: no test can observe an `active` row with mismatched visibility.

- [ ] **Step 6: Commit**

Commit migration/schema/domain/repository first, then client/service/tests.

---

### Task 4: Prove shared execution and make ownership transfer reachable

**Files:**

- Modify: `src/saas/storage/postgres-runtime-database.test.ts`
- Modify: `src/saas/actions/saas-action-runner.test.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/test/integration-action-execution.test.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/test/integration-reconciliation.test.ts`
- Modify: `../ai-backend-marketing-agent/apps/api/test/integrations.test.ts`
- Modify: `../ai-marketing-agent-user-mobile/tests/settings/connections.test.tsx` (or the existing connection-screen test owning this behavior)

- [ ] **Step 1: Add a real two-user shared-connection scenario**

Create owner A and member B in one workspace. A connects privately, an admin shares through the public backend route, B lists it and executes one read action, then the admin unshares it and B can neither list nor execute it. Repeat the execution attempt with a raw connector ID and prove it is ignored/rejected.

- [ ] **Step 2: Exercise ownership transfer**

Share A's connection first, call the existing connector transfer endpoint through `IntegrationReconciliationService.removeUser`, and prove the new owner can execute while the removed owner cannot. Verify a private connection is revoked rather than transferred and a transfer to a non-member fails closed.

- [ ] **Step 3: Keep the existing mobile UI**

The current visibility buttons remain backend-only. Update DTO/error handling only as needed for pending/reconciliation status. Do not expose connector IDs or add a connector UI.

- [ ] **Step 4: Verify**

Run focused connector, backend API/runtime, and mobile connection tests. Expected: the full `user -> workspace -> transfer -> user` sequence works with no direct database update in tests.

- [ ] **Step 5: Commit**

Commit tests and any minimal DTO/UI status changes in their owning repositories.

---

### Task 5: Implement redacted scoped run APIs

**Files:**

- Modify: `src/saas/server/saas-connect-server.ts`
- Modify: `src/saas/server/saas-connect-server.test.ts`
- Modify: `src/saas/storage/postgres-run-store.ts`
- Modify: `src/saas/storage/postgres-runtime-database.test.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/connector-client.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/test/integration-connector-client.test.ts`

- [ ] **Step 1: Replace both 501 tests with behavior tests**

Test cursor pagination, `service`, `actionId`, `caller`, and `ok` filters; exact query-key rejection; malformed cursor rejection; one-run lookup; `404` for another subject/workspace/tenant; and response-size limits.

- [ ] **Step 2: Route to the existing `PostgresRunStore`**

`GET /runs` calls `runtime.runLogStore.list`; `GET /runs/:executionId` calls `get`. Responses contain only the existing redacted `RunLog` fields. Never return request hash, input, output, provider body, credential profile secrets, or OpenBao references.

- [ ] **Step 3: Add bounded backend client methods**

Add strict Zod schemas and bounded pagination. The system-admin BFF may select a subject only after backend authorization and then mints the exact `admin:read` token for that subject.

- [ ] **Step 4: Verify**

```bash
npm test -- src/saas/server/saas-connect-server.test.ts src/saas/storage/postgres-runtime-database.test.ts
cd ../ai-backend-marketing-agent && npx vitest run packages/runtime/test/integration-connector-client.test.ts --maxWorkers=1
```

Expected: no `/internal/saas/runs*` request returns 501.

- [ ] **Step 5: Commit**

Commit connector and backend changes separately.

---

### Task 6: Add exact-user export and purge inside the connector

**Files:**

- Create: `src/saas/lifecycle/scoped-lifecycle-service.ts`
- Create: `src/saas/lifecycle/scoped-lifecycle-service.test.ts`
- Modify: `src/saas/storage/postgres-runtime-database.ts`
- Modify: `src/saas/storage/postgres-connection-store.ts`
- Modify: `src/saas/storage/postgres-oauth-state-store.ts`
- Modify: `src/saas/storage/postgres-transit-file-store.ts`
- Modify: `src/saas/files/seaweedfs-transit-files.ts`
- Modify: `src/saas/secrets/openbao-connection-store.ts`
- Modify: `src/saas/secrets/openbao-oauth-state-secret-store.ts`
- Modify: `src/saas/server/saas-connect-server.ts`
- Modify: `src/saas/server/saas-connect-server.test.ts`

- [ ] **Step 1: Write failure-injection tests**

Cover zero-row idempotence, many connections/states/files, OpenBao delete failure, SeaweedFS delete failure, PostgreSQL failure after external deletion, retry after each crash point, and complete isolation from another user/workspace/tenant.

- [ ] **Step 2: Implement safe export**

Return a bounded, paginated snapshot containing safe connection summaries, redacted run summaries/counts, and counts/statuses for OAuth states, idempotency rows, and transit files. Do not return secret refs, object keys that reveal another scope, raw run payloads, or OAuth state values.

- [ ] **Step 3: Implement idempotent purge**

For the exact verified user scope:

1. block all active connections;
2. attempt provider revocation through the configured revoker;
3. delete each exact OpenBao connection and OAuth-state secret;
4. delete each exact SeaweedFS object;
5. delete PostgreSQL rows in foreign-key order inside a transaction;
6. return counts and `correlationId` only after the scope is empty.

External `not found` is success. Any other external failure leaves PostgreSQL metadata sufficient for a retry and returns reconciliation-required; it must not erase the remaining secret reference first. Never use OpenBao prefix deletion.

- [ ] **Step 4: Verify**

```bash
npm test -- src/saas/lifecycle/scoped-lifecycle-service.test.ts src/saas/server/saas-connect-server.test.ts src/saas/storage/postgres-runtime-database.test.ts
```

Expected: a successful purge leaves zero exact-scope PostgreSQL rows, OpenBao secrets, and SeaweedFS objects while adjacent scopes are byte-for-byte unchanged.

- [ ] **Step 5: Commit**

Commit the lifecycle service, stores, routes, and tests.

---

### Task 7: Orchestrate user, workspace, and tenant lifecycle in the backend

**Files:**

- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/connector-client.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/reconciliation-service.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/membership/service.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/membership/repository.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/src/integrations/lifecycle-coordinator.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/test/integration-lifecycle-coordinator.test.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/test/integration-reconciliation.test.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/test/membership-service.test.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/billing/export-service.ts`
- Modify: the existing internal/admin tenant and workspace lifecycle routes; create a focused route module only if no owner exists

- [ ] **Step 1: Add failing orchestration tests**

Prove export-before-delete, one exact token per scope, all connections blocked before the first destructive call, shared ownership transfer before owner removal, retry after process restart, no membership/entity deletion while any scope requires reconciliation, and no work against another tenant.

- [ ] **Step 2: Implement one lifecycle coordinator**

Reuse `IntegrationReconciliationService`; do not create a second lifecycle model. The coordinator:

- snapshots backend-authoritative users/workspaces/connections before any FK cascade;
- exports safe backend metadata plus each connector user-scope export;
- transfers approved shared connections and revokes all others;
- purges every exact connector user scope;
- verifies all responses match tenant/workspace/subject and correlation;
- only then removes membership/workspace/tenant data.

Persist progress in the existing internal outbox/lifecycle ledger so restart resumes from the last completed scope. No in-memory-only deletion workflow.

- [ ] **Step 3: Wire membership removal**

`WorkspaceMembershipService.removeMember` must invoke lifecycle cleanup before repository deletion. A map of shared connection ownership targets is validated against current workspace members. If no target is supplied, shared connections are revoked; they are never orphaned.

- [ ] **Step 4: Wire workspace/tenant delete and export**

Use system-admin/internal routes with existing authentication. Public tenant users do not gain a connector lifecycle URL. Return the backend-owned export; never stream OpenBao data.

- [ ] **Step 5: Verify**

```bash
cd ../ai-backend-marketing-agent
npx vitest run packages/runtime/test/integration-reconciliation.test.ts packages/runtime/test/integration-lifecycle-coordinator.test.ts packages/runtime/test/membership-service.test.ts --maxWorkers=1
npx tsc --noEmit
```

Expected: backend deletion is impossible until connector cleanup is confirmed for every recorded exact scope.

- [ ] **Step 6: Commit**

Commit coordinator/repository changes, then route/service integration and tests.

---

### Task 8: Contract migration debt and expand the startup probe

**Files:**

- Create: `src/saas/storage/migrations/0006_contract_connection_identity.sql`
- Modify: `src/saas/storage/postgres-runtime-database.ts`
- Modify: `src/saas/storage/postgres-runtime-database.test.ts`
- Modify: `src/saas/storage/scoped-query.test.ts`
- Modify: `scripts/saas-backfill-connections.ts`
- Modify: deployment/runbook commands owning connector migration

- [ ] **Step 1: Add failing readiness tests**

Startup must fail when `connection_revocation_receipts` is absent, owned by the runtime role, lacks `ENABLE/FORCE RLS`, or is missing its applied migration checksum. It must also fail when `connections.local_connection_id` remains nullable after the contract release.

- [ ] **Step 2: Execute expand/backfill/contract in order**

1. stop all pre-contract connector images;
2. generate mappings from backend `app.integration_connections` under tenant/workspace/owner scope;
3. run `npm run saas:backfill-connections -- <mapping.json>` in bounded batches;
4. run `--verify` with the separate audit credential;
5. apply migration `0006`, which aborts if any null remains and then sets `NOT NULL`;
6. remove `--contract` as an out-of-band schema mutation after the migration owns the invariant.

Never fabricate an owner for an unmapped row. Any unmapped row blocks deployment and requires explicit operator resolution.

- [ ] **Step 3: Expand `requiredRuntimeTables`**

Include `connection_revocation_receipts` and any lifecycle table introduced by this plan. Verify owner, `ENABLE RLS`, `FORCE RLS`, policy presence, and migration checksum.

- [ ] **Step 4: Remove nullable runtime branches**

After the migration gate passes, remove `local_connection_id IS NOT NULL` compatibility filters and nullable row typing. The schema, TypeScript, and startup probe must agree that it is required.

- [ ] **Step 5: Verify**

Run migration tests from an empty database and an expand-state database containing mapped and unmapped legacy rows. Expected: mapped upgrade succeeds; unmapped upgrade aborts without partial contract.

- [ ] **Step 6: Commit**

Commit migration/probe/tests and runbook changes.

---

### Task 9: Final cross-database security and lifecycle gate

**Files:**

- Create or modify the existing connector/backend end-to-end integration test owning the SaaS stack
- Modify: `CHANGELOG.md` in each changed repository only after all checks pass

- [ ] **Step 1: Run a clean-stack scenario**

Use PostgreSQL with forced RLS, OpenBao, SeaweedFS, backend JWKS, backend API, and the connector SaaS image. Create two tenants, two users in one workspace, and one user in the other tenant.

- [ ] **Step 2: Exercise the complete sequence**

```text
private OAuth connection
-> share to workspace
-> second member executes read action
-> list redacted run
-> transfer ownership during member removal
-> export workspace
-> purge workspace
-> verify tenant B unchanged
-> export tenant A
-> purge tenant A
```

- [ ] **Step 3: Probe IDOR and crash points**

Try foreign local IDs, connector IDs, subject IDs, workspace IDs, reused hashes, expired tokens, wrong purposes, and process restarts between every cross-service lifecycle step. All attempts fail closed and produce no cross-scope row/secret/object changes.

- [ ] **Step 4: Run repository checks**

```bash
# open-connector
npm run fix-check
npm run build
npm run test:saas

# backend
cd ../ai-backend-marketing-agent
npx tsc --noEmit
npm test

# mobile, only if DTO/UI files changed
cd ../ai-marketing-agent-user-mobile
npx tsc --noEmit
npm test
```

- [ ] **Step 5: Record the release gate**

The plan is complete only when:

- backend and connector visibility agree for every active connection;
- ownership transfer is reached only after sharing;
- run routes return no 501;
- user/workspace/tenant export and purge are restart-safe;
- zero nullable local connection IDs remain;
- startup probes every RLS table, including revocation receipts;
- no cross-tenant/workspace/user test changes data.

- [ ] **Step 6: Add changelog entries and commit**

Document behavior and migration order, not secrets or internal deployment addresses.

---

## Completion handoff

After this plan passes, execute:

1. `2026-08-04-full-provider-rollout.md`
2. `2026-08-04-single-runtime-multitenant-cutover.md`

Do not declare OpenConnector fully multi-tenant before the final plan removes every executable single-instance entrypoint.
