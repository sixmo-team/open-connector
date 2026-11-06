# OpenConnector Release-Critical Gates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans`. Work in the order below. Do not weaken a gate to make it green, do not replace real PostgreSQL/OpenBao/SeaweedFS with in-memory doubles, and do not mark production evidence complete from repository state alone.

**Актуальная рамка (2026-11-06):** [Границы сервисов](../specs/2026-11-06-service-boundaries-and-upstream-sync-design.md) и [будущее обновление main → multitenant](2026-11-06-upstream-main-multitenant-sync.md). Эти условия применяются к результату контролируемого переноса, включая изменения без текстовых конфликтов. Исторические результаты ниже не доказывают состояние нового коммита/образа; ни один признак изоляции не заменяется выбором всей стороны слияния.

**Goal:** Block release until shared-connection identity semantics are correct, all real RLS suites pass together, the final Docker image is inspected, one clean command proves the backend-to-storage chain, and the production cutover is backed by live non-secret evidence.

**Repositories:**

- `open-connector`
- `../ai-backend-marketing-agent`

## Scope decisions

All six items are release-critical and remain in scope. They are ordered by dependency rather than by implementation convenience:

1. Fix shared-connection subject semantics first; the E2E gate must prove the intended contract, not preserve the current mismatch.
2. Make real PostgreSQL RLS tests one reliable CI gate before relying on them for release safety.
3. Verify the built image before using that image in clean-stack or production evidence.
4. Make clean-stack E2E mandatory and self-provisioning.
5. Require live production cutover evidence as the deployment approval gate.
6. Run one no-exceptions acceptance gate over the exact revisions and image digest being promoted.

Full-catalog product admission is intentionally out of scope. OpenConnector may retain the complete upstream catalog while the marketing product exposes only a reviewed subset and expands it incrementally. This does not make the runtime migration incomplete.

Do not add a second runtime, a test-only production endpoint, a permanent legacy importer, a new secrets service, broad operational telemetry, or a generated safety classification.

## Current audit baseline

The 2026-08-06 audit reproduced this exact state:

| Area                     | Current result                                                                                                                                                                                   | Required result                                                            |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| Source/runtime cutover   | `upstream:protected`, source `verify:no-legacy-runtime`, and typecheck pass                                                                                                                      | Preserve                                                                   |
| SaaS suites              | 226 passed, 27 skipped                                                                                                                                                                           | External gates execute rather than skip                                    |
| Real PostgreSQL RLS gate | 27 passed, 1 failed on a fresh PostgreSQL 16 database                                                                                                                                            | Green twice against clean isolated databases                               |
| Shared visibility        | `get()` sees the shared row; execution `list()` is empty under an unrelated `local_connection_id` binding                                                                                        | Tests distinguish exact execution list from unselected safe list           |
| Backend focused security | 90 passed; clean-stack E2E skipped                                                                                                                                                               | Mandatory clean-stack run passes                                           |
| Catalog admission        | Intentional product subset: 696/13,389 actions and 26/1,258 providers available; 1,232 explicit unavailable-provider pins cover 12,691 actions; 2 exact action denials; no catalog-wide fallback | Preserve fail-closed admission; expand only when product scope requires it |
| Production proof         | Verifier and reusable workflow exist; no repository caller or signed live record is proven                                                                                                       | Protected live collector/caller emits an attested passing record           |

Passing source checks do not cancel a failed external gate.

## Non-negotiable invariants

1. `actor_user_id` is the requester who initiated the action.
2. For a private connection, `subject_user_id` is its owner and therefore equals the requester.
3. For a workspace-shared connection, `subject_user_id` is the connection owner even when another member executes it.
4. Backend membership, billing, product admission, role and visibility authorize the requester before owner scope is derived; action enablement is resolved by OpenConnector for that requester. The caller never supplies or widens owner scope, and neither service overrides the other's denial.
5. The execution JWT, credential/run PostgreSQL scope, OpenBao path, run intent, idempotency and resource lifecycle use the authoritative connection owner as subject. Action-policy lookup uses the verified requester as actor, not that owner. Audit retains both identities.
6. Every PostgreSQL runtime table has `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY`; the runtime role is neither owner, superuser, `BYPASSRLS`, nor a member of an owning role.
7. CI inspects the filesystem and config of the exact Docker image it executes. Source-tree checks alone are insufficient.
8. The clean-stack gate starts from empty volumes and provisions all identities, policies, keys, schemas, buckets, and fixtures itself.
9. Production cutover evidence comes from the live deployment and references an immutable image digest. A tag, Compose file, plan checkbox, or repository commit is not deployment evidence.
10. Product admission is independent from tenant isolation: only explicitly bounded actions are exposed, and omitted providers do not block a multi-tenant cutover.

**Planned ownership amendment (2026-11-06):** [Общие разрешения OpenConnector](2026-11-06-default-integration-action-permissions.md) gives OpenConnector sole action-enable storage and enforcement; backend business checks and exact user consent remain separate. There are no real users: use direct cutover and empty new policy stores, not a test-data import or old compatibility model. These target invariants and the flow below include that change; the historical audit baseline is not evidence it is implemented. Rerun release gates after the contract, own-service schema and independent deployment changes.

---

### Task 1: Correct shared-connection execution identity

**Primary files:**

- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/action-execution-service.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/repository.ts` only if a narrower owner-bearing lookup is required
- Modify: `../ai-backend-marketing-agent/packages/runtime/test/integration-action-execution.test.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/test/connector-token-service.test.ts`
- Modify: `../ai-backend-marketing-agent/apps/api/test/integration-action-runtime.test.ts`
- Modify: `../ai-backend-marketing-agent/apps/api/test/saas-stack.e2e.test.ts`
- Modify connector contract tests only where they currently encode requester-as-subject for a shared owner row
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/connector-client.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/service.ts`
- Modify: `../ai-backend-marketing-agent/apps/api/src/routes/integrations.ts`
- Modify: `../ai-backend-marketing-agent/apps/api/test/integrations.test.ts`
- Modify: `src/saas/files/seaweedfs-transit-files.test.ts`

- [ ] **Step 1: Add the failing shared-owner contract test**

Create a workspace owner and member. The owner owns an active workspace-shared connection; the member has current membership and the applicable action grant. Execute as the member and assert:

- authorization is evaluated for the member;
- the resolved connection owner is not accepted from request context or action input;
- the execution JWT has `actor_user_id = member`, `subject_user_id = owner`, and `sub = owner`;
- the connector can resolve the owner-scoped row and secret;
- backend and connector run records retain member-as-actor and owner-as-subject;
- a private owner connection remains unavailable to the member;
- a removed member, removed owner, inactive connection, foreign workspace, and forged owner all fail before provider egress.

The test must fail against the current requester-as-subject implementation.

- [ ] **Step 2: Split authorization scope from resource execution scope**

In `RepositoryIntegrationActionExecutionAuthority.reauthorize`:

1. Parse the incoming requester scope and require its actor and subject to match at the user-facing boundary.
2. Reload the requester's workspace membership.
3. Resolve the connection under requester visibility rules; load backend billing/product/role/approval state and request OpenConnector's effective action permission for the requester. Do not resolve individual/default inheritance in the backend.
4. After the connection is authorized, derive an execution scope from the stored `ownerUserId`: keep requester as actor and set owner as subject.
5. Reject an owner who is no longer a valid workspace member or a connection whose ownership/visibility transition is incomplete.

Return explicit `authorizationScope` and `executionScope` fields rather than mutating one ambiguous `scope`. Do not add a compatibility alias.

- [ ] **Step 3: Use each scope only for its owner fact**

- Backend business/safety/approval checks use `authorizationScope`; OpenConnector action-policy reads use its verified requester. Owner resource scope never changes whose action rule is evaluated.
- Connector token issuance, connector request binding, connector run intent/idempotency, and owner-scoped lifecycle state use `executionScope`.
- Backend audit always records the requester as actor and the connection owner as subject where the schema supports both.
- Request hashes continue to bind the backend-local connection ID, connector connection ID, action ID, and input; the scope split must not weaken replay protection.

The original shared-identity correction did not require changing `ConnectorTokenService`: it already sets `sub` and `subject_user_id` from the supplied scope. Correct that caller identity; the separately planned action-policy cutover must also migrate execution purpose to `action:execute:v2` and isolate management signing authority.

- [ ] **Step 4: Remove contradictory expectations**

Replace the current clean-stack expectation that member execution against an owner-scoped shared connection returns `409 authorization_failed`. The required result is one successful read action through the backend execution service, followed by assertions on JWT claims, run records, secret scope, and unchanged adjacent tenant state.

- [ ] **Step 5: Keep transit-file downloads owner-scoped without trusting a bare file ID**

Owner-subject execution writes transit metadata under the owner scope. Replace the public bare-ID route with:

```text
GET /integrations/connections/{localConnectionId}/files/{fileId}
```

The backend resolves `localConnectionId` under the requester's current membership/visibility, derives the authoritative owner from the stored connection, and mints `file:read` with requester as actor, owner as subject, and exact `file_id`. The connector continues to authorize PostgreSQL metadata before SeaweedFS. Remove `/integrations/files/{fileId}` without a compatibility route. Prove private denial, membership loss, visibility change, foreign connection/file pairs, expired token, and ownership transfer. The client may rewrite a connector-internal URL only after binding it to the backend-local connection selected for that execution.

- [ ] **Step 6: Verify the identity cutover**

```bash
cd ../ai-backend-marketing-agent
npm test -- packages/runtime/test/integration-action-execution.test.ts packages/runtime/test/connector-token-service.test.ts apps/api/test/integration-action-runtime.test.ts apps/api/test/integrations.test.ts
npm run check

cd ../open-connector
npm test -- src/saas/actions/saas-action-runner.test.ts src/saas/files/seaweedfs-transit-files.test.ts
```

**Gate:** No executable path may issue a shared-connection action/file token with requester/member as subject. Actor and subject remain distinct and test-visible.

---

### Task 2: Make all real RLS tests one CI gate

**Primary files:**

- Modify: `src/saas/testing/postgres-test-database.ts`
- Modify: `src/saas/storage/scoped-query.test.ts`
- Modify: `src/saas/storage/postgres-runtime-database.test.ts`
- Modify: `src/saas/oauth/postgres-refresh-coordinator.test.ts`
- Modify any other test discovered to call `migratePostgres` against `TEST_POSTGRES_URL`
- Modify: `package.json`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Reproduce the remaining failure with the named gate**

`test:rls`, the PostgreSQL 16 CI service, and per-suite database helper now exist. On a fresh PostgreSQL 16 instance the current gate reports 27 passed and one failure:

```text
updates visibility only for the active scoped owner with an owner or admin role
```

The failing fixture creates `memberStore` with a deterministic `localConnectionId` unrelated to the shared connection, proves `get()` can see the workspace row, then expects execution-oriented `list()` to ignore the JWT local-connection binding. Preserve this reproduction before changing the assertion.

- [ ] **Step 2: Freeze the two list contracts**

Add explicit real-RLS tests:

- `list()` with a scope bound to the shared connection's backend-local UUID returns only that selected shared connection;
- `list()` with a foreign/unrelated `local_connection_id` returns no row;
- `listSafeConnections()` returns all safe active private-owned/workspace-shared metadata visible to the requester without a selected connection;
- tenant, workspace, private-owner, inactive-status, and foreign-ID probes remain empty.

Do not make the gate green by deleting:

```sql
AND ($4::uuid IS NULL OR local_connection_id = $4)
```

Change production SQL only if the correctly bound execution test still fails.

- [ ] **Step 3: Preserve database-boundary test isolation**

Keep `src/saas/testing/postgres-test-database.ts` as the one helper using `pg` and the existing CI PostgreSQL server:

- connect through an administrative URL;
- create a random database and unique migrator/runtime roles per suite;
- run connector migrations only inside that database;
- return admin, migrator, and runtime connection strings;
- terminate remaining connections, drop the database, drop owned objects, and drop roles in `finally`;
- include process/worker/random identity in names and safely quote identifiers;
- fail cleanup loudly while preserving the original test failure.

Every real suite owns its database from `beforeAll` through `afterAll`. Do not solve failures with Vitest serialization, retries, sleeps, shared-schema truncation, or order-dependent cleanup.

- [ ] **Step 4: Add the mandatory CI service and gate**

In `.github/workflows/ci.yml`, start PostgreSQL 16 with a health check and a CI-only administrative user allowed to create databases and roles. Run `npm run test:rls` as a separate named step after unit tests. The command must fail when `TEST_POSTGRES_URL` is absent; only the default unit-test command may skip external PostgreSQL suites.

- [ ] **Step 5: Verify combined and repeated execution**

```bash
TEST_POSTGRES_URL=postgres://... npm run test:rls
TEST_POSTGRES_URL=postgres://... npm run test:rls
```

Run the gate twice against the same server to prove teardown is complete. Then run the exact CI job locally or in the PR workflow.

**Gate:** Every real RLS suite passes together, twice, with no skipped suite, leaked database, leaked role, or order dependence.

---

### Task 3: Verify the final Docker image, not only source

**Primary files:**

- Modify: `scripts/verify-no-legacy-runtime.ts`
- Modify: `scripts/verify-no-legacy-runtime.test.ts`
- Modify: `package.json`
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/publish-docker.yml`
- Modify: `docker/Dockerfile` only if the verifier finds an actual image defect

- [ ] **Step 1: Define a denylist over executable behavior**

The verifier must reject an image containing or launching any removed runtime surface, including:

- legacy server/Cloudflare/SQLite/D1/static-token/direct-MCP/provider-proxy entrypoints;
- legacy runtime/admin token configuration;
- an additional server command or alternate Docker runtime;
- original public console assets or runtime-token UI;
- package scripts that can launch a legacy path.

Keep the denylist centralized and shared with source/config checks. Do not use a single repository text search: comments, plans, and tests are not executable image contents.

- [ ] **Step 2: Add image mode**

`npm run verify:no-legacy-runtime -- --image <immutable-ref-or-local-id>` must:

1. inspect OCI config (`Entrypoint`, `Cmd`, user, working directory, environment, healthcheck, exposed ports);
2. create but not start a container and export its root filesystem;
3. inspect the shipped `package.json`, application files, production dependencies, scripts, built assets, and executable import targets;
4. assert the sole runtime command is the SaaS entrypoint, the user is non-root, and no denied file/config/script exists;
5. run the image with required configuration intentionally absent and require a non-zero fail-closed exit before listen;
6. emit only paths/config keys and hashes, never file contents that may contain secrets.

Use Docker/OCI primitives already available in CI. Do not add an image-scanning dependency just for archive traversal.

- [ ] **Step 3: Test the verifier against synthetic bad images/filesystems**

Cover at minimum: legacy entrypoint restored, hidden alternate npm script, forbidden built web asset, wrong `Cmd`, root user, extra exposed public port, and clean SaaS image. The test must demonstrate that source mode can pass while image mode fails.

- [ ] **Step 4: Gate both CI and publication**

The PR CI job builds `docker/Dockerfile`, loads the image locally, and runs image mode. In `publish-docker.yml`, verify each architecture-specific image digest before it is admitted to the merged manifest. A failed architecture must prevent all release tags from being created.

- [ ] **Step 5: Verify**

```bash
docker build -f docker/Dockerfile -t open-connector:verify .
npm run verify:no-legacy-runtime -- --image open-connector:verify
```

**Gate:** The exact image intended for execution passes; checking out clean source is not sufficient.

---

### Task 4: Add a mandatory self-provisioning clean-stack E2E

**Primary files:**

- Modify: `../ai-backend-marketing-agent/apps/api/test/saas-stack.e2e.test.ts`
- Modify: `../ai-backend-marketing-agent/infra/saas-e2e/docker-compose.yml`
- Modify: `../ai-backend-marketing-agent/scripts/run-saas-clean-stack.ts`
- Modify as needed: `../ai-backend-marketing-agent/infra/saas-e2e/provider-fixture/**`
- Modify: `../ai-backend-marketing-agent/package.json`
- Create: `../ai-backend-marketing-agent/.github/workflows/open-connector-clean-stack.yml`
- Reuse the connector image produced and verified by Task 3

- [ ] **Step 1: Replace environment-heavy manual setup with one command**

Provide:

```bash
npm run test:saas-stack:clean
```

The command must:

1. create a unique Compose project and empty volumes;
2. start PostgreSQL 16, OpenBao, SeaweedFS, a deterministic provider fixture, the backend image, and the verified connector image;
3. initialize backend and connector schemas, separate migrator/runtime roles, forced RLS, OpenBao mounts/policies/tokens, JWKS signing material, and a dedicated SeaweedFS bucket;
4. create two tenants, an owner and member in tenant A, and an adjacent user in tenant B through one explicit fixture/bootstrap owner;
5. wait on readiness, run the scenario once, and always destroy containers, networks, and volumes.

No pre-existing database, manually minted JWT, root OpenBao token used by the connector, external SaaS credential, or developer machine state may be required.

- [ ] **Step 2: Use production paths without adding a production test endpoint**

The E2E runner may invoke production backend service composition from a one-shot test container, but must not add an HTTP action-execution endpoint to the production API. It must call the real backend authorization/repository/token service and real connector HTTP client. The connector must run its normal image command.

Use an existing self-hosted provider whose guarded runtime supports the deployment-gated private-network option, backed by a deterministic fixture server on the E2E network. Enable private-network provider access only in this isolated Compose project. Do not weaken the default SSRF policy or ship a fake provider in the connector image.

- [ ] **Step 3: Exercise the complete chain**

The scenario must prove:

```text
backend membership/role/billing/product checks and remote OpenConnector permission decision
-> backend execution intent and audit
-> exact owner-subject action:execute:v2 JWT, retaining requester as actor
-> connector JWT verification and current requester action-policy check
-> owner-scoped forced-RLS transaction and OpenBao credential read
-> guarded provider read action
-> connector/backend run completion
-> SeaweedFS transit object create/read/purge
-> shared ownership transfer during member removal
-> workspace export and purge
-> adjacent tenant unchanged in PostgreSQL, OpenBao, and SeaweedFS
```

Also probe private-connection access, foreign local/connector/workspace/subject IDs, mismatched request hash, wrong purpose, expired token, replayed lifecycle request, and restart between durable lifecycle steps.

- [ ] **Step 4: Make skip impossible in gate mode**

`SAAS_STACK_E2E=1` with missing configuration must throw before test discovery rather than produce a skipped green test. The orchestrator owns all generated values and passes them explicitly to the runner. Default unit tests may continue to exclude this expensive suite.

- [ ] **Step 5: Gate every releasable connector change**

Run the clean-stack command in CI for changes to connector runtime/storage/auth/Docker files or backend integration/auth/storage files, and unconditionally on release candidates. Upload container logs and non-secret state summaries on failure. Never upload OpenBao tokens, credentials, JWTs, database URLs, or object contents.

**Gate:** One clean command, from empty volumes, proves the complete backend → connector → PostgreSQL → OpenBao → SeaweedFS path and tenant-B non-interference using the already verified image.

---

### Task 5: Require live production cutover evidence

**Primary files:**

- Modify: `../ai-backend-marketing-agent/scripts/verify-open-connector-cutover.ts`
- Modify: `../ai-backend-marketing-agent/scripts/verify-open-connector-cutover.test.ts`
- Create: `../ai-backend-marketing-agent/scripts/collect-open-connector-cutover-evidence.ts`
- Create: `../ai-backend-marketing-agent/scripts/collect-open-connector-cutover-evidence.test.ts`
- Create: `../ai-backend-marketing-agent/.github/workflows/open-connector-production-cutover.yml`
- Modify: `../ai-backend-marketing-agent/.github/workflows/open-connector-cutover-gate.yml`
- Modify: `../ai-backend-marketing-agent/infra/operations/pilot-go-live-checklist.md`
- Reuse: image verifier and clean-stack evidence from Tasks 3–4

- [x] **Step 1: Define a machine-readable, non-secret evidence record**

The production verification command writes one JSON record containing:

- environment and timestamp;
- approved connector manifest digest and actual running container/task digest;
- backend and connector migration versions/checksums;
- forced-RLS probe result and runtime-role attributes;
- legacy SQLite/D1/KV/R2/static-token inventory counts and stable non-secret hashes;
- backend/connector connection reconciliation counts and mismatch count;
- OpenBao policy names plus capability results;
- SeaweedFS bucket access/prefix probe result;
- clean-stack workflow run/revision that qualified the same digest;
- verifier version/revision and overall pass/fail.

Never include tokens, secret values, JWTs, database URLs, OpenBao paths containing customer identifiers, plaintext mappings, or object contents.

The collector, not the verifier, owns live probes. It must read deployment state, PostgreSQL catalogs/migration ledgers, legacy inventories, OpenBao self-capabilities, SeaweedFS prefix permissions, reconciliation counts, backup-restore records, and the image/clean-stack qualifications. The verifier remains a pure fail-closed evaluator of the resulting schema. Tests recursively reject secret-bearing keys and prove that manually asserting `passed` cannot replace an absent probe.

- [x] **Step 2: Fail closed on legacy data and reconciliation**

Before rollout:

- run the legacy-state audit against every known deployed legacy store;
- if the result is zero, record zero-state evidence;
- if rows exist, require an operator-supplied exact tenant/workspace/owner/local-ID mapping and run the isolated migration described by the single-runtime cutover plan;
- abort on unmapped, duplicate, foreign, or guessed ownership;
- require backend rows, connector rows, owner/visibility/provider/local IDs, OpenBao secret counts, and active SeaweedFS references to reconcile exactly.

Do not keep a permanent credential importer in either production image.

- [x] **Step 3: Prove least-privilege OpenBao access with the deployed token**

Use OpenBao's token lookup and `sys/capabilities-self` with the actual connector token. Require only the exact capabilities needed for connector connection/OAuth secret paths. Explicitly require denial for root/system administration, policy/auth/mount management, backend service-secret prefixes, a foreign/unowned prefix, and broad list operations not used by runtime code. Root-token or dev-mode OpenBao is an automatic production failure.

- [x] **Step 4: Prove immutable deployment identity**

Resolve the approved multi-arch manifest to the platform digest and compare it with the digest reported by the running production workload. Tags are informational only. Abort when Compose/task configuration references a mutable tag, when the running digest differs, or when the digest lacks successful image-verifier and clean-stack attestations from the same commit.

- [x] **Step 5: Make verification an environment-protected deployment gate**

The production deployment workflow must execute, in order:

1. backups/snapshots and restore verification;
2. pre-cutover legacy-state and ACL checks;
3. migration under the dedicated migrator identity;
4. rollout by immutable digest;
5. readiness and live digest verification;
6. reconciliation and tenant-isolation probes;
7. signed evidence upload to the protected deployment record.

Any mismatch blocks promotion and leaves the prior image available for rollback. Production credentials stay in the protected environment and are never available to pull-request workflows.

`open-connector-production-cutover.yml` is the missing in-repository caller. It runs on a protected self-hosted runner that can reach private services, collects evidence with short-lived/read-only credentials, uploads the evidence artifact, invokes `open-connector-cutover-gate.yml`, attests the passing record, and makes promotion depend on that job. A reusable `workflow_call` file with no caller is not a release gate.

- [ ] **Step 6: Verify fail-closed behavior before production use**

Against a staging deployment, deliberately test: mutable tag, wrong digest, one legacy row, one reconciliation mismatch, runtime role with `BYPASSRLS`, excessive OpenBao capability, root token, missing SeaweedFS access, and absent clean-stack attestation. Every case must block promotion.

**Production gate:** Promotion is allowed only when Tasks 1–4 are green and the protected production job emits a passing live evidence record for the exact running digest. Repository state alone can never satisfy Task 5.

---

### Task 6: Run the final no-exceptions acceptance gate

**Files and evidence:**

- Modify after success: `CHANGELOG.md`
- Modify after success: `../ai-backend-marketing-agent/CHANGELOG.md`
- Modify: `../ai-backend-marketing-agent/infra/operations/pilot-go-live-checklist.md`
- Produce without committing secrets: image qualification, clean-stack qualification, and signed production cutover record

- [ ] **Step 1: Run connector gates from a clean checkout**

```bash
npm ci
npm run fix-check
npm run build
npm run upstream:protected
npm run verify:no-legacy-runtime
npm test
TEST_POSTGRES_URL=postgres://... npm run test:rls
docker build -f docker/Dockerfile -t open-connector:final .
npm run verify:no-legacy-runtime -- --image open-connector:final
```

No skipped RLS suite, source-only image substitute, retry masking, or warning downgrade is accepted.

- [ ] **Step 2: Run backend and clean-stack gates from a clean checkout**

```bash
cd ../ai-backend-marketing-agent
npm ci
npm run check
npm run lint
npm test
npm run check:integration-catalog
npm run test:saas-stack:clean
```

The clean-stack qualification records the exact backend commit, connector commit, and image digest. Gate mode fails if any scenario skips.

- [ ] **Step 3: Execute the complete negative matrix**

For tenant, workspace, actor, subject, role, purpose, action, local/connector connection, request hash, OAuth state, file/connection pair, lifecycle target, and idempotency key, test missing, foreign, expired, replayed, and mismatched values. Assert no foreign PostgreSQL row, OpenBao path, SeaweedFS object, provider request, or audit attribution changes.

- [ ] **Step 4: Run protected staging and production workflows**

Staging deliberately proves fail-closed behavior for wrong digest, one legacy row, one reconciliation mismatch, `BYPASSRLS`, excessive OpenBao capability, missing SeaweedFS prefix permission, failed restore verification, and absent/mismatched clean-stack qualification. Production then collects fresh live evidence for the candidate digest and emits the signed record.

- [ ] **Step 5: Apply the declaration gate**

The project may say **“OpenConnector is fully multi-user/multi-tenant”** only when all are simultaneously true:

1. member execution of an owner-scoped shared connection succeeds with member-as-actor and owner-as-subject;
2. owner-scoped transit files download only through a currently authorized backend-local connection/file pair;
3. every real RLS suite passes together twice, with no skip, leak, or order dependence;
4. the final per-platform image digest passes image-mode legacy verification;
5. mandatory clean-stack qualification proves adjacent-tenant non-interference across PostgreSQL, OpenBao, SeaweedFS, provider egress, and lifecycle;
6. the running production workload equals the approved immutable digest;
7. legacy state is zero or explicitly migrated and reconciled;
8. deployed OpenBao and SeaweedFS credentials have only the required scoped capabilities;
9. a protected signed record links production, image verification, clean-stack qualification, migration checksums, restore verification, and the same backend/connector revisions.

- [ ] **Step 6: Update changelogs only after the signed gate passes**

Document verified behavior, final factual catalog counts, and the non-secret evidence record identifier. Do not publish internal addresses, credentials, JWTs, database URLs, customer mappings, secret paths containing customer identifiers, or object contents.

---

## Completion criteria

A failed RLS test, skipped clean-stack scenario, missing deployment caller, unsigned/stale production record, subject-model contradiction, or bare file-ID authorization keeps the cutover status **incomplete**. There is no follow-up phase for an item in this plan.
