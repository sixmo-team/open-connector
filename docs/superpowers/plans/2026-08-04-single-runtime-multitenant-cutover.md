# Single-Runtime Multi-Tenant Cutover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans`. This is the final destructive cutover. Complete the workspace/lifecycle and full-provider plans first.

**Goal:** Make the multi-tenant SaaS runtime the only executable OpenConnector runtime, remove the SQLite/D1/static-token/direct-MCP/proxy/public-console paths, publish one production image, and prove that every supported start/development/deployment path enforces the same tenant/workspace/user boundary.

**Superseded decisions:** This plan intentionally supersedes the following constraints from `2026-08-04-native-multitenant-integration-runtime.md`:

- preserving upstream local/SQLite and Cloudflare behavior;
- treating all existing `src/server/**` and original console/runtime files as permanently protected;
- retaining separate `Dockerfile` and `Dockerfile.saas` product paths;
- keeping upstream runtime entrypoints available after product cutover.

Provider definitions, action schemas, executors, generated-registry mechanics, and reusable core OAuth/execution code remain upstream-syncable. Only unsafe single-instance runtime surfaces are removed.

## Required end state

1. `npm start`, `npm run dev`, the published Docker image, and backend Compose all launch `src/saas/index.ts` (or its built equivalent) and fail closed without PostgreSQL, OpenBao, JWKS, and SeaweedFS configuration.
2. No package script, Dockerfile, workflow, worker config, import, or documentation can launch `src/server/index.ts`, SQLite, D1, static runtime/admin tokens, direct MCP, arbitrary provider proxy, public static console, or Cloudflare single-instance runtime.
3. Exactly one OpenConnector runtime image exists. There is no safe/unsafe image selection left to operators.
4. The system-admin SaaS console remains a separate build/container reachable only through the existing SSH-tunnel + backend-admin boundary. The original user-facing OpenConnector console is removed.
5. Existing production data is either explicitly mapped/imported into tenant/workspace/user scope or blocks cutover. No row receives a guessed owner and no legacy credential is silently discarded.
6. CI proves the absence of legacy runtime entrypoints and scans the built image/package, not only source imports.
7. The backend remains the only Internet-facing component and the only identity/lifecycle authority.

## Removal inventory

The implementation agent must confirm references before deleting, but the intended runtime removals are:

```text
src/server/index.ts
src/server/connect-app.ts
src/server/connect-server.ts
src/server/cloudflare.ts
src/server/cloudflare/**
src/server/proxy/**
src/server/secrets/** legacy local/D1 codecs
src/server/storage/sqlite-runtime-store*
src/server/storage/d1-runtime-store*
src/server/storage/runtime-token-service*
src/server/api/** legacy static/admin/runtime/MCP/proxy routes
src/server/files/** local/KV/R2 implementations
scripts/dev-local.ts
wrangler.example.jsonc
original web entry/build configuration and pages not imported by web/src/saas/**
```

Small contracts/utilities currently imported by `src/saas/**` are moved to `src/core/**` or `src/saas/**` first. Do not keep the whole legacy runtime merely because the SaaS code imports five interfaces/helpers from it.

---

### Task 1: Replace the old protected-upstream rule with a cutover guard

**Files:**

- Modify: `.upstream-base`
- Modify: `scripts/check-protected-upstream.ts`
- Modify: `scripts/check-protected-upstream.test.ts`
- Create: `scripts/legacy-runtime-denylist.ts`
- Create: `scripts/legacy-runtime-denylist.test.ts`
- Modify: `.github/workflows/upstream-compat.yml`
- Modify: `package.json`

- [ ] **Step 1: Add failing guard tests**

The guard must fail when any supported script/image/workflow references legacy entrypoints or forbidden environment variables, when a deleted legacy runtime file is restored, or when provider/core source changes without upstream review. It must pass deliberate deletion of the enumerated runtime files.

Deny at minimum:

```text
src/server/index.ts
src/server/cloudflare.ts
SqliteRuntimeDatabase
D1RuntimeDatabase
OOMOL_CONNECT_RUNTIME_TOKEN
OOMOL_CONNECT_ADMIN_TOKEN
/api/mcp
/mcp
provider proxy routes
wrangler deploy
```

Do not flag reusable type names after they are moved to safe owners; the guard checks executable/import/config behavior, not comments in this plan.

- [ ] **Step 2: Preserve upstream sync where it still matters**

Protect `src/providers/**`, provider registries/generators, `src/core/**`, and reusable OAuth/connection services against unreviewed fork drift. Replace the former blanket protection of all `src/server/**`/`web/**` with an explicit post-cutover allow/deny policy.

- [ ] **Step 3: Add `npm run verify:no-legacy-runtime` to CI**

The command inspects package scripts, source import graph, Dockerfiles, Compose/workflows, and final build/image contents. It must not rely on a text search alone.

- [ ] **Step 4: Verify**

```bash
npm test -- scripts/check-protected-upstream.test.ts scripts/legacy-runtime-denylist.test.ts
npm run upstream:check
npm run upstream:protected
npm run verify:no-legacy-runtime
```

Expected: guard tests pass against the pre-cutover inventory while identifying every removal target.

- [ ] **Step 5: Commit**

Commit guard changes before deleting protected legacy files.

---

### Task 2: Move the few SaaS-owned contracts out of `src/server/**`

**Files:**

- Move: `src/server/actions/action-idempotency.ts` to a core/SaaS owner
- Move: `src/server/actions/run-log-summary.ts` to a core/SaaS owner
- Move: `src/server/files/transit-file-store.ts` to a core/SaaS owner
- Move: `src/server/storage/idempotency-store.ts` to a core/SaaS owner
- Move: `src/server/storage/runtime-store.ts` to a core/SaaS owner
- Move the minimal runtime action-result parser used by `src/saas/storage/postgres-idempotency-store.ts`
- Modify every SaaS import and focused test import

- [ ] **Step 1: Use symbol references before each move**

Identify all consumers. Keep only contracts/helpers used by the SaaS runtime or provider core. Do not move legacy route handlers, static-token types, SQLite/D1 abstractions, proxy APIs, or UI-specific models.

- [ ] **Step 2: Move without compatibility re-exports**

Use one canonical owner. Update every caller and test. Do not leave barrels, aliases, or deprecated `src/server/**` shims.

- [ ] **Step 3: Verify focused behavior**

```bash
npm test -- src/saas/actions src/saas/files src/saas/storage
npm run typecheck
```

Expected: `src/saas/**` has no import from `src/server/**`.

- [ ] **Step 4: Commit**

Commit pure moves/import updates separately from deletions.

---

### Task 3: Gate legacy state before deleting import code

**Files:**

- Create: `scripts/audit-legacy-runtime-state.ts`
- Create: `scripts/audit-legacy-runtime-state.test.ts`
- Create temporarily only when needed: an operator-only import program outside production runtime imports
- Modify: deployment runbook owning the connector cutover

- [ ] **Step 1: Inventory every deployed legacy store**

Check known SQLite data paths, D1 databases/namespaces, KV/R2 transit files, and legacy secret-codec configuration. Produce counts and non-secret stable hashes only. Never print credentials, OAuth state, token values, or decrypted payloads.

- [ ] **Step 2: Take the zero-state fast path when proven**

If no legacy deployment/data exists, record the signed deployment evidence and proceed. Do not build a speculative permanent importer.

- [ ] **Step 3: If rows exist, require an explicit mapping**

Each connection mapping includes exact tenant, workspace, owner user, backend local connection UUID, provider, and legacy connection ID. Validate current backend membership and uniqueness. Unmapped/duplicate/foreign rows abort the import; never infer tenancy from a connection name or label.

- [ ] **Step 4: Import through the new stores**

Decrypt only in the isolated migration process, write credentials directly to exact OpenBao paths, write connector PostgreSQL metadata under forced-RLS scope, verify safe fingerprints/counts, then destroy plaintext buffers and the temporary import artifact. Do not send credentials through backend HTTP or logs.

OAuth states, static runtime/admin tokens, and expired transit files are not migrated. Active transit objects are migrated only if an authoritative tenant/workspace/user owner exists and the product still references them.

- [ ] **Step 5: Prove reconciliation before cutover**

For every imported connection, backend and connector IDs/owner/provider/visibility agree; `local_connection_id` is non-null; OpenBao holds one scoped secret; and the legacy store remains read-only until final acceptance.

- [ ] **Step 6: Verify and commit only the reusable audit gate**

The temporary credential importer must not remain in the runtime package or production image after migration. The committed audit command blocks future cutovers when legacy data reappears.

---

### Task 4: Delete Node and Cloudflare single-instance runtimes

**Files:**

- Delete the confirmed legacy files under `src/server/**`
- Delete: `scripts/dev-local.ts`
- Delete: `wrangler.example.jsonc`
- Delete Cloudflare-only generated registry/build/copy paths if no safe consumer remains
- Modify: `scripts/generate-provider-registry.ts`
- Modify: `scripts/typecheck.ts`
- Modify: `tsconfig.json`
- Modify: `vitest.config.ts`

- [ ] **Step 1: Delete executable surfaces and their tests together**

Remove local server, ConnectApp, static/admin/runtime API, direct MCP, proxy, SQLite/D1/runtime-token storage, Cloudflare worker/bindings, local/KV/R2 file service, and local secret-codec implementations. Delete tests that test only removed behavior; do not translate them into SaaS tests unless they defend a still-required provider/core contract.

- [ ] **Step 2: Remove dead dependencies and generation outputs**

Remove packages used only by SQLite/D1/Cloudflare/static UI runtime. Generate only the provider registries consumed by the remaining runtime. Do not add replacement abstractions.

- [ ] **Step 3: Prove no dangling import/config**

```bash
npm run typecheck
npm run verify:no-legacy-runtime
npm test -- src/saas src/core src/oauth src/providers
```

Expected: no source/build/test imports a deleted runtime module and all provider executors remain loadable lazily.

- [ ] **Step 4: Commit**

Commit runtime deletion and dependency cleanup in one reviewable cutover commit.

---

### Task 5: Remove the original console and keep only the SaaS admin build

**Files:**

- Delete: `web/src/main.tsx`
- Delete original console pages/tests not imported by `web/src/saas/**`
- Delete or replace: `web/vite.config.ts`
- Modify: `web/package.json`
- Modify: root `package.json`
- Modify: `web/vite.saas.config.ts`
- Modify: SaaS admin tests only where imports move

- [ ] **Step 1: Trace SaaS imports**

Keep shared components, styles, theme, icons, and provider display models actually imported by `web/src/saas/**`. Delete original unlock/access/policy/runtime-token/resource pages and routes that have no SaaS consumer.

- [ ] **Step 2: Make SaaS admin the only web build**

`npm run build:web` builds the system-admin SaaS console. Remove `build:web:saas` duplication if it no longer distinguishes anything. No build emits an unauthenticated original console shell.

- [ ] **Step 3: Preserve the network boundary**

The built admin assets remain served only by the backend management container bound to server loopback and protected by system-admin auth. OpenConnector itself does not serve static assets.

- [ ] **Step 4: Verify**

```bash
npm run build:web
npm test --workspace web
npm run verify:no-legacy-runtime
```

Inspect the build output: no runtime-token prompt, direct connector URL, MCP/proxy page, original API client, or public console route exists.

- [ ] **Step 5: Commit**

Commit console deletion/build simplification.

---

### Task 6: Collapse scripts and Dockerfiles to one SaaS runtime

**Files:**

- Modify: `package.json`
- Replace: `docker/Dockerfile` with the current hardened SaaS image definition
- Delete: `docker/Dockerfile.saas`
- Modify: `.github/workflows/publish-docker.yml`
- Modify: other build/release workflows referencing either image
- Modify: `../ai-backend-marketing-agent/docker-compose.yml`
- Modify: `../ai-backend-marketing-agent/.env.example`

- [ ] **Step 1: Make every supported command equivalent**

Target scripts:

```json
{
  "start": "node src/saas/index.ts",
  "start:saas": "node src/saas/index.ts",
  "dev": "node --watch src/saas/index.ts"
}
```

`start:saas` may remain temporarily as an exact alias for deployment compatibility, but it cannot point elsewhere. Remove `dev:api`, Cloudflare deploy/dev, local runtime data, and original web scripts.

- [ ] **Step 2: Publish one image**

Move the existing multi-stage, non-root, read-only-compatible SaaS build to `docker/Dockerfile`; delete the alternate Dockerfile. The image command starts only SaaS, exposes only the internal runtime port, and has `/health`/`/ready` checks.

- [ ] **Step 3: Fail closed on configuration**

All start/dev/image paths call `readSaasConfig()` before listening. Missing PostgreSQL runtime role, migrator checksum, forced RLS, JWKS, OpenBao, or SeaweedFS configuration exits non-zero. There is no SQLite or plaintext fallback.

- [ ] **Step 4: Update backend deployment**

Compose references one immutable image digest and contains no rollout stage/canary variables after the provider plan. Connector has no host port/public ingress; only backend integration network access remains.

- [ ] **Step 5: Verify image contents and command**

Build the published Dockerfile, inspect its configured command and file list, start it once with missing config (must fail), then with the full test stack (must become ready). Run `verify:no-legacy-runtime` against the image filesystem.

- [ ] **Step 6: Commit**

Commit OpenConnector packaging/workflows, then backend Compose/env changes.

---

### Task 7: Update public/operator documentation to the only supported model

**Files:**

- Modify: `README.md`
- Modify existing deployment/security/operator documentation
- Modify: `docs/contracts/saas-runtime.openapi.yaml` only if stale
- Modify: `AGENTS.md`

- [ ] **Step 1: Remove unsafe instructions**

Delete instructions for local SQLite runtime, static admin/runtime tokens, direct MCP/proxy access, Cloudflare/D1 deployment, original console, and upstream GHCR image if that image is not this fork's verified SaaS image.

- [ ] **Step 2: Document one architecture**

Document backend-only ingress, exact JWT purposes, PostgreSQL forced RLS role, OpenBao paths/policy, SeaweedFS, system-admin console tunnel, migration order, lifecycle reconciliation, and one production image.

- [ ] **Step 3: State development requirements honestly**

Local development requires the same scoped dependencies or test doubles that preserve claims and isolation. Do not advertise a convenient single-user fallback.

- [ ] **Step 4: Update repository instructions**

Remove the old rule requiring preservation of local/Cloudflare behavior and protected legacy files. Keep provider metadata/executor/lazy-loading/style rules.

- [ ] **Step 5: Verify links/commands**

Run every documented start/build/migrate command in the test environment. No documentation path may start a legacy server.

- [ ] **Step 6: Commit**

Commit documentation only after runtime/image smoke tests pass.

---

### Task 8: Run the final multi-tenant cutover proof

**Files:**

- Create or modify the existing full-stack SaaS smoke test
- Modify release workflow gates
- Modify `CHANGELOG.md` only after success

- [ ] **Step 1: Start the exact release graph**

Use the published-candidate OpenConnector image, backend API image, PostgreSQL with separate owner/migrator/runtime roles, OpenBao with least privilege, SeaweedFS, and backend JWKS. Do not launch source entrypoints or test-only bypass services.

- [ ] **Step 2: Exercise all runtime surfaces**

For two tenants and multiple users:

```text
catalog -> OAuth and credential connections -> private execution
-> workspace sharing -> second-user execution -> run listing
-> ownership transfer -> user export/purge -> workspace export/purge
-> tenant export/purge -> restart -> idempotent reconciliation
```

Use at least one Google OAuth provider, one non-Google OAuth provider, one API-key/custom provider, and the existing native Yandex Direct or VK Ads path to prove collision handling.

- [ ] **Step 3: Attempt every removed path**

Confirm no listener/route/build supports original `/api`, direct MCP, arbitrary proxy, static runtime/admin token, original console, Cloudflare worker, SQLite file, D1 binding, or old Docker command. Requests return 404/connection refusal; they do not redirect to a compatibility shim.

- [ ] **Step 4: Run cross-scope attacks**

Attempt foreign local/connector connection IDs, forged identity headers, service catalog token on data routes, actor/subject swaps, workspace-shared access from another workspace, lifecycle replay, stale visibility correlations, and direct database access as runtime role. No foreign row, OpenBao secret, object, run, OAuth state, or provider call is reachable.

- [ ] **Step 5: Run all release checks**

```bash
# open-connector
npm ci
npm run upstream:check
npm run upstream:protected
npm run verify:no-legacy-runtime
npm run generate:catalog
npm run fix-check
npm run build:web
npm test

# backend
cd ../ai-backend-marketing-agent
npm ci
npx tsc --noEmit
npm test

# mobile if its contract changed
cd ../ai-marketing-agent-user-mobile
npm ci
npx tsc --noEmit
npm test
npm run export:web
```

- [ ] **Step 6: Inspect release artifacts**

Verify image digest, non-root user, command, no host port, no legacy files/dependencies, migration checksums, SBOM/dependency audit, and readiness probes. The release workflow refuses any second runtime image.

- [ ] **Step 7: Completion criteria**

OpenConnector may be called fully multi-user/multi-tenant only when all are true:

- every supported start/dev/deploy command launches the SaaS runtime;
- one production image exists;
- private/workspace visibility and transfer pass end to end;
- all admitted providers use the same scoped boundary;
- run/export/delete lifecycle is complete and restart-safe;
- `local_connection_id` is `NOT NULL`;
- every runtime table is forced-RLS probed;
- no SQLite/D1/static-token/direct-MCP/proxy/original-console runtime remains;
- release artifact and live graph pass the cross-tenant proof.

- [ ] **Step 8: Add changelog and commit**

Record this as a clean cutover with no compatibility runtime. Do not retain aliases, shims, deprecated routes, or a second image.

---

## Rollback rule

Rollback uses the previous **multi-tenant SaaS** image and compatible database migration state. It must never restart the deleted single-instance runtime. If the contract migration has applied, rollback images must understand required `local_connection_id`, visibility synchronization, lifecycle tables, and every probed RLS table.

## Final architectural statement

After this plan, the repository contains reusable provider/core code plus one scoped SaaS runtime. “OpenConnector” no longer means “safe only when the operator happens to choose `Dockerfile.saas`”; the unsafe choice does not exist.
