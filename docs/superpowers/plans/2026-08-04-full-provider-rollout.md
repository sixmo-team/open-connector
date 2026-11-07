# Full Provider Catalog Rollout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans`. Complete `2026-08-04-workspace-sharing-and-lifecycle-completion.md` first.

**Актуальная рамка (2026-11-06):** [Границы сервисов](../specs/2026-11-06-service-boundaries-and-upstream-sync-design.md) и [будущее обновление main → multitenant](2026-11-06-upstream-main-multitenant-sync.md). Прочитать все актуальные основания до слияния; сохранить полный внутренний каталог, но не включать исходные добавления автоматически. Допуск интеграции в продукт принадлежит бекенду ИИ-маркетолога, разрешения её функций — OpenConnector.

**Goal:** Remove the Google-only and canary-only product restrictions while preserving fail-closed authorization, per-action safety classification, per-tenant entitlements/grants, schema-drift checks, and exact tenant/user connection selection.

**Historical starting gaps (August 2026; verify against current implementation before executing):**

- `packages/runtime/src/integrations/service.ts` filters catalog, connection, reconnect, revoke, visibility, and provider resolution through `googleProviderIds`.
- `INTEGRATION_CONNECTOR_ROLLOUT_STAGE` defaults to `disabled`, and tool-registry startup depends on one canary tenant/workspace/user.
- action classifications cover only the confirmed Google set;
- provider credential revocation is Google-specific;
- the UI can render dynamic providers, but backend policy prevents non-Google providers from reaching it.

**Definition of full rollout:** Every exposed action has reviewed classification and schema fingerprints; product availability is independently constrained by backend configuration, authentication readiness and entitlement. After the action-policy cutover, OpenConnector alone stores/resolves the requester's individual/default action permissions and checks them before execution. Missing both still denies; backend role, billing and approval checks remain mandatory.

**Service-boundary follow-up (2026-11-06):** [Общие разрешения действий OpenConnector](2026-11-06-default-integration-action-permissions.md) gives OpenConnector sole action-enable ownership and adds common rules using the existing bulk console. There are no real users: use empty new policy tables and a direct cutover, not import or compatibility with old test grants. This is planned, not current behavior. The separate `Product integration configuration` section below records future backend-owned settings; safety review and the user's consent are not replaced by action enablement.

## Invariants

1. No action is exposed to an agent without a source-controlled classification and exact schema fingerprint.
2. Catalog discovery is not authorization. The backend reloads business access, connection visibility, role, approval and exact request hash; OpenConnector independently reloads its actor-specific effective permission before execution and completed replay.
3. A provider is connectable only when at least one declared auth method is operational. Missing OAuth client configuration is a safe unavailable state, not a late token-exchange failure.
4. Removing canary rollout never removes the billing feature gate or OpenConnector action permissions.
5. Catalog reads use a service-purpose token that cannot list connections, read a database scope, execute actions, access secrets, or call lifecycle routes.
6. Provider/action drift blocks release. It never silently grants a new upstream action.
7. API-key/custom-credential disconnect destroys the local secret. OAuth revocation is attempted when supported; unsupported remote revocation is recorded explicitly and must not prevent legally required local erasure.
8. Yandex Direct and VK Ads remain backend-native providers until an explicit migration plan replaces them; no duplicate connector provider is shown under the same product ID.

## Target product flow

```text
OpenConnector complete generated catalog
-> backend reviewed action support, schemas and safety classification
-> backend product integration configuration, authentication readiness and entitlement
-> OpenConnector batch permission decisions for the requester
-> existing bounded tool search and exact local connection selection
-> backend repeated role/billing/safety/approval checks
-> exact body-bound action:execute:v2 token
-> OpenConnector current actor permission and owner-scoped resource checks
-> existing provider executor
```

---

### Task 1: Add a catalog-only service identity

**Files:**

- Modify: `src/saas/contracts.ts`
- Modify: `src/saas/contracts.test.ts`
- Modify: `src/saas/auth/saas-jwt-verifier.ts`
- Modify: `src/saas/auth/saas-jwt-verifier.test.ts`
- Modify: `src/saas/auth/scoped-request.ts`
- Modify: `src/saas/server/saas-connect-server.ts`
- Modify: `src/saas/server/saas-connect-server.test.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/connector-token-service.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/test/connector-token-service.test.ts`

- [ ] **Step 1: Write failing privilege-separation tests**

A `catalog:read` service token may call only provider/action catalog routes. It must be rejected by connections, OAuth, actions, runs, visibility, transfer, and lifecycle routes. Tenant-scoped tokens continue to work unchanged.

- [ ] **Step 2: Define a separate strict claim shape**

Use `subject_kind: "service"`, exact issuer/audience/purpose/permission, `sub`, `jti`, `iat`, `nbf`, and `exp`. Omit tenant/workspace/user claims so no fake customer principal is required. The verifier returns a catalog principal only to catalog middleware; it can never create a `SaasRequestScope` or call `withScopedClient`.

- [ ] **Step 3: Add backend issuance**

Add a dedicated `issueCatalogToken()` path. Do not overload caller-supplied scope with sentinel tenant IDs. Keep lifetime at most 60 seconds and forbid wildcard permissions.

- [ ] **Step 4: Verify**

```bash
npm test -- src/saas/contracts.test.ts src/saas/auth/saas-jwt-verifier.test.ts src/saas/server/saas-connect-server.test.ts
cd ../ai-backend-marketing-agent && npx vitest run packages/runtime/test/connector-token-service.test.ts --maxWorkers=1
```

Expected: catalog loading no longer depends on a tenant and the service token has no data-plane capability.

- [ ] **Step 5: Commit**

Commit connector and backend changes separately.

---

### Task 2: Build a reviewed full-catalog admission manifest

**Files:**

- Create: `../ai-backend-marketing-agent/packages/runtime/src/integrations/action-classifications/` provider-owned classification modules
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/action-classification.ts`
- Create: `../ai-backend-marketing-agent/scripts/check-integration-catalog.ts`
- Create: `../ai-backend-marketing-agent/packages/runtime/test/integration-catalog-completeness.test.ts`
- Modify: `../ai-backend-marketing-agent/package.json`

- [ ] **Step 1: Generate an inventory, never a safety decision**

The script fetches every paginated connector provider/action with a catalog service token and writes/compares a deterministic inventory containing provider ID, action ID, auth types, required scopes/permissions, and input/output schema fingerprint. It may generate missing-entry stubs in a temporary output, but it must never infer risk, approval, role, idempotency, or limits.

- [ ] **Step 2: Split the existing classifications by provider**

Move the current Google entries without changing values. Use one provider-owned module per provider or a small coherent group when a provider has only a few actions. Generate a deterministic aggregate at build time; do not hand-maintain duplicate provider lists.

- [ ] **Step 3: Classify every executable action**

For each action, review the executor and provider API behavior, then set:

- `risk`: read/write/destructive/access_change;
- `requiresApproval`;
- `idempotency`: safe/keyed/unsafe;
- minimum workspace role;
- bounded input/output bytes;
- exact schema fingerprint.

Unknown, ambiguous, arbitrary-code, arbitrary-HTTP, proxy, credential, permission, billing, deletion, publication, messaging, payment, deployment, or account-management actions default to unavailable until explicitly reviewed. `unsafe` side effects require approval and remain non-replayable after uncertain provider dispatch.

- [ ] **Step 4: Make completeness a release gate**

The test fails when:

- a connector action lacks a classification;
- a classification references a missing action/provider;
- provider IDs differ;
- schema fingerprints drift;
- duplicate action IDs or model tool names exist;
- the catalog exceeds the existing hard admission ceiling;
- a newly introduced provider has no reviewed auth availability policy.

- [ ] **Step 5: Verify**

```bash
cd ../ai-backend-marketing-agent
npm run check:integration-catalog
npx vitest run packages/runtime/test/integration-catalog-completeness.test.ts packages/runtime/test/integration-action-tool-registry.test.ts --maxWorkers=1
```

Expected: zero unclassified executable actions and zero stale classifications.

- [ ] **Step 6: Commit in reviewable provider groups**

Do not commit one unreviewable generated safety blob. Each commit identifies the provider group reviewed and includes its completeness tests.

---

### Task 3: Derive provider availability instead of hard-coding Google

**Files:**

- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/action-classification.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/service.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/admin-service.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/action-tool-registry.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/test/provider-integration-service.test.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/test/integration-admin-service.test.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/test/integration-action-tool-registry.test.ts`

- [ ] **Step 1: Add failing non-Google tests**

Use at least Slack, Notion, HubSpot, GitHub, Jira, Shopify, Stripe, Airtable, Telegram, and one API-key-only provider. Prove catalog listing, credential/OAuth connection, reconnect, visibility, revoke, tool discovery, and execution reach the same generic path as Gmail.

- [ ] **Step 2: Delete `confirmedGoogleIntegrationProviderIds` and `googleProviderIds` as product gates**

Derive the admitted provider set from the reviewed action classifications plus provider availability. Keep product-native `yandex-direct` and `vk-ads` excluded only by an explicit collision map that names their backend-native owner; do not hide unrelated providers.

- [ ] **Step 3: Replace every Google filter**

Update provider listing, connection listing/get, credential connection, OAuth start/reconnect, revoke, visibility, admin totals, and tool registry. There must be one admission predicate reused by all paths, not another independent list.

- [ ] **Step 4: Preserve fail-closed behavior**

A provider absent from the reviewed admission manifest returns 404/unavailable. A connection row cannot make an unadmitted provider executable.

- [ ] **Step 5: Verify**

```bash
cd ../ai-backend-marketing-agent
npx vitest run packages/runtime/test/provider-integration-service.test.ts packages/runtime/test/integration-admin-service.test.ts packages/runtime/test/integration-action-tool-registry.test.ts --maxWorkers=1
npx tsc --noEmit
```

Expected: no production code path references the Google-only set.

- [ ] **Step 6: Commit**

```bash
git add packages/runtime/src/integrations packages/runtime/test
git commit -m "feat: admit the reviewed connector provider catalog"
```

---

### Task 4: Report authentication readiness per provider

**Files:**

- Modify: `src/saas/contracts.ts`
- Modify: `src/saas/server/saas-connect-server.ts`
- Modify: `src/saas/server/saas-connect-server.test.ts`
- Modify: `src/saas/secrets/openbao-oauth-client-config-store.ts`
- Modify: `src/saas/index.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/connector-client.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/service.ts`
- Modify: relevant connector/backend catalog tests

- [ ] **Step 1: Add safe readiness fields**

For each provider, expose only which declared auth types are operational. API-key/custom credential methods are available from definitions. OAuth2 is available only when the platform application exists in OpenBao and passes strict client/config validation. Never expose client IDs, secret refs, redirect secrets, or OpenBao error text.

- [ ] **Step 2: Probe all admitted OAuth applications at startup**

Read exact allowlisted OpenBao paths. Produce a bounded readiness summary. Production startup fails if a provider marked required by the backend admission manifest lacks its OAuth application; optional providers remain hidden/unavailable rather than failing on user callback.

- [ ] **Step 3: Filter connection methods, not provider truth**

A provider with a valid API-key method remains connectable even if OAuth is unconfigured. The backend and mobile render only operational methods.

- [ ] **Step 4: Verify**

Test configured, missing, malformed, wrong-scope, and denied OpenBao paths. Expected: no late OAuth start for an unavailable application and no secret material in catalog/logs.

- [ ] **Step 5: Commit**

Commit connector contract/readiness and backend consumer changes separately.

---

### Task 5: Generalize credential revocation and local erasure

**Files:**

- Rename or replace: `src/saas/connections/google-credential-revoker.ts`
- Create: `src/saas/connections/provider-credential-revoker.ts`
- Create: `src/saas/connections/provider-credential-revoker.test.ts`
- Modify provider OAuth definition types only where optional revocation metadata belongs
- Modify: `src/saas/index.ts`
- Modify: `src/saas/server/saas-connect-server.ts`
- Modify: `src/saas/lifecycle/scoped-lifecycle-service.ts`
- Modify relevant revoke/lifecycle tests

- [ ] **Step 1: Define explicit revocation capabilities**

Reuse provider definition metadata. Add optional revocation endpoint/method/token-kind/auth metadata only where the provider officially supports it. Do not guess endpoints from token URLs and do not encode provider secrets in source.

- [ ] **Step 2: Implement a bounded generic revoker**

Allow only HTTPS endpoints declared in reviewed provider definitions, fixed methods/content types, bounded request/response sizes, no redirects, deadlines, and no private-network targets. Treat documented already-invalid/already-revoked responses as idempotent success.

- [ ] **Step 3: Separate remote revocation from local erasure**

Outcomes are `revoked`, `unsupported`, or `failed`:

- `revoked`: delete local credential and metadata;
- `unsupported`: record a safe audit outcome and delete local credential/metadata;
- `failed`: block execution and retain the secret reference for bounded retry/reconciliation; tenant erasure policy eventually performs cryptographic local erasure with an explicit unresolved-remote-revocation audit record.

API keys/custom credentials normally use `unsupported`; OpenBao deletion still completes disconnect. Never return the credential to the backend to revoke it there.

- [ ] **Step 4: Verify representative providers**

Test Google plus at least two different OAuth revocation shapes, one provider without revocation, API key, malformed provider response, timeout, redirect, private address, and retry after uncertain failure.

- [ ] **Step 5: Commit**

Commit definition metadata separately from generic revoker/runtime wiring.

---

### Task 6: Remove canary and percentage rollout as a product gate

**Files:**

- Modify: `../ai-backend-marketing-agent/packages/runtime/src/config/app-env.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/test/app-env.test.ts`
- Modify: `../ai-backend-marketing-agent/apps/api/src/app.ts`
- Modify: `../ai-backend-marketing-agent/apps/api/test/startup-health.test.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/service.ts`
- Modify: `../ai-backend-marketing-agent/packages/runtime/src/integrations/action-execution-authority.ts`
- Modify: `../ai-backend-marketing-agent/.env.example`
- Modify: `../ai-backend-marketing-agent/docker-compose.yml`

- [ ] **Step 1: Add entitlement-only gate tests**

An entitled tenant can use admitted providers without being a canary. A non-entitled tenant cannot list/connect/execute even when it knows provider, action, local connection, and connector IDs. Grants remain required.

- [ ] **Step 2: Delete rollout-stage selection**

Remove `INTEGRATION_CONNECTOR_ROLLOUT_STAGE`, canary tenant/workspace/actor settings, percentage hashing, and `isCanaryTenant`. `IntegrationConnectorFeatureGate` becomes the existing billing/feature entitlement check only.

- [ ] **Step 3: Remove startup dependence on a customer principal**

`createProductionIntegrationActionToolRuntime` loads the catalog with `issueCatalogToken()`, checks the expected catalog fingerprint, and builds the registry once. It no longer queries a canary membership.

- [ ] **Step 4: Keep operational controls in the right layer**

Emergency product disable belongs to backend product configuration and business gates; the future mutable setting is an intersection with reviewed support, not a replacement for it. OpenConnector independently owns individual/common action permissions; a common default is not a mandatory ceiling over individual exceptions. Preserve existing connection metadata and safe revocation/export when a provider is disabled. Do not add percentage rollout or a second action-permission resolver to the backend.

- [ ] **Step 5: Verify**

```bash
cd ../ai-backend-marketing-agent
npx vitest run packages/runtime/test/app-env.test.ts apps/api/test/startup-health.test.ts packages/runtime/test/provider-integration-service.test.ts packages/runtime/test/integration-action-execution-authority.test.ts --maxWorkers=1
npx tsc --noEmit
```

Expected: repository search finds no `INTEGRATION_CONNECTOR_ROLLOUT_STAGE`, canary integration principal, or `isCanaryTenant`.

- [ ] **Step 6: Commit**

```bash
git add packages/runtime/src/config apps/api/src/app.ts .env.example docker-compose.yml packages/runtime/test apps/api/test
git commit -m "feat: enable connector for entitled tenants"
```

---

### Task 7: Verify dynamic end-user catalog and account selection

**Files:**

- Modify only if needed: `../ai-marketing-agent-user-mobile/src/types/integrations.ts`
- Modify only if needed: `../ai-marketing-agent-user-mobile/src/api/integrations.ts`
- Modify only if needed: `../ai-marketing-agent-user-mobile/app/settings/connections.tsx`
- Modify: existing mobile connection tests
- Modify: backend integration route tests

- [ ] **Step 1: Test representative non-Google catalog entries**

The mobile UI renders provider display name/icon, only operational auth methods, multiple accounts of one provider, private/workspace status, reconnect/revoke, and unavailable-provider messaging from backend DTOs.

- [ ] **Step 2: Keep provider behavior data-driven**

Do not add Slack/Notion/etc. branches to the mobile app. All provider-specific fields come from the safe catalog schema. Native Yandex Direct/VK Ads keep their existing product-owned flows until a separate migration removes them.

- [ ] **Step 3: Prove model account selection**

With two connections of the same provider, the model tool requires a backend-local connection ID from request context; it cannot invent or directly submit a connector ID. With one connection, selection remains automatic.

- [ ] **Step 4: Verify**

Run focused backend route and mobile connection tests plus mobile TypeScript. Expected: no Google-only UI filter remains.

- [ ] **Step 5: Commit only changed files**

If existing dynamic UI already satisfies the contract, add tests only; do not rewrite it.

---

### Task 8: Full-catalog model and security evaluation

**Files:**

- Modify: existing fixed integration tool-selection benchmark/evaluation fixture
- Modify: catalog drift and tenant-boundary test suites
- Modify changelogs only after success

- [ ] **Step 1: Freeze the evaluated catalog**

Record the exact connector image digest, catalog fingerprint, provider/action count, classification count, and model ID. The counts must match the completeness gate.

- [ ] **Step 2: Run tool-selection scenarios**

Include ambiguous cross-provider requests, multiple accounts, read/write/destructive actions, prompt injection in provider data, inaccessible connections, missing grants, and native Yandex/VK collisions. The model never sees the entire action catalog at once; ToolSearchProcessor remains bounded.

- [ ] **Step 3: Run tenant-boundary probes**

For every representative auth type, attempt foreign tenant/workspace/user connection IDs, catalog service token reuse, unclassified actions, schema drift, expired JWTs, wrong purpose, and disabled entitlement. No provider request may start.

- [ ] **Step 4: Run repository checks**

```bash
# connector
npm run fix-check
npm run build
npm run test:saas

# backend
cd ../ai-backend-marketing-agent
npx tsc --noEmit
npm test
npm run check:integration-catalog

# mobile if changed
cd ../ai-marketing-agent-user-mobile
npx tsc --noEmit
npm test
```

- [ ] **Step 5: Completion criteria**

This plan is complete only when:

- no Google-only provider gate remains;
- no canary/percentage rollout gate remains;
- every executable exposed action is classified and fingerprinted;
- every provider reports operational auth methods safely;
- entitled tenants can use representative non-Google providers end to end;
- unentitled tenants and ungranted actions remain inaccessible;
- catalog service tokens cannot access tenant data;
- local erasure works for every auth type and remote revocation outcomes are explicit.

- [ ] **Step 6: Add changelog entries and commit**

Then proceed to `2026-08-04-single-runtime-multitenant-cutover.md`.

## Product integration configuration

**Status:** planned follow-up, recorded at the user's request on 2026-11-06; not implemented by this planning change. This section supersedes wording that treats the source-reviewed provider set as the permanent operator configuration.

### Current fact and ownership

Today `action-classifications/` and `action-classification.ts` derive the allowed product set from reviewed source decisions. There is no separate editable provider-enable setting or environment allowlist. The recorded current set is 26 integrations / 696 actions. The optional catalog fingerprint setting detects drift; it is not a provider on/off configuration.

The future configuration belongs to **`ai-backend-marketing-agent`**, including storage, validation, API and its own future administration UI. OpenConnector owns provider implementation/authentication and per-action permissions, not which integrations the AI-marketer product advertises. Mobile continues to consume the server catalog; do not introduce a second mobile allowlist.

### Add a layer; preserve the achieved safety behavior

```text
effective product availability =
  reviewed supported provider/actions
  AND explicit backend product setting enabled
  AND operational connection method
  AND current entitlement/business access

action execution additionally requires OpenConnector's effective action permission.
```

- Keep reviewed input/output fingerprints, risk, minimum roles, confirmation, byte limits and replay policy in their existing source modules. The future administration UI may toggle product availability but cannot make an unreviewed/unsupported action executable.
- Store product provider settings in a dedicated backend configuration table/module, following the existing global-settings/revision/audit pattern; do not put them into OpenConnector action tables, billing-provider settings or an untyped shared settings bag. Provider ID is a string using existing exact IDs, not a new hard-coded enum or renamed key.
- Prepare settings with `providerId`, `enabled`, revision, verified editor, reason and timestamp so the future AI-backend administration UI does not need another persistence redesign. Do not build that UI, a generic configuration framework or provider-specific mobile switches in the action-permission cutover.
- The first migration uses a reviewed snapshot of the current product set: seed exactly the currently admitted 26 IDs with their existing product-enable behavior. Keep readiness and tariff checks separate, so seeding does not expose a provider that is not operational today. Preserve already stored operator settings with conflict-safe insertion, not unconditional overwrite.
- Missing/new provider settings mean disabled. A newly installed catalog provider, source review or upstream update does not automatically enable it for the product. Do not seed from whatever full catalog happens to be present at migration time.

### Required read paths and preservation checks

- Use one backend product-policy reader for public catalog, new connection, reconnect, connection guide, tool discovery and authorization immediately before signing execution. Known but disabled product providers do not reach an external action even through an already-loaded tool or scheduled/resumed work.
- Registry startup still validates complete catalog/schema review and fingerprints. Operational authentication is required for enabled product integrations; an intentionally disabled integration must not prevent startup solely because its authentication application is unconfigured.
- Disabling product availability does not delete credentials, existing connections, audit or OpenConnector personal/common permissions. Preserve an authenticated safe path for disconnect/export/cleanup and the existing installed-connection presentation; do not blindly apply the new hide filter to deletion/recovery.
- Changes are checked on the next relevant request and before signing execution, not only at process startup. Configuration-read failure denies affected use; no fallback to an implicit “all reviewed providers are enabled”.
- Before rollout, compare all previously admitted provider IDs, API responses, connection methods and tool access with the initial settings snapshot. Prove missing/unknown disabled, unsupported cannot be activated, dynamic disable blocks stale tools, enable/disable does not erase existing data, and two tenants retain independent connections.

### Bounded implementation map for the future task

Backend configuration storage/migration and typed product-policy module; readers in `packages/runtime/src/integrations/service.ts`, `action-tool-registry.ts`, `tool-search-processor.ts`, `action-execution-service.ts`, and the OpenConnector connection-guide route. Reuse platform admin authentication/revision/audit when its UI is implemented. All action enable/default calculation and final checks stay in OpenConnector.
