# Bounded committee problem: preserve member removal and safe recovery

Analysis only. This is a slice of an already authorized independent audit/refactor, not a request to redesign the product or add speculative infrastructure.

## Existing source and authority

Backend isolated root: `/home/main_user/.paseo/worktrees/2rthbyj5/open-connector-permissions-backend`, current `e6cfe354fd79c465386afb43c354f08929e863c3`, before-task `c10a5cc519335f00d6ebd36df82802ce04d6c8fb`.
Connector isolated root: `/home/main_user/.paseo/worktrees/287czvc8/open-connector-multitenant-sync`, `ffb0a1641ce5848c0f9e00e20aeb3e6456750470`.
Read canonical spec `/home/main_user/dev/open-connector/docs/superpowers/specs/2026-11-06-service-boundaries-and-upstream-sync-design.md`.

Primary backend files: `packages/runtime/src/integrations/lifecycle-coordinator.ts` (1192 lines), `membership/service.ts` and `membership/repository.ts`, `integrations/reconciliation-service.ts`, `apps/api/src/routes/workspace-memberships.ts`, `apps/api/src/routes/system.ts`, `apps/api/src/app.ts:930-990,1050-1063`, `integrations/connector-token-service.ts`, `db/transaction.ts`, existing actual-PG lifecycle tests.
Existing native callback implementations are injected in app composition; inspect their actual semantics in `ad-connections/repository.ts`, `credentials/service.ts` and referenced provider-credential owner only as needed, without modifying native provider execution.

End-user mobile is read-only adjacent root `/home/main_user/dev/ai-marketing-agent-user-mobile`; relevant unchanged files `src/api/memberships.ts:210-236` and `app/settings/workspace/members/[userId].tsx:157-195,494-542`. That checkout has substantial unrelated dirty user work and is NOT an edit workspace. Avoid a mobile rewrite; prefer preserving its established contract through bounded backend changes if sound.

## Observed current mechanics

- New member removal freezes complete canonical dispositions, captured membership UUID, integration connections, native per-step pending/processing/completed progress, actor, target and original correlation in `app.integration_lifecycle_operations`, and commits its membership fence atomically.
- `drainStartedAt` is persisted after fence COMMIT. A real 185-second postcommit drain is security-required (60-second old authority + 5-second skew allowance + 120-second native processing upper bound). Never shorten/remove it or mint fresh age after authority/key awaits.
- `execute()` obtains durable `executionId` through `open`; tenant xact advisory lock serializes claim assignment but ends at open COMMIT. All later saves/block/delete are executionId-CAS bound. Exact generation final deletion and completed phase are atomic.
- `execute` calls finish only on normal result or CHAT_SCOPE_DELETION_PENDING; finish refuses native `processing`, otherwise clears claim. A process loss after open commit can leave nonnull executionId permanently; open rejects any unfinished tenant operation with one. There is no supported reclaim/reconcile method or route.
- Existing registered `notificationDispatcher.recoverLifecycle` handles chat/task recovery, native writer resume and `createConnectorMaintenanceRecovery`. The latter selects active/unfenced memberships and invokes OO maintenance, never reads lifecycle operation rows. Do not add another timer.
- Native transfer/revoke callbacks are intentionally progress-marked before invocation. A lost callback result is not proof of completion. Do not blindly replay uncertain native effects or use timeout alone as proof the old executor died.
- Remote OO export, transfer, revocation, policy purge and scope/config purge exist behind exact signed lifecycle purposes. Inspect actual idempotency/ownership behavior before asserting replay safety.
- Current mobile supplies a new random correlation for EVERY remove mutation, only displays a 202 recovery correlation and cannot reuse it. Mandatory initial drain now makes normal removals return 202; a second ordinary attempt therefore tries a new operation and hits the already-fenced target. Reloading removal-impact also fails because its action-permission count callback requires the fenced target's business integration access.
- Existing public DELETE response is `{status,correlationId}` but service returns only boolean and route echoes input correlation. Existing UI selections describe the full original native/integration dispositions; changed actor/target/disposition must never be silently accepted.

## Required outcome

1. Normal end-user removal can continue from the existing Android/iOS UI, including repeated click/retry/network loss and returning to the page, without out-of-band internal replay or re-opening target business authority. Preserve frozen original intent, actor, scope, membership generation and canonical operation identity; changed intent must reject rather than be silently substituted.
2. An abandoned claim has a supported safe recovery path. Safe pre-dispatch/read-only work must not permanently lock the tenant. Uncertain side effects remain fail-closed until concrete reconciliation. Concurrent/multi-instance execution and old executor continuation must be accounted for; no blind elapsed-time reset, process-local mutex, fake success, hidden epoch registry or separate permission store.
3. Reuse existing PostgreSQL/SDK/recovery facilities and operation row. Explain the smallest sound design, whether an existing worker or explicit authenticated endpoint is appropriate, and precise claim release/reclaim and side-effect invariants. Avoid growing a patchwork of flags/timers or proposing a wholesale Mastra rewrite without a demonstrated applicable guarantee.
4. Suggest focused actual-PG/HTTP failure-injection checks that distinguish a running executor, clean pending drain, crash-before-I/O, uncertain native result, changed original intent, replaced membership and a late old executor.

No previous acceptance report proves these cases. Do not assume your counterpart's design. Distinguish source evidence from inferred interleavings; show exact source prerequisites. Return a compact implementable plan and rejected alternatives with reasons, not implementation code.

This is analysis only. Do NOT edit, create, or delete any files. Do NOT write code. Do not run builds, tests, linters, formatters, services, installs or database operations. Read-only Git/source investigation is allowed.
