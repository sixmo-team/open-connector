# Independent full-change audit — execution plan

## Goal and authority

Audit the complete current-chat implementation, not merely the last corrective commit. The user's six-part audit request is the acceptance contract. Canonical product spec: `/home/main_user/dev/open-connector/docs/superpowers/specs/2026-11-06-service-boundaries-and-upstream-sync-design.md`. Existing sync, permission, sharing/lifecycle and release plans remain requirements, not evidence that their implementation is correct. Existing completion reports are historical claims requiring corroboration.

No production deploy, push, application database access, dependency refresh for freshness, unrelated cleanup, or automatic replacement of user changes. Work only in the two already-isolated linked worktrees. Ordinary technical decisions are made from requirements/code/official docs; no approval loop.

## Exact review baseline

- Original connector pre-work HEAD: `5bdf2f1eb9f8e5b917814eb5a265ef141627333f`.
- Full preserved initial user snapshot T: `6f7aefe92137a2ae7c032c014ed5f56bcc3c74ab`; its 16 original dirty paths are user work, not author-created code. Keep that distinction.
- Current complete connector result P: `ffb0a1641ce5848c0f9e00e20aeb3e6456750470`.
- Upstream source U: `156d2d597fc7afc42686c3f8e058dba8125139c7`. Use both T→P for prior behavior and U→P for deliberate native adaptations; neither alone covers the task.
- Backend before work: `c10a5cc519335f00d6ebd36df82802ce04d6c8fb`; complete result: `e6cfe354fd79c465386afb43c354f08929e863c3`.
- Connector initial→result: 6315 exact non-rename path records; U→P: 591. Backend complete range:104. First-parent history includes all9connector and8backend commits after those baselines.
- All staged, unstaged, untracked and ignored execution reports are accounted separately. The two original untracked Chatwoot documents are unrelated user work; never alter them.

## Audit ownership and interfaces

| Owner                               | Complete review slice                                                                                                                                                                                                                                           | Required output                                                                                                                                   |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Fresh reviewer: connector boundary  | Native signed authority, common/personal policy selection/storage/audit, dispatch/replay, request lifetime, scoped transactions/RLS, privilege split                                                                                                            | Evidence-backed findings with reachable inputs and file/line references; old behavior preserved or intentionally changed; exact unreviewed limits |
| Fresh reviewer: backend and console | Complete backend104path range, role/billing/consent/Mastra integration, lifecycle/retry/concurrency, protected BFF, web/src/saas UI, adjacent mobile consumers                                                                                                  | Same, including UI state/races/batch limits; distinguish native mobile consumers from the intentionally browser-only operator console             |
| Parent                              | Complete historical/path accounting, upstream feature survival/removals, OAuth/managed/Marketplace/triggers/transit/native persistence, SDK/library/lock versions, dependency necessity, generators/tooling/image/publication; reproduce findings and implement | Reconciled preservation matrix and root-cause corrections, not acceptance of reviews by label                                                     |

Both reviewers are read-only: no edits, services, databases, builds, tests, installs, lint or formatters. Read-only Git history/diff is required. Parent alone changes source and runs heavy checks serially.

## 1. Context/history/preservation

- [ ] Read repository instructions and binding product plans. Capture original and isolated working tree/index status, all commits and full path dispositions.
- [ ] Trace old and new consumers and state transitions, including deleted paths, renamed providers, removed global entrypoints and retained protected equivalents.
- [ ] Separate third-party imported provider changes, inherited scoped implementation, current-task changes and unrelated user files. No unexamined file group may silently disappear from the inventory.

## 2. Versioned contracts and platforms

- [ ] Establish exact locked and installed versions, rather than semver declarations or stale planning prose.
- [ ] Consult official corresponding documentation and installed source/types for touched PostgreSQL/pg, Node, Hono, JOSE, React, Mastra, assistant-ui and Expo/RN contracts where actually relevant.
- [ ] Check the Android and iOS end-user integration consumers. A built operator web console does not prove mobile runtime compatibility; do not rewrite it into a mobile screen.

## 3. Architecture and concrete simplification

- [ ] Verify one policy owner in OpenConnector and existing business/consent owners in backend. Trace actual request, trust-profile and resource boundaries.
- [ ] Review every own major subsystem for SDK duplication, unsafe casts, unnecessary wrappers/state copying/timers, suppressed errors and missing lifecycle branches.
- [ ] Require a reachable bug, concrete architecture defect or unsupported API before changing adjacent implementation. Preserve useful behavior; do not rewrite for taste.

## 4. Dependency decisions

- [ ] Compare original, upstream and current lockfiles and real usage. Identify exactly which imported native feature needs each new dependency.
- [ ] Update only if a specific required documented API replaces a current inferior mechanism safely; otherwise record that no version refresh was justified.

## 5. Root-cause correction and actual proof

- [ ] Verify reviewer findings independently. Add a deterministic consumer-visible regression or focused runnable smoke; observe the expected failure before changing implementation.
- [ ] Fix the common owner, not one named caller. Preserve authorization, input validation, cancellation, exact identities and existing features.
- [ ] Run affected checks during correction, then complete native/backend types, configured lint/build/tests, actual-PG isolation and the real separate-service cold flow serially. No skipped DB gate is a pass and no increased timeout hides a defect.
- [ ] Exercise actual operator UI and relevant mobile bundling/consumer checks; declare native runtime limits honestly. Use controlled providers, never customer accounts.

## 6. Delivery

- [ ] Produce a concise report for the entire reviewed range: retained decisions and why, disproved decisions and fixes, old behavior preserved, documentation links, file/line references, actual checks and concrete limits.
- [ ] Keep original user work, exact source/image/evidence binding and private isolated cleanup. Do not imply a production release or universal proof of zero regressions.

## Rulings

- This is a new audit, not continuation of the prior completed implementation plan. New verification and reviewer findings will be recorded here; the previous green report does not waive this review.
- No speculative implementation is planned before evidence identifies a defect. For any resulting correction use systematic debugging and RED→GREEN, then the smallest maintainable change. The user explicitly authorized autonomous execution, so the generic planning skill's optional handoff/confirmation is not used.
