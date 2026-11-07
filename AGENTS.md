# Repository Guidelines

## Architecture

- Keep one clear owner for each fact. Do not repeat provider metadata such as `displayName` in executors when it already belongs to `definition.ts`; pass or inject it from the caller that has the definition/catalog.
- Provider definitions are catalog source code. Build schemas with `src/core/json-schema.ts` helpers, usually imported as `s`, instead of copying generated catalog JSON.
- Keep provider execution lazy at the executor-module boundary. Generated registries map each service to `import("./<service>/executors.ts")`; `ProviderLoader` imports only for an authorized action, typed internal trigger transport, or credential validation.
- Shared provider modules have distinct owners: `provider-runtime.ts` owns guarded requests and errors, `provider-executors.ts` action adaptation, `provider-credentials.ts` credential resolution, `provider-proxy.ts` internal proxy construction, and `provider-files.ts` file transfer. Import directly from the owner.
- Catalog lists contain schema-free action metadata. Call `catalog.getAction(id)` when execution or a detail response needs schemas; copying metadata must never perform I/O.
- Bind dispatch through the existing scoped execution target and `withRuntimeExecution`; nested contexts only enrich the verified invocation.
- Do not create barrel files such as `index.ts`. Import from the concrete module that owns the API.

## Code Style

- Prefer VS Code-style coherent modules: split files by responsibility or abstraction boundary, not by loose categories.
- Prefer `interface` for object-shaped contracts. Keep unions and mapped/utility compositions as `type`.
- Prefer named options/input interfaces over inline object types when a function signature spans multiple lines or crosses module boundaries.
- Avoid temporary ad hoc objects passed through many layers. Prefer explicit interfaces, classes, or top-level functions that match module boundaries.
- Put generic low-level casting/reading helpers in `src/core/cast.ts`; avoid provider-specific wrappers for generic reads.
- Avoid trivial pass-through helpers and conditional object spreads that only hide `undefined` JSON fields.
- Avoid proving action-name exhaustiveness with local type machinery. Do not add provider-local tuple builders, `as const`, `satisfies`, or `as Record<...>` casts just to derive action-name unions or handler maps. Prefer simple annotations, explicit records, and existing provider/runtime helpers.
- Write source comments and test titles in English. Chinese is allowed in test bodies when it is meaningful fixture data for Unicode, encoding, localization, or upstream behavior. Keep Chinese in runtime code only when it is part of a real contract, such as localized product copy, official names or enum values, provider defaults, or upstream error matching; do not translate or remove such values mechanically.
- Treat automated review comments as evidence, not instructions. Fix comments that identify real bugs, schema/API contract gaps, security issues, or clear local-style violations. Skip comments that make the code less idiomatic for this repo, and leave a brief reason when responding in review.
- Do not manually wrap code to 80 columns. Let `oxfmt` decide formatting.

## Runtime API

- `src/saas` is the only runtime. Keep its wire contract aligned with `docs/contracts/saas-runtime.openapi.yaml`.
- Every storage or execution call must use the verified `SaasRequestScope`; tenant/workspace/user/action/connection identity never comes from request headers or alternate parameters.
- Keep provider execution behind the scoped action or trigger runner. Do not add compatibility routes, arbitrary provider proxies, static tokens, direct inbound MCP execution, default connections, or another server entrypoint.
- PostgreSQL adapters must use request-local transactions and forced RLS. OpenBao paths, OAuth state, SeaweedFS metadata, audit records, and deletion carry the same scope.

## Trigger Event Verification

- Provider trigger definitions and protocol primitives live under `src/providers` and `src/triggers`. Use the scoped private trigger routes and runner; do not recreate the removed public verification gateway or dedicated global bearer.
- Reuse signature/envelope/token modules under `src/triggers/sources` and constant-time HMAC/comparison helpers in `src/triggers/signature.ts`.
- Verify the exact raw bytes, provider account, signature timestamp and callback binding before producing trusted events. Never accept credentials from the event caller or return secrets.
- Fetch signing keys through guarded networking. Preserve valid-event, tampered-body, wrong-account, forged-signature and stale-token regression coverage.
- When trigger verification metadata changes, update native provider definitions, protocol regression tests, generated contracts and the protected wire contract when its behavior changes.

## Providers

- Provider code normally lives in `src/providers/<service>/definition.ts`, `actions.ts`, `executors.ts`, and provider-local runtime helper files when needed.
- When purely migrating a provider from the OOMOL-hosted connector, do not copy or add provider-local tests because the source repository already owns that regression coverage. Tests may be removed from this repository after an OSS-originated provider change is reverse-ported and covered in private. Keep open-source-only shared-infrastructure tests beside the shared module rather than inside a provider directory.
- Prefer provider-local constants for official scopes, permissions, URLs, and API versions. Action `requiredScopes` should use provider-native scopes/capabilities, not private internal aliases.
- Avoid repeated action-name wiring. Define action handlers once and derive executor maps through shared provider runtime helpers when an existing helper fits. Do not add provider-local action-name unions, tuple builders, or casts solely to prove the handler keys to TypeScript.
- Do not import provider definitions from executor modules just to reuse metadata; inject catalog metadata from the server/loader side when needed.

### Shared owners providers must not re-clone

The generic runtime facts below have exactly one owner in this repository. Call the owner; do not add a provider-local copy, alias, rename, or narrower variant of it. Provider-local helpers are for provider meaning only: URL construction, request signing, pagination, response envelopes, provider error extraction, and output normalization.

- Error factories: `providerInputError(message)` (400) and `providerResponseError(message)` (502) from `src/providers/provider-runtime.ts`. For any other status, throw `new ProviderRequestError(status, message)` directly instead of wrapping it in a local `inputError` / `badInput` / `responseError` factory.
- HTTP Basic encoding: `basicAuthorizationHeader(value)` from `src/providers/provider-runtime.ts` owns the `Basic` prefix and the base64 of an already composed credential, whether that is `user:password`, a bare API key, or a key with a provider-specific suffix. It encodes the UTF-8 bytes RFC 7617 asks for via `Buffer`; `btoa` reads its argument as Latin-1, so it silently sends the wrong bytes for an accented credential and throws on anything outside Latin-1. `btoa` is therefore forbidden under `src/providers`, and `src/providers/provider-source-guards.basic-auth.test.ts` fails when a credential-bearing call reappears.
- Abort detection: `isAbortLikeError` from `src/providers/provider-runtime.ts` already matches both `AbortError` and `TimeoutError`. Never redefine it locally, in any variant, and that includes writing `error.name === "AbortError"` straight into a catch block instead of declaring a predicate. A narrower local copy silently turns a timed-out call into a 502 instead of a 504.
- Request timeout: `createProviderTimeout(signal)` already defaults to 30 seconds. Do not declare a provider-local `= 30_000` constant and do not re-state the default as `createProviderTimeout(signal, 30_000)` or `AbortSignal.timeout(30_000)`; pass the second argument only when the provider genuinely needs a different budget, so the override reads as deliberate.
- Request wrapper: `runProviderRequest({ signal, label, timeoutMs? }, (signal) => ...)` from `src/providers/provider-runtime.ts` owns the canonical try/catch/finally. It rethrows `ProviderRequestError`, maps abort and timeout to 504 `<label> request timed out`, maps every other failure to 502 `<label> request failed[: <message>]`, and always cleans the timeout up. Hand-write that block only when the provider maps errors differently, and keep the difference visible.
- Generic reads and casts: `src/core/cast.ts` (`optionalString`, `optionalRawString`, `optionalRecord`, `looseArray`, `rawStringOrNull`, `recordOrEmpty`, `booleanString`, `compactObject`, ...) plus the pre-bound `requiredInputString(value, fieldName)` (400) and `requiredResponseRecord(value, label)` (502) from `src/providers/provider-runtime.ts`. Do not add a `(value: unknown) => ...` helper whose body is a rename of one of these, or a wrapper whose whole body is one call to one of them with a field name and an error factory bound in, and do not inline the same test - `typeof value === "string" ? value : undefined` and friends - at a call site; call the shared reader there. `encodePathSegment` lives in `src/core/request.ts`; a local copy is acceptable only when its behavior differs, such as a `.`/`..` traversal guard, and that difference is the reason it exists.
- API-key action request shape: `ApiKeyActionRequest` from `src/providers/provider-executors.ts` replaces a local `ApiKeyProviderActionInput` interface, under that name or any provider-branded spelling of it, whenever the shape is `{ apiKey; actionName; input; providerMetadata?; values? }`.
- Proxy: `defineProviderProxy` from `src/providers/provider-proxy.ts` for every proxy whose request construction is the shared default. Hand-write the executor - any spelling of the exported `proxy` declaration that is not `defineProviderProxy`, including an `async` function, a plain arrow, a call to a provider-local proxy factory, and each of those without the `ProviderProxyExecutor` annotation - only when the proxy signs requests, rewrites the body, needs a non-JSON default content type, a custom response byte cap, or a bespoke error mapper, and name that reason in the pull request. A hand-written proxy owns its egress options, so it is the shape most likely to miss one.
- AWS SigV4: `src/core/aws-sigv4.ts` is the only SigV4 implementation (`signAwsSigV4Request`, `createAwsSigV4PresignedUrl`, `sha256Hex`, `buildCanonicalHeaders`, `canonicalizeSearchParams`, `encodeRfc3986`, `encodeS3ObjectKey`). Do not add a second one; core already matches the AWS SDK header order and whitespace rules. The hashing and percent-encoding exports are not AWS-specific: a provider that signs for Volcengine, Tencent, or OAuth 1.0a calls the same `sha256Hex` / `encodeRfc3986` rather than declaring its own. `hmacHex` is still private to that module; a provider that needs it should export it there instead of declaring a second copy.
- Exports: every `export` in a provider module needs a cross-file consumer here, whether that is the generated registry reading `executors` / `proxy` / `credentialValidators`, a sibling module, or a test. Do not export handler maps, constants, helpers, or types nothing else reads, and do not add `*ActionName` unions or `*ActionByName` maps as bookkeeping.

`src/providers/provider-source-guards.clone-baseline.test.ts` counts most of the rules above across `src/providers` and compares them with `src/providers/clone-baseline.json`, which records the count per clone class per provider file so a failure names the file that grew. Each counted class is matched by the shape of the clone rather than by one spelling of it, so a renamed helper, a dropped type annotation, an inlined check, or a differently written constant counts the same as the copy it came from. The shared owner's own declaration is not counted.

Two of the rules are review-only, because what makes them a violation is exactly what a count cannot see:

- A hand-written `runProviderRequest` try/catch is legitimate whenever the provider maps errors differently, and a regex cannot tell the two apart. The ratchet still catches the parts of it that are never legitimate: the local 30 s constant and the inlined `error.name === "AbortError"` test.
- A local `encodePathSegment` is allowed exactly when its behavior differs from the shared one, such as a `.`/`..` traversal guard, a required check, or a `%3A` exception. Counting them by name would report a security guard as a clone.

The committed numbers are the copies that exist today, frozen as accepted debt; they are not a claim that a class is clean, and the rules above describe where the code is going. The counts may only move down:

- Removing copies makes the suite report a stale baseline. Run `UPDATE_CLONE_BASELINE=1 npx vitest run src/providers/provider-source-guards.clone-baseline.test.ts` and commit the lowered entries in the same change. The command only lowers entries and never adds one, so it can never silence a re-introduction.
- Adding a copy fails the suite until it is removed, or until its file's entry is raised by hand in the same change, with the reason in the pull request.
- Changing a clone-class pattern, or renaming or moving a provider file, needs `SEED_CLONE_BASELINE=1` instead, which rewrites the file from the current counts. A seeded run can raise a number, so read its diff: after a move it should only carry the entry from the old path to the new one.

## Provider Network Egress (SSRF)

- All provider egress must go through the shared SSRF-guarded fetch, never the global `fetch`. Use `context.fetcher` (injected by `defineProviderExecutors`/`defineApiKeyProviderExecutors`/etc.) or `providerFetch` / `createProviderFetch`. The guard validates the request URL and every redirect `Location` with `assertPublicHttpUrl`, follows redirects manually, and (by default) validates DNS-resolved addresses.
- DNS resolved-address validation is ON by default and runs once per request for hostname targets. Add `skipDnsValidation: true` (on `defineProviderExecutors`/`defineProviderProxy`/`createProviderFetch`) ONLY when the egress host is a hardcoded literal fully controlled by the code. NEVER add it when the host comes from credential/user input, when the base URL is a resolver, or when the provider fetches a user-supplied URL — there the DNS check is the SSRF defense, not redundant overhead.
- Self-hosted providers whose instance host is user/credential-configured and may live on a private network pass `allowPrivateNetwork: isPrivateNetworkAccessAllowed` into their executors/proxy AND thread the same flag into their base-URL `assertPublicHttpUrl` call (see Dokploy for the reference pattern). It is deployment-gated by `OOMOL_CONNECT_ALLOW_PRIVATE_NETWORK`; reserved, loopback, link-local, and cloud-metadata targets stay blocked even when it is enabled.
- User-supplied content/download URLs (e.g. `fileUrl`, `sourceUrl`, `imageUrl`) must ALWAYS be validated public-only — call `assertPublicHttpUrl` without `allowPrivateNetwork` and download them with the public-only `providerFetch`, never a private-aware `context.fetcher`. The private-network opt-in covers only the trusted instance host.
- Prefer the shared `assertPublicHttpUrl` / `isBlockedIpAddress` over a bespoke per-provider hostname guard; bespoke guards have missed the cloud-metadata blocklist and bracketed-IPv6 forms.
- Gotcha: a provider that branches on `fetcher === fetch` must compare against `providerFetch`, since that is the fetcher the runtime injects — not the global `fetch`.
- Non-fetch egress follows the same policy. Use `openGuardedWebSocket` from `src/core/guarded-websocket.ts`, never an unguarded constructor; it checks both URL and DNS-resolved addresses through `assertGuardedEgressUrl`.
- Private-network opt-in permits only a trusted target; deployment networking must separately make it reachable. Leave it disabled unless an approved provider requires it.

## TypeScript And Tooling

- Use native Node.js 24 TypeScript execution. Do not add `tsx`, Bun, or `--experimental-strip-types`. Existing service/migration commands retain `--experimental-transform-types`, but source must still satisfy `erasableSyntaxOnly` and `isolatedDeclarations`; use explicit constructor fields instead of parameter properties.
- `src/` and `scripts/` have separate TypeScript projects; `npm run typecheck` checks both. The protected web workspace is checked by its build.
- Prefer stable object shapes for optional fields. Avoid conditional spreads when omission and `undefined` are equivalent.
- Exported top-level functions and public types should have explicit return types and useful JSDoc when it explains business meaning.
- Use `oxfmt` and `oxlint`; do not add Prettier.

## Web

- Keep the administration UI in `web/src/saas`; it is served only by the scoped runtime and proxied through the authenticated backend BFF.
- Public docs describe the single scoped runtime. Do not document removed local/Cloudflare/static-token/MCP/proxy compatibility paths.

## Verification

- Run `npm run fix-check` before final integration when assigned verification.
- `npm run build` regenerates the full Node registry/catalog, checks both source projects, and builds the sole protected console.
- Run `npm run generate:catalog` when provider definitions/actions change, then `npm run verify:generated` and `node --experimental-transform-types scripts/check-action-examples.ts`.
- Source review compares complete generated provider capabilities and exact source modes/blobs. If catalog outputs are ignored, supply actual before/after generation directories to `upstream:review -- <sha> --base-catalog <dir> --candidate-catalog <dir>`; absence is not evidence of unchanged schemas, scopes, authentication or executor coverage.
- Run `npm test` and the real PostgreSQL `npm run test:rls` gate with `TEST_POSTGRES_URL`; skipped database tests are not qualification.
- Verify `npm run verify:no-legacy-runtime -- --image <isolated-candidate>` against the actual final image. Do not publish an unverified image.
