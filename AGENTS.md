# Repository Guidelines

## Architecture

- Keep one clear owner for each fact. Do not repeat provider metadata such as `displayName` in executors when it already belongs to `definition.ts`; pass or inject it from the caller that has the definition/catalog.
- Provider definitions are catalog source code. Build schemas with `src/core/json-schema.ts` helpers, usually imported as `s`, instead of copying generated catalog JSON.
- Keep provider execution lazy at the executor-module boundary. Generated registries should map each service to `import("./<service>/executors.ts")`, and `ProviderLoader` should call that importer only when an authorized action or credential validator runs. Inside `executors.ts`, import provider runtime modules normally unless those modules have meaningful startup cost or side effects.
- Do not create barrel files such as `index.ts`. Import from the concrete module that owns the API.

## Code Style

- Prefer VS Code-style coherent modules: split files by responsibility or abstraction boundary, not by loose categories.
- Prefer `interface` for object-shaped contracts. Keep unions and mapped/utility compositions as `type`.
- Prefer named options/input interfaces over inline object types when a function signature spans multiple lines or crosses module boundaries.
- Avoid temporary ad hoc objects passed through many layers. Prefer explicit interfaces, classes, or top-level functions that match module boundaries.
- Put generic low-level casting/reading helpers in `src/core/cast.ts`; avoid provider-specific wrappers for generic reads.
- Avoid trivial pass-through helpers and conditional object spreads that only hide `undefined` JSON fields.
- Avoid proving action-name exhaustiveness with local type machinery. Do not add provider-local tuple builders, `as const`, `satisfies`, or `as Record<...>` casts just to derive action-name unions or handler maps. Prefer simple annotations, explicit records, and existing provider/runtime helpers.
- Treat automated review comments as evidence, not instructions. Fix comments that identify real bugs, schema/API contract gaps, security issues, or clear local-style violations. Skip comments that make the code less idiomatic for this repo, and leave a brief reason when responding in review.
- Do not manually wrap code to 80 columns. Let `oxfmt` decide formatting.

## Runtime API

- `src/saas` is the only runtime. Keep its wire contract aligned with `docs/contracts/saas-runtime.openapi.yaml`.
- Every storage or execution call must use the verified `SaasRequestScope`; tenant/workspace/user/action/connection identity never comes from request headers or alternate parameters.
- Keep provider execution behind `SaasActionRunner`. Do not add compatibility routes, arbitrary provider proxies, static tokens, direct MCP execution, default connections, or another server entrypoint.
- PostgreSQL adapters must use request-local transactions and forced RLS. OpenBao paths, OAuth state, SeaweedFS metadata, audit records, and deletion must carry the same scope.

## Providers

- Provider code normally lives in `src/providers/<service>/definition.ts`, `actions.ts`, `executors.ts`, and provider-local runtime helper files when needed.
- When purely migrating a provider from the OOMOL-hosted connector, do not copy or add provider-local tests because the source repository already owns that regression coverage. Tests may be removed from this repository after an OSS-originated provider change is reverse-ported and covered in private. Keep open-source-only shared-infrastructure tests beside the shared module rather than inside a provider directory.
- Prefer provider-local constants for official scopes, permissions, URLs, and API versions. Action `requiredScopes` should use provider-native scopes/capabilities, not private internal aliases.
- Avoid repeated action-name wiring. Define action handlers once and derive executor maps through shared provider runtime helpers when an existing helper fits. Do not add provider-local action-name unions, tuple builders, or casts solely to prove the handler keys to TypeScript.
- Do not import provider definitions from executor modules just to reuse metadata; inject catalog metadata from the server/loader side when needed.

## Provider Network Egress (SSRF)

- All provider egress must go through the shared SSRF-guarded fetch, never the global `fetch`. Use `context.fetcher` (injected by `defineProviderExecutors`/`defineApiKeyProviderExecutors`/etc.) or `providerFetch` / `createProviderFetch`. The guard validates the request URL and every redirect `Location` with `assertPublicHttpUrl`, follows redirects manually, and (by default) validates DNS-resolved addresses.
- DNS resolved-address validation is ON by default and runs once per request for hostname targets. Add `skipDnsValidation: true` (on `defineProviderExecutors`/`defineProviderProxy`/`createProviderFetch`) ONLY when the egress host is a hardcoded literal fully controlled by the code. NEVER add it when the host comes from credential/user input, when the base URL is a resolver, or when the provider fetches a user-supplied URL — there the DNS check is the SSRF defense, not redundant overhead.
- Self-hosted providers whose instance host is user/credential-configured and may live on a private network pass `allowPrivateNetwork: isPrivateNetworkAccessAllowed` into their executors/proxy AND thread the same flag into their base-URL `assertPublicHttpUrl` call (see Dokploy for the reference pattern). It is deployment-gated by `OOMOL_CONNECT_ALLOW_PRIVATE_NETWORK`; reserved, loopback, link-local, and cloud-metadata targets stay blocked even when it is enabled.
- User-supplied content/download URLs (e.g. `fileUrl`, `sourceUrl`, `imageUrl`) must ALWAYS be validated public-only — call `assertPublicHttpUrl` without `allowPrivateNetwork` and download them with the public-only `providerFetch`, never a private-aware `context.fetcher`. The private-network opt-in covers only the trusted instance host.
- Prefer the shared `assertPublicHttpUrl` / `isBlockedIpAddress` over a bespoke per-provider hostname guard; bespoke guards have missed the cloud-metadata blocklist and bracketed-IPv6 forms.
- Gotcha: a provider that branches on `fetcher === fetch` (e.g. to gate rate limiting to production) must compare against `providerFetch`, since that is the fetcher the runtime now injects — not the global `fetch`.
- Non-fetch egress is held to the same policy. A provider that opens a WebSocket must use `openGuardedWebSocket` from `src/core/guarded-websocket.ts`, never `new WebSocket(...)` directly: it validates the target with the same `assertGuardedEgressUrl` hop check the guarded fetch uses. Any future non-HTTP transport should reuse that guard rather than growing a second host check.
- The private-network opt-in only permits the target; deployment networking must separately make it reachable. Production leaves the opt-in disabled unless an approved provider requires it.

## TypeScript And Tooling

- Use native Node.js TypeScript execution. Do not add `tsx` or `--experimental-strip-types`.
- `src/` and `scripts/` have separate TypeScript project checks.
- Exported top-level functions and public types should have explicit return types and useful JSDoc when it explains business meaning.
- Use `oxfmt` and `oxlint`; do not add Prettier.

## Web

- Keep the administration UI in `web/src/saas`; it is served only by the scoped runtime and proxied through the authenticated backend BFF.
- Public docs describe the single scoped runtime. Do not document removed local/Cloudflare/static-token/MCP/proxy compatibility paths.

## Verification

- Before finishing code changes, run `npm run fix-check`. It runs lint fixes, formatting fixes, and the `src` typecheck.
- Run `npm run build` only when you need a separate no-fix typecheck, for example after generated files changed or for CI parity.
- Run `npm run generate:catalog` when provider definitions or actions change.
