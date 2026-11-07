# Scoped managed OAuth connections

The native managed client keeps third-party access/refresh tokens, OAuth app secrets and provider secrets on the external SaaS. OpenConnector stores the project key through OpenBao, durable scoped request/account references in PostgreSQL, and safe metadata. Inputs and outputs travel through that actual remote service. Managed projects and Marketplace API keys are separate configurations; neither enables an OpenConnector function automatically.

## Scope and source selection

Configure the actual workspace project and selected provider source through the authenticated backend and [private contract](contracts/saas-runtime.openapi.yaml). There is no global project, public console settings page, static administrator token, public connector callback or default connection fallback. Project discovery validates the real origin/project/key before use. Key replacement retains the established origin/project; deletion must not discard pending references or cleanup.

New managed authorization uses the selected workspace project/provider configuration. Existing connections retain their captured local/custom/managed source on reconnect; selecting a managed workspace default must not move an existing local connection. Managed authorization rejects request-level client/scope/secret overrides; configure these at the actual remote provider configuration. Local custom-client admission remains explicitly restricted.

A trusted deployment-supplied managed completion URI (`OOMOL_CONNECT_MANAGED_COMPLETION_URI`) and the working backend continuation handler are required. The scoped wrapper binds start/poll/cancel/completion to the original verified session, owner and local connection lineage. Poll a known request, respect Retry-After, and complete the original attempt; never start another authorization merely because a response was lost. A mismatched project/config/external-user/account/alias is not adopted. The remote external-user selector is deterministically tied to the genuine tenant/workspace/local lineage, not a process-global instance or fabricated user.

## Readiness and execution

Selected managed readiness uses current scoped source/project/key discovery rather than a startup snapshot or a local-app fallback. Missing/malformed/rejected configuration is distinct from a database, OpenBao or vendor outage. Do not label an unavailable source as operational or erase its saved selection.

The scoped action runner checks the original actor's current OpenConnector rule, exact signed action/input/connection and active owner/visibility before native managed execution. The adapter rereads every stored account selector and actual source binding. Only the intersection of local catalog and current remote capability is executable. The remote transport retains safe errors, Retry-After and remote execution IDs; it does not expose a public arbitrary proxy.

Cancellation and the inherited connector processing deadline bound local waiting/vendor work. A timeout, lost response or caller abort does not prove a remote mutation failed and never authorizes automatic replay, switching accounts, or local fallback. Inspect the real remote execution/provider resource first. Remote billing/credits remain the vendor's responsibility; OpenConnector does not fabricate balances or new spending caps.

## Unknown results and recovery

Retain known local request/account references through cleanup. If vendor retention has expired or identity is uncertain, require operator investigation rather than reporting successful deletion. Compare the real bound project, provider configuration, external-user selector, exact request/account ID and attempt alias; an email/display name alone is insufficient. Restore references from a verified backup when needed. Do not reset storage to hide an outage.

Switching to local OAuth is explicit: preserve the old managed row/cleanup, provision the real scoped local client, create a new connection with a distinct alias, authorize/verify its account/scopes, and update exact backend selectors after policy checks. Reconnecting the existing managed row still uses its original source. See [scoped cleanup](saas-maintenance.md) and [deployment recovery](saas-deployment.md). Actual vendor consent, continuation, credit/error behavior and infrastructure require live qualification; source code or protocol fixtures do not establish that qualification.
