# Security Policy

OpenConnector (`oomol-lab/open-connector`) is a connector gateway that stores and brokers sensitive
user credentials — API keys, OAuth client secrets, and OAuth access/refresh tokens — on behalf of
many third-party providers. It may also retain completed Action response payloads for idempotent
HTTP retries. We take security reports seriously and are grateful to the researchers and users who
help keep the project and its users safe.

This policy explains which versions receive security fixes, how to report a vulnerability privately,
what to expect after you report, and how operators and contributors share responsibility for keeping
credentials safe.

## Supported Versions

Security fixes are delivered on the **latest released version** and the **`main`** branch. We
recommend always running the latest release.

| Version                 | Security fixes |
| ----------------------- | -------------- |
| Latest release / `main` | ✅             |
| Older releases          | ❌             |

## Reporting a Vulnerability

**Please report security vulnerabilities privately.** Do not open a public issue, pull request, or
discussion, and do not post details on social media or any other public channel, until we have
released a fix and coordinated disclosure with you. Public reports expose every user of the project
to the vulnerability before a patch exists.

Use one of these private channels:

1. **GitHub private vulnerability reporting (preferred).** Open
   <https://github.com/oomol-lab/open-connector/security/advisories/new>, or go to the repository's
   **Security** tab → **Advisories** → **Report a vulnerability**. This creates a private advisory
   visible only to you and the maintainers, and is the fastest path to a coordinated fix and a CVE.
2. **Email.** If GitHub private reporting is unavailable to you, email **support@oomol.com** with
   the subject line prefixed `[security]`. Use this only as a fallback; it is not an encrypted
   channel, so keep secrets out of the message (see below).

If you do not receive an acknowledgement within **3 business days**, please re-send through the other
channel in case a message was missed.

### What to include

A good report lets us reproduce and assess the issue quickly. Where possible, include:

- A description of the vulnerability and its security impact (what an attacker can do).
- Step-by-step reproduction, proof-of-concept, or the relevant code path.
- The affected version, release, or commit and the deployment topology.
- Any known mitigation or workaround.

### Protect secrets in your report

Because this project handles credentials, **do not include real user tokens, API keys, OAuth client
secrets, passwords, or customer data** in your report. Redact them and use placeholder values (for
example, `github_pat_REDACTED`). If a proof-of-concept requires a credential, describe how to
generate a disposable test one instead of sharing a live secret.

## What to Expect After Reporting

We follow a coordinated disclosure process:

- **Acknowledgement** within **3 business days** that we received your report.
- An **initial assessment and expected timeline** within **10 business days**. We triage by severity
  using [CVSS](https://www.first.org/cvss/calculator/4.0).
- **Regular status updates** as we work on a fix, and notification when it ships.
- **Credit** to you in the advisory and release notes when the fix is published, unless you ask to
  remain anonymous.

## Coordinated Disclosure

- Keep the report **private** until a fix is released. We aim to publish within **90 days** of the
  report; for actively exploited issues we move faster.
- We develop and review the fix in a **private** GitHub security advisory or fork — never in a public
  issue or pull request, which would reveal the vulnerability before a patch is available.
- When the fix is ready, we publish a **GitHub Security Advisory** and, for qualifying issues, request
  a **CVE** through GitHub (a CVE Numbering Authority) so downstream users are notified.
- We will coordinate the public disclosure date with you and credit your contribution.

## Scope

**In scope** — vulnerabilities in this repository's own code and defaults, for example:

- Tenant-scoped PostgreSQL/OpenBao/SeaweedFS storage, key handling, token refresh, and idempotency.
- JWT verification, purpose/permission enforcement, connection ownership, membership, and row-level isolation.
- Scoped OAuth authorization/state/callback handling.
- Leakage of secrets through API responses, audit records, run logs, or errors.
- Action-policy bypass, SSRF, injection, path traversal, webhook verification, or transit-file abuse.
- The SaaS administration UI and scoped HTTP/OpenAPI runtime surface.

**Out of scope** — please do not report these as vulnerabilities in OpenConnector:

- Vulnerabilities in third-party providers or their APIs. Report those to the provider.
- Insecure **self-hosted configuration** that this project documents how to avoid — for example a
  schema-owning or `BYPASSRLS` runtime role, a root/overbroad OpenBao token, wildcard action grants,
  plaintext production OpenBao transport, or public connector/admin ingress. See
  [Hardening your deployment](#hardening-your-deployment).
- The hosted [OOMOL](https://oomol.com/) service and other OOMOL products. These are maintained
  separately from this repository and are not covered by this policy; report issues in them to
  support@oomol.com.
- Reports from automated scanners with no demonstrated impact, missing security headers without a
  concrete exploit, volumetric denial-of-service, social engineering, and physical attacks.

## Safe Harbor

We will not pursue or support legal action against researchers who, in good faith:

- follow this policy and stay within the scope above,
- avoid privacy violations, data destruction, and disruption of others' service, and
- give us a reasonable opportunity to remediate before any disclosure.

If in doubt about whether an action is authorized, ask us first at support@oomol.com. We do not
currently run a paid bug-bounty program, but we credit every reporter whose finding leads to a fix.

## Hardening Your Deployment

OpenConnector holds live provider credentials and tenant data. Operators share responsibility for
the deployment boundary. At minimum:

- **Separate database authority.** Run migrations with a schema owner that is never injected into
  the service. The runtime role must be a non-owner, non-superuser without `BYPASSRLS`; forced RLS
  and request-local scope must remain enabled.
- **Scope secrets.** Give the connector a renewable least-privilege OpenBao token through the
  read-only token file. Production OpenBao must use verified TLS. Never use a root token or put the
  token in the environment, image, logs, or persistent volume.
- **Require verified identity.** Accept only asymmetric JWTs from the configured issuer/audience and
  authenticated JWKS endpoint. Keep lifetimes short and restrict purpose and permission claims.
  Never derive tenant, workspace, user, connection, or action scope from caller headers.
- **Control network exposure.** Do not publish the connector port. Put it on the private backend
  control network plus a connector-only egress network. Publish the administration BFF only on
  loopback and do not route it through a public API, reverse proxy, tunnel service, or public DNS.
- **Protect provider access.** Grant only reviewed actions. Unknown actions, unowned connections,
  stale membership, revoked credentials, ambiguous accounts, and unsafe classifications must fail
  closed. The runtime has no arbitrary provider proxy or direct MCP execution route.
- **Protect storage and files.** Use a dedicated SeaweedFS bucket/key, bounded transit-file
  lifetimes, tenant-scoped deletion, and verified backups for PostgreSQL, OpenBao, and object
  storage.
- **Pin and verify releases.** Deploy immutable image digests, run the one-shot same-image migration
  job, require `/ready`, and retain tenant-scoped audit evidence.

See [docs/saas-deployment.md](docs/saas-deployment.md) for the complete production boundary and
rollback procedure.

## Runtime Security Baseline

CVE-2026-111497 affects native Brotli decoders. This branch requires patched Node.js **24.22.2+ within the Node 24 line**; see the [Node.js advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases). It does not ship Bun, a standalone executable, an npm-embedded global runtime, or a Cloudflare Worker.

- **Docker:** both stages pin Node 24.22.2. Rebuild and redeploy the reviewed immutable image; existing containers never update automatically. Verify the running container's `node --version`.
- **Source development:** update the Node 24 runtime and restart the service. Package managers can merely warn about `engines`, so verify the actual executable rather than trusting the manifest.

Provider actions, downloads, and proxy requests use guarded fetch, whose underlying runtime
can automatically decode upstream `Content-Encoding: br` responses. The SSRF guard restricts
network destinations; it does not prevent a public upstream from sending malicious compressed
bytes. Encoding negotiation remains unchanged: requesting only gzip/deflate cannot stop a
malicious upstream from returning Brotli, and checking response headers after `fetch` is not a
reliable barrier before native decoding. A patched runtime is required.

The scoped inbound server does not install a Brotli request decompressor. Operators must independently update any proxy or middleware that decompresses inbound bodies; a patched connector cannot qualify a different process's decoder.

## Handling Credentials in the Codebase

For contributors and anyone working with this repository:

- **Never commit** credentials, tokens, OAuth client secrets, API keys, `.env` files, or captured
  provider responses that contain user data.
- If a secret is committed by mistake, treat it as **compromised**: revoke and rotate it at the
  provider immediately, then report it privately through the channels above. Removing it from later
  commits or rewriting git history is not sufficient — assume it was captured.
- Keep provider secrets behind the runtime boundary. Do not add logging, error messages, or API
  responses that echo raw tokens, client secrets, or authorization headers; the run-log summarizer
  and logger redaction exist to prevent this and should not be weakened.

Thank you for helping keep OpenConnector and its users secure.
