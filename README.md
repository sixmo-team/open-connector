# OpenConnector

OpenConnector is the self-hosted integration/tool runtime used by the multi-tenant marketing SaaS. It exposes one production runtime: the scoped Node service in `src/saas`.

## Runtime boundary

Every authenticated request carries verified tenant, workspace, subject-user, purpose, permission, and connection/action claims. PostgreSQL forced row-level security, scoped OpenBao paths, scoped OAuth state, and scoped SeaweedFS metadata enforce the same identity boundary. The runtime PostgreSQL role is distinct from the migration owner and cannot bypass RLS.

The repository retains the provider catalog, action schemas, provider executors, OAuth services, and the SaaS administration UI. It does not ship the former SQLite/D1 runtime, static admin/runtime tokens, direct MCP endpoint, provider proxy routes, Cloudflare Worker, Fly deployment, or public original console.

## Commands

Use Node.js 24.22.2 or later in the Node 24 release line. The service executes TypeScript with Node's `--experimental-transform-types` because native modules use parameter properties.

```bash
npm ci
npm run build
npm test
npm run test:rls
```

The real PostgreSQL gate requires `TEST_POSTGRES_URL` and fails closed when it is absent. `build` generates the full Node catalog, checks `src` and `scripts`, then builds the protected `web` workspace. `web/saas.html` and `web/src/saas` produce `dist/web-saas/saas.html` and prefixed `/integration-console/` assets; they are not a standalone public console.

- `npm run dev` starts the scoped SaaS runtime.
- `npm run start` starts the same runtime without watch mode.
- `npm run migrate` applies PostgreSQL migrations with distinct owner/runtime URLs.
- `npm run backfill-connections` performs the one-time connection identity backfill when upgrading an existing database.
- `npm run upstream:protected` rejects legacy-runtime reintroduction and unreviewed provider/core/OAuth drift.

## Production image

`docker/Dockerfile` is the only release image. It generates the full Node provider registry and catalog, builds the SaaS UI, installs production dependencies including optional provider SDKs, runs as the non-root `node` user, and starts `node --experimental-transform-types src/saas/index.ts`.

The backend Compose graph pins this image by digest. A one-shot migration service uses the same image before the runtime starts. The connector has no host port. The authenticated `integration-admin` BFF is the only published console boundary and privately proxies the built UI from the connector.

The existing [Helm chart](deploy/helm/open-connector/README.md) uses that same scoped image and private service boundary; it does not deploy PostgreSQL, OpenBao, SeaweedFS, the backend, or a public console.

See [docs/saas-deployment.md](docs/saas-deployment.md) for deployment and rollback procedures and [docs/contracts/saas-runtime.openapi.yaml](docs/contracts/saas-runtime.openapi.yaml) for the backend-to-connector contract.

## Catalog and provider development

Provider definitions and executors live under `src/providers`. Generate the registry and catalog with:

```bash
npm run generate:catalog
npm run verify:generated
```

New providers remain ordinary provider packages; they do not add another runtime or deployment path. Catalog format details are in [docs/catalog-format.md](docs/catalog-format.md).

## License

Unless otherwise noted, source, scripts, generated scaffolding, tests and documentation authored for this repository use the OpenConnector License, a modified Apache License 2.0. See [LICENSE.txt](LICENSE.txt) and [NOTICE.md](NOTICE.md). Providing OpenConnector to third parties as a hosted connector service requires a commercial license from OOMOL; releases through v1.9.4 remain under the unmodified Apache License 2.0.

This license does not grant rights to third-party providers, APIs, trademarks, logos, icons, documentation or other materials owned by their respective holders.
