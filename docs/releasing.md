# Releasing the scoped service

`package.json` remains private at `0.0.0-development`; source tags and reviewed image digests identify candidates. This branch distributes one Node 24 scoped container, not an embeddable npm runtime or Bun single-file product. The Release workflow computes a tag/draft, invokes the existing container workflow and publishes the release only after that job succeeds. The separate Helm workflow retains chart packaging for the same private image/boundary.

Before any release, qualify the exact source candidate with Node 24.22.2+ in the Node 24 line:

```sh
npm ci
npm run build
npm run verify:generated
node --experimental-transform-types scripts/check-action-examples.ts
npm test
TEST_POSTGRES_URL="$ISOLATED_TEST_POSTGRES_URL" npm run test:rls
npm run verify:no-legacy-runtime
docker build -f docker/Dockerfile -t open-connector:verify .
npm run verify:no-legacy-runtime -- --image open-connector:verify
helm lint deploy/helm/open-connector -f scripts/fixtures/helm-scoped-values.yaml
helm template smoke deploy/helm/open-connector -f scripts/fixtures/helm-scoped-values.yaml
```

These are required commands, not a record of execution. A skipped database gate is not success; rendering the inert Helm fixture does not deploy or qualify infrastructure. Record actual full-suite, restricted-role/RLS, two-tenant, OAuth, file/asset/download and processing-drain evidence for the same candidate. Preserve generation/drift and protected-source review checks; do not move `.upstream-base` to suppress unreviewed source changes.

Source review must include authentication, scopes, permissions, trigger contracts and executor/index/generator coverage, not only action input/output schemas. For revisions with ignored generated catalogs, generate each exact source snapshot using its own lockfile and generator, then run `npm run upstream:review -- <candidate-sha> --base-catalog <before/catalog/apps> --candidate-catalog <after/catalog/apps>`. The review refuses missing catalog evidence when catalog-producing source changed; its source mode/blob fingerprints retain the exact changed code even when generated output is ignored. Keep the original source review before accepting a new baseline.

Builds and local image verification do not authorize registry publication. Use the approved release process and immutable same-image migration/runtime digests. Do not overwrite a released version or tag. On failure, inspect the genuine failed step and existing release/artifact state before rerunning; do not infer vendor/registry outcomes from a lost response. The [deployment runbook](saas-deployment.md) owns restore drills, shadow migration, canary, private ingress, token renewal and rollback gates.
