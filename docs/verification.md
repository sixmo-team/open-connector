# Verification

Catalog coverage, local execution, and external API verification are separate states.

When documenting a provider, distinguish:

- Catalog-only actions: schemas and metadata are available for discovery.
- Locally executable actions: the open source runtime has an executor for the action.
- Verified coverage: maintainers have current evidence that the action or provider works against the real upstream API.

Do not imply that every catalog action is end-to-end verified unless that evidence is available in
public project artifacts. Prefer verification notes that users can reproduce from this repository,
such as example scripts, smoke tests, or public status pages.

## Private scoped runtime

Use the repository's Node 24 version and the installed lockfile dependencies:

```bash
npm run verify:no-legacy-runtime
npm run verify:generated
npm run typecheck
npm run lint
npm run build:web
npm run test:rls
npm test
```

`test:rls` requires `TEST_POSTGRES_URL` for a dedicated disposable PostgreSQL database;
never use an application or production database. It enables the required database gate rather
than treating skipped database checks as permission-isolation proof. Keep the database configured
for the full test run as well.

The scoped server has no global-token SQLite benchmark or public `/api` listener. Qualify the
actual immutable image with the backend's isolated `test:saas-stack:clean` command and explicit
`OPEN_CONNECTOR_SOURCE_ROOT`. That proof must exercise separate services, restricted database
roles, current common/personal policy, revocation, replay and the real processing/drain limits.
A client timeout or a test with a shortened delay does not establish the owner-side limit.

## Metadata-only developer commands

```bash
npm run export:feishu-permissions
npm run export:feishu-permissions -- /path/to/feishu-permissions.json
npm run generate:provider -- dokploy /path/to/pinned-openapi.json /path/to/output
node scripts/search-actions.ts --query "send email" --service gmail --limit 5
```

The Feishu exporter writes the sorted unique provider permission names declared by current
actions, either to standard output or the selected file. These are provider authorization
requirements, not OpenConnector action grants.

Provider generation invokes the selected provider's existing generator and preserves its
arguments and exit status. Review that generator's pinned input and output paths before running
it: generation can update provider source as well as the output directory.

Action search reads the generated compact catalog without loading action schemas. These
commands neither connect accounts nor grant execution rights; they do not restore the retired
global server or its permission model.
