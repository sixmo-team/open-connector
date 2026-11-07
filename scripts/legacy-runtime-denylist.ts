export const requiredRuntimePaths = [
  "src/saas/index.ts",
  "web/saas.html",
  "web/vite.config.ts",
  "docker/Dockerfile",
  "scripts/saas-migrate.ts",
  "src/providers/registry.generated.ts",
  "catalog/apps",
] as const;

export const forbiddenRuntimePaths = [
  "src/server",
  "src/mcp.ts",
  "src/mcp.test.ts",
  "scripts/dev-local.ts",
  "scripts/runtime-data.ts",
  "scripts/copy-catalog-assets.ts",
  "scripts/copy-catalog-assets.test.ts",
  "scripts/runtime-data.test.ts",
  "scripts/d1-runtime-data.ts",
  "scripts/d1-runtime-data.test.ts",
  "scripts/build-binary.ts",
  "scripts/build-runtime-package.ts",
  "scripts/smoke-binary.ts",
  "scripts/smoke-headless-build.ts",
  "scripts/test-mcp-oauth.py",
  "scripts/benchmark-runtime-execution.ts",
  "scripts/benchmark-sqlite-token-statements.ts",
  ".bun-version",
  ".github/workflows/build-binary.yml",
  ".github/workflows/publish-npm.yml",
  "wrangler.example.jsonc",
  "wrangler.local.jsonc",
  "docker/Dockerfile.saas",
  "docker-compose.yml",
  "docker-compose.build.yml",
  "fly.toml",
  "migrations",
  "web/index.html",
  "web/vite.saas.config.ts",
  "web/src/main.tsx",
  "src/providers/registry.cloudflare.generated.ts",
] as const;

export const forbiddenRuntimeMarkers = [
  "src/server/",
  "wrangler",
  "runtime:data",
  "start:saas",
  "saas:migrate",
  "dev:cloudflare",
  "OOMOL_CONNECT_RUNTIME_TOKEN",
  "OOMOL_CONNECT_ADMIN_TOKEN",
  "OPEN_CONNECTOR_ADMIN_TOKEN",
  '"/api/mcp"',
  '"/mcp"',
] as const;

export const forbiddenImageContentMarkers = [
  "src/server/",
  "OOMOL_CONNECT_RUNTIME_TOKEN",
  "OOMOL_CONNECT_ADMIN_TOKEN",
  "OPEN_CONNECTOR_ADMIN_TOKEN",
  '"/api/mcp"',
  '"/mcp"',
] as const;

export const expectedImageCommand = ["node", "--experimental-transform-types", "src/saas/index.ts"] as const;
export const expectedImageWorkingDirectory = "/app";
export const expectedImagePort = "3000/tcp";
