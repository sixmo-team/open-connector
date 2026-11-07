import { spawnSync } from "node:child_process";

// Postinstall repairs output; verify:generated itself is strictly read-only.
const checked = spawnSync(process.execPath, ["scripts/generate-catalog.ts", "--check"], {
  cwd: process.cwd(),
  encoding: "utf8",
});
if (checked.error) throw checked.error;
if (checked.status !== 0) {
  const generated = spawnSync(process.execPath, ["scripts/generate-catalog.ts"], {
    cwd: process.cwd(),
    stdio: "inherit",
  });
  if (generated.error) throw generated.error;
  if (generated.status !== 0) process.exit(generated.status ?? 1);
}
