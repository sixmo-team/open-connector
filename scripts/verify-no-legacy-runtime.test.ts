import type { RuntimeImageSnapshot } from "./verify-no-legacy-runtime.ts";

import { describe, expect, it } from "vitest";
import { findCutoverViolations } from "./check-protected-upstream.ts";
import { findRuntimeImageViolations } from "./verify-no-legacy-runtime.ts";

function cleanSnapshot(): RuntimeImageSnapshot {
  return {
    config: {
      Cmd: ["node", "src/saas/index.ts"],
      User: "node",
      WorkingDir: "/app",
      Env: ["NODE_ENV=production"],
      ExposedPorts: { "3000/tcp": {} },
      Healthcheck: { Test: ["CMD-SHELL", "wget --spider -q http://127.0.0.1:3000/ready || exit 1"] },
    },
    paths: ["app", "app/package.json", "app/src", "app/src/saas", "app/src/saas/index.ts"],
    packageJson: JSON.stringify({ scripts: { start: "node src/saas/index.ts" } }),
    executableText: [["app/src/saas/index.ts", "export {};\n"]],
  };
}

const forbiddenBuiltAsset: RuntimeImageSnapshot["executableText"] = [["app/dist/web.js", 'fetch("/api/mcp")']];

describe("final runtime image verification", () => {
  it("accepts the sole non-root SaaS runtime image contract", () => {
    expect(findRuntimeImageViolations(cleanSnapshot())).toEqual([]);
  });

  it.each([
    ["legacy entrypoint", { paths: [...cleanSnapshot().paths, "app/src/server/index.ts"] }, "legacy image path"],
    [
      "alternate package script",
      {
        packageJson: JSON.stringify({
          scripts: { start: "node src/saas/index.ts", local: "node src/server/index.ts" },
        }),
      },
      "legacy image package script",
    ],
    ["forbidden built asset", { executableText: forbiddenBuiltAsset }, "legacy executable marker"],
    ["wrong command", { config: { ...cleanSnapshot().config, Cmd: ["node", "src/server/index.ts"] } }, "image command"],
    ["root user", { config: { ...cleanSnapshot().config, User: "root" } }, "non-root"],
    [
      "extra public port",
      { config: { ...cleanSnapshot().config, ExposedPorts: { "3000/tcp": {}, "8080/tcp": {} } } },
      "expose only",
    ],
  ])("rejects %s even when source cutover checks pass", (_label, change, expected) => {
    expect(findCutoverViolations(process.cwd())).toEqual([]);
    const violations = findRuntimeImageViolations({ ...cleanSnapshot(), ...change });
    expect(violations.join("\n")).toContain(expected);
  });
});
