import { expect, it } from "vitest";
import { ExecutionError } from "../../core/execution-error.ts";
import { slackMessagePosted } from "./trigger-on-message-posted.ts";

it("preserves a missing Slack history scope as a native forbidden execution", async () => {
  const pending = slackMessagePosted.poll({
    checkpoint: null,
    config: { channelId: "C123" },
    connector: { execute: async () => ({ status: 200, data: { ok: false, error: "missing_scope" } }) },
    now: new Date("2026-11-06T00:00:00Z"),
  });
  await expect(pending).rejects.toBeInstanceOf(ExecutionError);
  await expect(pending).rejects.toMatchObject({ code: "scope_missing", kind: "forbidden" });
});
