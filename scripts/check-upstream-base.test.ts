import { describe, expect, it } from "vitest";
import { APPROVED_UPSTREAM_BASE, validateUpstreamBase } from "./check-upstream-base.ts";

describe("validateUpstreamBase", () => {
  it("accepts the pinned OpenConnector baseline", () => {
    expect(validateUpstreamBase(APPROVED_UPSTREAM_BASE)).toBe(true);
    expect(validateUpstreamBase(`\n${APPROVED_UPSTREAM_BASE}\n`)).toBe(true);
  });

  it("rejects an unreviewed baseline", () => {
    expect(validateUpstreamBase("0000000000000000000000000000000000000000")).toBe(false);
  });

  it("rejects malformed and uppercase SHAs", () => {
    expect(validateUpstreamBase(APPROVED_UPSTREAM_BASE.toUpperCase())).toBe(false);
    expect(validateUpstreamBase(APPROVED_UPSTREAM_BASE.slice(1))).toBe(false);
  });
});
