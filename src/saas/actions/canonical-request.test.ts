import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { actionInputMaxDepth } from "./action-idempotency.ts";
import {
  CanonicalActionRequestError,
  canonicalActionPolicyRequestHash,
  canonicalActionRequestHash,
  canonicalRequestHash,
} from "./canonical-request.ts";

describe("canonicalActionRequestHash", () => {
  it("sorts object keys recursively", () => {
    expect(canonicalActionRequestHash("gmail.messages_list", "c1", { b: 2, nested: { z: 3, a: 1 } })).toBe(
      canonicalActionRequestHash("gmail.messages_list", "c1", { nested: { a: 1, z: 3 }, b: 2 }),
    );
    expect(canonicalActionRequestHash("gmail.messages_list", "c1", { b: 2, a: 1 })).toBe(
      "6A4Fk497LhpuK-w_fCiOztyhOHTJVjH495B-ZKF39YI",
    );
  });

  it("preserves array order while canonicalizing array entries", () => {
    const first = canonicalActionRequestHash("gmail.messages_list", "c1", [{ b: 2, a: 1 }, "second"]);
    expect(first).toBe(canonicalActionRequestHash("gmail.messages_list", "c1", [{ a: 1, b: 2 }, "second"]));
    expect(first).not.toBe(canonicalActionRequestHash("gmail.messages_list", "c1", ["second", { a: 1, b: 2 }]));
  });

  it("binds every envelope field", () => {
    const hash = canonicalActionRequestHash("gmail.messages_list", "c1", { page: 1 });
    expect(hash).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(hash).not.toBe(canonicalActionRequestHash("gmail.messages_get", "c1", { page: 1 }));
    expect(hash).not.toBe(canonicalActionRequestHash("gmail.messages_list", "c2", { page: 1 }));
    expect(hash).not.toBe(canonicalActionRequestHash("gmail.messages_list", "c1", { page: 2 }));
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])(
    "rejects the non-finite number %s",
    (value) => {
      expect(() => canonicalActionRequestHash("example.echo", "c1", { value })).toThrow(
        "Canonical action requests require finite numbers.",
      );
    },
  );

  it("rejects unsupported JSON values", () => {
    for (const input of [undefined, 1n, Symbol("value"), () => undefined, new Date()]) {
      expect(() => canonicalActionRequestHash("example.echo", "c1", input)).toThrow(CanonicalActionRequestError);
    }

    const sparse = Array<string>(1);
    expect(() => canonicalActionRequestHash("example.echo", "c1", sparse)).toThrow("dense JSON arrays");

    const cyclic: { self?: unknown } = {};
    cyclic.self = cyclic;
    expect(() => canonicalActionRequestHash("example.echo", "c1", cyclic)).toThrow("cyclic values");
  });

  it("accepts the existing input depth limit and rejects deeper inputs", () => {
    expect(() => canonicalActionRequestHash("example.echo", "c1", nestedInput(actionInputMaxDepth))).not.toThrow();
    expect(() => canonicalActionRequestHash("example.echo", "c1", nestedInput(actionInputMaxDepth + 1))).toThrow(
      `Action input must not exceed an object/array nesting depth of ${actionInputMaxDepth} levels.`,
    );
  });
});

describe("canonicalRequestHash", () => {
  it("canonicalizes input while binding the fixed operation", () => {
    const hash = canonicalRequestHash("lifecycle.purge", {
      correlationId: "00000000-0000-4000-8000-000000000001",
      options: { b: 2, a: 1 },
    });
    expect(hash).toBe(
      canonicalRequestHash("lifecycle.purge", {
        options: { a: 1, b: 2 },
        correlationId: "00000000-0000-4000-8000-000000000001",
      }),
    );
    expect(hash).not.toBe(
      canonicalRequestHash("lifecycle.export", {
        correlationId: "00000000-0000-4000-8000-000000000001",
        options: { b: 2, a: 1 },
      }),
    );
    expect(hash).not.toBe(
      canonicalRequestHash("lifecycle.purge", {
        correlationId: "00000000-0000-4000-8000-000000000002",
        options: { b: 2, a: 1 },
      }),
    );
  });
});

describe("canonicalActionPolicyRequestHash", () => {
  it("uses the exact wire tuple without an operation wrapper or reason normalization", () => {
    const target = { kind: "platform" } as const;
    const body = { enabled: true, reason: "  reviewed  ", actionIds: ["gmail.messages_list"] };
    const path = "/internal/saas/action-policy/defaults";
    const hash = canonicalActionPolicyRequestHash("put", path, target, body);
    const expectedJson =
      '{"body":{"actionIds":["gmail.messages_list"],"enabled":true,"reason":"  reviewed  "},"method":"PUT","path":"/internal/saas/action-policy/defaults","target":{"kind":"platform"}}';
    expect(hash).toBe(createHash("sha256").update(expectedJson).digest("base64url"));
    expect(hash).toBe(
      canonicalActionPolicyRequestHash("PUT", path, target, {
        reason: body.reason,
        actionIds: body.actionIds,
        enabled: true,
      }),
    );
    expect(hash).not.toBe(
      canonicalActionPolicyRequestHash("PUT", path, target, { ...body, reason: body.reason.trim() }),
    );
    expect(hash).not.toBe(canonicalActionPolicyRequestHash("POST", path, target, body));
    expect(hash).not.toBe(
      canonicalActionPolicyRequestHash("PUT", `${path}/gmail.messages_list`, target, {
        enabled: true,
        reason: body.reason,
      }),
    );
    expect(hash).not.toBe(
      canonicalActionPolicyRequestHash(
        "PUT",
        path,
        { kind: "tenant", tenantId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
        body,
      ),
    );
  });
});

function nestedInput(depth: number): unknown {
  let value: unknown = "leaf";
  for (let index = 0; index < depth; index += 1) {
    value = index % 2 === 0 ? { value } : [value];
  }
  return value;
}
