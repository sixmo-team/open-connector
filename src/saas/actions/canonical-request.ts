import type { ActionPolicyTarget } from "../contracts.ts";

import { createHash } from "node:crypto";
import { actionInputMaxDepth } from "./action-idempotency.ts";

export interface CanonicalActionEnvelope {
  actionId: string;
  connectorConnectionId: string;
  input: unknown;
}

export interface CanonicalRequestEnvelope {
  operation: string;
  input: unknown;
}

/** Raised when an action input cannot be represented as bounded JSON. */
export class CanonicalActionRequestError extends TypeError {}

/**
 * Hash the exact action, connector connection, and recursively canonicalized JSON input.
 */
export function canonicalActionRequestHash(actionId: string, connectorConnectionId: string, input: unknown): string {
  const envelope: CanonicalActionEnvelope = { actionId, connectorConnectionId, input };
  const canonical = canonicalize(envelope, 0, new WeakSet<object>());
  return createHash("sha256").update(JSON.stringify(canonical)).digest("base64url");
}

/** Hash a fixed operation and its recursively canonicalized JSON input. */
export function canonicalRequestHash(operation: string, input: unknown): string {
  const envelope: CanonicalRequestEnvelope = { operation, input };
  const canonical = canonicalize(envelope, 0, new WeakSet<object>());
  return createHash("sha256").update(JSON.stringify(canonical)).digest("base64url");
}

/** Bind policy mutations to their exact method, pathname, verified target and unnormalized wire body. */
export function canonicalActionPolicyRequestHash(
  method: string,
  path: string,
  target: ActionPolicyTarget,
  body: unknown,
): string {
  const canonical = canonicalize({ method: method.toUpperCase(), path, target, body }, 0, new WeakSet<object>());
  return createHash("sha256").update(JSON.stringify(canonical)).digest("base64url");
}

function canonicalize(value: unknown, depth: number, ancestors: WeakSet<object>): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new CanonicalActionRequestError("Canonical action requests require finite numbers.");
    }
    return value;
  }
  if (typeof value !== "object") {
    throw new CanonicalActionRequestError(`Canonical action requests do not support ${typeof value} values.`);
  }
  if (depth > actionInputMaxDepth) {
    throw new CanonicalActionRequestError(
      `Action input must not exceed an object/array nesting depth of ${actionInputMaxDepth} levels.`,
    );
  }
  if (ancestors.has(value)) {
    throw new CanonicalActionRequestError("Canonical action requests do not support cyclic values.");
  }

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = Object.keys(value);
      if (
        Object.getOwnPropertySymbols(value).length > 0 ||
        keys.length !== value.length ||
        !keys.every((key) => String(Number(key)) === key && Number(key) < value.length)
      ) {
        throw new CanonicalActionRequestError(
          "Canonical action requests require dense JSON arrays without extra keys.",
        );
      }
      return value.map((entry) => canonicalize(entry, depth + 1, ancestors));
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new CanonicalActionRequestError("Canonical action requests require plain JSON objects.");
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new CanonicalActionRequestError("Canonical action requests do not support symbol keys.");
    }

    const entries = Object.entries(value).sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
    return Object.fromEntries(entries.map(([key, entry]) => [key, canonicalize(entry, depth + 1, ancestors)]));
  } finally {
    ancestors.delete(value);
  }
}
