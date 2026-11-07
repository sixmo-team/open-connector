import type { ActionPolicyPage, ActionPolicyTarget } from "../contracts.ts";

import { actionPolicyPageSchema, actionPolicyTargetSchema } from "../contracts.ts";

export interface ScopedPagePosition {
  limit: number;
  key: string[];
}
interface ScopedCursor {
  v: 1;
  target: ActionPolicyTarget;
  kind: string;
  key: string[];
}

export function encodeScopedCursor(target: Readonly<ActionPolicyTarget>, kind: string, key: string[]): string {
  return Buffer.from(JSON.stringify({ v: 1, target, kind, key })).toString("base64url");
}

export function readScopedPage(
  page: ActionPolicyPage,
  target: Readonly<ActionPolicyTarget>,
  kind: string,
  arity: number,
): ScopedPagePosition {
  const parsed = actionPolicyPageSchema.parse(page);
  if (!parsed.cursor) return { limit: parsed.limit ?? 100, key: [] };
  let decoded: ScopedCursor;
  try {
    const bytes = Buffer.from(parsed.cursor, "base64url");
    if (bytes.toString("base64url") !== parsed.cursor) throw new Error("non-canonical cursor");
    decoded = JSON.parse(bytes.toString("utf8"));
    const expectedTarget = actionPolicyTargetSchema.parse(decoded.target);
    if (
      decoded.v !== 1 ||
      decoded.kind !== kind ||
      JSON.stringify(expectedTarget) !== JSON.stringify(target) ||
      !Array.isArray(decoded.key) ||
      decoded.key.length !== arity ||
      decoded.key.some((key) => typeof key !== "string" || key.length === 0) ||
      Object.keys(decoded).sort().join(",") !== "key,kind,target,v"
    )
      throw new Error("invalid cursor");
  } catch {
    throw new TypeError("Invalid scoped cursor");
  }
  return { limit: parsed.limit ?? 100, key: decoded.key };
}
