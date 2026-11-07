import type { ActionPermissionDecision } from "../contracts.ts";

/** A missing row inherits; an explicit false is a decision, never absence. */
export function resolveActionPermission(
  actionId: string,
  individualEnabled: boolean | null,
  defaultEnabled: boolean | null,
): ActionPermissionDecision {
  return {
    actionId,
    enabled: individualEnabled ?? defaultEnabled ?? false,
    source: individualEnabled !== null ? "individual" : defaultEnabled !== null ? "platform" : "none",
    individualEnabled,
    defaultEnabled,
  };
}
