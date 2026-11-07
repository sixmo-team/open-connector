import type { CatalogStore } from "../../catalog-store.ts";

/** The reserved namespace cannot collide with an ordinary action or prefix itself. */
export function triggerCapability(
  catalog: Pick<CatalogStore, "providers">,
  service: string,
  triggerId: string,
): string {
  const provider = catalog.providers.find((candidate) => candidate.service === service);
  if (
    triggerId.startsWith("trigger:") ||
    !triggerId.startsWith(`${service}.`) ||
    !provider?.triggers?.some((trigger) => trigger.provider === service && trigger.key === triggerId)
  )
    throw new TypeError("Unknown declared Trigger capability");
  return `trigger:${triggerId}`;
}
