import { expect, it } from "vitest";
import { resolveActionPermission } from "./action-permission-policy.ts";

const cases = [
  { individual: null, defaults: null, enabled: false, source: "none" },
  { individual: null, defaults: false, enabled: false, source: "platform" },
  { individual: null, defaults: true, enabled: true, source: "platform" },
  { individual: false, defaults: null, enabled: false, source: "individual" },
  { individual: false, defaults: false, enabled: false, source: "individual" },
  { individual: false, defaults: true, enabled: false, source: "individual" },
  { individual: true, defaults: null, enabled: true, source: "individual" },
  { individual: true, defaults: false, enabled: true, source: "individual" },
  { individual: true, defaults: true, enabled: true, source: "individual" },
] as const;

it.each(cases)("resolves individual=$individual platform=$defaults", ({ individual, defaults, enabled, source }) => {
  expect(resolveActionPermission("gmail.messages_list", individual, defaults)).toEqual({
    actionId: "gmail.messages_list",
    enabled,
    source,
    individualEnabled: individual,
    defaultEnabled: defaults,
  });
});
