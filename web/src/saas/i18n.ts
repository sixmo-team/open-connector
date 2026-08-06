import type { Locales } from "@embra/i18n";

import { I18n, detectLang } from "@embra/i18n";
import en from "./locales/en.json";
import ru from "./locales/ru.json";

export type AdminLang = "en" | "ru";

export const adminLangs = ["en", "ru"] as const satisfies readonly AdminLang[];
export const adminLangStorageKey = "oomol-connect.saas.lang";

const locales = { en, ru } satisfies Locales;

export function createAdminI18n(initialLang: AdminLang): I18n {
  return new I18n(initialLang, locales, { fallback: "en" });
}

export function readInitialAdminLang(storage: Storage | undefined = globalThis.localStorage): AdminLang {
  const stored = storage?.getItem(adminLangStorageKey);
  if (stored === "en" || stored === "ru") return stored;
  return detectLang()?.toLowerCase().startsWith("ru") ? "ru" : "en";
}

export function persistAdminLang(lang: AdminLang, storage: Storage | undefined = globalThis.localStorage): void {
  storage?.setItem(adminLangStorageKey, lang);
}
