import { I18nProvider } from "@embra/i18n/react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import { AdminApp } from "./admin-ui";
import { createAdminI18n, readInitialAdminLang } from "./i18n";
import "../style.css";

const i18n = createAdminI18n(readInitialAdminLang());

i18n.lang$.subscribe((lang) => {
  document.documentElement.lang = lang;
});

createRoot(document.getElementById("root")!).render(
  <I18nProvider i18n={i18n}>
    <BrowserRouter basename="/integration-console">
      <AdminApp />
    </BrowserRouter>
  </I18nProvider>,
);
