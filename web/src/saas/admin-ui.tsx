import type { ThemeMode } from "../theme";
import type { AdminActor, AdminData, AdminScope, AdminScopes } from "./admin-model";
import type { AdminLang } from "./i18n";
import type { ReactNode } from "react";

import { useI18n, useLang, useTranslate } from "@embra/i18n/react";
import {
  Activity,
  Cable,
  Home,
  Languages,
  Link2,
  Loader2,
  Monitor,
  Moon,
  RefreshCw,
  Sun,
  TerminalSquare,
  UserCog,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Navigate, NavLink, Route, Routes, useLocation } from "react-router";
import oomolConnectLogoUrl from "../assets/oomol-connect-logo.png";
import { EmptyState, InlineError, StatusDot } from "../shared-ui";
import { useThemeMode } from "../theme";
import { AdminActionsPage } from "./actions-page";
import { AdminApiError, getAdminScopes, loadAdminData, putAdminActionGrant, putAdminActionGrants } from "./admin-api";
import { emptyAdminData } from "./admin-model";
import { AdminConnectionsPage } from "./connections-page";
import { adminLangs, persistAdminLang } from "./i18n";
import { AdminOverviewPage } from "./overview-page";
import { AdminProvidersPage } from "./providers-page";
import { AdminRunsPage } from "./runs-page";
import { emptyAdminScope, isCompleteAdminScope, ScopeSelector } from "./scope-selector";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

const navItems = [
  { path: "/overview", labelKey: "nav.overview", icon: Home },
  { path: "/providers", labelKey: "nav.providers", icon: Cable },
  { path: "/actions", labelKey: "nav.actions", icon: TerminalSquare },
  { path: "/connections", labelKey: "nav.connections", icon: Link2 },
  { path: "/runs", labelKey: "nav.runs", icon: Activity },
] as const;

type AdminHeading = "overview" | "providers" | "actions" | "connections" | "runs";

const themeOptions = [
  { value: "auto", labelKey: "shell.themeMode.auto", icon: Monitor },
  { value: "light", labelKey: "shell.themeMode.light", icon: Sun },
  { value: "dark", labelKey: "shell.themeMode.dark", icon: Moon },
] as const;

export function AdminApp(): ReactNode {
  const t = useTranslate();
  const { theme, setTheme } = useThemeMode();
  const [scopes, setScopes] = useState<AdminScopes | null>(null);
  const [scope, setScope] = useState<AdminScope>(emptyAdminScope);
  const [data, setData] = useState<AdminData>(emptyAdminData);
  const [loadingScopes, setLoadingScopes] = useState(true);
  const [loadingData, setLoadingData] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshGeneration, setRefreshGeneration] = useState(0);
  const requestGeneration = useRef(0);

  useEffect(() => {
    let cancelled = false;
    getAdminScopes()
      .then((nextScopes) => {
        if (!cancelled) {
          setScopes(nextScopes);
          setError(null);
        }
      })
      .catch(() => {
        if (!cancelled) setError(t("errors.loadScopes"));
      })
      .finally(() => {
        if (!cancelled) setLoadingScopes(false);
      });
    return () => {
      cancelled = true;
    };
  }, [t]);

  useEffect(() => {
    const generation = ++requestGeneration.current;
    setData(emptyAdminData);
    if (!isCompleteAdminScope(scope)) {
      setLoadingData(false);
      return;
    }
    setError(null);

    setLoadingData(true);
    loadAdminData(scope)
      .then((nextData) => {
        if (generation === requestGeneration.current) setData(nextData);
      })
      .catch((caught: unknown) => {
        if (generation !== requestGeneration.current) return;
        setData(emptyAdminData);
        if (caught instanceof AdminApiError && (caught.status === 401 || caught.status === 403)) {
          setScope(emptyAdminScope);
        }
        setError(t("errors.loadData"));
      })
      .finally(() => {
        if (generation === requestGeneration.current) setLoadingData(false);
      });
  }, [scope, refreshGeneration, t]);

  function changeScope(nextScope: AdminScope): void {
    requestGeneration.current += 1;
    setData(emptyAdminData);
    setError(null);
    setScope(nextScope);
  }

  async function updateGrant(
    actionId: string,
    granted: boolean,
    approvalOverride: "inherit" | "always",
  ): Promise<void> {
    if (!isCompleteAdminScope(scope)) return;
    await putAdminActionGrant(actionId, scope, granted, approvalOverride);
    setData((current) => ({
      ...current,
      actions: current.actions.map((action) => (action.actionId === actionId ? { ...action, granted } : action)),
    }));
  }

  async function updateGrants(actionIds: string[], granted: boolean): Promise<void> {
    if (!isCompleteAdminScope(scope)) return;
    await putAdminActionGrants(actionIds, scope, granted, "inherit");
    const changed = new Set(actionIds);
    setData((current) => ({
      ...current,
      actions: current.actions.map((action) => (changed.has(action.actionId) ? { ...action, granted } : action)),
    }));
  }

  if (loadingScopes) {
    return (
      <main className="unlock-screen">
        <div className="loading-panel">
          <Loader2 className="spin" size={16} />
          {t("common.loading")}
        </div>
      </main>
    );
  }

  return (
    <AdminShell
      scopes={scopes}
      scope={scope}
      data={data}
      theme={theme}
      loading={loadingData}
      error={error}
      onScopeChange={changeScope}
      onRefresh={() => setRefreshGeneration((value) => value + 1)}
      onThemeChange={setTheme}
      onGrantChange={updateGrant}
      onBulkGrantChange={updateGrants}
    />
  );
}

interface AdminShellProps {
  scopes: AdminScopes | null;
  scope: AdminScope;
  data: AdminData;
  theme: ThemeMode;
  loading: boolean;
  error: string | null;
  onScopeChange(scope: AdminScope): void;
  onRefresh(): void;
  onThemeChange(theme: ThemeMode): void;
  onGrantChange(actionId: string, granted: boolean, approvalOverride: "inherit" | "always"): Promise<void>;
  onBulkGrantChange(actionIds: string[], granted: boolean): Promise<void>;
}

function AdminShell(props: AdminShellProps): ReactNode {
  const t = useTranslate();
  const location = useLocation();
  const heading = headingForPath(location.pathname);
  const currentNavItem = navItems.find((item) => item.path === `/${heading}`) ?? navItems[0];
  const CurrentNavIcon = currentNavItem.icon;
  const completeScope = isCompleteAdminScope(props.scope);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <img className="brand-mark" src={oomolConnectLogoUrl} alt="" />
          <div>
            <div className="brand-name">OOMOL Connect</div>
            <div className="brand-subtitle">{t("brand.subtitle")}</div>
          </div>
        </div>

        <nav className="sidebar-nav" aria-label={t("shell.primaryNav")}>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                className={({ isActive }) => (isActive ? "nav-item active" : "nav-item")}
                to={item.path}
              >
                <Icon size={16} />
                <span>{t(item.labelKey)}</span>
              </NavLink>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          {props.scopes?.actor ? <ActorContext actor={props.scopes.actor} /> : null}
          <LanguageSelect />
          <ThemeControl theme={props.theme} onThemeChange={props.onThemeChange} />
          <div className="runtime-status">
            <StatusDot ok={!props.error} />
            <span>{t(props.error ? "shell.statusUnavailable" : "shell.statusReady")}</span>
          </div>
          <Button
            variant="outline"
            size="icon-sm"
            disabled={!completeScope || props.loading}
            onClick={props.onRefresh}
            aria-label={t("shell.refreshData")}
          >
            {props.loading ? <Loader2 className="spin" size={15} /> : <RefreshCw size={15} />}
          </Button>
        </div>
      </aside>

      <div className="main-region">
        <header className="shell-header">
          <div className="shell-header-title">
            <CurrentNavIcon size={16} />
            <h1>{t(`shell.headings.${heading}`)}</h1>
          </div>
          {props.loading ? (
            <div className="loading-panel page-loading">
              <Loader2 className="spin" size={16} />
              {t("common.loading")}
            </div>
          ) : null}
        </header>

        <main className={heading === "overview" ? "main overview-main" : "main"}>
          {props.scopes && props.scopes.tenants.length > 0 ? (
            <div className="page-stack">
              <ScopeSelector
                tenants={props.scopes.tenants}
                value={props.scope}
                disabled={props.loading}
                onChange={props.onScopeChange}
              />
              {props.error ? <InlineError message={props.error} /> : null}
              {!completeScope ? (
                <EmptyState
                  title={t("scope.incompleteTitle")}
                  description={t("scope.incompleteDescription")}
                  icon={null}
                />
              ) : props.loading && props.data.overview === null ? (
                <div className="loading-panel">
                  <Loader2 className="spin" size={16} />
                  {t("common.loading")}
                </div>
              ) : (
                <Routes>
                  <Route index element={<Navigate to="/overview" replace />} />
                  <Route
                    path="/overview"
                    element={
                      props.data.overview ? (
                        <AdminOverviewPage overview={props.data.overview} onRefresh={props.onRefresh} />
                      ) : null
                    }
                  />
                  <Route path="/providers" element={<AdminProvidersPage providers={props.data.providers} />} />
                  <Route
                    path="/actions"
                    element={
                      <AdminActionsPage
                        actions={props.data.actions}
                        onGrantChange={props.onGrantChange}
                        onBulkGrantChange={props.onBulkGrantChange}
                      />
                    }
                  />
                  <Route path="/connections" element={<AdminConnectionsPage connections={props.data.connections} />} />
                  <Route path="/runs" element={<AdminRunsPage runs={props.data.runs} />} />
                  <Route path="*" element={<Navigate to="/overview" replace />} />
                </Routes>
              )}
            </div>
          ) : (
            <div className="page-stack">
              {props.error ? <InlineError message={props.error} /> : null}
              <EmptyState title={t("scope.emptyTitle")} description={t("scope.emptyDescription")} icon={null} />
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

function ActorContext(props: { actor: AdminActor }): ReactNode {
  const t = useTranslate();
  return (
    <div className="col-span-full grid gap-1 rounded-md border border-border bg-background p-3 text-xs">
      <span className="flex items-center gap-2 text-muted-foreground">
        <UserCog size={14} aria-hidden="true" />
        {t("actor.label")}
      </span>
      <strong className="truncate">{props.actor.displayName}</strong>
      {props.actor.email ? <span className="truncate text-muted-foreground">{props.actor.email}</span> : null}
    </div>
  );
}

function ThemeControl(props: { theme: ThemeMode; onThemeChange(theme: ThemeMode): void }): ReactNode {
  const t = useTranslate();
  return (
    <div className="theme-control" aria-label={t("shell.theme")}>
      <span>{t("shell.theme")}</span>
      <div className="theme-segmented-control" role="radiogroup" aria-label={t("shell.theme")}>
        {themeOptions.map((item) => {
          const Icon = item.icon;
          const selected = props.theme === item.value;
          return (
            <button
              key={item.value}
              type="button"
              className={selected ? "theme-segment active" : "theme-segment"}
              role="radio"
              aria-checked={selected}
              aria-label={t(item.labelKey)}
              title={t(item.labelKey)}
              onClick={() => props.onThemeChange(item.value)}
            >
              <Icon size={14} />
            </button>
          );
        })}
      </div>
    </div>
  );
}

function LanguageSelect(): ReactNode {
  const t = useTranslate();
  const i18n = useI18n();
  const lang = useLang() as AdminLang;
  return (
    <div className="language-select">
      <span className="language-select-label">
        <Languages className="inline" size={13} aria-hidden="true" /> {t("language.label")}
      </span>
      <Select
        value={lang}
        onValueChange={(value) => {
          const nextLang = value as AdminLang;
          persistAdminLang(nextLang);
          void i18n.switchLang(nextLang);
        }}
      >
        <SelectTrigger className="language-select-trigger" size="sm" aria-label={t("language.label")}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent className="language-select-content" position="popper" align="start">
          {adminLangs.map((item) => (
            <SelectItem key={item} value={item}>
              {t(`language.${item}`)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

function headingForPath(pathname: string): AdminHeading {
  const section = pathname.split("/").filter(Boolean)[0];
  return section === "providers" || section === "actions" || section === "connections" || section === "runs"
    ? section
    : "overview";
}
