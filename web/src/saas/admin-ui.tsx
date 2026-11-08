import type { ThemeMode } from "../theme";
import type { AdminActor, AdminActionMode, AdminData, AdminScope, AdminScopes } from "./admin-model";
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
import { Navigate, NavLink, Route, Routes, useLocation, useSearchParams } from "react-router";
import oomolConnectLogoUrl from "../assets/oomol-connect-logo.png";
import { EmptyState, InlineError, StatusDot } from "../shared-ui";
import { useThemeMode } from "../theme";
import { AdminActionsPage } from "./actions-page";
import {
  AdminApiError,
  getAdminScopes,
  getAdminActions,
  getAdminActionDefaults,
  loadAdminData,
  putAdminActionGrant,
  putAdminActionGrants,
  putAdminActionDefault,
  putAdminActionDefaults,
  putAdminActionApprovalOverride,
} from "./admin-api";
import { emptyAdminData } from "./admin-model";
import { AdminConnectionsPage } from "./connections-page";
import { adminLangs, persistAdminLang } from "./i18n";
import { ManagedProjectPage } from "./managed-project-page";
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
  { path: "/managed-project", labelKey: "nav.managedProject", icon: Cable },
] as const;

type AdminHeading = "overview" | "providers" | "actions" | "connections" | "runs" | "managed-project";

const themeOptions = [
  { value: "auto", labelKey: "shell.themeMode.auto", icon: Monitor },
  { value: "light", labelKey: "shell.themeMode.light", icon: Sun },
  { value: "dark", labelKey: "shell.themeMode.dark", icon: Moon },
] as const;

export function AdminApp(): ReactNode {
  const t = useTranslate();
  const { theme, setTheme } = useThemeMode();
  const location = useLocation();
  const [params] = useSearchParams();
  const actionsPage = location.pathname === "/actions";
  const managedPage = location.pathname === "/managed-project";
  const mode: AdminActionMode | null =
    params.get("mode") === "defaults" ? "defaults" : params.get("mode") === "individual" ? "individual" : null;
  const [scopes, setScopes] = useState<AdminScopes | null>(null);
  const [scope, setScope] = useState<AdminScope>(emptyAdminScope);
  const [data, setData] = useState<AdminData>(emptyAdminData);
  const [loadingScopes, setLoadingScopes] = useState(true);
  const [loadingData, setLoadingData] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshGeneration, setRefreshGeneration] = useState(0);
  const requestGeneration = useRef(0);
  const contextKey = JSON.stringify([location.pathname, actionsPage ? mode : null, scope]);
  const currentContext = useRef(contextKey);
  currentContext.current = contextKey;
  const [loadedContext, setLoadedContext] = useState<string | null>(null);

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
    const context = contextKey;
    const current = () => generation === requestGeneration.current && currentContext.current === context;
    setData(emptyAdminData);
    if (managedPage) {
      setLoadingData(false);
      setError(null);
      return;
    }
    if (
      !scopes ||
      (actionsPage
        ? mode === null || (mode === "individual" && !isCompleteAdminScope(scope))
        : !isCompleteAdminScope(scope))
    ) {
      setLoadingData(false);
      return;
    }
    setError(null);
    setLoadingData(true);
    const load = actionsPage
      ? (mode === "defaults" ? getAdminActionDefaults() : getAdminActions(scope)).then((actions) => ({
          ...emptyAdminData,
          actions,
        }))
      : loadAdminData(scope);
    load
      .then((nextData) => {
        if (current()) {
          setData(nextData);
          setLoadedContext(context);
        }
      })
      .catch((caught: unknown) => {
        if (!current()) return;
        setData(emptyAdminData);
        if (caught instanceof AdminApiError && (caught.status === 401 || caught.status === 403))
          setScope(emptyAdminScope);
        setError(t("errors.loadData"));
      })
      .finally(() => {
        if (current()) setLoadingData(false);
      });
    return () => {
      requestGeneration.current += 1;
    };
  }, [scope, scopes, actionsPage, managedPage, mode, contextKey, refreshGeneration, t]);

  function changeScope(nextScope: AdminScope): void {
    requestGeneration.current += 1;
    setData(emptyAdminData);
    setError(null);
    setScope(nextScope);
  }

  async function saveAndReread(write: () => Promise<void>): Promise<void> {
    const context = contextKey;
    const generation = ++requestGeneration.current;
    const current = () => generation === requestGeneration.current && currentContext.current === context;
    let failure: unknown;
    try {
      await write();
    } catch (caught) {
      failure = caught;
    }
    if (!current()) {
      if (currentContext.current === context) setRefreshGeneration((value) => value + 1);
      return;
    }
    try {
      const actions = await (mode === "defaults" ? getAdminActionDefaults() : getAdminActions(scope));
      if (current()) setData((previous) => ({ ...previous, actions }));
    } catch (caught) {
      if (current()) {
        setData((previous) => ({ ...previous, actions: [] }));
        setError(t("errors.loadData"));
      }
      failure ??= caught;
    }
    if (current() && failure) throw failure;
  }

  async function updateGrant(actionId: string, enabled: boolean | null, reason: string): Promise<void> {
    if (mode === "defaults") {
      if (enabled === null) throw new Error("Defaults must be boolean");
      await saveAndReread(() => putAdminActionDefault(actionId, enabled, reason));
    } else if (mode === "individual" && isCompleteAdminScope(scope)) {
      await saveAndReread(() => putAdminActionGrant(actionId, scope, enabled, reason));
    } else throw new Error("Select permission mode and scope");
  }

  async function updateGrants(actionIds: string[], enabled: boolean | null, reason: string): Promise<void> {
    if (mode === "defaults") {
      if (enabled === null) throw new Error("Defaults must be boolean");
      await saveAndReread(() => putAdminActionDefaults(actionIds, enabled, reason));
    } else if (mode === "individual" && isCompleteAdminScope(scope)) {
      await saveAndReread(() => putAdminActionGrants(actionIds, scope, enabled, reason));
    } else throw new Error("Select permission mode and scope");
  }

  async function updateApproval(
    actionId: string,
    approvalOverride: "inherit" | "always",
    reason: string,
  ): Promise<void> {
    if (mode !== "individual" || !isCompleteAdminScope(scope)) throw new Error("Select individual scope");
    await saveAndReread(() => putAdminActionApprovalOverride(actionId, scope, approvalOverride, reason));
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
      data={loadedContext === contextKey ? data : emptyAdminData}
      mode={mode}
      refreshVersion={refreshGeneration}
      theme={theme}
      loading={loadingData}
      error={error}
      onScopeChange={changeScope}
      onRefresh={() => setRefreshGeneration((value) => value + 1)}
      onThemeChange={setTheme}
      onGrantChange={updateGrant}
      onBulkGrantChange={updateGrants}
      onApprovalChange={updateApproval}
    />
  );
}

interface AdminShellProps {
  scopes: AdminScopes | null;
  scope: AdminScope;
  data: AdminData;
  mode: AdminActionMode | null;
  refreshVersion: number;
  theme: ThemeMode;
  loading: boolean;
  error: string | null;
  onScopeChange(scope: AdminScope): void;
  onRefresh(): void;
  onThemeChange(theme: ThemeMode): void;
  onGrantChange(actionId: string, enabled: boolean | null, reason: string): Promise<void>;
  onBulkGrantChange(actionIds: string[], enabled: boolean | null, reason: string): Promise<void>;
  onApprovalChange(actionId: string, approvalOverride: "inherit" | "always", reason: string): Promise<void>;
}

function AdminShell(props: AdminShellProps): ReactNode {
  const t = useTranslate();
  const location = useLocation();
  const heading = headingForPath(location.pathname);
  const currentNavItem = navItems.find((item) => item.path === `/${heading}`) ?? navItems[0];
  const CurrentNavIcon = currentNavItem.icon;
  const managedPage = heading === "managed-project";
  const completeScope = managedPage
    ? Boolean(props.scope.tenantId && props.scope.workspaceId)
    : isCompleteAdminScope(props.scope);
  const actionsPage = heading === "actions";
  const globalActions = actionsPage && props.mode === "defaults";
  const chooseMode = actionsPage && props.mode === null;
  const [params, setParams] = useSearchParams();

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
            disabled={(!globalActions && !completeScope) || chooseMode || props.loading}
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
          {props.scopes ? (
            <div className="page-stack">
              {actionsPage ? (
                <label className="grid gap-2">
                  <span>{t("actions.mode")}</span>
                  <select
                    className="rounded-md border border-border bg-background p-2"
                    value={props.mode ?? ""}
                    onChange={(event) => {
                      const next = new URLSearchParams(params);
                      next.set("mode", event.target.value);
                      setParams(next);
                    }}
                  >
                    <option value="" disabled>
                      {t("actions.chooseMode")}
                    </option>
                    <option value="defaults">{t("actions.defaults")}</option>
                    <option value="individual">{t("actions.individual")}</option>
                  </select>
                </label>
              ) : null}
              {!globalActions && !chooseMode && props.scopes.tenants.length > 0 ? (
                <ScopeSelector
                  tenants={props.scopes.tenants}
                  value={props.scope}
                  disabled={props.loading}
                  workspaceOnly={managedPage}
                  onChange={props.onScopeChange}
                />
              ) : null}
              {props.error ? <InlineError message={props.error} /> : null}
              {chooseMode ? (
                <EmptyState title={t("actions.chooseMode")} description={t("actions.modeHint")} icon={null} />
              ) : !globalActions && !completeScope ? (
                <EmptyState
                  title={t(props.scopes.tenants.length > 0 ? "scope.incompleteTitle" : "scope.emptyTitle")}
                  description={t(
                    props.scopes.tenants.length > 0
                      ? managedPage
                        ? "managed.selectWorkspace"
                        : "scope.incompleteDescription"
                      : "scope.emptyDescription",
                  )}
                  icon={null}
                />
              ) : props.loading ? (
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
                        key={JSON.stringify([props.mode, props.scope])}
                        mode={props.mode ?? "individual"}
                        actions={props.data.actions}
                        onGrantChange={props.onGrantChange}
                        onBulkGrantChange={props.onBulkGrantChange}
                        onApprovalChange={props.onApprovalChange}
                      />
                    }
                  />
                  <Route path="/connections" element={<AdminConnectionsPage connections={props.data.connections} />} />
                  <Route path="/runs" element={<AdminRunsPage runs={props.data.runs} />} />
                  <Route
                    path="/managed-project"
                    element={
                      <ManagedProjectPage
                        key={JSON.stringify([props.scope.tenantId, props.scope.workspaceId, props.refreshVersion])}
                        target={{ tenantId: props.scope.tenantId, workspaceId: props.scope.workspaceId }}
                      />
                    }
                  />
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
  return section === "providers" ||
    section === "actions" ||
    section === "connections" ||
    section === "runs" ||
    section === "managed-project"
    ? section
    : "overview";
}
