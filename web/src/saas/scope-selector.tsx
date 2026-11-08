import type { AdminScope, AdminTenant } from "./admin-model";
import type { ReactNode } from "react";

import { useTranslate } from "@embra/i18n/react";
import { Building2 } from "lucide-react";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

export const emptyAdminScope: AdminScope = { tenantId: "", workspaceId: "", subjectId: "" };

export type AdminScopeLevel = keyof AdminScope;

export function changeAdminScope(scope: AdminScope, level: AdminScopeLevel, value: string): AdminScope {
  if (level === "tenantId") return { tenantId: value, workspaceId: "", subjectId: "" };
  if (level === "workspaceId") return { tenantId: scope.tenantId, workspaceId: value, subjectId: "" };
  return { ...scope, subjectId: value };
}

export function isCompleteAdminScope(scope: AdminScope): boolean {
  return Boolean(scope.tenantId && scope.workspaceId && scope.subjectId);
}

interface ScopeSelectorProps {
  tenants: AdminTenant[];
  value: AdminScope;
  disabled?: boolean;
  workspaceOnly?: boolean;
  onChange(scope: AdminScope): void;
}

export function ScopeSelector(props: ScopeSelectorProps): ReactNode {
  const t = useTranslate();
  const tenant = props.tenants.find((item) => item.id === props.value.tenantId);
  const workspace = tenant?.workspaces.find((item) => item.id === props.value.workspaceId);

  function update(level: AdminScopeLevel, value: string): void {
    props.onChange(changeAdminScope(props.value, level, value));
  }

  return (
    <section className="detail-panel grid gap-4" aria-labelledby="admin-scope-title">
      <div className="section-heading-row !mb-0">
        <div className="detail-heading">
          <span className="action-mark" aria-hidden="true">
            <Building2 size={18} />
          </span>
          <h2 id="admin-scope-title">{t("scope.title")}</h2>
        </div>
      </div>
      <div className="page-toolbar flex-wrap">
        <ScopeSelect
          label={t("scope.tenant")}
          placeholder={t("scope.selectTenant")}
          value={props.value.tenantId}
          disabled={props.disabled || props.tenants.length === 0}
          onChange={(value) => update("tenantId", value)}
        >
          {props.tenants.map((item) => (
            <SelectItem key={item.id} value={item.id}>
              {item.displayName}
            </SelectItem>
          ))}
        </ScopeSelect>
        <ScopeSelect
          label={t("scope.workspace")}
          placeholder={t("scope.selectWorkspace")}
          value={props.value.workspaceId}
          disabled={props.disabled || !tenant}
          onChange={(value) => update("workspaceId", value)}
        >
          {tenant?.workspaces.map((item) => (
            <SelectItem key={item.id} value={item.id}>
              {item.displayName}
            </SelectItem>
          ))}
        </ScopeSelect>
        {!props.workspaceOnly ? (
          <ScopeSelect
            wide
            label={t("scope.subject")}
            placeholder={t("scope.selectSubject")}
            value={props.value.subjectId}
            disabled={props.disabled || !workspace}
            onChange={(value) => update("subjectId", value)}
          >
            {workspace?.subjects.map((item) => (
              <SelectItem key={item.id} value={item.id}>
                {item.displayName}
                {item.email ? ` · ${item.email}` : ""}
              </SelectItem>
            ))}
          </ScopeSelect>
        ) : null}
      </div>
    </section>
  );
}

function ScopeSelect(props: {
  label: string;
  wide?: boolean;
  placeholder: string;
  value: string;
  disabled?: boolean;
  onChange(value: string): void;
  children: ReactNode;
}): ReactNode {
  return (
    <div
      className={`select-filter min-w-0 basis-full flex-1 sm:min-w-64 ${
        props.wide ? "sm:basis-full !flex" : "sm:basis-auto"
      }`}
    >
      <span className="select-filter-label !text-foreground/75">{props.label}</span>
      <Select value={props.value || undefined} disabled={props.disabled} onValueChange={props.onChange}>
        <SelectTrigger className="select-filter-trigger" aria-label={props.label}>
          <SelectValue placeholder={props.placeholder} />
        </SelectTrigger>
        <SelectContent className="select-filter-content" position="popper" align="start">
          {props.children}
        </SelectContent>
      </Select>
    </div>
  );
}
