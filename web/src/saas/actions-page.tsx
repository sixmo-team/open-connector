import type { AdminAction, AdminActionMode } from "./admin-model";
import type { ReactNode } from "react";

import { useTranslate } from "@embra/i18n/react";
import { Loader2, ShieldCheck } from "lucide-react";
import { useMemo, useRef, useState } from "react";
import { Badge, EmptyState, InlineError } from "../shared-ui";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

interface AdminActionsPageProps {
  mode: AdminActionMode;
  actions: AdminAction[];
  onGrantChange(actionId: string, enabled: boolean | null, reason: string): Promise<void>;
  onBulkGrantChange(actionIds: string[], enabled: boolean | null, reason: string): Promise<void>;
  onApprovalChange(actionId: string, approvalOverride: "inherit" | "always", reason: string): Promise<void>;
}

export function AdminActionsPage(props: AdminActionsPageProps): ReactNode {
  const t = useTranslate();
  const providers = useMemo(
    () => [
      ...new Map(
        props.actions.map((action) => [action.providerId, { id: action.providerId, name: action.providerName }]),
      ).values(),
    ],
    [props.actions],
  );
  const [pending, setPending] = useState(false);
  const writing = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const [providerId, setProviderId] = useState("all");
  const [reason, setReason] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkTarget, setBulkTarget] = useState("visible");
  const selectedProviderId =
    providerId === "all" || providers.some((provider) => provider.id === providerId) ? providerId : "all";
  const visibleActions =
    selectedProviderId === "all"
      ? props.actions
      : props.actions.filter((action) => action.providerId === selectedProviderId);
  const batch = (
    bulkTarget === "selected" ? props.actions.filter((action) => selected.has(action.actionId)) : visibleActions
  ).map(({ actionId }) => actionId);
  const validReason = reason.trim().length > 0 && reason.trim().length <= 500;
  const disabled = pending || !validReason;

  async function save(write: (reason: string) => Promise<void>, confirmation?: string): Promise<void> {
    if (writing.current || !validReason) return;
    if (confirmation && !window.confirm(confirmation)) return;
    writing.current = true;
    setPending(true);
    setError(null);
    try {
      await write(reason.trim());
    } catch {
      setError(t("errors.grant"));
    } finally {
      writing.current = false;
      setPending(false);
    }
  }

  function bulk(enabled: boolean | null): void {
    if (batch.length === 0 || batch.length > 5000) return;
    void save(
      (trimmed) => props.onBulkGrantChange(batch, enabled, trimmed),
      `${t("actions.confirmBatch")} ${batch.length}`,
    );
  }

  return (
    <div className="page-stack">
      <Card className="runtime-strip">
        <div>
          <strong>{t("actions.title")}</strong>
          <span className="!text-foreground/75">
            {t(props.mode === "defaults" ? "actions.defaultsDescription" : "actions.description")}
          </span>
        </div>
        <ShieldCheck size={18} aria-hidden="true" />
      </Card>
      <label className="grid gap-2">
        <span>{t("actions.reason")}</span>
        <textarea
          className="min-h-20 rounded-md border border-border bg-background p-2 text-sm"
          value={reason}
          maxLength={500}
          required
          disabled={pending}
          onChange={(event) => setReason(event.target.value)}
        />
        <span className="muted-copy">{t("actions.reasonHint")}</span>
      </label>
      {error ? <InlineError message={error} /> : null}
      {props.actions.length > 0 ? (
        <div className="flex flex-wrap items-center gap-2">
          <Select value={selectedProviderId} onValueChange={setProviderId} disabled={pending}>
            <SelectTrigger className="w-64" aria-label={t("actions.providerFilter")}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t("actions.allProviders")}</SelectItem>
              {providers.map((provider) => (
                <SelectItem key={provider.id} value={provider.id}>
                  {provider.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <span className="muted-copy mr-auto">
            {t("actions.visibleCount")}: {visibleActions.length} · {t("actions.selectedCount")}:{" "}
            {props.actions.filter((action) => selected.has(action.actionId)).length}
          </span>
          <label className="flex items-center gap-2">
            {t("actions.bulkTarget")}
            <select
              className="rounded-md border border-border bg-background p-2"
              value={bulkTarget}
              disabled={pending}
              onChange={(event) => setBulkTarget(event.target.value)}
            >
              <option value="visible">{t("actions.visibleRows")}</option>
              <option value="selected">{t("actions.selectedRows")}</option>
            </select>
          </label>
          <Button disabled={disabled || batch.length === 0 || batch.length > 5000} onClick={() => bulk(true)}>
            {pending ? <Loader2 className="spin" size={14} /> : null}
            {t("actions.allow")}
          </Button>
          <Button
            variant="outline"
            disabled={disabled || batch.length === 0 || batch.length > 5000}
            onClick={() => bulk(false)}
          >
            {t("actions.deny")}
          </Button>
          {props.mode === "individual" ? (
            <Button
              variant="outline"
              disabled={disabled || batch.length === 0 || batch.length > 5000}
              onClick={() => bulk(null)}
            >
              {t("actions.inherit")}
            </Button>
          ) : null}
          {batch.length > 5000 ? <span role="alert">{t("actions.batchLimit")}</span> : null}
        </div>
      ) : null}
      <section className="table-panel">
        {props.actions.length === 0 ? (
          <EmptyState title={t("actions.emptyTitle")} description={t("actions.emptyDescription")} icon={null} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("actions.select")}</TableHead>
                <TableHead>{t("actions.table.action")}</TableHead>
                <TableHead>{t("actions.table.provider")}</TableHead>
                <TableHead>{t("actions.table.classification")}</TableHead>
                <TableHead>{t("actions.table.grant")}</TableHead>
                {props.mode === "individual" ? <TableHead>{t("actions.confirmationMode")}</TableHead> : null}
              </TableRow>
            </TableHeader>
            <TableBody>
              {visibleActions.map((action) => (
                <TableRow key={action.actionId}>
                  <TableCell>
                    <input
                      type="checkbox"
                      aria-label={`${t("actions.select")}: ${action.displayName}`}
                      checked={selected.has(action.actionId)}
                      disabled={pending}
                      onChange={(event) => {
                        const checked = event.target.checked;
                        setSelected((current) => {
                          const next = new Set(current);
                          if (checked) next.add(action.actionId);
                          else next.delete(action.actionId);
                          return next;
                        });
                      }}
                    />
                  </TableCell>
                  <TableCell>
                    <div className="grid gap-1">
                      <strong>{action.displayName}</strong>
                      <span className="muted-copy mono !text-foreground/75">{action.actionId}</span>
                    </div>
                  </TableCell>
                  <TableCell>{action.providerName}</TableCell>
                  <TableCell>
                    <div className="grid gap-2">
                      <div className="flex flex-wrap gap-2 [&_.badge]:!text-foreground/80">
                        <Badge
                          tone={
                            action.risk === "destructive" || action.risk === "access_change"
                              ? "error"
                              : action.risk === "write"
                                ? "warning"
                                : "success"
                          }
                        >
                          {t(`actions.risk.${action.risk}`)}
                        </Badge>
                        <Badge tone={action.requiresApproval ? "warning" : undefined}>
                          {action.requiresApproval
                            ? t("actions.approval")
                            : t(`actions.idempotency.${action.idempotency}`)}
                        </Badge>
                        <Badge>{t(`actions.role.${action.minimumRole}`)}</Badge>
                      </div>
                      <span className="muted-copy !text-foreground/75">
                        {t("actions.inputLimit")}: {formatBytes(action.maxInputBytes)} · {t("actions.outputLimit")}:{" "}
                        {formatBytes(action.maxOutputBytes)}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="grid gap-2">
                      <span>
                        {t(action.permission.enabled ? "common.enabled" : "common.disabled")} ·{" "}
                        {t(`actions.source.${action.permission.source}`)}
                      </span>
                      <label className="grid gap-1">
                        <span className="muted-copy">
                          {t(props.mode === "defaults" ? "actions.defaultRule" : "actions.individualRule")}
                        </span>
                        <select
                          className="rounded-md border border-border bg-background p-2"
                          aria-label={`${t("actions.table.grant")}: ${action.displayName}`}
                          disabled={disabled}
                          value={String(
                            props.mode === "defaults"
                              ? action.permission.defaultEnabled
                              : action.permission.individualEnabled,
                          )}
                          onChange={(event) => {
                            const enabled = event.target.value === "null" ? null : event.target.value === "true";
                            void save((trimmed) => props.onGrantChange(action.actionId, enabled, trimmed));
                          }}
                        >
                          {props.mode === "individual" ? (
                            <option value="null">{t("actions.inherit")}</option>
                          ) : action.permission.defaultEnabled === null ? (
                            <option value="null" disabled>
                              {t("actions.noDefault")}
                            </option>
                          ) : null}
                          <option value="true">{t("actions.allow")}</option>
                          <option value="false">{t("actions.deny")}</option>
                        </select>
                      </label>
                    </div>
                  </TableCell>
                  {props.mode === "individual" ? (
                    <TableCell>
                      <label className="grid gap-1">
                        <span className="muted-copy">{t("actions.confirmationHint")}</span>
                        <select
                          className="rounded-md border border-border bg-background p-2"
                          aria-label={`${t("actions.confirmationMode")}: ${action.displayName}`}
                          value={action.approvalOverride}
                          disabled={disabled}
                          onChange={(event) => {
                            const value = event.target.value as "inherit" | "always";
                            void save(
                              (trimmed) => props.onApprovalChange(action.actionId, value, trimmed),
                              t("actions.confirmApproval"),
                            );
                          }}
                        >
                          <option value="inherit">{t("actions.confirmationInherit")}</option>
                          <option value="always">{t("actions.confirmationAlways")}</option>
                        </select>
                      </label>
                    </TableCell>
                  ) : null}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </section>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1_000) return `${bytes} B`;
  if (bytes < 1_000_000) return `${(bytes / 1_000).toFixed(1)} kB`;
  return `${(bytes / 1_000_000).toFixed(1)} MB`;
}
