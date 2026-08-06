import type { AdminAction } from "./admin-model";
import type { ReactNode } from "react";

import { useTranslate } from "@embra/i18n/react";
import { Loader2, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { Badge, EmptyState, InlineError } from "../shared-ui";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

interface AdminActionsPageProps {
  actions: AdminAction[];
  onGrantChange(actionId: string, granted: boolean, approvalOverride: "inherit" | "always"): Promise<void>;
}

export function AdminActionsPage(props: AdminActionsPageProps): ReactNode {
  const t = useTranslate();
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function updateGrant(action: AdminAction): Promise<void> {
    setPendingAction(action.actionId);
    setError(null);
    try {
      await props.onGrantChange(action.actionId, !action.granted, action.approvalOverride);
    } catch {
      setError(t("errors.grant"));
    } finally {
      setPendingAction(null);
    }
  }

  return (
    <div className="page-stack">
      <Card className="runtime-strip">
        <div>
          <strong>{t("actions.title")}</strong>
          <span className="!text-foreground/75">{t("actions.description")}</span>
        </div>
        <ShieldCheck size={18} aria-hidden="true" />
      </Card>
      {error ? <InlineError message={error} /> : null}
      <section className="table-panel">
        {props.actions.length === 0 ? (
          <EmptyState title={t("actions.emptyTitle")} description={t("actions.emptyDescription")} icon={null} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("actions.table.action")}</TableHead>
                <TableHead>{t("actions.table.provider")}</TableHead>
                <TableHead>{t("actions.table.classification")}</TableHead>
                <TableHead className="text-right">{t("actions.table.grant")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {props.actions.map((action) => {
                const pending = pendingAction === action.actionId;
                return (
                  <TableRow key={action.actionId}>
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
                    <TableCell className="text-right">
                      <Button
                        variant={action.granted ? "outline" : "default"}
                        size="sm"
                        disabled={pending}
                        aria-busy={pending}
                        onClick={() => void updateGrant(action)}
                      >
                        {pending ? <Loader2 className="spin" size={14} /> : null}
                        {pending ? t("actions.updating") : t(action.granted ? "actions.revoke" : "actions.grant")}
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
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
