import type { SafeAdminRun } from "./admin-model";
import type { ReactNode } from "react";

import { useTranslate } from "@embra/i18n/react";
import { Activity } from "lucide-react";
import { Badge, EmptyState } from "../shared-ui";
import { Card } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export function AdminRunsPage(props: { runs: SafeAdminRun[] }): ReactNode {
  const t = useTranslate();

  return (
    <div className="page-stack">
      <Card className="runtime-strip">
        <div>
          <strong>{t("runs.title")}</strong>
          <span className="!text-foreground/75">{t("runs.description")}</span>
        </div>
        <Activity size={18} aria-hidden="true" />
      </Card>
      <section className="table-panel">
        {props.runs.length === 0 ? (
          <EmptyState title={t("runs.emptyTitle")} description={t("runs.emptyDescription")} icon={null} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="min-w-16 whitespace-normal">{t("runs.table.started")}</TableHead>
                <TableHead className="min-w-24 whitespace-normal">{t("runs.table.actorSubject")}</TableHead>
                <TableHead className="min-w-16 whitespace-normal">{t("runs.table.action")}</TableHead>
                <TableHead className="min-w-16 whitespace-normal">{t("runs.table.connection")}</TableHead>
                <TableHead className="min-w-16">{t("runs.table.status")}</TableHead>
                <TableHead className="min-w-16 text-right">{t("runs.table.duration")}</TableHead>
                <TableHead className="min-w-18 text-right">{t("runs.table.volume")}</TableHead>
                <TableHead className="min-w-16 whitespace-normal">{t("runs.table.error")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {props.runs.map((run, index) => (
                <TableRow key={`${run.startedAt}:${run.actorName}:${run.actionName}:${index}`}>
                  <TableCell className="min-w-16 whitespace-normal break-words">
                    {new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
                      new Date(run.startedAt),
                    )}
                  </TableCell>
                  <TableCell className="min-w-24 whitespace-normal break-all">
                    <div className="grid gap-1">
                      <strong>{run.actorName}</strong>
                      <span className="muted-copy !text-foreground/75">→ {run.subjectName}</span>
                    </div>
                  </TableCell>
                  <TableCell className="min-w-16 whitespace-normal break-words">
                    <div className="grid gap-1">
                      <strong>{run.providerName}</strong>
                      <span className="muted-copy !text-foreground/75">{run.actionName}</span>
                    </div>
                  </TableCell>
                  <TableCell className="min-w-16 whitespace-normal break-all">{run.connectionName}</TableCell>
                  <TableCell className="min-w-16">
                    <Badge
                      tone={run.status === "succeeded" ? "success" : run.status === "failed" ? "error" : "warning"}
                    >
                      {t(`runs.status.${run.status}`)}
                    </Badge>
                  </TableCell>
                  <TableCell className="min-w-16 text-right tabular-nums">{formatDuration(run.durationMs)}</TableCell>
                  <TableCell className="min-w-18 text-right tabular-nums">
                    <div className="grid gap-1">
                      <span>↓ {formatBytes(run.inputBytes)}</span>
                      <span>↑ {formatBytes(run.outputBytes)}</span>
                    </div>
                  </TableCell>
                  <TableCell className="mono min-w-16 whitespace-normal break-all">{run.errorCode ?? "—"}</TableCell>
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

function formatDuration(milliseconds: number): string {
  return milliseconds < 1_000 ? `${milliseconds} ms` : `${(milliseconds / 1_000).toFixed(2)} s`;
}
