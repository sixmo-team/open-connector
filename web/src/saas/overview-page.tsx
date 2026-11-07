import type { AdminOverview } from "./admin-model";
import type { ChartConfig } from "@/components/ui/chart";
import type { ReactNode } from "react";

import { useTranslate } from "@embra/i18n/react";
import { RefreshCw } from "lucide-react";
import { Bar, BarChart, CartesianGrid, Cell, XAxis, YAxis } from "recharts";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { ChartContainer, ChartTooltip, ChartTooltipContent } from "@/components/ui/chart";

interface AdminOverviewPageProps {
  overview: AdminOverview;
  onRefresh(): void;
}

export function AdminOverviewPage(props: AdminOverviewPageProps): ReactNode {
  const t = useTranslate();
  const outcomeChart = {
    calls: { label: t("overview.metrics.calls"), color: "var(--chart-1)" },
  } satisfies ChartConfig;
  const outcomes = [
    { label: t("overview.metrics.successes"), calls: props.overview.successes, color: "var(--chart-3)" },
    { label: t("overview.metrics.failures"), calls: props.overview.failures, color: "var(--chart-5)" },
  ];

  return (
    <div className="page-stack overview-page">
      <Card className="runtime-strip">
        <div>
          <strong>{t("overview.scopeReady")}</strong>
          <span className="!text-foreground/75">{t("overview.scopeReadyDescription")}</span>
        </div>
        <Button variant="outline" size="sm" onClick={props.onRefresh}>
          <RefreshCw size={15} />
          {t("common.refresh")}
        </Button>
      </Card>

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3" aria-label={t("nav.overview")}>
        <FormattedMetric label={t("overview.metrics.connections")} value={props.overview.connections} />
        <FormattedMetric label={t("overview.metrics.activeConnections")} value={props.overview.activeConnections} />
        <FormattedMetric label={t("overview.metrics.providers")} value={props.overview.providers} />
        <FormattedMetric label={t("overview.metrics.activeProviders")} value={props.overview.activeProviders} />
        <FormattedMetric label={t("overview.metrics.actions")} value={props.overview.actions} />
        <FormattedMetric label={t("overview.metrics.enabledActions")} value={props.overview.enabledActions} />
        <FormattedMetric label={t("overview.metrics.calls")} value={props.overview.calls} />
        <FormattedMetric label={t("overview.metrics.successes")} value={props.overview.successes} />
        <FormattedMetric label={t("overview.metrics.failures")} value={props.overview.failures} />
        <FormattedMetric label={t("overview.metrics.inputBytes")} value={formatBytes(props.overview.inputBytes)} />
        <FormattedMetric label={t("overview.metrics.outputBytes")} value={formatBytes(props.overview.outputBytes)} />
        <FormattedMetric
          label={t("overview.metrics.totalDuration")}
          value={formatDuration(props.overview.durationMs)}
        />
      </section>

      <section className="content-grid">
        <Card className="detail-panel">
          <div className="section-heading-row">
            <h2>{t("overview.callOutcome")}</h2>
          </div>
          <ChartContainer config={outcomeChart} className="h-64 w-full">
            <BarChart data={outcomes} margin={{ top: 12, right: 8, left: -8, bottom: 0 }}>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="label" axisLine={false} tickLine={false} tickMargin={10} />
              <YAxis allowDecimals={false} axisLine={false} tickLine={false} tickMargin={10} width={32} />
              <ChartTooltip content={<ChartTooltipContent />} />
              <Bar dataKey="calls" radius={4} isAnimationActive={false}>
                {outcomes.map((outcome) => (
                  <Cell key={outcome.label} fill={outcome.color} />
                ))}
              </Bar>
            </BarChart>
          </ChartContainer>
        </Card>

        <Card className="detail-panel">
          <div className="section-heading-row">
            <h2>{t("overview.duration")}</h2>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <FormattedMetric label="p50" value={formatDuration(props.overview.durationP50Ms)} />
            <FormattedMetric label="p95" value={formatDuration(props.overview.durationP95Ms)} />
          </div>
        </Card>
      </section>
    </div>
  );
}

function FormattedMetric(props: { label: string; value: string | number }): ReactNode {
  return (
    <Card className="gap-2 p-4">
      <span className="text-sm text-muted-foreground">{props.label}</span>
      <strong className="text-2xl tabular-nums">{props.value}</strong>
    </Card>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1_000) return `${bytes} B`;
  if (bytes < 1_000_000) return `${(bytes / 1_000).toFixed(1)} kB`;
  if (bytes < 1_000_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  return `${(bytes / 1_000_000_000).toFixed(1)} GB`;
}

function formatDuration(milliseconds: number): string {
  if (milliseconds < 1_000) return `${milliseconds} ms`;
  return `${(milliseconds / 1_000).toFixed(2)} s`;
}
