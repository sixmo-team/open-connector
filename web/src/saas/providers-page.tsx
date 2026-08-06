import type { ProviderDisplay } from "../shared-ui";
import type { AdminProvider } from "./admin-model";
import type { ReactNode } from "react";

import { useTranslate } from "@embra/i18n/react";
import { Badge, EmptyState, ProviderIcon } from "../shared-ui";
import { Card } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export function AdminProvidersPage(props: { providers: AdminProvider[] }): ReactNode {
  const t = useTranslate();

  return (
    <div className="page-stack">
      <Card className="runtime-strip">
        <div>
          <strong>{t("providers.title")}</strong>
          <span className="!text-foreground/75">{t("providers.description")}</span>
        </div>
      </Card>
      <section className="table-panel">
        {props.providers.length === 0 ? (
          <EmptyState title={t("providers.emptyTitle")} description={t("providers.emptyDescription")} icon={null} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("providers.table.provider")}</TableHead>
                <TableHead>{t("providers.table.availability")}</TableHead>
                <TableHead className="text-right">{t("providers.table.connections")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {props.providers.map((provider) => {
                const iconProvider: ProviderDisplay = {
                  service: provider.displayName.toLowerCase().replaceAll(/[^a-z0-9]+/g, "-"),
                  displayName: provider.displayName,
                };
                return (
                  <TableRow key={provider.displayName}>
                    <TableCell>
                      <div className="detail-heading">
                        <ProviderIcon provider={iconProvider} />
                        <strong>{provider.displayName}</strong>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge tone={provider.available ? "success" : "warning"}>
                        {t(provider.available ? "common.available" : "common.unavailable")}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{provider.enabledConnections}</TableCell>
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
