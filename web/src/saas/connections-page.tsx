import type { SafeAdminConnection } from "./admin-model";
import type { ReactNode } from "react";

import { useTranslate } from "@embra/i18n/react";
import { Shield } from "lucide-react";
import { Badge, EmptyState } from "../shared-ui";
import { Card } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export function AdminConnectionsPage(props: { connections: SafeAdminConnection[] }): ReactNode {
  const t = useTranslate();

  return (
    <div className="page-stack">
      <Card className="runtime-strip">
        <div>
          <strong>{t("connections.title")}</strong>
          <span className="!text-foreground/75">{t("connections.description")}</span>
        </div>
        <Shield size={18} aria-hidden="true" />
      </Card>
      <section className="table-panel">
        {props.connections.length === 0 ? (
          <EmptyState title={t("connections.emptyTitle")} description={t("connections.emptyDescription")} icon={null} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("connections.table.provider")}</TableHead>
                <TableHead>{t("connections.table.account")}</TableHead>
                <TableHead>{t("connections.table.owner")}</TableHead>
                <TableHead>{t("connections.table.visibility")}</TableHead>
                <TableHead>{t("connections.table.status")}</TableHead>
                <TableHead>{t("connections.table.verified")}</TableHead>
                <TableHead className="text-right">{t("connections.table.calls")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {props.connections.map((connection, index) => (
                <TableRow key={`${connection.providerName}:${connection.accountName}:${connection.ownerName}:${index}`}>
                  <TableCell>
                    <strong>{connection.providerName}</strong>
                  </TableCell>
                  <TableCell>
                    <div className="grid gap-1">
                      <span>{connection.accountName}</span>
                      {connection.accountEmail ? (
                        <span className="muted-copy !text-foreground/75">{connection.accountEmail}</span>
                      ) : null}
                    </div>
                  </TableCell>
                  <TableCell>{connection.ownerName}</TableCell>
                  <TableCell>
                    <Badge>{t(`connections.visibility.${connection.visibility}`)}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge
                      tone={
                        connection.status === "active"
                          ? "success"
                          : connection.status === "failed" ||
                              connection.status === "revoked" ||
                              connection.status === "reconnect_required"
                            ? "error"
                            : "warning"
                      }
                    >
                      {t(`connections.status.${connection.status}`)}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {connection.lastVerifiedAt
                      ? new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
                          new Date(connection.lastVerifiedAt),
                        )
                      : t("common.notAvailable")}
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{connection.calls}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </section>
    </div>
  );
}
