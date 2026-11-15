import { ArrowRight, Plus, Server as ServerIcon } from "lucide-react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAlerts, useMigrations, useServers } from "@/api/hooks";
import { formatBytes, formatPercent } from "@/lib/format";
import { AlertRow } from "@/components/AlertRow";
import { PageHeader } from "@/components/PageHeader";
import { ServerCard } from "@/components/ServerCard";
import { StatusBadge } from "@/components/StatusBadge";
import { CardGridSkeleton, EmptyState, ErrorState } from "@/components/States";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";

function Stat({ label, value, detail }: { label: string; value: string | number; detail?: string }) {
  return (
    <Card>
      <CardContent className="p-4 sm:p-5">
        <p className="text-sm text-muted-foreground">{label}</p>
        <p className="tnum mt-1 font-mono text-3xl font-semibold leading-none">{value}</p>
        {detail ? <p className="mt-2 text-xs text-muted-foreground">{detail}</p> : null}
      </CardContent>
    </Card>
  );
}

export default function Overview() {
  const { t, i18n } = useTranslation("fleet");
  const lang = i18n.language;
  const servers = useServers();
  const alerts = useAlerts();
  const migrations = useMigrations();

  const firing = (alerts.data ?? []).filter((a) => a.state === "firing").sort((a, b) => (a.severity === b.severity ? 0 : a.severity === "critical" ? -1 : 1));
  const critical = firing.filter((a) => a.severity === "critical").length;
  const running = (migrations.data ?? []).filter((m) => !["completed", "aborted", "failed", "draft"].includes(m.state));
  const dbTotal = (servers.data ?? []).reduce((n, s) => n + s.databaseCount, 0);

  return (
    <>
      <PageHeader
        title={t("overview.title")}
        description={t("overview.subtitle")}
        actions={
          <Button asChild>
            <Link to="/servers/new">
              <Plus aria-hidden="true" />
              {t("overview.addServer")}
            </Link>
          </Button>
        }
      />

      <section aria-label={t("overview.title")} className="mb-8 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label={t("overview.summary.servers")} value={servers.data?.length ?? "–"} />
        <Stat label={t("overview.summary.databases")} value={servers.data ? dbTotal : "–"} />
        <Stat
          label={t("overview.summary.alerts")}
          value={alerts.data ? firing.length : "–"}
          detail={alerts.data ? t("overview.summary.alertsDetail", { critical, warning: firing.length - critical }) : undefined}
        />
        <Stat label={t("overview.summary.migrations")} value={migrations.data ? running.length : "–"} />
      </section>

      <section aria-labelledby="attention" className="mb-8">
        <div className="mb-3 flex items-center justify-between gap-2">
          <h2 id="attention" className="text-lg font-semibold">
            {t("overview.attention")}
          </h2>
          <Button asChild variant="link" size="sm">
            <Link to="/alerts">
              {t("overview.viewAllAlerts")}
              <ArrowRight aria-hidden="true" />
            </Link>
          </Button>
        </div>
        {alerts.isError ? (
          <ErrorState onRetry={() => void alerts.refetch()} />
        ) : alerts.isPending ? (
          <div role="status" aria-label={t("loading", { ns: "common" })} className="lk-skeleton h-24" />
        ) : firing.length === 0 ? (
          <EmptyState title={t("overview.attentionEmpty")} />
        ) : (
          <Card>
            <CardContent className="p-4 sm:p-5">
              <ul className="divide-y">
                {firing.slice(0, 4).map((a) => (
                  <AlertRow key={a.id} alert={a} />
                ))}
              </ul>
            </CardContent>
          </Card>
        )}
      </section>

      {running.length > 0 ? (
        <section aria-labelledby="mig" className="mb-8">
          <h2 id="mig" className="mb-3 text-lg font-semibold">
            {t("overview.migrationHeading")}
          </h2>
          {running.map((m) => {
            const total = m.databases.reduce((n, d) => n + d.totalBytes, 0);
            const done = m.databases.reduce((n, d) => n + d.copiedBytes, 0);
            const ratio = total ? done / total : 0;
            return (
              <Card key={m.id}>
                <CardHeader className="flex-row flex-wrap items-center justify-between gap-2">
                  <CardTitle className="font-mono">
                    {m.sourceId} <ArrowRight aria-hidden="true" className="inline size-4" /> {m.targetId}
                  </CardTitle>
                  <StatusBadge tone="info" label={t(`state.${m.state}`, { ns: "migration", defaultValue: m.state })} />
                </CardHeader>
                <CardContent className="space-y-3">
                  <Progress value={ratio * 100} aria-label={t("overview.migrationHeading")} />
                  <p className="tnum text-sm text-muted-foreground">
                    {formatBytes(done, lang)} / {formatBytes(total, lang)} ({formatPercent(ratio, lang, 0)})
                  </p>
                  <Button asChild variant="outline" size="sm">
                    <Link to={`/migrations/${m.id}`}>{t("overview.migrationOpen")}</Link>
                  </Button>
                </CardContent>
              </Card>
            );
          })}
        </section>
      ) : null}

      <section aria-labelledby="srv">
        <h2 id="srv" className="mb-3 text-lg font-semibold">
          {t("overview.serversHeading")}
        </h2>
        {servers.isError ? (
          <ErrorState onRetry={() => void servers.refetch()} />
        ) : servers.isPending ? (
          <CardGridSkeleton />
        ) : servers.data.length === 0 ? (
          <EmptyState
            icon={<ServerIcon className="size-8" />}
            title={t("servers.emptyTitle")}
            hint={t("servers.emptyHint")}
            action={
              <Button asChild>
                <Link to="/servers/new">{t("overview.addServer")}</Link>
              </Button>
            }
          />
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
            {servers.data.map((s) => (
              <ServerCard key={s.id} server={s} />
            ))}
          </div>
        )}
      </section>
    </>
  );
}
