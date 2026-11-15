import { SearchX } from "lucide-react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAlerts, useDatabases, useServer, useSlots } from "@/api/hooks";
import { ApiError, type ServerSummary } from "@/api/types";
import { AlertRow } from "@/components/AlertRow";
import { EmptyState, ErrorState } from "@/components/States";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Callout } from "@/components/server/Callout";
import { DatabasesTable } from "@/components/server/DatabasesTable";
import { MetricsPanel } from "@/components/server/MetricsPanel";
import { ServerHeader } from "@/components/server/ServerHeader";
import { SlotsPanel } from "@/components/server/SlotsPanel";

const TABS = ["databases", "metrics", "slots", "alerts"] as const;
type Tab = (typeof TABS)[number];
const isTab = (v: string | null): v is Tab => TABS.includes(v as Tab);

function DatabasesTab({ server }: { server: ServerSummary }) {
  const { t } = useTranslation("server");
  const q = useDatabases(server.id);
  return (
    <section aria-labelledby="databases-title">
      <h2 id="databases-title" className="text-lg font-semibold">{t("databases.title")}</h2>
      <p className="mb-3 mt-1 text-sm text-muted-foreground">{t("databases.hint")}</p>
      {q.isError ? (
        <ErrorState onRetry={() => void q.refetch()} />
      ) : q.isPending ? (
        <Skeleton className="h-48" />
      ) : q.data.length === 0 ? (
        <EmptyState title={server.reachable ? t("databases.empty") : t("databases.emptyUnreachable")} />
      ) : (
        <DatabasesTable databases={q.data} engine={server.engine} serverName={server.name} />
      )}
    </section>
  );
}

function SlotsTab({ server }: { server: ServerSummary }) {
  const { t } = useTranslation("server");
  const q = useSlots(server.id);
  if (server.engine !== "postgres") {
    return (
      <section aria-labelledby="slots-title">
        <h2 id="slots-title" className="sr-only">{t("slots.title")}</h2>
        <Callout tone="info" title={t("slots.notApplicableTitle")}>
          <p>{t("slots.notApplicableBody")}</p>
        </Callout>
      </section>
    );
  }
  return (
    <section aria-labelledby="slots-title">
      <h2 id="slots-title" className="mb-3 text-lg font-semibold">{t("slots.title")}</h2>
      {q.isError ? <ErrorState onRetry={() => void q.refetch()} /> : q.isPending ? <Skeleton className="h-40" /> : <SlotsPanel slots={q.data} serverName={server.name} />}
    </section>
  );
}

function AlertsTab({ server }: { server: ServerSummary }) {
  const { t } = useTranslation("server");
  const q = useAlerts(server.id);
  const firing = (q.data ?? []).filter((a) => a.state === "firing");
  return (
    <section aria-labelledby="alerts-title">
      <h2 id="alerts-title" className="mb-3 text-lg font-semibold">{t("alertsTab.title")}</h2>
      {q.isError ? (
        <ErrorState onRetry={() => void q.refetch()} />
      ) : q.isPending ? (
        <Skeleton className="h-24" />
      ) : firing.length === 0 ? (
        <EmptyState title={t("alertsTab.empty")} />
      ) : (
        <div className="rounded-xl border bg-card p-4 sm:p-5">
          <ul className="divide-y">
            {firing.map((a) => (
              <AlertRow key={a.id} alert={a} showServer={false} />
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

export default function ServerDetail() {
  const { id = "" } = useParams();
  const { t } = useTranslation("server");
  const [params, setParams] = useSearchParams();
  const server = useServer(id);
  const alerts = useAlerts(id);

  if (server.isError) {
    if (server.error instanceof ApiError && server.error.code === "not_found") {
      return (
        <EmptyState
          icon={<SearchX className="size-8" />}
          title={t("notFound.title")}
          hint={t("notFound.hint", { id })}
          action={
            <Button asChild>
              <Link to="/servers">{t("notFound.back")}</Link>
            </Button>
          }
        />
      );
    }
    return <ErrorState onRetry={() => void server.refetch()} />;
  }
  if (server.isPending) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-24" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  const s = server.data;
  const tabParam = params.get("tab");
  const tab: Tab = isTab(tabParam) ? tabParam : "databases";
  const firingCount = (alerts.data ?? []).filter((a) => a.state === "firing").length;
  const onTab = (v: string) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (v === "databases") next.delete("tab");
        else next.set("tab", v);
        return next;
      },
      { replace: true },
    );

  return (
    <>
      <ServerHeader server={s} />

      {!s.reachable ? (
        <div className="mb-6">
          <Callout tone="warning" title={t("unreachable.title")} role="status">
            <p>{t("unreachable.body")}</p>
          </Callout>
        </div>
      ) : null}

      <Tabs value={tab} onValueChange={onTab}>
        <TabsList aria-label={t("tabs.label")}>
          <TabsTrigger value="databases">{t("tabs.databases")}</TabsTrigger>
          <TabsTrigger value="metrics">{t("tabs.metrics")}</TabsTrigger>
          <TabsTrigger value="slots">{t("tabs.slots")}</TabsTrigger>
          <TabsTrigger value="alerts">
            {t("tabs.alerts")}
            {firingCount > 0 ? <span className="tnum rounded-full bg-crit-soft px-1.5 font-mono text-xs text-crit">{firingCount}</span> : null}
          </TabsTrigger>
        </TabsList>
        <TabsContent value="databases"><DatabasesTab server={s} /></TabsContent>
        <TabsContent value="metrics">
          <h2 className="sr-only">{t("metrics.title")}</h2>
          <MetricsPanel server={s} />
        </TabsContent>
        <TabsContent value="slots"><SlotsTab server={s} /></TabsContent>
        <TabsContent value="alerts"><AlertsTab server={s} /></TabsContent>
      </Tabs>
    </>
  );
}
