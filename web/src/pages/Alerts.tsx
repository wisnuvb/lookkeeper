import { BellOff } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAlerts, useServers } from "@/api/hooks";
import type { Alert } from "@/api/types";
import { FilterSelect } from "@/components/alerts/FilterSelect";
import { AlertRow } from "@/components/AlertRow";
import { PageHeader } from "@/components/PageHeader";
import { EmptyState, ErrorState } from "@/components/States";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

const SEVERITIES = ["critical", "warning"] as const;
const rank = (a: Alert) => (a.severity === "critical" ? 0 : 1);

function AlertList({ id, title, alerts }: { id: string; title: string; alerts: Alert[] }) {
  if (alerts.length === 0) return null;
  return (
    <section aria-labelledby={id} className="mb-8">
      <h2 id={id} className="mb-3 text-lg font-semibold">{title}</h2>
      <Card>
        <CardContent className="p-4 sm:p-5">
          <ul className="divide-y">
            {alerts.map((a) => (
              <AlertRow key={a.id} alert={a} />
            ))}
          </ul>
        </CardContent>
      </Card>
    </section>
  );
}

export default function Alerts() {
  const { t } = useTranslation("alerts");
  const [params, setParams] = useSearchParams();
  const alerts = useAlerts();
  const servers = useServers();

  const severityParam = params.get("severity");
  const severity = SEVERITIES.find((s) => s === severityParam) ?? "";
  const server = params.get("server") ?? "";

  const set = (key: string, v: string) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (v) next.set(key, v);
        else next.delete(key);
        return next;
      },
      { replace: true },
    );

  const filtered = (alerts.data ?? [])
    .filter((a) => (!severity || a.severity === severity) && (!server || a.serverId === server))
    .sort((a, b) => rank(a) - rank(b) || new Date(a.since).getTime() - new Date(b.since).getTime());
  const firing = filtered.filter((a) => a.state === "firing");
  const resolved = filtered.filter((a) => a.state === "resolved");
  const filtering = severity !== "" || server !== "";

  return (
    <>
      <PageHeader title={t("title")} description={t("subtitle")} />

      <form role="search" aria-label={t("filters.label")} onSubmit={(e) => e.preventDefault()} className="mb-4 flex flex-wrap items-end gap-3">
        <FilterSelect
          label={t("filters.severity")}
          value={severity}
          onChange={(v) => set("severity", v)}
          options={[{ value: "", label: t("filters.allSeverities") }, ...SEVERITIES.map((s) => ({ value: s, label: t(`severity.${s}`, { ns: "common" }) }))]}
        />
        <FilterSelect
          label={t("filters.server")}
          value={server}
          onChange={(v) => set("server", v)}
          options={[{ value: "", label: t("filters.allServers") }, ...(servers.data ?? []).map((s) => ({ value: s.id, label: s.name }))]}
        />
        {filtering ? (
          <Button variant="ghost" onClick={() => setParams({}, { replace: true })}>
            {t("filters.clear")}
          </Button>
        ) : null}
      </form>

      {alerts.data ? (
        <p role="status" className="mb-4 text-sm text-muted-foreground">{t("shown", { count: filtered.length })}</p>
      ) : null}

      {alerts.isError ? (
        <ErrorState onRetry={() => void alerts.refetch()} />
      ) : alerts.isPending ? (
        <Skeleton className="h-40" />
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={<BellOff className="size-8" />}
          title={filtering ? t("emptyFiltered") : t("empty")}
          hint={filtering ? t("emptyFilteredHint") : undefined}
        />
      ) : (
        <>
          <AlertList id="firing-title" title={t("firing")} alerts={firing} />
          <AlertList id="resolved-title" title={t("resolved")} alerts={resolved} />
        </>
      )}
    </>
  );
}
