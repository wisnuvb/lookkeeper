import { useState } from "react";
import { Pause, Play } from "lucide-react";
import { useTranslation } from "react-i18next";
import type { MetricKey, ServerSummary } from "@/api/types";
import { TimeSeriesChart } from "@/components/charts/TimeSeriesChart";
import { useLiveSeries } from "@/components/charts/useLiveSeries";
import { ErrorState } from "@/components/States";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";

const RANGES = [
  { minutes: 60, key: "h1" },
  { minutes: 360, key: "h6" },
  { minutes: 1440, key: "h24" },
] as const;

/** Which charts make sense depends on the engine and on what the server actually reports. */
export function metricsFor(server: ServerSummary): MetricKey[] {
  const list: MetricKey[] = ["connectionsUsedRatio", "cacheHitRatio"];
  if (server.engine === "postgres") list.push("retainedWalBytes", "xidAgeRatio");
  if (server.gauges.replicationLagSeconds !== null) list.push("replicationLagSeconds");
  return list;
}

function MetricChart({ serverId, metric, minutes, rangeLabel, paused }: { serverId: string; metric: MetricKey; minutes: number; rangeLabel: string; paused: boolean }) {
  const { t } = useTranslation("server");
  const q = useLiveSeries(serverId, metric, minutes, paused);
  if (q.isError) return <ErrorState onRetry={() => void q.refetch()} />;
  if (q.isPending) return <Skeleton className="h-80" />;
  return <TimeSeriesChart title={t(`metrics.names.${metric}`)} series={q.data} rangeLabel={rangeLabel} />;
}

export function MetricsPanel({ server }: { server: ServerSummary }) {
  const { t } = useTranslation("server");
  const [minutes, setMinutes] = useState<number>(60);
  const [paused, setPaused] = useState(false);
  const rangeLabel = t(`metrics.range.${RANGES.find((r) => r.minutes === minutes)?.key ?? "h1"}`);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div role="group" aria-label={t("metrics.range.label")} className="inline-flex rounded-md border">
          {RANGES.map((r) => (
            <Button
              key={r.minutes}
              variant={minutes === r.minutes ? "secondary" : "ghost"}
              size="sm"
              aria-pressed={minutes === r.minutes}
              onClick={() => setMinutes(r.minutes)}
              className="rounded-none first:rounded-l-md last:rounded-r-md"
            >
              {t(`metrics.range.${r.key}`)}
            </Button>
          ))}
        </div>
        <div className="flex items-center gap-3">
          <p role="status" className="text-sm text-muted-foreground">{paused ? t("metrics.livePaused") : t("metrics.liveOn")}</p>
          <Button variant="outline" size="sm" onClick={() => setPaused((p) => !p)}>
            {paused ? <Play aria-hidden="true" /> : <Pause aria-hidden="true" />}
            {paused ? t("metrics.resume") : t("metrics.pause")}
          </Button>
        </div>
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        {metricsFor(server).map((m) => (
          <MetricChart key={m} serverId={server.id} metric={m} minutes={minutes} rangeLabel={rangeLabel} paused={paused} />
        ))}
      </div>
    </div>
  );
}
