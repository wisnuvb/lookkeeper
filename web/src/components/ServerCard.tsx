import { Database, Server as ServerIcon } from "lucide-react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import type { ServerSummary } from "@/api/types";
import { formatBytes, formatPercent, formatDuration, formatRelative } from "@/lib/format";
import { isStale } from "@/lib/alerts";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { StatusBadge } from "./StatusBadge";

function Gauge({ label, value, tone }: { label: string; value: string; tone?: "warn" | "crit" }) {
  return (
    <div className="min-w-0">
      <dt className="truncate text-xs text-muted-foreground">{label}</dt>
      <dd className={`tnum font-mono text-sm font-medium ${tone === "crit" ? "text-crit" : tone === "warn" ? "text-warn" : ""}`}>{value}</dd>
    </div>
  );
}

export function ServerCard({ server }: { server: ServerSummary }) {
  const { t, i18n } = useTranslation("fleet");
  const lang = i18n.language;
  const g = server.gauges;
  const stale = isStale(server.lastSampleAt);
  const dash = "–";
  return (
    <Card className="relative transition-colors hover:border-input focus-within:border-input">
      <CardHeader className="gap-2">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <h3 className="flex items-center gap-2 text-base font-semibold">
              <ServerIcon aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
              <Link to={`/servers/${server.id}`} className="truncate font-mono after:absolute after:inset-0 after:content-[''] focus-visible:after:rounded-xl">
                {server.name}
              </Link>
            </h3>
            <p className="mt-0.5 text-sm text-muted-foreground">
              {t(`engine.${server.engine}`, { ns: "common" })} · {server.version.replace(/^(PostgreSQL|MySQL) /, "")} · {t(`managed.${server.managed}`, { ns: "common" })}
            </p>
          </div>
          <StatusBadge tone={server.health} />
        </div>
        <p className="wrap-anywhere font-mono text-xs text-muted-foreground">
          {server.host}:{server.port}
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        {server.reachable ? (
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2">
            <Gauge label={t("card.connections")} value={formatPercent(g.connectionsUsedRatio, lang, 0)} tone={g.connectionsUsedRatio > 0.9 ? "crit" : g.connectionsUsedRatio > 0.8 ? "warn" : undefined} />
            {g.retainedWalBytes !== null ? (
              <Gauge label={t("card.retainedWal")} value={formatBytes(g.retainedWalBytes, lang)} tone={g.retainedWalBytes > 20 * 1024 ** 3 ? "crit" : g.retainedWalBytes > 5 * 1024 ** 3 ? "warn" : undefined} />
            ) : (
              <Gauge label={t("card.replLag")} value={g.replicationLagSeconds !== null ? formatDuration(g.replicationLagSeconds, lang) : dash} tone={g.replicationLagSeconds !== null && g.replicationLagSeconds > 60 ? "warn" : undefined} />
            )}
            <Gauge label={t("card.cacheHit")} value={g.cacheHitRatio !== null ? formatPercent(g.cacheHitRatio, lang) : dash} />
            <Gauge label={t("overview.summary.databases")} value={`${server.databaseCount} · ${formatBytes(server.totalSizeBytes, lang, 0)}`} />
          </dl>
        ) : (
          <p className="flex items-center gap-2 rounded-md bg-unknown-soft px-3 py-2 text-sm text-unknown">
            <Database aria-hidden="true" className="size-4" />
            {t("card.unreachable")}
          </p>
        )}
        <p className={`text-xs ${stale ? "font-medium text-warn" : "text-muted-foreground"}`}>
          {stale ? `${t("card.stale")} · ` : ""}
          {t("card.lastSample", { when: formatRelative(server.lastSampleAt, lang) })}
          {" · "}
          {server.activeAlerts > 0 ? t("card.alerts", { count: server.activeAlerts }) : t("card.noAlerts")}
        </p>
      </CardContent>
    </Card>
  );
}
