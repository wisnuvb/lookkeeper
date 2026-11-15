import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import type { Alert } from "@/api/types";
import { formatRelative } from "@/lib/format";
import { formatAlertValue, ruleKey } from "@/lib/alerts";
import { StatusBadge } from "./StatusBadge";

export function AlertRow({ alert, showServer = true }: { alert: Alert; showServer?: boolean }) {
  const { t, i18n } = useTranslation("rules");
  const lang = i18n.language;
  const key = ruleKey(alert.rule);
  const title = i18n.exists(`rules:${key}`) ? t(key) : t("unknown_rule", { rule: alert.rule });
  const labels = Object.entries(alert.labels);
  return (
    <li className="flex flex-col gap-2 py-3 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge tone={alert.severity} />
          <span className="font-medium">{title}</span>
        </div>
        <p className="wrap-anywhere text-sm text-muted-foreground">
          {showServer ? (
            <Link to={`/servers/${alert.serverId}`} className="font-medium text-foreground underline-offset-4 hover:underline">
              {alert.serverId}
            </Link>
          ) : null}
          {showServer && alert.database ? " / " : null}
          {alert.database ? <span className="font-mono">{alert.database}</span> : null}
          {labels.map(([k, v]) => (
            <span key={k} className="ml-2 rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
              {k}={v}
            </span>
          ))}
        </p>
      </div>
      <div className="shrink-0 text-sm sm:text-right">
        {/* A bare count (e.g. "unreachable = 1") carries no information, so only measured values are shown. */}
        {alert.unit !== "count" ? (
          <p className="tnum font-mono">
            {formatAlertValue(alert.unit, alert.value, lang)}
            <span className="text-muted-foreground"> / {formatAlertValue(alert.unit, alert.threshold, lang)}</span>
          </p>
        ) : null}
        <p className="text-muted-foreground">{formatRelative(alert.since, lang)}</p>
      </div>
    </li>
  );
}
