import { ArrowLeft, ArrowRightLeft } from "lucide-react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import type { ServerSummary } from "@/api/types";
import { formatRelative } from "@/lib/format";
import { isStale } from "@/lib/alerts";
import { PageHeader } from "@/components/PageHeader";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";

export function ServerHeader({ server }: { server: ServerSummary }) {
  const { t, i18n } = useTranslation("server");
  const lang = i18n.language;
  const stale = isStale(server.lastSampleAt);
  const canPlan = server.engine === "postgres" && server.reachable;
  const disabledReasonKey = server.engine === "postgres" ? "header.planDisabledUnreachable" : "header.planDisabledReason";
  const reasonId = `plan-reason-${server.id}`;

  return (
    <>
      <nav aria-label={t("breadcrumb")} className="mb-3">
        <Link to="/servers" className="inline-flex min-h-8 items-center gap-1.5 text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline">
          <ArrowLeft aria-hidden="true" className="size-4" />
          {t("back")}
        </Link>
      </nav>

      <PageHeader
        title={server.name}
        actions={
          canPlan ? (
            <Button asChild>
              <Link to={`/migrations/new?source=${encodeURIComponent(server.id)}`}>
                <ArrowRightLeft aria-hidden="true" />
                {t("header.planMigration")}
              </Link>
            </Button>
          ) : (
            <div className="flex flex-col items-start gap-1 sm:items-end">
              <Button disabled aria-describedby={reasonId}>
                <ArrowRightLeft aria-hidden="true" />
                {t("header.planMigration")}
              </Button>
              <p id={reasonId} className="max-w-xs text-xs text-muted-foreground sm:text-right">{t(disabledReasonKey)}</p>
            </div>
          )
        }
      />

      <div className="mb-6 space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge tone={server.health} />
          <span className="text-sm text-muted-foreground">
            {t(`engine.${server.engine}`, { ns: "common" })} · {server.version.replace(/^(PostgreSQL|MySQL) /, "")} · {t(`managed.${server.managed}`, { ns: "common" })}
          </span>
        </div>
        <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2 lg:grid-cols-4">
          <div className="min-w-0">
            <dt className="text-xs text-muted-foreground">{t("header.hostLabel")}</dt>
            <dd className="font-mono"><span className="wrap-anywhere">{server.host}</span><span className="whitespace-nowrap">:{server.port}</span></dd>
          </div>
          <div className="min-w-0">
            <dt className="text-xs text-muted-foreground">{t("header.tlsLabel")}</dt>
            <dd>{t(`tls.${server.tls}`, { ns: "common" })}</dd>
          </div>
          <div className="min-w-0">
            <dt className="text-xs text-muted-foreground">{t("header.originLabel")}</dt>
            <dd>{t(`origin.${server.origin}`, { ns: "common" })}</dd>
          </div>
          <div className="min-w-0">
            <dt className="text-xs text-muted-foreground">{t("header.lastSampleLabel")}</dt>
            <dd className={stale ? "font-medium text-warn" : ""}>
              {stale ? `${t("header.stale")} · ` : ""}
              {formatRelative(server.lastSampleAt, lang)}
            </dd>
          </div>
        </dl>
      </div>
    </>
  );
}
