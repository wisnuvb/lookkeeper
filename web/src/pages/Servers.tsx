import { Plus, Server as ServerIcon } from "lucide-react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useServers } from "@/api/hooks";
import { formatBytes, formatRelative } from "@/lib/format";
import { PageHeader } from "@/components/PageHeader";
import { ServerCard } from "@/components/ServerCard";
import { StatusBadge } from "@/components/StatusBadge";
import { CardGridSkeleton, EmptyState, ErrorState } from "@/components/States";
import { Button } from "@/components/ui/button";

export default function Servers() {
  const { t, i18n } = useTranslation("fleet");
  const lang = i18n.language;
  const servers = useServers();
  const th = "px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-muted-foreground";

  return (
    <>
      <PageHeader
        title={t("servers.title")}
        description={t("servers.subtitle")}
        actions={
          <Button asChild>
            <Link to="/servers/new">
              <Plus aria-hidden="true" />
              {t("overview.addServer")}
            </Link>
          </Button>
        }
      />
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
        <>
          <div className="hidden overflow-x-auto rounded-xl border bg-card md:block">
            <table className="w-full text-sm">
              <caption className="sr-only">{t("servers.title")}</caption>
              <thead className="border-b bg-muted/50">
                <tr>
                  <th scope="col" className={th}>{t("servers.columns.name")}</th>
                  <th scope="col" className={th}>{t("servers.columns.engine")}</th>
                  <th scope="col" className={th}>{t("servers.columns.status")}</th>
                  <th scope="col" className={`${th} text-right`}>{t("servers.columns.databases")}</th>
                  <th scope="col" className={`${th} text-right`}>{t("servers.columns.size")}</th>
                  <th scope="col" className={th}>{t("servers.columns.lastSample")}</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {servers.data.map((s) => (
                  <tr key={s.id} className="hover:bg-accent/40">
                    <th scope="row" className="px-4 py-3 text-left font-normal">
                      <Link to={`/servers/${s.id}`} className="font-mono font-medium underline-offset-4 hover:underline">
                        {s.name}
                      </Link>
                      <p className="wrap-anywhere max-w-xs font-mono text-xs text-muted-foreground">{s.host}:{s.port}</p>
                    </th>
                    <td className="px-4 py-3">
                      {t(`engine.${s.engine}`, { ns: "common" })}
                      <p className="text-xs text-muted-foreground">{s.version.replace(/^(PostgreSQL|MySQL) /, "")}</p>
                    </td>
                    <td className="px-4 py-3"><StatusBadge tone={s.health} /></td>
                    <td className="tnum px-4 py-3 text-right font-mono">{s.databaseCount}</td>
                    <td className="tnum px-4 py-3 text-right font-mono">{formatBytes(s.totalSizeBytes, lang, 0)}</td>
                    <td className="px-4 py-3 text-muted-foreground">{formatRelative(s.lastSampleAt, lang)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 md:hidden">
            {servers.data.map((s) => (
              <ServerCard key={s.id} server={s} />
            ))}
          </div>
        </>
      )}
    </>
  );
}
