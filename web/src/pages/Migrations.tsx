import { ArrowRight, ArrowRightLeft, Plus } from "lucide-react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useMigrations } from "@/api/hooks";
import type { MigrationSummary } from "@/api/types";
import { formatBytes, formatPercent, formatRelative } from "@/lib/format";
import { PageHeader } from "@/components/PageHeader";
import { CardGridSkeleton, EmptyState, ErrorState } from "@/components/States";
import { MigrationStateBadge } from "@/components/migration/MigrationStateBadge";
import { overallProgress } from "@/components/migration/progress";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";

function RouteText({ m }: { m: MigrationSummary }) {
  return (
    <span className="wrap-anywhere font-mono">
      {m.sourceId} <ArrowRight aria-hidden="true" className="inline size-3.5" /> {m.targetId}
    </span>
  );
}

function ProgressCell({ m, lang }: { m: MigrationSummary; lang: string }) {
  const { t } = useTranslation("migration");
  const { done, total, ratio } = overallProgress(m);
  return (
    <div className="min-w-40 space-y-1">
      <Progress value={ratio * 100} aria-label={t("list.progressLabel", { id: m.id })} />
      <p className="tnum text-xs text-muted-foreground">
        {formatPercent(ratio, lang, 0)} · {formatBytes(done, lang, 0)} / {formatBytes(total, lang, 0)}
      </p>
    </div>
  );
}

export default function Migrations() {
  const { t, i18n } = useTranslation("migration");
  const lang = i18n.language;
  const migrations = useMigrations();
  const th = "px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-muted-foreground";

  const planButton = (
    <Button asChild>
      <Link to="/migrations/new">
        <Plus aria-hidden="true" />
        {t("list.plan")}
      </Link>
    </Button>
  );

  return (
    <>
      <PageHeader title={t("list.title")} description={t("list.subtitle")} actions={planButton} />
      {migrations.isError ? (
        <ErrorState onRetry={() => void migrations.refetch()} />
      ) : migrations.isPending ? (
        <CardGridSkeleton count={2} />
      ) : migrations.data.length === 0 ? (
        <EmptyState icon={<ArrowRightLeft className="size-8" />} title={t("list.emptyTitle")} hint={t("list.emptyHint")} action={planButton} />
      ) : (
        <>
          <div className="hidden overflow-x-auto rounded-xl border bg-card md:block">
            <table className="w-full text-sm">
              <caption className="sr-only">{t("list.title")}</caption>
              <thead className="border-b bg-muted/50">
                <tr>
                  <th scope="col" className={th}>{t("list.columns.route")}</th>
                  <th scope="col" className={th}>{t("list.columns.state")}</th>
                  <th scope="col" className={th}>{t("list.columns.progress")}</th>
                  <th scope="col" className={th}>{t("list.columns.created")}</th>
                  <th scope="col" className={th}>{t("list.columns.updated")}</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {migrations.data.map((m) => (
                  <tr key={m.id} className="hover:bg-accent/40">
                    <th scope="row" className="px-4 py-3 text-left font-normal">
                      <Link to={`/migrations/${m.id}`} className="font-medium underline-offset-4 hover:underline">
                        <RouteText m={m} />
                      </Link>
                      <p className="font-mono text-xs text-muted-foreground">{m.id}</p>
                    </th>
                    <td className="px-4 py-3"><MigrationStateBadge state={m.state} /></td>
                    <td className="px-4 py-3"><ProgressCell m={m} lang={lang} /></td>
                    <td className="px-4 py-3 text-muted-foreground">{formatRelative(m.createdAt, lang)}</td>
                    <td className="px-4 py-3 text-muted-foreground">{formatRelative(m.updatedAt, lang)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <ul className="grid gap-4 sm:grid-cols-2 md:hidden">
            {migrations.data.map((m) => (
              <li key={m.id}>
                <Card className="relative">
                  <CardHeader className="gap-2">
                    <div className="flex items-start justify-between gap-2">
                      <Link to={`/migrations/${m.id}`} className="min-w-0 font-medium after:absolute after:inset-0 after:content-[''] focus-visible:after:rounded-xl">
                        <RouteText m={m} />
                      </Link>
                      <MigrationStateBadge state={m.state} />
                    </div>
                    <p className="font-mono text-xs text-muted-foreground">{m.id}</p>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <ProgressCell m={m} lang={lang} />
                    <p className="text-xs text-muted-foreground">
                      {t("list.columns.updated")}: {formatRelative(m.updatedAt, lang)}
                    </p>
                  </CardContent>
                </Card>
              </li>
            ))}
          </ul>
        </>
      )}
    </>
  );
}
