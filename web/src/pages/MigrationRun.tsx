import { ArrowRight, Ban, Eraser, OctagonAlert, TriangleAlert } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useMigration } from "@/api/hooks";
import { ApiError, type DbMigrationProgress } from "@/api/types";
import { formatBytes, formatDateTime, formatPercent, formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";
import { PageHeader } from "@/components/PageHeader";
import { CardGridSkeleton, EmptyState, ErrorState } from "@/components/States";
import { CopyButton } from "@/components/form/CopyButton";
import { MigrationStateBadge, PhaseBadge } from "@/components/migration/MigrationStateBadge";
import { Timeline } from "@/components/migration/Timeline";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";

const WAL_WARN_BYTES = 5 * 1024 ** 3;

function DatabaseCard({ db, lang }: { db: DbMigrationProgress; lang: string }) {
  const { t } = useTranslation("migration");
  const ratio = db.totalBytes > 0 ? Math.min(1, db.copiedBytes / db.totalBytes) : 0;
  const walHigh = (db.retainedWalBytes ?? 0) > WAL_WARN_BYTES;
  const dash = "–";
  return (
    <Card>
      <CardHeader className="flex-row flex-wrap items-center justify-between gap-2">
        <CardTitle className="wrap-anywhere font-mono">{db.database}</CardTitle>
        <PhaseBadge phase={db.phase} />
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="space-y-1">
          <Progress value={ratio * 100} aria-label={t("run.dbProgress", { database: db.database })} />
          <p className="tnum text-sm text-muted-foreground">
            {formatPercent(ratio, lang, 0)} · {formatBytes(db.copiedBytes, lang)} / {formatBytes(db.totalBytes, lang)}
          </p>
        </div>
        <dl className="grid grid-cols-2 gap-x-4 gap-y-2">
          <div>
            <dt className="text-xs text-muted-foreground">{t("run.lag")}</dt>
            <dd className="tnum font-mono text-sm font-medium">{db.lagBytes !== null ? formatBytes(db.lagBytes, lang) : dash}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">{t("run.retainedWal")}</dt>
            <dd className={cn("tnum flex items-center gap-1 font-mono text-sm font-medium", walHigh && "text-warn")}>
              {walHigh ? <TriangleAlert aria-hidden="true" className="size-4" /> : null}
              {db.retainedWalBytes !== null ? formatBytes(db.retainedWalBytes, lang) : dash}
              {walHigh ? <span className="font-sans text-xs">({t("run.walHigh")})</span> : null}
            </dd>
          </div>
          <div className="col-span-2">
            <dt className="text-xs text-muted-foreground">{t("run.slot")}</dt>
            <dd className="wrap-anywhere font-mono text-xs">{db.slot}</dd>
          </div>
        </dl>
      </CardContent>
    </Card>
  );
}

export default function MigrationRun() {
  const { t, i18n } = useTranslation("migration");
  const lang = i18n.language;
  const { id = "" } = useParams();
  const query = useMigration(id);

  if (query.isPending) {
    return (
      <>
        <PageHeader title={t("run.loadingTitle")} />
        <CardGridSkeleton count={3} />
      </>
    );
  }

  if (query.isError) {
    if (query.error instanceof ApiError && query.error.code === "not_found") {
      return (
        <>
          <PageHeader title={t("run.notFoundTitle")} />
          <EmptyState
            icon={<OctagonAlert className="size-8" />}
            title={t("run.notFoundBody", { id })}
            hint={t("run.notFoundHint")}
            action={
              <Button asChild>
                <Link to="/migrations">{t("run.backToList")}</Link>
              </Button>
            }
          />
        </>
      );
    }
    return (
      <>
        <PageHeader title={t("run.title")} />
        <ErrorState onRetry={() => void query.refetch()} />
      </>
    );
  }

  const m = query.data;
  const ended = m.state === "aborted" || m.state === "failed";

  return (
    <>
      <PageHeader
        title={`${m.sourceId} → ${m.targetId}`}
        description={t("run.subtitle", { id: m.id })}
        actions={<MigrationStateBadge state={m.state} />}
      />

      <dl className="mb-6 grid gap-x-8 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
        <dt className="text-muted-foreground">{t("run.planHash")}</dt>
        <dd className="flex flex-wrap items-center gap-2">
          <code className="wrap-anywhere font-mono text-xs" title={m.planHash}>
            {m.planHash.slice(0, 16)}…
          </code>
          <CopyButton text={m.planHash} label={t("run.copyHash")} failedLabel={t("copyFailed")} />
        </dd>
        <dt className="text-muted-foreground">{t("run.created")}</dt>
        <dd>{formatDateTime(m.createdAt, lang)}</dd>
        <dt className="text-muted-foreground">{t("run.updated")}</dt>
        <dd>{formatRelative(m.updatedAt, lang)}</dd>
        {m.rollbackWindowEndsAt ? (
          <>
            <dt className="text-muted-foreground">{t("run.rollbackWindow")}</dt>
            <dd>{formatDateTime(m.rollbackWindowEndsAt, lang)}</dd>
          </>
        ) : null}
      </dl>

      {ended ? (
        <Callout tone="danger" role="status" className="mb-6" title={t(`state.${m.state}`)}>
          {t("run.endedBody")}
        </Callout>
      ) : null}

      <section aria-labelledby="tl" className="mb-8">
        <h2 id="tl" className="mb-3 text-lg font-semibold">
          {t("run.timeline")}
        </h2>
        <Timeline state={m.state} />
        <p className="mt-2 text-sm text-muted-foreground">{t("run.phase4Note")}</p>
      </section>

      {m.warnings.length > 0 ? (
        <section aria-labelledby="warn" className="mb-8 space-y-2">
          <h2 id="warn" className="text-lg font-semibold">
            {t("run.warnings")}
          </h2>
          {m.warnings.map((w) => (
            <Callout key={w} tone="warning">
              {w}
            </Callout>
          ))}
        </section>
      ) : null}

      <section aria-labelledby="dbs" className="mb-8">
        <h2 id="dbs" className="mb-3 text-lg font-semibold">
          {t("run.databases")}
        </h2>
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {m.databases.map((d) => (
            <DatabaseCard key={d.database} db={d} lang={lang} />
          ))}
        </div>
      </section>

      <section aria-labelledby="rb" className="mb-8">
        <h2 id="rb" className="sr-only">
          {t("run.rollbackHeading")}
        </h2>
        <Callout tone="danger" title={t("run.rollbackTitle")}>
          {t("run.rollbackBody")}
        </Callout>
      </section>

      <section aria-labelledby="act" className="space-y-3">
        <h2 id="act" className="text-lg font-semibold">
          {t("run.actions")}
        </h2>
        <Callout tone="info" id="actions-note">
          {t("run.actionsUnavailable")}
        </Callout>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" disabled aria-describedby="actions-note">
            <Ban aria-hidden="true" />
            {t("run.abort")}
          </Button>
          <Button variant="outline" disabled aria-describedby="actions-note">
            <Eraser aria-hidden="true" />
            {t("run.cleanup")}
          </Button>
        </div>
        <p className="text-sm text-muted-foreground">
          <Link to="/migrations" className="inline-flex items-center gap-1 underline underline-offset-4">
            <ArrowRight aria-hidden="true" className="size-3.5 rotate-180" />
            {t("run.backToList")}
          </Link>
        </p>
      </section>
    </>
  );
}
