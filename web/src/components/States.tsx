import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";

export function EmptyState({ icon, title, hint, action }: { icon?: ReactNode; title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed p-8 text-center">
      {icon ? <div aria-hidden="true" className="text-muted-foreground">{icon}</div> : null}
      <p className="font-medium">{title}</p>
      {hint ? <p className="max-w-md text-sm text-muted-foreground">{hint}</p> : null}
      {action}
    </div>
  );
}

export function ErrorState({ onRetry, message }: { onRetry?: () => void; message?: string }) {
  const { t } = useTranslation();
  return (
    <div role="alert" className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-crit/40 bg-crit-soft p-4 text-crit">
      <p className="text-sm font-medium">{message ?? t("loadError")}</p>
      {onRetry ? (
        <Button variant="outline" size="sm" onClick={onRetry}>
          {t("retry")}
        </Button>
      ) : null}
    </div>
  );
}

export function CardGridSkeleton({ count = 3 }: { count?: number }) {
  const { t } = useTranslation();
  return (
    <div role="status" aria-label={t("loading")} className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
      {Array.from({ length: count }, (_, i) => (
        <Skeleton key={i} className="h-44" />
      ))}
    </div>
  );
}
