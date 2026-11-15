import { Check, CircleDashed, Loader2, Lock } from "lucide-react";
import { useTranslation } from "react-i18next";
import type { MigrationState } from "@/api/types";
import { cn } from "@/lib/utils";

export const STAGES = ["planned", "approved", "copying", "following", "caught_up", "verify", "cutover", "cleanup"] as const;
type Stage = (typeof STAGES)[number];

/** Verify, cutover and cleanup are Phase 4: they are shown, honestly marked as not available. */
const UNAVAILABLE: ReadonlySet<Stage> = new Set(["verify", "cutover", "cleanup"]);

const CURRENT_INDEX: Record<MigrationState, number> = {
  draft: -1,
  planned: 0,
  approved: 1,
  copying: 2,
  following: 3,
  caught_up: 4,
  verifying: 5,
  cutover_ready: 6,
  completed: 7,
  aborted: -1,
  failed: -1,
};

export function Timeline({ state }: { state: MigrationState }) {
  const { t } = useTranslation("migration");
  const current = CURRENT_INDEX[state];
  return (
    <ol aria-label={t("run.timeline")} className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
      {STAGES.map((stage, i) => {
        const unavailable = UNAVAILABLE.has(stage);
        const done = !unavailable && i < current;
        const active = !unavailable && i === current;
        const Icon = unavailable ? Lock : done ? Check : active ? Loader2 : CircleDashed;
        return (
          <li
            key={stage}
            aria-current={active ? "step" : undefined}
            className={cn("flex items-start gap-2.5 rounded-lg border p-3", active && "border-primary bg-accent", unavailable && "border-dashed")}
          >
            <Icon aria-hidden="true" className={cn("mt-0.5 size-4 shrink-0", done && "text-ok", active && "animate-spin text-primary", !done && !active && "text-muted-foreground")} />
            <div className="min-w-0">
              <p className={cn("text-sm font-medium", !done && !active && "text-muted-foreground")}>
                {t(`run.stage.${stage}`)}
                {done ? <span className="sr-only"> ({t("run.stageDone")})</span> : null}
                {active ? <span className="sr-only"> ({t("run.stageCurrent")})</span> : null}
              </p>
              {unavailable ? <p className="text-xs text-muted-foreground">{t("run.notAvailable")}</p> : null}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
