import { useTranslation } from "react-i18next";
import type { DbMigrationPhase, MigrationState } from "@/api/types";
import { StatusBadge } from "@/components/StatusBadge";

const STATE_TONE = {
  draft: "unknown",
  planned: "info",
  approved: "info",
  copying: "info",
  following: "info",
  caught_up: "ok",
  verifying: "info",
  cutover_ready: "ok",
  completed: "ok",
  aborted: "unknown",
  failed: "critical",
} as const satisfies Record<MigrationState, "ok" | "info" | "unknown" | "critical">;

const PHASE_TONE = {
  waiting: "unknown",
  schema: "info",
  copying: "info",
  following: "info",
  caught_up: "ok",
  done: "ok",
  failed: "critical",
} as const satisfies Record<DbMigrationPhase, "ok" | "info" | "unknown" | "critical">;

export function MigrationStateBadge({ state }: { state: MigrationState }) {
  const { t } = useTranslation("migration");
  return <StatusBadge tone={STATE_TONE[state]} label={t(`state.${state}`)} />;
}

export function PhaseBadge({ phase }: { phase: DbMigrationPhase }) {
  const { t } = useTranslation("migration");
  return <StatusBadge tone={PHASE_TONE[phase]} label={t(`phase.${phase}`)} />;
}
