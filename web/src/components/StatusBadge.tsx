import { AlertTriangle, CheckCircle2, CircleDashed, OctagonAlert, Info } from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";
import type { Health } from "@/api/types";

type Tone = Health | "info" | "blocker";

const STYLE: Record<Tone, string> = {
  ok: "bg-ok-soft text-ok",
  warning: "bg-warn-soft text-warn",
  critical: "bg-crit-soft text-crit",
  blocker: "bg-crit-soft text-crit",
  info: "bg-info-soft text-info",
  unknown: "bg-unknown-soft text-unknown",
};
const ICON = { ok: CheckCircle2, warning: AlertTriangle, critical: OctagonAlert, blocker: OctagonAlert, info: Info, unknown: CircleDashed } as const;

/** Status is always icon + text + colour, never colour alone (WCAG 1.4.1). */
export function StatusBadge({ tone, label, className }: { tone: Tone; label?: string; className?: string }) {
  const { t } = useTranslation();
  const Icon = ICON[tone];
  const text = label ?? (tone === "info" || tone === "blocker" ? t(`severity.${tone}`) : t(`health.${tone}`));
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium", STYLE[tone], className)}>
      <Icon aria-hidden="true" className="size-3.5 shrink-0" />
      {text}
    </span>
  );
}
