import type { ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Info, OctagonAlert } from "lucide-react";
import { cn } from "@/lib/utils";

const TONES = {
  info: { box: "border-info/40 bg-info-soft", text: "text-info", Icon: Info },
  warning: { box: "border-warn/40 bg-warn-soft", text: "text-warn", Icon: AlertTriangle },
  danger: { box: "border-crit/40 bg-crit-soft", text: "text-crit", Icon: OctagonAlert },
  ok: { box: "border-ok/40 bg-ok-soft", text: "text-ok", Icon: CheckCircle2 },
} as const;

export type CalloutTone = keyof typeof TONES;

/** Icon + title + text, so the tone is never conveyed by colour alone. Use role="alert" only for messages that appear after an action. */
export function Callout({
  tone = "info",
  title,
  children,
  role = "note",
  className,
  id,
}: {
  tone?: CalloutTone;
  title?: string;
  children?: ReactNode;
  role?: "note" | "alert" | "status";
  className?: string;
  id?: string;
}) {
  const { box, text, Icon } = TONES[tone];
  return (
    <div id={id} role={role} className={cn("flex gap-3 rounded-lg border p-3 text-sm", box, className)}>
      <Icon aria-hidden="true" className={cn("mt-0.5 size-4 shrink-0", text)} />
      <div className="min-w-0 space-y-1">
        {title ? <p className={cn("font-medium", text)}>{title}</p> : null}
        {children ? <div className="text-foreground">{children}</div> : null}
      </div>
    </div>
  );
}
