import type { ReactNode } from "react";
import { AlertTriangle, Info } from "lucide-react";
import { cn } from "@/lib/utils";

const TONE = {
  warning: { box: "border-warn/40 bg-warn-soft text-warn", Icon: AlertTriangle },
  info: { box: "border-info/40 bg-info-soft text-info", Icon: Info },
} as const;

/** A titled message. Icon + text carry the meaning; colour only reinforces it. */
export function Callout({ tone, title, children, role }: { tone: keyof typeof TONE; title: string; children?: ReactNode; role?: "status" | "alert" }) {
  const { box, Icon } = TONE[tone];
  return (
    <div role={role} className={cn("flex gap-3 rounded-xl border p-4", box)}>
      <Icon aria-hidden="true" className="mt-0.5 size-5 shrink-0" />
      <div className="min-w-0 space-y-1">
        <p className="font-semibold">{title}</p>
        {children ? <div className="text-sm text-foreground">{children}</div> : null}
      </div>
    </div>
  );
}
