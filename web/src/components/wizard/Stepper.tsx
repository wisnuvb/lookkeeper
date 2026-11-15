import { Check } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Step indicator: "Step n of N" as visible text, an ordered list with aria-current="step", and the
 * labels of the other steps kept for screen readers on narrow screens.
 */
export function Stepper({
  steps,
  current,
  ariaLabel,
  stepOfText,
  completedLabel,
}: {
  steps: string[];
  current: number;
  ariaLabel: string;
  stepOfText: string;
  completedLabel: string;
}) {
  return (
    <nav aria-label={ariaLabel} className="mb-6">
      <p className="tnum mb-2 text-sm font-medium text-muted-foreground">{stepOfText}</p>
      <ol className="flex flex-wrap items-center gap-x-3 gap-y-2">
        {steps.map((label, i) => {
          const done = i < current;
          const active = i === current;
          return (
            <li key={label} aria-current={active ? "step" : undefined} className="flex items-center gap-2">
              <span
                aria-hidden="true"
                className={cn(
                  "tnum flex size-7 shrink-0 items-center justify-center rounded-full border text-xs font-semibold",
                  done && "border-primary bg-primary text-primary-foreground",
                  active && "border-primary text-foreground ring-2 ring-primary/40",
                  !done && !active && "text-muted-foreground",
                )}
              >
                {done ? <Check className="size-3.5" /> : i + 1}
              </span>
              <span className={cn("text-sm", active ? "font-semibold" : "text-muted-foreground", !active && "max-md:sr-only")}>
                {label}
                {done ? <span className="sr-only"> ({completedLabel})</span> : null}
              </span>
              {i < steps.length - 1 ? <span aria-hidden="true" className="hidden h-px w-6 bg-border md:block" /> : null}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
