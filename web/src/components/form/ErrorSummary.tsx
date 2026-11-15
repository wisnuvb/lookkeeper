import { useEffect, useRef } from "react";
import { OctagonAlert } from "lucide-react";

export interface SummaryItem {
  /** DOM id of the invalid control. */
  id: string;
  message: string;
}

/**
 * A focusable summary shown after a failed submit. Every item links to its field. `focusKey` is
 * bumped on each failed submit so the summary takes focus again even when the list is unchanged.
 */
export function ErrorSummary({ title, items, focusKey }: { title: string; items: SummaryItem[]; focusKey: number }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (focusKey > 0) ref.current?.focus();
  }, [focusKey]);
  if (items.length === 0) return null;
  return (
    <div ref={ref} tabIndex={-1} role="alert" className="rounded-lg border border-crit/40 bg-crit-soft p-3 text-sm outline-none focus-visible:outline-2">
      <p className="flex items-center gap-2 font-medium text-crit">
        <OctagonAlert aria-hidden="true" className="size-4 shrink-0" />
        {title}
      </p>
      <ul className="mt-2 list-inside list-disc space-y-1">
        {items.map((it) => (
          <li key={it.id}>
            <a
              href={`#${it.id}`}
              className="underline underline-offset-4"
              onClick={(e) => {
                e.preventDefault();
                document.getElementById(it.id)?.focus();
              }}
            >
              {it.message}
            </a>
          </li>
        ))}
      </ul>
    </div>
  );
}
