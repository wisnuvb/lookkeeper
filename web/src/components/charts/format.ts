import type { Series } from "@/api/types";
import { formatBytes, formatDuration, formatPercent } from "@/lib/format";

/** One place that turns a series value into text, for the axis, tooltip, summary and data table. */
export function formatSeriesValue(unit: Series["unit"], value: number, lang: string): string {
  switch (unit) {
    case "bytes":
      return formatBytes(value, lang);
    case "seconds":
      return formatDuration(value, lang);
    case "ratio":
      return formatPercent(value, lang, 1);
  }
}
