import type { Alert } from "@/api/types";
import { formatBytes, formatDuration, formatNumber, formatPercent } from "./format";

/** i18next treats "." as a key separator, so rule ids such as "pg.slot.x" become "pg_slot_x". */
export const ruleKey = (rule: string): string => rule.replaceAll(".", "_");

export function formatAlertValue(unit: Alert["unit"], value: number, lang: string): string {
  switch (unit) {
    case "bytes":
      return formatBytes(value, lang);
    case "seconds":
      return formatDuration(value, lang);
    case "ratio":
      return formatPercent(value, lang, 0);
    case "count":
      return formatNumber(value, lang);
  }
}

/** A sample older than this many seconds is shown as stale (monitor interval is 30 s by default). */
export const STALE_AFTER_SECONDS = 120;
export const isStale = (iso: string, now = Date.now()): boolean => (now - new Date(iso).getTime()) / 1000 > STALE_AFTER_SECONDS;
