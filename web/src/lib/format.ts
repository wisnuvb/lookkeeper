// Locale-aware formatting. Always pass the active i18n language so ID and EN read naturally.

const UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"] as const;

export function formatBytes(bytes: number, lang: string, digits = 1): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "–";
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024;
    i++;
  }
  const nf = new Intl.NumberFormat(lang, { maximumFractionDigits: i === 0 ? 0 : digits });
  return `${nf.format(v)} ${UNITS[i]}`;
}

export function formatNumber(n: number, lang: string, digits = 0): string {
  return new Intl.NumberFormat(lang, { maximumFractionDigits: digits }).format(n);
}

export function formatPercent(ratio: number, lang: string, digits = 1): string {
  return new Intl.NumberFormat(lang, { style: "percent", maximumFractionDigits: digits }).format(ratio);
}

export function formatDuration(seconds: number, lang: string): string {
  if (seconds < 1) return `${new Intl.NumberFormat(lang, { maximumFractionDigits: 2 }).format(seconds)} s`;
  const parts: string[] = [];
  let s = Math.round(seconds);
  const d = Math.floor(s / 86400);
  s -= d * 86400;
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  if (d) parts.push(`${d} d`);
  if (h) parts.push(`${h} h`);
  if (m && !d) parts.push(`${m} m`);
  if (s && !d && !h) parts.push(`${s} s`);
  return parts.join(" ") || "0 s";
}

export function formatRelative(iso: string, lang: string, now = Date.now()): string {
  const diff = (new Date(iso).getTime() - now) / 1000;
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: "auto" });
  const abs = Math.abs(diff);
  if (abs < 60) return rtf.format(Math.round(diff), "second");
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), "hour");
  return rtf.format(Math.round(diff / 86400), "day");
}

export function formatDateTime(iso: string, lang: string): string {
  return new Intl.DateTimeFormat(lang, { dateStyle: "medium", timeStyle: "short" }).format(new Date(iso));
}
