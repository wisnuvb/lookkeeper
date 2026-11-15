import { useId, useMemo, useState } from "react";
import { Table2, LineChart as LineChartIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { CartesianGrid, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Series } from "@/api/types";
import { Button } from "@/components/ui/button";
import { formatSeriesValue } from "./format";
import { seriesStats } from "./stats";
import { useReducedMotion } from "./useReducedMotion";

interface Props {
  title: string;
  series: Series;
  /** Human text for the visible range, e.g. "1 hour"; used in the summary and table caption. */
  rangeLabel: string;
}

const CHART_HEIGHT = 240;

// Thresholds are drawn only when they are within reach of the data, otherwise a 5 GiB line would
// flatten a 30 MiB series. They are ALWAYS listed in text under the chart, so nothing is hidden.
function yDomain(series: Series, dataMax: number): [number, number] {
  if (series.unit === "ratio" && series.metric !== "cacheHitRatio") return [0, 1];
  if (series.metric === "cacheHitRatio") return [0.9, 1];
  let max = Math.max(dataMax * 1.15, 1e-9);
  for (const th of [series.warning, series.critical]) if (th !== undefined && th <= dataMax * 3) max = Math.max(max, th * 1.05);
  return [0, max];
}

/**
 * Time-series line chart. Accessibility is built in, not bolted on:
 *  - a "View as table" toggle swaps the SVG for a real data table (the required alternative);
 *  - a one-sentence summary (current/min/max/trend) is available to screen readers;
 *  - warning/critical lines differ in dash pattern AND carry a text label, not colour alone;
 *  - colours come from CSS tokens; animation is off under prefers-reduced-motion.
 */
export function TimeSeriesChart({ title, series, rangeLabel }: Props) {
  const { t, i18n } = useTranslation("server");
  const lang = i18n.language;
  const reduced = useReducedMotion();
  const [asTable, setAsTable] = useState(false);
  const titleId = useId();
  const summaryId = useId();
  const stats = useMemo(() => seriesStats(series.points), [series.points]);

  const fmt = (v: number) => formatSeriesValue(series.unit, v, lang);
  const timeFmt = useMemo(() => new Intl.DateTimeFormat(lang, { hour: "2-digit", minute: "2-digit" }), [lang]);
  const fullFmt = useMemo(() => new Intl.DateTimeFormat(lang, { dateStyle: "short", timeStyle: "medium" }), [lang]);

  if (!stats) {
    return (
      <figure aria-labelledby={titleId} className="rounded-xl border bg-card p-4">
        <figcaption id={titleId} className="font-medium">{title}</figcaption>
        <p className="mt-3 text-sm text-muted-foreground">{t("chart.noData")}</p>
      </figure>
    );
  }

  const domain = yDomain(series, stats.max);
  const summary = t("chart.summary", { title, current: fmt(stats.current), min: fmt(stats.min), max: fmt(stats.max), trend: t(`chart.trend.${stats.trend}`), range: rangeLabel });
  const thresholds = [
    series.warning !== undefined ? { key: "warning" as const, value: series.warning } : null,
    series.critical !== undefined ? { key: "critical" as const, value: series.critical } : null,
  ].filter((x): x is { key: "warning" | "critical"; value: number } => x !== null);
  // Only draw a line that falls inside the plot; every threshold is still listed in text below.
  const drawn = thresholds.filter((th) => th.value >= domain[0] && th.value <= domain[1]);

  return (
    <figure aria-labelledby={titleId} aria-describedby={summaryId} className="min-w-0 rounded-xl border bg-card p-4 sm:p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <figcaption id={titleId} className="text-sm font-medium text-muted-foreground">{title}</figcaption>
          <p className="mt-1 text-xs text-muted-foreground">{t("chart.current")}</p>
          <p className="tnum font-mono text-3xl font-semibold leading-none">{fmt(stats.current)}</p>
        </div>
        <Button variant="outline" size="sm" aria-pressed={asTable} onClick={() => setAsTable((v) => !v)}>
          {asTable ? <LineChartIcon aria-hidden="true" /> : <Table2 aria-hidden="true" />}
          {asTable ? t("chart.viewChart") : t("chart.viewTable")}
        </Button>
      </div>

      <p id={summaryId} className="sr-only">{summary}</p>

      {asTable ? (
        <div
          role="region"
          tabIndex={0}
          aria-label={t("chart.tableRegion", { title })}
          className="mt-4 max-h-72 overflow-auto rounded-md border"
        >
          <table className="w-full text-sm">
            <caption className="sr-only">{t("chart.tableCaption", { title, range: rangeLabel })}</caption>
            <thead className="sticky top-0 bg-muted">
              <tr>
                <th scope="col" className="px-3 py-2 text-left text-xs font-medium text-muted-foreground">{t("chart.time")}</th>
                <th scope="col" className="px-3 py-2 text-right text-xs font-medium text-muted-foreground">{t("chart.value")}</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {[...series.points].reverse().map((p) => (
                <tr key={p.t}>
                  <td className="tnum px-3 py-1.5 font-mono text-xs">{fullFmt.format(p.t)}</td>
                  <td className="tnum px-3 py-1.5 text-right font-mono text-xs">{fmt(p.v)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="mt-4" style={{ height: CHART_HEIGHT }}>
          <ResponsiveContainer width="100%" height="100%" initialDimension={{ width: 640, height: CHART_HEIGHT }}>
            <LineChart data={series.points} margin={{ top: 8, right: 12, bottom: 0, left: 0 }}>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
              <XAxis
                dataKey="t"
                type="number"
                scale="time"
                domain={["dataMin", "dataMax"]}
                tickFormatter={(v: number) => timeFmt.format(v)}
                tick={{ fill: "var(--muted-foreground)", fontSize: 12 }}
                stroke="var(--border)"
                minTickGap={48}
              />
              <YAxis
                domain={domain}
                tickFormatter={(v: number) => fmt(v)}
                tick={{ fill: "var(--muted-foreground)", fontSize: 12 }}
                stroke="var(--border)"
                width={series.unit === "bytes" ? 72 : 56}
                tickCount={5}
              />
              <Tooltip
                labelFormatter={(v) => fullFmt.format(Number(v))}
                formatter={(v) => [fmt(Number(v)), title]}
                contentStyle={{ background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 8, color: "var(--popover-foreground)", fontSize: 13 }}
                labelStyle={{ color: "var(--muted-foreground)" }}
                itemStyle={{ color: "var(--popover-foreground)" }}
              />
              {drawn.map((th) => (
                <ReferenceLine
                  key={th.key}
                  y={th.value}
                  stroke={th.key === "critical" ? "var(--crit)" : "var(--warn)"}
                  strokeDasharray={th.key === "critical" ? "2 3" : "8 4"}
                  strokeWidth={1.5}
                  label={{ value: `${t(`chart.${th.key}`)} · ${fmt(th.value)}`, position: "insideTopRight", fill: th.key === "critical" ? "var(--crit)" : "var(--warn)", fontSize: 12 }}
                />
              ))}
              <Line type="monotone" dataKey="v" stroke="var(--chart-1)" strokeWidth={2} dot={false} isAnimationActive={!reduced} activeDot={{ r: 4 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      {thresholds.length > 0 ? (
        <p className="mt-3 text-xs text-muted-foreground">
          {t("chart.thresholds")}:{" "}
          {thresholds.map((th, i) => (
            <span key={th.key}>
              {i > 0 ? " · " : ""}
              {t(`chart.${th.key}`)} <span className="tnum font-mono">{fmt(th.value)}</span>
            </span>
          ))}
        </p>
      ) : null}
    </figure>
  );
}
