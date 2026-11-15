import type { SeriesPoint } from "@/api/types";

export type Trend = "rising" | "falling" | "steady";
export interface SeriesStats {
  current: number;
  min: number;
  max: number;
  trend: Trend;
}

const mean = (xs: number[]): number => xs.reduce((a, b) => a + b, 0) / xs.length;

/**
 * Current / min / max and a coarse trend. The trend compares the mean of the first quarter with the
 * mean of the last quarter, so noise around a flat line reads "steady" instead of flickering.
 */
export function seriesStats(points: SeriesPoint[]): SeriesStats | null {
  if (points.length === 0) return null;
  const values = points.map((p) => p.v);
  const q = Math.max(1, Math.floor(values.length / 4));
  const a = mean(values.slice(0, q));
  const b = mean(values.slice(-q));
  const denom = Math.max(Math.abs(a), Math.abs(b), 1e-9);
  const rel = (b - a) / denom;
  const trend: Trend = Math.abs(rel) < 0.05 ? "steady" : rel > 0 ? "rising" : "falling";
  return { current: values[values.length - 1]!, min: Math.min(...values), max: Math.max(...values), trend };
}
