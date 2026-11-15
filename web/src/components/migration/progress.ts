import type { MigrationSummary } from "@/api/types";

export function overallProgress(m: MigrationSummary): { done: number; total: number; ratio: number } {
  const total = m.databases.reduce((n, d) => n + d.totalBytes, 0);
  const done = m.databases.reduce((n, d) => n + d.copiedBytes, 0);
  return { done, total, ratio: total > 0 ? Math.min(1, done / total) : 0 };
}
