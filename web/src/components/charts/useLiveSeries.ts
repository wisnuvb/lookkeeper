import { useQuery } from "@tanstack/react-query";
import { useApi } from "@/api/hooks";
import type { MetricKey } from "@/api/types";

export const LIVE_INTERVAL_MS = 15_000;

/** Same data as useSeries, but polling can be paused (a keyboard-reachable control, WCAG 2.2.2). */
export function useLiveSeries(serverId: string, metric: MetricKey, rangeMinutes: number, paused: boolean) {
  const api = useApi();
  return useQuery({
    queryKey: ["series", serverId, metric, rangeMinutes],
    queryFn: () => api.getSeries(serverId, metric, rangeMinutes),
    refetchInterval: paused ? false : LIVE_INTERVAL_MS,
    staleTime: 5_000,
  });
}
