import { createContext, useContext, useMemo, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { LockkeeperApi } from "./client";
import type { ApproveInput, MetricKey, NewServerInput } from "./types";

const ApiContext = createContext<LockkeeperApi | null>(null);

export function ApiProvider({ api, children }: { api: LockkeeperApi; children: ReactNode }) {
  return <ApiContext.Provider value={api}>{children}</ApiContext.Provider>;
}

export function useApi(): LockkeeperApi {
  const api = useContext(ApiContext);
  if (!api) throw new Error("useApi must be used inside <ApiProvider>");
  return api;
}

// Live data is polled; the "last sample" age shown in the UI makes staleness visible.
const LIVE = { refetchInterval: 15_000, staleTime: 5_000 } as const;

export const useServers = () => {
  const api = useApi();
  return useQuery({ queryKey: ["servers"], queryFn: () => api.listServers(), ...LIVE });
};
export const useServer = (id: string) => {
  const api = useApi();
  return useQuery({ queryKey: ["server", id], queryFn: () => api.getServer(id), ...LIVE });
};
export const useDatabases = (id: string) => {
  const api = useApi();
  return useQuery({ queryKey: ["databases", id], queryFn: () => api.listDatabases(id), ...LIVE });
};
export const useSlots = (id: string) => {
  const api = useApi();
  return useQuery({ queryKey: ["slots", id], queryFn: () => api.listSlots(id), ...LIVE });
};
export const useSeries = (id: string, metric: MetricKey, rangeMinutes: number) => {
  const api = useApi();
  return useQuery({ queryKey: ["series", id, metric, rangeMinutes], queryFn: () => api.getSeries(id, metric, rangeMinutes), ...LIVE });
};
export const useAlerts = (serverId?: string) => {
  const api = useApi();
  return useQuery({ queryKey: ["alerts", serverId ?? "all"], queryFn: () => api.listAlerts({ serverId }), ...LIVE });
};
export const useMigrations = () => {
  const api = useApi();
  return useQuery({ queryKey: ["migrations"], queryFn: () => api.listMigrations(), ...LIVE });
};
export const useMigration = (id: string) => {
  const api = useApi();
  return useQuery({ queryKey: ["migration", id], queryFn: () => api.getMigration(id), ...LIVE });
};

export function useTestConnection() {
  const api = useApi();
  return useMutation({ mutationFn: (input: NewServerInput) => api.testConnection(input) });
}
export function useCreateServer() {
  const api = useApi();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: NewServerInput) => api.createServer(input),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["servers"] }),
  });
}
export function usePreflight() {
  const api = useApi();
  return useMutation({ mutationFn: (v: { sourceId: string; targetId: string }) => api.runPreflight(v.sourceId, v.targetId) });
}
export function useBuildPlan() {
  const api = useApi();
  return useMutation({ mutationFn: (v: { sourceId: string; targetId: string }) => api.buildPlan(v.sourceId, v.targetId) });
}
export function useApprove() {
  const api = useApi();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: ApproveInput) => api.approveMigration(input),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["migrations"] }),
  });
}

export function useStableApi(factory: () => LockkeeperApi): LockkeeperApi {
  return useMemo(factory, [factory]);
}
