import type {
  Alert,
  ApproveInput,
  ConnectionTestResult,
  DatabaseInfo,
  MetricKey,
  MigrationPlan,
  MigrationSummary,
  NewServerInput,
  PreflightReport,
  ReplicationSlot,
  Series,
  ServerSummary,
} from "./types";

// The seam between screens and data. U0 injects the mock; U2 injects an HTTP implementation of the
// same interface, so no screen changes when the real server arrives.
export interface LockkeeperApi {
  /** True while the data is invented. The shell shows a permanent banner when this is true. */
  readonly isDemo: boolean;

  listServers(): Promise<ServerSummary[]>;
  getServer(id: string): Promise<ServerSummary>;
  listDatabases(serverId: string): Promise<DatabaseInfo[]>;
  listSlots(serverId: string): Promise<ReplicationSlot[]>;
  getSeries(serverId: string, metric: MetricKey, rangeMinutes: number): Promise<Series>;
  listAlerts(opts?: { serverId?: string }): Promise<Alert[]>;

  /** Read-only: opens a session, reports version/TLS/privileges and discovers databases. */
  testConnection(input: NewServerInput): Promise<ConnectionTestResult>;
  createServer(input: NewServerInput): Promise<ServerSummary>;

  listMigrations(): Promise<MigrationSummary[]>;
  getMigration(id: string): Promise<MigrationSummary>;
  runPreflight(sourceId: string, targetId: string): Promise<PreflightReport>;
  buildPlan(sourceId: string, targetId: string): Promise<MigrationPlan>;
  /** The server verifies the hash and the typed phrase; the UI cannot skip either. */
  approveMigration(input: ApproveInput): Promise<MigrationSummary>;
}
