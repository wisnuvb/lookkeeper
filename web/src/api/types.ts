// The UI's view of the Lockkeeper API (ADR 0006 item 6). In stage U0 these are served by the mock
// in ./mock.ts; in U2 the same shapes come from /api/v1 and the types are generated from OpenAPI.
//
// Rules that the real API will enforce and the mock imitates:
//  - secrets are write-only: no type here has a field that carries a stored password or token;
//  - the server, not the UI, validates plan hashes and typed confirmations;
//  - a connection is a SERVER; databases are discovered beneath it (never registered one by one).

export type Engine = "postgres" | "mysql";
export type Health = "ok" | "warning" | "critical" | "unknown";
export type TlsMode = "verify-full" | "verify-ca" | "require" | "disable";
export type ConnectionOrigin = "registry" | "yaml"; // yaml entries are read-only in the UI

export interface ServerGauges {
  connectionsUsedRatio: number; // 0..1
  retainedWalBytes: number | null; // PostgreSQL only
  cacheHitRatio: number | null; // 0..1
  replicationLagSeconds: number | null;
}

export interface ServerSummary {
  id: string;
  name: string;
  engine: Engine;
  version: string;
  host: string;
  port: number;
  tls: TlsMode;
  origin: ConnectionOrigin;
  managed: "rds" | "aurora" | "self-hosted";
  health: Health;
  reachable: boolean;
  lastSampleAt: string; // ISO 8601
  databaseCount: number;
  totalSizeBytes: number;
  activeAlerts: number;
  gauges: ServerGauges;
}

export interface DatabaseInfo {
  name: string;
  sizeBytes: number;
  connections: number;
  cacheHitRatio: number | null;
  xidAgeRatio: number | null; // fraction of the wraparound limit used (PostgreSQL)
  tablesWithoutPrimaryKey: number;
  health: Health;
}

export type AlertSeverity = "warning" | "critical";

export interface Alert {
  id: string;
  serverId: string;
  database?: string;
  rule: string; // stable rule id, e.g. "pg.slot.retained_wal_bytes"
  severity: AlertSeverity;
  state: "firing" | "resolved";
  since: string; // ISO 8601
  value: number;
  threshold: number;
  unit: "bytes" | "seconds" | "ratio" | "count";
  labels: Record<string, string>; // e.g. { slot: "demo_orphan_slot" }
}

export type MetricKey =
  | "connectionsUsedRatio"
  | "cacheHitRatio"
  | "retainedWalBytes"
  | "replicationLagSeconds"
  | "xidAgeRatio";

export interface SeriesPoint {
  t: number; // epoch ms
  v: number;
}
export interface Series {
  metric: MetricKey;
  unit: "bytes" | "seconds" | "ratio";
  points: SeriesPoint[];
  warning?: number;
  critical?: number;
}

export interface ReplicationSlot {
  name: string;
  type: "logical" | "physical";
  database: string | null;
  active: boolean;
  retainedWalBytes: number;
  plugin: string | null;
  ownedByMigration: string | null; // migration id when Lockkeeper created it
}

// ---- Connections -----------------------------------------------------------------------------

export interface NewServerInput {
  name: string;
  engine: Engine;
  host: string;
  port: number;
  database: string; // the database used to open the session
  user: string;
  password: string; // write-only: sent once, never returned
  tls: TlsMode;
  caPem?: string;
}

export type FindingSeverity = "blocker" | "warning" | "info";

export interface Finding {
  id: string;
  severity: FindingSeverity;
  title: string;
  detail: string;
  remedy?: string; // a command for the OPERATOR to run; Lockkeeper never runs it for monitoring
}

export interface ConnectionTestResult {
  ok: boolean;
  error?: { code: "unreachable" | "tls" | "auth" | "refused-address"; message: string };
  version?: string;
  tls?: { mode: TlsMode; verified: boolean };
  managed?: "rds" | "aurora" | "self-hosted";
  privileges?: { superuser: boolean; replication: boolean; monitor: boolean; readOnlySession: boolean };
  findings: Finding[];
  discovered: Array<{ name: string; sizeBytes: number }>;
}

// ---- Migration ---------------------------------------------------------------------------------

export type MigrationState =
  | "draft"
  | "planned"
  | "approved"
  | "copying"
  | "following"
  | "caught_up"
  | "verifying"
  | "cutover_ready"
  | "completed"
  | "aborted"
  | "failed";

export type DbMigrationPhase = "waiting" | "schema" | "copying" | "following" | "caught_up" | "done" | "failed";

export interface DbMigrationProgress {
  database: string;
  phase: DbMigrationPhase;
  copiedBytes: number;
  totalBytes: number;
  lagBytes: number | null;
  retainedWalBytes: number | null;
  slot: string;
}

export interface MigrationSummary {
  id: string; // "m" + 8 hex, derived from the plan inputs
  sourceId: string;
  targetId: string;
  state: MigrationState;
  createdAt: string;
  updatedAt: string;
  planHash: string;
  databases: DbMigrationProgress[];
  warnings: string[];
  rollbackWindowEndsAt?: string;
}

export interface PlanAction {
  id: string;
  side: "source" | "target";
  mutatesSource: boolean;
  title: string;
  sql?: string;
  command?: string;
  notice?: string;
}

export interface MigrationPlan {
  sourceId: string;
  targetId: string;
  databases: string[];
  actions: PlanAction[];
  hash: string; // the server computes this over the canonical plan
  confirmationPhrase: string; // what an admin must type to approve
  notices: string[];
}

export interface PreflightReport {
  sourceId: string;
  targetId: string;
  databases: string[];
  findings: Finding[];
  readOnly: true;
}

export interface ApproveInput {
  sourceId: string;
  targetId: string;
  planHash: string;
  confirmation: string;
}

export class ApiError extends Error {
  readonly code: "plan_hash_mismatch" | "confirmation_mismatch" | "forbidden" | "not_found" | "invalid";
  constructor(code: ApiError["code"], message: string) {
    super(message);
    this.code = code;
  }
}
