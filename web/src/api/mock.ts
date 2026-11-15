import type { LockkeeperApi } from "./client";
import {
  ApiError,
  type Alert,
  type ApproveInput,
  type ConnectionTestResult,
  type DatabaseInfo,
  type Finding,
  type MetricKey,
  type MigrationPlan,
  type MigrationSummary,
  type NewServerInput,
  type PreflightReport,
  type ReplicationSlot,
  type Series,
  type ServerSummary,
} from "./types";

// Invented data for the U0 prototype. Nothing here describes a real database.
// Names and numbers are chosen to exercise every state the UI must handle: critical, warning, ok,
// unreachable, read-only YAML entries, a running migration, a PK-less table, an orphan slot.

const GiB = 1024 ** 3;
const MiB = 1024 ** 2;
const delay = <T,>(v: T, ms = 220): Promise<T> => new Promise((r) => setTimeout(() => r(v), ms));
const ago = (min: number) => new Date(Date.now() - min * 60_000).toISOString();

const servers: ServerSummary[] = [
  {
    id: "rds-main",
    name: "rds-main",
    engine: "postgres",
    version: "PostgreSQL 16.4",
    host: "main-prod.c9x1example.eu-west-1.rds.amazonaws.com",
    port: 5432,
    tls: "verify-full",
    origin: "yaml",
    managed: "rds",
    health: "critical",
    reachable: true,
    lastSampleAt: ago(0.4),
    databaseCount: 6,
    totalSizeBytes: 148 * GiB,
    activeAlerts: 2,
    gauges: { connectionsUsedRatio: 0.71, retainedWalBytes: 18.4 * GiB, cacheHitRatio: 0.987, replicationLagSeconds: null },
  },
  {
    id: "ovh-main",
    name: "ovh-main",
    engine: "postgres",
    version: "PostgreSQL 17.2",
    host: "vps-1234.ovh.example.net",
    port: 5432,
    tls: "verify-full",
    origin: "registry",
    managed: "self-hosted",
    health: "ok",
    reachable: true,
    lastSampleAt: ago(0.3),
    databaseCount: 1,
    totalSizeBytes: 9 * MiB,
    activeAlerts: 0,
    gauges: { connectionsUsedRatio: 0.04, retainedWalBytes: 0, cacheHitRatio: 0.999, replicationLagSeconds: null },
  },
  {
    id: "mysql-billing",
    name: "mysql-billing",
    engine: "mysql",
    version: "MySQL 8.4.3",
    host: "billing-db.internal.example.net",
    port: 3306,
    tls: "verify-full",
    origin: "registry",
    managed: "self-hosted",
    health: "warning",
    reachable: true,
    lastSampleAt: ago(0.5),
    databaseCount: 3,
    totalSizeBytes: 22 * GiB,
    activeAlerts: 1,
    gauges: { connectionsUsedRatio: 0.38, retainedWalBytes: null, cacheHitRatio: 0.962, replicationLagSeconds: 74 },
  },
  {
    id: "staging-pg",
    name: "staging-pg",
    engine: "postgres",
    version: "PostgreSQL 15.8",
    host: "staging.internal.example.net",
    port: 5432,
    tls: "verify-full",
    origin: "registry",
    managed: "self-hosted",
    health: "unknown",
    reachable: false,
    lastSampleAt: ago(37),
    databaseCount: 4,
    totalSizeBytes: 3 * GiB,
    activeAlerts: 1,
    gauges: { connectionsUsedRatio: 0, retainedWalBytes: null, cacheHitRatio: null, replicationLagSeconds: null },
  },
];

const databases: Record<string, DatabaseInfo[]> = {
  "rds-main": [
    { name: "shop", sizeBytes: 71 * GiB, connections: 38, cacheHitRatio: 0.991, xidAgeRatio: 0.12, tablesWithoutPrimaryKey: 1, health: "ok" },
    { name: "billing", sizeBytes: 34 * GiB, connections: 12, cacheHitRatio: 0.984, xidAgeRatio: 0.41, tablesWithoutPrimaryKey: 0, health: "warning" },
    { name: "auth", sizeBytes: 19 * GiB, connections: 21, cacheHitRatio: 0.995, xidAgeRatio: 0.09, tablesWithoutPrimaryKey: 0, health: "ok" },
    { name: "analytics", sizeBytes: 16 * GiB, connections: 4, cacheHitRatio: 0.93, xidAgeRatio: 0.18, tablesWithoutPrimaryKey: 3, health: "ok" },
    { name: "notifications", sizeBytes: 6.2 * GiB, connections: 6, cacheHitRatio: 0.99, xidAgeRatio: 0.07, tablesWithoutPrimaryKey: 0, health: "ok" },
    { name: "postgres", sizeBytes: 7.4 * MiB, connections: 1, cacheHitRatio: 0.999, xidAgeRatio: 0.02, tablesWithoutPrimaryKey: 0, health: "ok" },
  ],
  "ovh-main": [
    { name: "postgres", sizeBytes: 7.4 * MiB, connections: 1, cacheHitRatio: 0.999, xidAgeRatio: 0.01, tablesWithoutPrimaryKey: 0, health: "ok" },
  ],
  "mysql-billing": [
    { name: "invoices", sizeBytes: 15 * GiB, connections: 22, cacheHitRatio: 0.958, xidAgeRatio: null, tablesWithoutPrimaryKey: 0, health: "warning" },
    { name: "ledger", sizeBytes: 6.5 * GiB, connections: 9, cacheHitRatio: 0.971, xidAgeRatio: null, tablesWithoutPrimaryKey: 0, health: "ok" },
    { name: "reports", sizeBytes: 0.5 * GiB, connections: 1, cacheHitRatio: 0.99, xidAgeRatio: null, tablesWithoutPrimaryKey: 2, health: "ok" },
  ],
  "staging-pg": [],
};

const slots: Record<string, ReplicationSlot[]> = {
  "rds-main": [
    { name: "demo_orphan_slot", type: "logical", database: "shop", active: false, retainedWalBytes: 18.4 * GiB, plugin: "pgoutput", ownedByMigration: null },
    { name: "lk_m5f3a9c21_shop", type: "logical", database: "shop", active: true, retainedWalBytes: 42 * MiB, plugin: "pgoutput", ownedByMigration: "m5f3a9c21" },
    { name: "lk_m5f3a9c21_billing", type: "logical", database: "billing", active: true, retainedWalBytes: 3 * MiB, plugin: "pgoutput", ownedByMigration: "m5f3a9c21" },
  ],
};

const alerts: Alert[] = [
  { id: "a1", serverId: "rds-main", database: "shop", rule: "pg.slot.retained_wal_bytes", severity: "critical", state: "firing", since: ago(190), value: 18.4 * GiB, threshold: 20 * GiB * 0.9, unit: "bytes", labels: { slot: "demo_orphan_slot" } },
  { id: "a2", serverId: "rds-main", database: "billing", rule: "pg.xid.age_ratio", severity: "warning", state: "firing", since: ago(1440), value: 0.41, threshold: 0.4, unit: "ratio", labels: {} },
  { id: "a3", serverId: "mysql-billing", rule: "mysql.replication.lag_s", severity: "warning", state: "firing", since: ago(22), value: 74, threshold: 60, unit: "seconds", labels: { channel: "primary-a" } },
  { id: "a4", serverId: "staging-pg", rule: "monitor.unreachable", severity: "critical", state: "firing", since: ago(37), value: 1, threshold: 1, unit: "count", labels: {} },
];

// Deterministic pseudo-random so the charts do not jump between renders.
function rng(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

function seriesFor(serverId: string, metric: MetricKey, rangeMinutes: number): Series {
  const n = Math.min(120, Math.max(24, Math.floor(rangeMinutes / 2)));
  const step = (rangeMinutes * 60_000) / n;
  const r = rng([...serverId, ...metric].reduce((a, c) => a * 31 + c.charCodeAt(0), 7));
  const now = Date.now();
  const points: Series["points"] = [];
  const orphan = serverId === "rds-main" && metric === "retainedWalBytes";
  for (let i = 0; i < n; i++) {
    const t = now - (n - 1 - i) * step;
    const x = i / (n - 1);
    let v: number;
    switch (metric) {
      case "connectionsUsedRatio":
        v = 0.55 + 0.18 * Math.sin(x * 9) + (r() - 0.5) * 0.05;
        break;
      case "cacheHitRatio":
        v = 0.985 + (r() - 0.5) * 0.008;
        break;
      case "retainedWalBytes":
        v = orphan ? (2 + 16.4 * x ** 1.4) * GiB + r() * 0.1 * GiB : (30 + r() * 25) * MiB;
        break;
      case "replicationLagSeconds":
        v = serverId === "mysql-billing" ? 10 + 70 * x ** 2 + r() * 6 : r() * 0.4;
        break;
      case "xidAgeRatio":
        v = 0.38 + 0.03 * x + r() * 0.004;
        break;
    }
    points.push({ t, v: Math.max(0, v) });
  }
  const unit: Series["unit"] =
    metric === "retainedWalBytes" ? "bytes" : metric === "replicationLagSeconds" ? "seconds" : "ratio";
  const thresholds: Partial<Record<MetricKey, [number, number]>> = {
    connectionsUsedRatio: [0.8, 0.95],
    retainedWalBytes: [5 * GiB, 20 * GiB],
    replicationLagSeconds: [60, 300],
    xidAgeRatio: [0.4, 0.7],
  };
  const th = thresholds[metric];
  return { metric, unit, points, warning: th?.[0], critical: th?.[1] };
}

// ---- Migration fixtures ---------------------------------------------------------------------------

const migrations: MigrationSummary[] = [
  {
    id: "m5f3a9c21",
    sourceId: "rds-main",
    targetId: "ovh-main",
    state: "copying",
    createdAt: ago(300),
    updatedAt: ago(0.2),
    planHash: "9b1f3c0e7a52d84e6f21b0a9c3d5e7f8a1b2c3d4e5f60718293a4b5c6d7e8f90",
    databases: [
      { database: "shop", phase: "copying", copiedBytes: 44 * GiB, totalBytes: 71 * GiB, lagBytes: null, retainedWalBytes: 42 * MiB, slot: "lk_m5f3a9c21_shop" },
      { database: "billing", phase: "caught_up", copiedBytes: 34 * GiB, totalBytes: 34 * GiB, lagBytes: 180 * 1024, retainedWalBytes: 3 * MiB, slot: "lk_m5f3a9c21_billing" },
      { database: "auth", phase: "waiting", copiedBytes: 0, totalBytes: 19 * GiB, lagBytes: null, retainedWalBytes: null, slot: "lk_m5f3a9c21_auth" },
    ],
    warnings: [
      "A slot of this migration still retains WAL on the source. Check progress with `lockkeeper migrate status`, and use abort and cleanup if you stop.",
      "Schema changes on the source must stay frozen until cutover: logical replication carries no DDL.",
    ],
  },
];

function findingsFor(sourceId: string): Finding[] {
  const src = servers.find((s) => s.id === sourceId);
  const f: Finding[] = [
    { id: "source.replication_privilege", severity: "blocker", title: "The role cannot create replication slots", detail: 'Role "lockkeeper" lacks REPLICATION and, on RDS, membership of rds_replication.', remedy: 'GRANT rds_replication TO migration_role;  -- changes the SOURCE; asked for explicitly with a plan hash' },
    { id: "source.max_slot_wal_keep_size", severity: "warning", title: "max_slot_wal_keep_size is unlimited", detail: "A slot that is not read keeps WAL forever and can fill the source disk.", remedy: "Set a limit in the parameter group, larger than the WAL produced during the copy but smaller than the free disk." },
    { id: "tables.no_pk", severity: "warning", title: "4 tables have no primary key", detail: "UPDATE and DELETE on them would not replicate unless REPLICA IDENTITY is set.", remedy: 'ALTER TABLE "public"."audit_log" REPLICA IDENTITY FULL;' },
    { id: "network.target_to_source", severity: "warning", title: "Target to source reachability cannot be verified read-only", detail: "Testing it would need to create something on the target.", remedy: "From the TARGET host run: psql 'postgresql://…/postgres?sslmode=verify-full' -c 'SELECT 1'" },
    { id: "data.sizes", severity: "info", title: `${src?.databaseCount ?? 0} databases, about ${Math.round((src?.totalSizeBytes ?? 0) / GiB)} GiB`, detail: "Target should have at least 1.5× that free. Free disk cannot be read over SQL." },
    { id: "tls.source", severity: "info", title: "TLS to the source is verified", detail: "verify-full against the configured CA bundle." },
  ];
  return f;
}

function planFor(sourceId: string, targetId: string): MigrationPlan {
  const dbs = (databases[sourceId] ?? []).map((d) => d.name).filter((n) => n !== "postgres");
  const actions: MigrationPlan["actions"] = [
    { id: "src.role", side: "source", mutatesSource: true, title: "Create the per-migration role", sql: "CREATE ROLE lk_m5f3a9c21 LOGIN REPLICATION PASSWORD '<SCRAM verifier>';", notice: "A SCRAM verifier is sent, never the clear password." },
    ...dbs.map((d) => ({ id: `src.pub.${d}`, side: "source" as const, mutatesSource: true, title: `Create publication for "${d}"`, sql: `CREATE PUBLICATION lk_m5f3a9c21_${d} FOR TABLE <explicit table list>;` })),
    { id: "src.replident", side: "source", mutatesSource: true, title: "Set REPLICA IDENTITY FULL on tables without a key", sql: 'ALTER TABLE "public"."audit_log" REPLICA IDENTITY FULL;', notice: "Takes a brief ACCESS EXCLUSIVE lock per table (lock_timeout 10s) and is not reverted by cleanup." },
    ...dbs.map((d) => ({ id: `dst.copy.${d}`, side: "target" as const, mutatesSource: false, title: `Bulk copy "${d}" inside an exported snapshot`, command: `pgcopydb clone --snapshot <id> --source <passwordless URI> --target <passwordless URI>` })),
    ...dbs.map((d) => ({ id: `dst.sub.${d}`, side: "target" as const, mutatesSource: false, title: `Create and enable subscription for "${d}"`, sql: `CREATE SUBSCRIPTION lk_m5f3a9c21_${d} CONNECTION '<hidden>' PUBLICATION lk_m5f3a9c21_${d} WITH (create_slot=false, copy_data=false, enabled=false);` })),
  ];
  return {
    sourceId,
    targetId,
    databases: dbs,
    actions,
    hash: "9b1f3c0e7a52d84e6f21b0a9c3d5e7f8a1b2c3d4e5f60718293a4b5c6d7e8f90",
    confirmationPhrase: `migrate ${sourceId} to ${targetId}`,
    notices: [
      "This plan changes the SOURCE server (role, publications, replica identity) and creates replication slots that retain WAL until cleanup.",
      "After cutover, writes on the target do NOT flow back to the source. The rollback window is recorded and blocks cleanup.",
      "Nothing in this prototype has been validated against real RDS or Aurora.",
    ],
  };
}

// ---- The mock API ----------------------------------------------------------------------------------

export function createMockApi(): LockkeeperApi {
  const preflightRuns = new Map<string, number>();
  const state = { servers: [...servers], migrations: [...migrations] };
  const find = (id: string) => {
    const s = state.servers.find((x) => x.id === id);
    if (!s) throw new ApiError("not_found", `Server "${id}" not found`);
    return s;
  };

  return {
    isDemo: true,
    listServers: () => delay([...state.servers]),
    getServer: (id) => delay(find(id)),
    listDatabases: (id) => (find(id), delay(databases[id] ?? [])),
    listSlots: (id) => (find(id), delay(slots[id] ?? [])),
    getSeries: (id, metric, range) => (find(id), delay(seriesFor(id, metric, range), 320)),
    listAlerts: (opts) => delay(alerts.filter((a) => !opts?.serverId || a.serverId === opts.serverId)),

    async testConnection(input: NewServerInput): Promise<ConnectionTestResult> {
      await delay(null, 900);
      if (/169\.254\.|metadata/i.test(input.host)) {
        return { ok: false, error: { code: "refused-address", message: "This address is never allowed (link-local / cloud metadata)." }, findings: [], discovered: [] };
      }
      if (/unreachable|down/i.test(input.host)) {
        return { ok: false, error: { code: "unreachable", message: `Could not connect to ${input.host}:${input.port} (timeout after 10 s).` }, findings: [], discovered: [] };
      }
      if (input.password.length === 0) {
        return { ok: false, error: { code: "auth", message: "Authentication failed for the given user." }, findings: [], discovered: [] };
      }
      if (input.tls === "disable" && !/^(127\.|localhost)/.test(input.host)) {
        return { ok: false, error: { code: "tls", message: "TLS is required for remote servers. Choose verify-full, or opt in explicitly." }, findings: [], discovered: [] };
      }
      const admin = /^(postgres|root|admin)$/i.test(input.user);
      const findings: Finding[] = [];
      if (admin) findings.push({ id: "role.superuser", severity: "warning", title: "This account is a superuser", detail: "Monitoring should use a dedicated least-privilege role. A read-only session is not a security boundary.", remedy: input.engine === "postgres" ? "CREATE ROLE lockkeeper LOGIN PASSWORD '…'; GRANT pg_monitor TO lockkeeper;" : "GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'lockkeeper'@'%';" });
      findings.push({ id: "tls.ok", severity: "info", title: input.tls === "disable" ? "Session is not encrypted (loopback only)" : "Server certificate verified", detail: input.tls === "disable" ? "Loopback connections are exempt from the TLS requirement." : "The certificate chain and host name were verified." });
      return {
        ok: true,
        version: input.engine === "postgres" ? "PostgreSQL 16.4" : "MySQL 8.4.3",
        tls: { mode: input.tls, verified: input.tls === "verify-full" || input.tls === "verify-ca" },
        managed: /rds\.amazonaws/.test(input.host) ? "rds" : "self-hosted",
        privileges: { superuser: admin, replication: admin, monitor: true, readOnlySession: true },
        findings,
        discovered: [
          { name: "app_production", sizeBytes: 12.5 * GiB },
          { name: "app_reporting", sizeBytes: 2.1 * GiB },
          { name: input.engine === "postgres" ? "postgres" : "mysql", sizeBytes: 7.4 * MiB },
        ],
      };
    },

    async createServer(input: NewServerInput): Promise<ServerSummary> {
      await delay(null, 500);
      if (state.servers.some((s) => s.id === input.name)) throw new ApiError("invalid", `A server named "${input.name}" already exists.`);
      const created: ServerSummary = {
        id: input.name,
        name: input.name,
        engine: input.engine,
        version: input.engine === "postgres" ? "PostgreSQL 16.4" : "MySQL 8.4.3",
        host: input.host,
        port: input.port,
        tls: input.tls,
        origin: "registry",
        managed: /rds\.amazonaws/.test(input.host) ? "rds" : "self-hosted",
        health: "ok",
        reachable: true,
        lastSampleAt: new Date().toISOString(),
        databaseCount: 3,
        totalSizeBytes: 14.6 * GiB,
        activeAlerts: 0,
        gauges: { connectionsUsedRatio: 0.12, retainedWalBytes: input.engine === "postgres" ? 0 : null, cacheHitRatio: 0.99, replicationLagSeconds: null },
      };
      state.servers = [...state.servers, created];
      databases[created.id] = [
        { name: "app_production", sizeBytes: 12.5 * GiB, connections: 9, cacheHitRatio: 0.99, xidAgeRatio: 0.05, tablesWithoutPrimaryKey: 0, health: "ok" },
        { name: "app_reporting", sizeBytes: 2.1 * GiB, connections: 2, cacheHitRatio: 0.98, xidAgeRatio: 0.03, tablesWithoutPrimaryKey: 0, health: "ok" },
        { name: input.engine === "postgres" ? "postgres" : "mysql", sizeBytes: 7.4 * MiB, connections: 1, cacheHitRatio: 0.999, xidAgeRatio: 0.01, tablesWithoutPrimaryKey: 0, health: "ok" },
      ];
      return created;
    },

    listMigrations: () => delay([...state.migrations]),
    getMigration: async (id) => {
      const m = state.migrations.find((x) => x.id === id);
      if (!m) throw new ApiError("not_found", `Migration "${id}" not found`);
      return delay(m);
    },
    async runPreflight(sourceId, targetId): Promise<PreflightReport> {
      find(sourceId);
      find(targetId);
      await delay(null, 1100);
      // The first run reports the blocker; a re-run simulates an operator who applied the remedy
      // (the real pre-flight is read-only and never applies it), so the demo can reach Plan/Approve.
      const key = `${sourceId}>${targetId}`;
      const runs = (preflightRuns.get(key) ?? 0) + 1;
      preflightRuns.set(key, runs);
      const findings = findingsFor(sourceId).filter((f) => runs === 1 || f.severity !== "blocker");
      return { sourceId, targetId, databases: (databases[sourceId] ?? []).map((d) => d.name), findings, readOnly: true };
    },
    async buildPlan(sourceId, targetId) {
      find(sourceId);
      find(targetId);
      return delay(planFor(sourceId, targetId), 600);
    },
    async approveMigration(input: ApproveInput): Promise<MigrationSummary> {
      await delay(null, 700);
      const plan = planFor(input.sourceId, input.targetId);
      // Same two checks the real server makes. The UI cannot bypass them.
      if (input.planHash !== plan.hash) throw new ApiError("plan_hash_mismatch", "The plan changed since it was shown. Review the new plan.");
      if (input.confirmation.trim() !== plan.confirmationPhrase) throw new ApiError("confirmation_mismatch", "The confirmation text does not match.");
      const created: MigrationSummary = {
        id: "m7c2e4d10",
        sourceId: input.sourceId,
        targetId: input.targetId,
        state: "approved",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        planHash: plan.hash,
        databases: plan.databases.map((d) => ({ database: d, phase: "waiting" as const, copiedBytes: 0, totalBytes: (databases[input.sourceId]?.find((x) => x.name === d)?.sizeBytes ?? 0), lagBytes: null, retainedWalBytes: null, slot: `lk_m7c2e4d10_${d}` })),
        warnings: [],
      };
      state.migrations = [created, ...state.migrations];
      return created;
    },
  };
}
