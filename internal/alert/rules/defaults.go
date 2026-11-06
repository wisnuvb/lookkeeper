package rules

import (
	"time"

	"github.com/wisnuvb/lockkeeper/internal/model"
)

// Metric names emitted by the Postgres collector and used by default rules.
const (
	MetricPGUp                = "pg.up"
	MetricPGConnectionsRatio  = "pg.connections.used_ratio"
	MetricPGIdleInTxAge       = "pg.idle_in_tx.max_age_s"
	MetricPGLongestQuery      = "pg.query.longest_s"
	MetricPGBlockedSeconds    = "pg.locks.blocked_s"
	MetricPGSlotRetainedWAL   = "pg.slot.retained_wal_bytes"
	MetricPGSlotActive        = "pg.slot.active"
	MetricPGReplLagBytes      = "pg.repl.lag_bytes"
	MetricPGReplLagSeconds    = "pg.repl.lag_s"
	MetricPGStandbyLagSeconds = "pg.standby.replay_lag_s"
	MetricPGXIDAge            = "pg.xid.age"
	MetricPGMXIDAge           = "pg.mxid.age"
	MetricPGCacheHitRatio     = "pg.cache.hit_ratio"
	gib                       = float64(1 << 30)
	mib                       = float64(1 << 20)
	day                       = float64(24 * 3600)
)

// Metric names of the extra PostgreSQL metrics (collector file extras.go).
//
// Informational metrics have no default rule: MetricPGTempBytesRate,
// MetricPGDBSize, MetricPGAutovacuumNeverVacuumed and the MetricPGStatements*
// family. They are stored and exported (Prometheus) but never alert unless an
// operator adds a rule for them.
const (
	// MetricPGTableDeadRatio is n_dead_tup / (n_live_tup + n_dead_tup) of a table
	// with at least 100000 dead tuples (top 20), labels database/schema/table.
	MetricPGTableDeadRatio = "pg.table.dead_tuple_ratio"
	// MetricPGAutovacuumAge is the seconds since the last (auto)vacuum of a large
	// table (at least 1 GiB, top 20). Never-vacuumed tables are not reported here.
	MetricPGAutovacuumAge = "pg.autovacuum.last_age_s"
	// MetricPGAutovacuumNeverVacuumed is 1 for a large table with no recorded
	// vacuum. Informational: statistics are lost on a crash or pg_upgrade, so it
	// is not proof that autovacuum is failing.
	MetricPGAutovacuumNeverVacuumed = "pg.autovacuum.never_vacuumed"
	// MetricPGCheckpointReqRatio is the share of requested (WAL-triggered)
	// checkpoints among the most recent checkpoints.
	MetricPGCheckpointReqRatio = "pg.checkpoint.req_ratio"
	// MetricPGTempBytesRate is the bytes per second spilled to temporary files,
	// per database. Informational.
	MetricPGTempBytesRate = "pg.temp.bytes_rate"
	// MetricPGDBSize is the size of each database in bytes. Informational.
	MetricPGDBSize = "pg.db.size_bytes"
	// pg_stat_statements (optional extension), top 10 by total execution time.
	// Labels are database and queryid, never query text. Informational.
	MetricPGStatementsTime  = "pg.statements.total_exec_time_s"
	MetricPGStatementsCalls = "pg.statements.calls"
	MetricPGStatementsRows  = "pg.statements.rows"
)

func lv(sev model.Severity, thr float64, f time.Duration) Level {
	return Level{Severity: sev, Threshold: thr, For: f}
}

// Defaults returns all built-in rules: PostgreSQL (SPEC 10.1), MySQL (10.2) and RDS
// infrastructure rules. Each family lives in its own file so they can evolve
// independently. Thresholds are conservative starting points and can be overridden
// in configuration.
func Defaults() []Rule {
	out := PostgresDefaults()
	out = append(out, MySQLDefaults()...)
	out = append(out, RDSDefaults()...)
	return out
}

// PostgresDefaults returns the built-in PostgreSQL rules.
func PostgresDefaults() []Rule {
	w, c := model.SeverityWarning, model.SeverityCritical
	const m = time.Minute
	return []Rule{
		{
			Metric: MetricPGUp, Description: "database reachability", Op: Below, Unit: UnitFlag,
			Levels: []Level{lv(c, 1, 2*m)},
		},
		{
			Metric: MetricPGConnectionsRatio, Description: "connection usage", Op: Above, Unit: UnitRatio, Hysteresis: 0.05,
			Levels: []Level{lv(w, 0.80, 5*m), lv(c, 0.95, 2*m)},
		},
		{
			Metric: MetricPGIdleInTxAge, Description: "oldest idle-in-transaction session", Op: Above, Unit: UnitSeconds, Hysteresis: 0.05,
			Levels: []Level{lv(w, 300, 0), lv(c, 1800, 0)},
		},
		{
			Metric: MetricPGLongestQuery, Description: "longest running query", Op: Above, Unit: UnitSeconds, Hysteresis: 0.05,
			Levels: []Level{lv(w, 300, 0), lv(c, 1800, 0)},
		},
		{
			Metric: MetricPGBlockedSeconds, Description: "longest lock wait", Op: Above, Unit: UnitSeconds, Hysteresis: 0.05,
			Levels: []Level{lv(w, 30, 0), lv(c, 300, 0)},
		},
		{
			Metric: MetricPGSlotRetainedWAL, Description: "WAL retained by replication slot", Op: Above, Unit: UnitBytes, Hysteresis: 0.05,
			Levels: []Level{lv(w, 5*gib, 0), lv(c, 20*gib, 0)},
		},
		{
			Metric: MetricPGSlotActive, Description: "replication slot consumer", Op: Below, Unit: UnitFlag, NeedsHistory: true,
			Levels: []Level{lv(w, 1, 10*m), lv(c, 1, 60*m)},
		},
		{
			Metric: MetricPGReplLagBytes, Description: "replication lag", Op: Above, Unit: UnitBytes, Hysteresis: 0.05,
			Levels: []Level{lv(w, 256*mib, 2*m), lv(c, 2*gib, 2*m)},
		},
		{
			Metric: MetricPGReplLagSeconds, Description: "replication replay lag", Op: Above, Unit: UnitSeconds, Hysteresis: 0.05,
			Levels: []Level{lv(w, 60, 2*m), lv(c, 600, 2*m)},
		},
		{
			Metric: MetricPGStandbyLagSeconds, Description: "standby replay delay", Op: Above, Unit: UnitSeconds, Hysteresis: 0.05,
			Levels: []Level{lv(w, 60, 2*m), lv(c, 600, 2*m)},
		},
		{
			Metric: MetricPGXIDAge, Description: "transaction ID age (wraparound risk)", Op: Above, Unit: UnitCount, Hysteresis: 0.02,
			Levels: []Level{lv(w, 750e6, 0), lv(c, 1.5e9, 0)},
		},
		{
			Metric: MetricPGMXIDAge, Description: "multixact ID age (wraparound risk)", Op: Above, Unit: UnitCount, Hysteresis: 0.02,
			Levels: []Level{lv(w, 750e6, 0), lv(c, 1.5e9, 0)},
		},
		{
			Metric: MetricPGCacheHitRatio, Description: "buffer cache hit ratio", Op: Below, Unit: UnitRatio, Hysteresis: 0.01,
			Levels: []Level{lv(w, 0.95, 15*m), lv(c, 0.90, 15*m)},
		},
		// SPEC 10.1 expresses this as "ratio > 20% and > 100k rows" (critical: 40%
		// and > 1M rows). The absolute part is a collector filter, not a rule
		// condition: only tables with at least 100000 dead tuples are reported at
		// all. The 1M-row condition for critical is NOT applied separately.
		{
			Metric: MetricPGTableDeadRatio, Description: "table dead tuple ratio", Op: Above, Unit: UnitRatio, Hysteresis: 0.05,
			Levels: []Level{lv(w, 0.20, 0), lv(c, 0.40, 0)},
		},
		{
			Metric: MetricPGAutovacuumAge, Description: "time since last vacuum of a large table", Op: Above, Unit: UnitSeconds, Hysteresis: 0.02,
			Levels: []Level{lv(w, 3*day, 0), lv(c, 14*day, 0)},
		},
		{
			Metric: MetricPGCheckpointReqRatio, Description: "requested (WAL-triggered) checkpoint ratio", Op: Above, Unit: UnitRatio, Hysteresis: 0.05,
			Levels: []Level{lv(w, 0.30, 0), lv(c, 0.60, 0)},
		},
	}
}
