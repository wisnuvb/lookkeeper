package rules

import (
	"time"

	"github.com/wisnuvb/lockkeeper/internal/model"
)

// Metric names emitted by the MySQL collector and used by default rules.
const (
	MetricMySQLUp                = "my.up"
	MetricMySQLConnectionsRatio  = "my.connections.used_ratio"
	MetricMySQLThreadsRunning    = "my.threads.running"
	MetricMySQLTrxOldest         = "my.trx.oldest_s"
	MetricMySQLReplIORunning     = "my.repl.io_running"
	MetricMySQLReplSQLRunning    = "my.repl.sql_running"
	MetricMySQLReplLag           = "my.repl.lag_s"
	MetricMySQLSlowQueriesRate   = "my.slow_queries.rate"
	MetricMySQLBufferPoolHit     = "my.innodb.buffer_pool_hit"
	MetricMySQLRowLockWaitsRate  = "my.innodb.row_lock_waits"
	MetricMySQLHistoryListLength = "my.innodb.history_list_length"
	MetricMySQLBinlogDiskBytes   = "my.binlog.disk_bytes"
)

// MySQLDefaults returns the built-in MySQL rules (SPEC section 10.2).
//
// Choices the SPEC leaves open:
//
//   - my.threads.running: the SPEC says 2x / 4x the CPU cores, but the collector
//     does not know the core count (and RDS hides it). The defaults are absolute
//     numbers that assume about 16 cores (32 / 64 running threads) and need
//     lowering on smaller machines through alerts.rules.
//   - my.slow_queries.rate, my.innodb.row_lock_waits and my.binlog.disk_bytes are
//     "configurable" in the SPEC. A rule must exist for an override to be accepted,
//     so each has a deliberately high placeholder that only catches extreme cases.
//     Tune them to the workload.
//   - my.trx.oldest_s mirrors the Postgres long-transaction thresholds. It is not
//     in the SPEC table. A nightly mysqldump --single-transaction legitimately
//     holds one transaction open for its whole run; raise the thresholds if you
//     take such dumps.
//   - my.repl.io_running / sql_running are not marked NeedsHistory: a replica
//     whose thread is stopped is wrong right now, and a one-shot check must say so.
//     The 1m duration only damps flapping in the daemon (the IO thread reports
//     "Connecting", which counts as not running, while it reconnects).
func MySQLDefaults() []Rule {
	w, c := model.SeverityWarning, model.SeverityCritical
	const m = time.Minute
	const giB = float64(1 << 30)
	lv := func(sev model.Severity, thr float64, f time.Duration) Level {
		return Level{Severity: sev, Threshold: thr, For: f}
	}
	return []Rule{
		{
			Metric: MetricMySQLUp, Description: "database reachability", Op: Below, Unit: UnitFlag,
			Levels: []Level{lv(c, 1, 2*m)},
		},
		{
			Metric: MetricMySQLConnectionsRatio, Description: "connection usage", Op: Above, Unit: UnitRatio, Hysteresis: 0.05,
			Levels: []Level{lv(w, 0.80, 5*m), lv(c, 0.95, 2*m)},
		},
		{
			Metric: MetricMySQLThreadsRunning, Description: "threads running (assumes about 16 cores)", Op: Above, Unit: UnitCount, Hysteresis: 0.05,
			Levels: []Level{lv(w, 32, 2*m), lv(c, 64, 2*m)},
		},
		{
			Metric: MetricMySQLTrxOldest, Description: "oldest InnoDB transaction", Op: Above, Unit: UnitSeconds, Hysteresis: 0.05,
			Levels: []Level{lv(w, 300, 0), lv(c, 1800, 0)},
		},
		{
			Metric: MetricMySQLReplIORunning, Description: "replica IO thread running", Op: Below, Unit: UnitFlag,
			Levels: []Level{lv(c, 1, m)},
		},
		{
			Metric: MetricMySQLReplSQLRunning, Description: "replica SQL thread running", Op: Below, Unit: UnitFlag,
			Levels: []Level{lv(c, 1, m)},
		},
		{
			Metric: MetricMySQLReplLag, Description: "replication lag (Seconds_Behind_Source)", Op: Above, Unit: UnitSeconds, Hysteresis: 0.05,
			Levels: []Level{lv(w, 60, 2*m), lv(c, 600, 2*m)},
		},
		{
			Metric: MetricMySQLSlowQueriesRate, Description: "slow queries per second", Op: Above, Unit: UnitCount, Hysteresis: 0.05,
			Levels: []Level{lv(w, 5, 5*m), lv(c, 20, 5*m)},
		},
		{
			Metric: MetricMySQLBufferPoolHit, Description: "InnoDB buffer pool hit ratio", Op: Below, Unit: UnitRatio, Hysteresis: 0.01,
			Levels: []Level{lv(w, 0.99, 15*m), lv(c, 0.95, 15*m)},
		},
		{
			Metric: MetricMySQLRowLockWaitsRate, Description: "InnoDB row lock waits per second", Op: Above, Unit: UnitCount, Hysteresis: 0.05,
			Levels: []Level{lv(w, 10, 5*m), lv(c, 100, 5*m)},
		},
		{
			Metric: MetricMySQLHistoryListLength, Description: "InnoDB history list length", Op: Above, Unit: UnitCount, Hysteresis: 0.05,
			Levels: []Level{lv(w, 100_000, 5*m), lv(c, 1_000_000, 5*m)},
		},
		{
			Metric: MetricMySQLBinlogDiskBytes, Description: "binary log disk usage", Op: Above, Unit: UnitBytes, Hysteresis: 0.05,
			Levels: []Level{lv(w, 50*giB, 0), lv(c, 200*giB, 0)},
		},
	}
}
