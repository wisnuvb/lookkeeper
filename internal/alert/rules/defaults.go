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
)

func lv(sev model.Severity, thr float64, f time.Duration) Level {
	return Level{Severity: sev, Threshold: thr, For: f}
}

// Defaults returns the built-in rules (SPEC section 10.1). Thresholds are
// conservative starting points and can be overridden in configuration.
func Defaults() []Rule {
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
			Metric: MetricPGSlotActive, Description: "replication slot consumer", Op: Below, Unit: UnitFlag,
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
	}
}
