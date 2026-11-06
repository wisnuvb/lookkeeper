package rules

import (
	"time"

	"github.com/wisnuvb/lockkeeper/internal/model"
)

// Metric names for RDS infrastructure data read from CloudWatch.
const (
	// MetricRDSFreeStorageRatio is free storage as a share of disk_total_gb. It is
	// only produced when disk_total_gb is configured next to the CloudWatch reader.
	MetricRDSFreeStorageRatio = "rds.free_storage_ratio"
	// MetricPGSlotRetainedWALFreeRatio is, per replication slot, retained WAL
	// divided by current free storage (SPEC 10.3). Derived when both inputs are
	// present in one collection.
	MetricPGSlotRetainedWALFreeRatio = "pg.slot.retained_wal_free_ratio"
)

// RDSDefaults returns rules for AWS RDS infrastructure metrics read from
// CloudWatch.
func RDSDefaults() []Rule {
	w, c := model.SeverityWarning, model.SeverityCritical
	const m = time.Minute
	return []Rule{
		{
			// A short "for" ignores a brief dip from temporary files; CloudWatch
			// publishes one datapoint a minute, so 2m and 5m are two and five points.
			Metric: MetricRDSFreeStorageRatio, Description: "RDS free storage", Op: Below, Unit: UnitRatio, Hysteresis: 0.05,
			Levels: []Level{lv(w, 0.20, 5*m), lv(c, 0.10, 2*m)},
		},
		{
			// The WAL guardrail of SPEC 10.3: no "for", because a slot that already
			// holds half of the remaining disk can fill it within minutes.
			Metric: MetricPGSlotRetainedWALFreeRatio, Description: "WAL retained by replication slot as a share of free storage", Op: Above, Unit: UnitRatio, Hysteresis: 0.05,
			Levels: []Level{lv(w, 0.25, 0), lv(c, 0.50, 0)},
		},
	}
}
