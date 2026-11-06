// Package collector defines how metrics are gathered from a database target.
package collector

import (
	"context"

	"github.com/wisnuvb/lockkeeper/internal/model"
)

// Collector gathers one batch of samples for one target.
type Collector interface {
	// Target is the configured name of the database being observed.
	Target() string
	// Collect returns the samples it could gather. complete is true only when
	// every query succeeded; the alert engine uses it to decide whether absent
	// series may be treated as gone. A failure to reach the database is reported
	// as data (an "up = 0" sample), not only as an error.
	Collect(ctx context.Context) (samples []model.Sample, complete bool, err error)
	// Close releases the underlying connection.
	Close() error
}
