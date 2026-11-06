// Package prom exposes Lockkeeper's latest samples in the Prometheus text
// exposition format (version 0.0.4), using only the standard library.
//
// The endpoint is optional and off by default. It has no authentication and its
// labels can contain table names, so the server listens on loopback unless the
// operator opts in (see Start). Query text never reaches this package: collectors
// do not produce it (threat T10).
package prom

import (
	"sync"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/model"
)

// Registry is the in-memory view of the latest collection per target. It is safe
// for concurrent use: monitor loops write, the HTTP handler reads. All methods
// are no-ops on a nil *Registry, so callers need no "is it enabled" checks.
type Registry struct {
	mu      sync.RWMutex
	targets map[string]*targetData
	alerts  []model.Event
}

type targetData struct {
	series      map[string]model.Sample // by series key
	lastSuccess time.Time               // zero until a complete collection
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{targets: map[string]*targetData{}}
}

// UpdateTarget replaces the exported series of target with samples. Only the
// latest value of each series is kept, and a series that is absent from samples
// disappears from the output: the endpoint reflects exactly what the last
// collection returned (Prometheus then marks the series stale), never a value
// remembered from an earlier tick.
//
// complete is the collector's "every query succeeded" flag; only a complete
// collection moves the last-success timestamp to at.
func (r *Registry) UpdateTarget(target string, samples []model.Sample, complete bool, at time.Time) {
	if r == nil {
		return
	}
	series := make(map[string]model.Sample, len(samples))
	for _, s := range samples {
		s.Labels = copyLabels(s.Labels)
		series[s.SeriesKey()] = s // a later duplicate wins
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	td := r.targets[target]
	if td == nil {
		td = &targetData{}
		r.targets[target] = td
	}
	td.series = series
	if complete {
		td.lastSuccess = at
	}
}

// SetAlerts replaces the set of currently firing alerts.
func (r *Registry) SetAlerts(active []model.Event) {
	if r == nil {
		return
	}
	cp := make([]model.Event, len(active))
	for i, e := range active {
		e.Labels = copyLabels(e.Labels)
		cp[i] = e
	}
	r.mu.Lock()
	r.alerts = cp
	r.mu.Unlock()
}

func copyLabels(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
