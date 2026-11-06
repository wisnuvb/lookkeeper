// Package model holds the small, serialisable types shared by collectors, the
// alert engine, notifiers and the store. It has no dependencies on other
// Lockkeeper packages, which keeps the seams between them clean.
package model

import (
	"sort"
	"strings"
	"time"
)

// Sample is one observed metric value for one target.
type Sample struct {
	Target string            `json:"target"`
	Metric string            `json:"metric"`
	Labels map[string]string `json:"labels,omitempty"`
	Value  float64           `json:"value"`
	At     time.Time         `json:"at"`
}

// SeriesKey identifies the series a sample belongs to (metric + sorted labels),
// independent of the target.
func (s Sample) SeriesKey() string { return SeriesKey(s.Metric, s.Labels) }

// SeriesKey builds a stable key from a metric name and labels.
func SeriesKey(metric string, labels map[string]string) string {
	if len(labels) == 0 {
		return metric
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(metric)
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(labels[k])
	}
	b.WriteByte('}')
	return b.String()
}

// Severity ranks how serious an alert is.
type Severity string

// Severities, from least to most serious.
const (
	SeverityOK       Severity = "ok"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Rank returns an integer for ordering (higher is more serious).
func (s Severity) Rank() int {
	switch s {
	case SeverityWarning:
		return 1
	case SeverityCritical:
		return 2
	default:
		return 0
	}
}

// Valid reports whether s is an alertable severity.
func (s Severity) Valid() bool { return s == SeverityWarning || s == SeverityCritical }

// EventState is the lifecycle step an Event reports.
type EventState string

// Event states.
const (
	// StateFiring: the alert became active, or its severity changed.
	StateFiring EventState = "firing"
	// StateReminder: the alert is still active and the repeat interval elapsed.
	StateReminder EventState = "reminder"
	// StateResolved: the alert is no longer active.
	StateResolved EventState = "resolved"
)

// Event is what the alert engine emits and notifiers deliver. It deliberately
// contains no query text or credentials: only identifiers, numbers and
// human-readable summaries.
type Event struct {
	Rule      string            `json:"rule"`
	Target    string            `json:"target"`
	Labels    map[string]string `json:"labels,omitempty"`
	State     EventState        `json:"state"`
	Severity  Severity          `json:"severity"`
	Value     float64           `json:"value"`
	Threshold float64           `json:"threshold"`
	Since     time.Time         `json:"since"`
	At        time.Time         `json:"at"`
	Summary   string            `json:"summary"`
}

// Key identifies the alert (not the event) for de-duplication.
func (e Event) Key() string { return e.Target + "|" + e.Rule + "|" + SeriesKey("", e.Labels) }
