// Package rules is Lockkeeper's alert engine. It is pure: it turns samples and
// the current time into events, performs no I/O, and holds only in-memory state
// that can be exported and restored (so a restart does not re-notify).
package rules

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/model"
)

// Op says which side of the threshold is a breach.
type Op int

const (
	// Above: value greater than the threshold is a breach.
	Above Op = iota
	// Below: value less than the threshold is a breach.
	Below
)

// Unit controls how values are rendered in summaries.
type Unit int

// Units.
const (
	UnitCount Unit = iota
	UnitRatio
	UnitBytes
	UnitSeconds
	UnitFlag // 1 = healthy/up, 0 = not
)

// Level is one severity step of a rule.
type Level struct {
	Severity  model.Severity
	Threshold float64
	// For is how long the breach must persist before the level fires.
	For time.Duration
}

// Rule evaluates one metric. The rule ID is the metric name.
type Rule struct {
	Metric      string
	Description string
	Op          Op
	Unit        Unit
	// Hysteresis is the relative margin by which a value must recover past a
	// threshold before the level clears (0.05 = 5%). Use 0 for flags.
	Hysteresis float64
	// NeedsHistory marks rules whose meaning is the duration itself (for example
	// "slot inactive for 10 minutes"). A one-shot snapshot cannot judge them, so
	// `check` skips them and only the monitor daemon evaluates them.
	NeedsHistory bool
	// Levels are ordered warning then critical; either may be absent.
	Levels []Level
}

func (r Rule) level(s model.Severity) (Level, bool) {
	for _, l := range r.Levels {
		if l.Severity == s {
			return l, true
		}
	}
	return Level{}, false
}

// Validate checks that thresholds are ordered sensibly.
func (r Rule) Validate() error {
	w, hasW := r.level(model.SeverityWarning)
	c, hasC := r.level(model.SeverityCritical)
	if !hasW && !hasC {
		return fmt.Errorf("rule %s: no thresholds defined", r.Metric)
	}
	if hasW && hasC {
		if r.Op == Above && w.Threshold > c.Threshold {
			return fmt.Errorf("rule %s: warning threshold %v must not exceed critical threshold %v", r.Metric, w.Threshold, c.Threshold)
		}
		if r.Op == Below && w.Threshold < c.Threshold {
			return fmt.Errorf("rule %s: warning threshold %v must not be below critical threshold %v", r.Metric, w.Threshold, c.Threshold)
		}
	}
	for _, l := range r.Levels {
		if l.For < 0 {
			return fmt.Errorf("rule %s: negative duration", r.Metric)
		}
		if math.IsNaN(l.Threshold) {
			return fmt.Errorf("rule %s: threshold is not a number", r.Metric)
		}
	}
	return nil
}

// Options tunes the engine.
type Options struct {
	// RepeatInterval re-sends a still-active alert. Zero disables reminders.
	RepeatInterval time.Duration
	// Cooldown delays re-firing of an alert that resolved recently (flap damping).
	Cooldown time.Duration
}

// Engine evaluates rules. It is safe for concurrent use.
type Engine struct {
	rules  map[string]Rule
	opts   Options
	mu     sync.Mutex
	series map[string]*seriesState
}

// New builds an engine. Rules are validated.
func New(rs []Rule, opts Options) (*Engine, error) {
	m := make(map[string]Rule, len(rs))
	for _, r := range rs {
		if err := r.Validate(); err != nil {
			return nil, err
		}
		if _, dup := m[r.Metric]; dup {
			return nil, fmt.Errorf("duplicate rule for metric %s", r.Metric)
		}
		m[r.Metric] = r
	}
	return &Engine{rules: m, opts: opts, series: map[string]*seriesState{}}, nil
}

type seriesState struct {
	Target string
	Metric string
	Labels map[string]string

	Pending      map[model.Severity]time.Time
	Active       model.Severity // empty when not firing
	Since        time.Time
	LastNotified time.Time
	ResolvedAt   time.Time
	LastValue    float64
	Threshold    float64
}

func stateKey(target, metric string, labels map[string]string) string {
	return target + "|" + model.SeriesKey(metric, labels)
}

// breached reports whether v is past threshold t, optionally relaxed by the
// hysteresis margin when the level is already active.
func (r Rule) breached(v, t float64, relaxed bool) bool {
	if relaxed && r.Hysteresis > 0 && t > 0 {
		if r.Op == Above {
			t *= 1 - r.Hysteresis
		} else {
			t *= 1 + r.Hysteresis
		}
	}
	if r.Op == Above {
		return v > t
	}
	return v < t
}

// Eval evaluates one target's samples at time now and returns the resulting
// events. complete must be true only if the collection for this target
// succeeded in full: then a series that has stopped being reported is treated as
// gone and its alert is resolved. When false (a partial or failed collection),
// absent series are left untouched, so an outage never silently clears alerts.
func (e *Engine) Eval(now time.Time, target string, samples []model.Sample, complete bool) []model.Event {
	e.mu.Lock()
	defer e.mu.Unlock()

	var events []model.Event
	seen := map[string]bool{}

	for _, s := range samples {
		rule, ok := e.rules[s.Metric]
		if !ok || s.Target != target {
			continue
		}
		key := stateKey(target, s.Metric, s.Labels)
		seen[key] = true
		st := e.series[key]
		if st == nil {
			st = &seriesState{Target: target, Metric: s.Metric, Labels: copyLabels(s.Labels), Pending: map[model.Severity]time.Time{}}
			e.series[key] = st
		}
		if ev, ok := e.step(now, rule, st, s.Value); ok {
			events = append(events, ev)
		}
	}

	if complete {
		for key, st := range e.series {
			if st.Target != target || seen[key] {
				continue
			}
			if st.Active != "" {
				events = append(events, e.resolve(now, e.rules[st.Metric], st, "no longer reported"))
			}
			delete(e.series, key)
		}
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].Key() < events[j].Key() })
	return events
}

func (e *Engine) step(now time.Time, r Rule, st *seriesState, v float64) (model.Event, bool) {
	st.LastValue = v

	// Update pending start times and find the highest eligible severity.
	var eligible model.Severity
	var eligibleLevel Level
	for _, l := range r.Levels {
		relaxed := st.Active != "" && st.Active.Rank() >= l.Severity.Rank()
		if r.breached(v, l.Threshold, relaxed) {
			if _, ok := st.Pending[l.Severity]; !ok {
				st.Pending[l.Severity] = now
			}
			if now.Sub(st.Pending[l.Severity]) >= l.For && l.Severity.Rank() > eligible.Rank() {
				eligible, eligibleLevel = l.Severity, l
			}
		} else {
			delete(st.Pending, l.Severity)
		}
	}

	switch {
	case st.Active == "" && eligible != "":
		if e.opts.Cooldown > 0 && !st.ResolvedAt.IsZero() && now.Sub(st.ResolvedAt) < e.opts.Cooldown {
			return model.Event{}, false // flap damping: stay pending until the cooldown ends
		}
		st.Active, st.Since, st.LastNotified, st.Threshold = eligible, now, now, eligibleLevel.Threshold
		return e.event(now, r, st, model.StateFiring, ""), true

	case st.Active != "" && eligible == "":
		return e.resolve(now, r, st, ""), true

	case st.Active != "" && eligible != st.Active:
		st.Active, st.LastNotified, st.Threshold = eligible, now, eligibleLevel.Threshold
		return e.event(now, r, st, model.StateFiring, "severity changed"), true

	case st.Active != "" && e.opts.RepeatInterval > 0 && now.Sub(st.LastNotified) >= e.opts.RepeatInterval:
		st.LastNotified = now
		return e.event(now, r, st, model.StateReminder, "still active"), true
	}
	return model.Event{}, false
}

func (e *Engine) resolve(now time.Time, r Rule, st *seriesState, note string) model.Event {
	ev := e.event(now, r, st, model.StateResolved, note)
	st.Active, st.ResolvedAt = "", now
	st.Pending = map[model.Severity]time.Time{}
	return ev
}

func (e *Engine) event(now time.Time, r Rule, st *seriesState, state model.EventState, note string) model.Event {
	ev := model.Event{
		Rule: r.Metric, Target: st.Target, Labels: copyLabels(st.Labels), State: state,
		Severity: st.Active, // for a resolve this is the severity that just cleared (state is reset afterwards)
		Value:    st.LastValue, Threshold: st.Threshold, Since: st.Since, At: now,
	}
	ev.Summary = summarize(r, ev, note)
	return ev
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

// Active returns the currently firing alerts, most serious first.
func (e *Engine) Active() []model.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []model.Event
	for _, st := range e.series {
		if st.Active == "" {
			continue
		}
		r := e.rules[st.Metric]
		out = append(out, e.event(st.Since, r, st, model.StateFiring, ""))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity.Rank() != out[j].Severity.Rank() {
			return out[i].Severity.Rank() > out[j].Severity.Rank()
		}
		return out[i].Key() < out[j].Key()
	})
	return out
}

// Snapshot is the persistable state of one series.
type Snapshot struct {
	Target       string                       `json:"target"`
	Metric       string                       `json:"metric"`
	Labels       map[string]string            `json:"labels,omitempty"`
	Pending      map[model.Severity]time.Time `json:"pending,omitempty"`
	Active       model.Severity               `json:"active,omitempty"`
	Since        time.Time                    `json:"since"`
	LastNotified time.Time                    `json:"last_notified"`
	ResolvedAt   time.Time                    `json:"resolved_at"`
	LastValue    float64                      `json:"last_value"`
	Threshold    float64                      `json:"threshold"`
}

// Export returns the engine state for persistence.
func (e *Engine) Export() []Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Snapshot, 0, len(e.series))
	for _, st := range e.series {
		p := make(map[model.Severity]time.Time, len(st.Pending))
		for k, v := range st.Pending {
			p[k] = v
		}
		out = append(out, Snapshot{
			Target: st.Target, Metric: st.Metric, Labels: copyLabels(st.Labels), Pending: p,
			Active: st.Active, Since: st.Since, LastNotified: st.LastNotified, ResolvedAt: st.ResolvedAt,
			LastValue: st.LastValue, Threshold: st.Threshold,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return stateKey(out[i].Target, out[i].Metric, out[i].Labels) < stateKey(out[j].Target, out[j].Metric, out[j].Labels)
	})
	return out
}

// Import restores previously exported state. Snapshots for unknown metrics are ignored.
func (e *Engine) Import(snaps []Snapshot) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range snaps {
		if _, ok := e.rules[s.Metric]; !ok {
			continue
		}
		p := s.Pending
		if p == nil {
			p = map[model.Severity]time.Time{}
		}
		e.series[stateKey(s.Target, s.Metric, s.Labels)] = &seriesState{
			Target: s.Target, Metric: s.Metric, Labels: copyLabels(s.Labels), Pending: p,
			Active: s.Active, Since: s.Since, LastNotified: s.LastNotified, ResolvedAt: s.ResolvedAt,
			LastValue: s.LastValue, Threshold: s.Threshold,
		}
	}
}

// Rules returns the rules in a stable order.
func (e *Engine) Rules() []Rule {
	out := make([]Rule, 0, len(e.rules))
	for _, r := range e.rules {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Metric < out[j].Metric })
	return out
}

// Override adjusts a default rule from configuration. Nil fields keep defaults.
type Override = config.RuleOverride

// ApplyOverrides merges overrides into rules and validates the result. Unknown
// metric names are errors, so a typo cannot silently disable an alert.
func ApplyOverrides(base []Rule, overrides map[string]Override) ([]Rule, error) {
	out := make([]Rule, len(base))
	idx := map[string]int{}
	for i, r := range base {
		out[i] = r
		out[i].Levels = append([]Level(nil), r.Levels...)
		idx[r.Metric] = i
	}
	names := make([]string, 0, len(overrides))
	for n := range overrides {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		i, ok := idx[name]
		if !ok {
			return nil, fmt.Errorf("alerts.rules.%s: unknown rule (known rules: %v)", name, knownNames(base))
		}
		ov := overrides[name]
		r := &out[i]
		apply := func(sev model.Severity, thr *config.Threshold, forD *config.Duration) {
			if thr == nil && forD == nil {
				return
			}
			for j := range r.Levels {
				if r.Levels[j].Severity == sev {
					if thr != nil {
						r.Levels[j].Threshold = thr.F()
					}
					if forD != nil {
						r.Levels[j].For = forD.D()
					}
					return
				}
			}
			l := Level{Severity: sev}
			if thr != nil {
				l.Threshold = thr.F()
			}
			if forD != nil {
				l.For = forD.D()
			}
			r.Levels = append(r.Levels, l)
		}
		apply(model.SeverityWarning, ov.Warning, ov.ForWarning)
		apply(model.SeverityCritical, ov.Critical, ov.ForCritical)
		sort.Slice(r.Levels, func(a, b int) bool { return r.Levels[a].Severity.Rank() < r.Levels[b].Severity.Rank() })
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("alerts.rules.%s: %w", name, err)
		}
	}
	return out, nil
}

func knownNames(rs []Rule) []string {
	n := make([]string, len(rs))
	for i, r := range rs {
		n[i] = r.Metric
	}
	sort.Strings(n)
	return n
}
