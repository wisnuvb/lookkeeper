package rules

import (
	"strings"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/model"
)

var t0 = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func at(min float64) time.Time { return t0.Add(time.Duration(min * float64(time.Minute))) }

func sample(target, metric string, v float64, labels map[string]string) model.Sample {
	return model.Sample{Target: target, Metric: metric, Labels: labels, Value: v}
}

func aboveRule(w, c float64, forW, forC time.Duration) Rule {
	return Rule{
		Metric: "m", Description: "thing", Op: Above, Unit: UnitCount, Hysteresis: 0.10,
		Levels: []Level{{model.SeverityWarning, w, forW}, {model.SeverityCritical, c, forC}},
	}
}

func newEngine(t *testing.T, r Rule, o Options) *Engine {
	t.Helper()
	e, err := New([]Rule{r}, o)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func eval(e *Engine, now time.Time, target string, v float64) []model.Event {
	return e.Eval(now, target, []model.Sample{sample(target, "m", v, nil)}, true)
}

func TestFiresOnlyAfterForDuration(t *testing.T) {
	e := newEngine(t, aboveRule(80, 95, 5*time.Minute, 0), Options{})
	if ev := eval(e, at(0), "db", 90); len(ev) != 0 {
		t.Fatalf("must not fire immediately: %v", ev)
	}
	if ev := eval(e, at(4), "db", 90); len(ev) != 0 {
		t.Fatalf("must not fire before 5m: %v", ev)
	}
	ev := eval(e, at(5), "db", 90)
	if len(ev) != 1 || ev[0].State != model.StateFiring || ev[0].Severity != model.SeverityWarning {
		t.Fatalf("expected a warning to fire at 5m, got %v", ev)
	}
	if ev := eval(e, at(6), "db", 90); len(ev) != 0 {
		t.Fatalf("must not re-fire while active: %v", ev)
	}
}

func TestBreachInterruptedResetsTimer(t *testing.T) {
	e := newEngine(t, aboveRule(80, 95, 5*time.Minute, 0), Options{})
	eval(e, at(0), "db", 90)
	eval(e, at(3), "db", 50) // recovers: timer must reset
	eval(e, at(4), "db", 90)
	if ev := eval(e, at(8), "db", 90); len(ev) != 0 {
		t.Fatalf("timer should have restarted at minute 4: %v", ev)
	}
	if ev := eval(e, at(9), "db", 90); len(ev) != 1 {
		t.Fatalf("expected firing at minute 9, got %v", ev)
	}
}

func TestEscalationAndDeescalation(t *testing.T) {
	e := newEngine(t, aboveRule(80, 95, 0, 0), Options{})
	if ev := eval(e, at(0), "db", 85); len(ev) != 1 || ev[0].Severity != model.SeverityWarning {
		t.Fatalf("warning expected: %v", ev)
	}
	ev := eval(e, at(1), "db", 99)
	if len(ev) != 1 || ev[0].Severity != model.SeverityCritical || ev[0].State != model.StateFiring {
		t.Fatalf("escalation to critical expected: %v", ev)
	}
	// 80 is below critical*0.9=85.5 so critical clears, but still above warning's relaxed bound.
	ev = eval(e, at(2), "db", 82)
	if len(ev) != 1 || ev[0].Severity != model.SeverityWarning || !strings.Contains(ev[0].Summary, "severity changed") {
		t.Fatalf("de-escalation to warning expected: %v", ev)
	}
}

func TestHysteresisPreventsFlapping(t *testing.T) {
	e := newEngine(t, aboveRule(100, 1000, 0, 0), Options{})
	if ev := eval(e, at(0), "db", 101); len(ev) != 1 {
		t.Fatalf("expected fire: %v", ev)
	}
	// Values hovering just under the threshold stay "active" thanks to the 10% margin.
	for i, v := range []float64{99, 100.5, 95, 92} {
		if ev := eval(e, at(float64(i+1)), "db", v); len(ev) != 0 {
			t.Fatalf("v=%v must not resolve or re-fire: %v", v, ev)
		}
	}
	ev := eval(e, at(10), "db", 85) // below 100*0.9 = 90: recovered
	if len(ev) != 1 || ev[0].State != model.StateResolved {
		t.Fatalf("expected resolve: %v", ev)
	}
	if ev[0].Severity != model.SeverityWarning {
		t.Errorf("resolved event should carry the severity that cleared, got %q", ev[0].Severity)
	}
}

func TestCooldownDampsRefire(t *testing.T) {
	e := newEngine(t, aboveRule(100, 1000, 0, 0), Options{Cooldown: 5 * time.Minute})
	eval(e, at(0), "db", 150)
	if ev := eval(e, at(1), "db", 10); len(ev) != 1 || ev[0].State != model.StateResolved {
		t.Fatalf("resolve expected: %v", ev)
	}
	if ev := eval(e, at(2), "db", 150); len(ev) != 0 {
		t.Fatalf("re-fire inside cooldown must be suppressed: %v", ev)
	}
	ev := eval(e, at(6.5), "db", 150) // cooldown over and still breaching
	if len(ev) != 1 || ev[0].State != model.StateFiring {
		t.Fatalf("expected fire after cooldown: %v", ev)
	}
}

func TestReminderAfterRepeatInterval(t *testing.T) {
	e := newEngine(t, aboveRule(100, 1000, 0, 0), Options{RepeatInterval: time.Hour})
	eval(e, at(0), "db", 150)
	if ev := eval(e, at(59), "db", 150); len(ev) != 0 {
		t.Fatalf("too early for a reminder: %v", ev)
	}
	ev := eval(e, at(60), "db", 150)
	if len(ev) != 1 || ev[0].State != model.StateReminder {
		t.Fatalf("reminder expected: %v", ev)
	}
	if ev := eval(e, at(61), "db", 150); len(ev) != 0 {
		t.Fatalf("reminder must not repeat immediately: %v", ev)
	}
}

func TestBelowOperator(t *testing.T) {
	r := Rule{
		Metric: "m", Description: "hit ratio", Op: Below, Unit: UnitRatio, Hysteresis: 0.01,
		Levels: []Level{{model.SeverityWarning, 0.95, 0}, {model.SeverityCritical, 0.90, 0}},
	}
	e := newEngine(t, r, Options{})
	if ev := eval(e, at(0), "db", 0.97); len(ev) != 0 {
		t.Fatalf("healthy: %v", ev)
	}
	if ev := eval(e, at(1), "db", 0.93); len(ev) != 1 || ev[0].Severity != model.SeverityWarning {
		t.Fatalf("warning expected: %v", ev)
	}
	if ev := eval(e, at(2), "db", 0.85); len(ev) != 1 || ev[0].Severity != model.SeverityCritical {
		t.Fatalf("critical expected: %v", ev)
	}
}

func TestFlagRuleHasNoHysteresisSurprise(t *testing.T) {
	var up Rule
	for _, r := range Defaults() {
		if r.Metric == MetricPGUp {
			up = r
		}
	}
	e := newEngine(t, up, Options{})
	e.Eval(at(0), "db", []model.Sample{sample("db", MetricPGUp, 0, nil)}, true)
	if ev := e.Eval(at(1), "db", []model.Sample{sample("db", MetricPGUp, 0, nil)}, true); len(ev) != 0 {
		t.Fatalf("must wait the 2m for-duration: %v", ev)
	}
	if ev := e.Eval(at(2), "db", []model.Sample{sample("db", MetricPGUp, 0, nil)}, true); len(ev) != 1 || ev[0].Severity != model.SeverityCritical {
		t.Fatalf("critical expected after 2m down: %v", ev)
	}
	ev := e.Eval(at(3), "db", []model.Sample{sample("db", MetricPGUp, 1, nil)}, true)
	if len(ev) != 1 || ev[0].State != model.StateResolved {
		t.Fatalf("up=1 must resolve immediately (flag, no hysteresis): %v", ev)
	}
}

func TestSeriesAreIndependentPerLabelAndTarget(t *testing.T) {
	e := newEngine(t, aboveRule(100, 1000, 0, 0), Options{})
	batch := []model.Sample{
		sample("db1", "m", 150, map[string]string{"slot": "a"}),
		sample("db1", "m", 10, map[string]string{"slot": "b"}),
	}
	ev := e.Eval(at(0), "db1", batch, true)
	if len(ev) != 1 || ev[0].Labels["slot"] != "a" {
		t.Fatalf("only slot a should fire: %v", ev)
	}
	// Another target with the same metric is tracked separately.
	ev = e.Eval(at(0), "db2", []model.Sample{sample("db2", "m", 150, map[string]string{"slot": "a"})}, true)
	if len(ev) != 1 || ev[0].Target != "db2" {
		t.Fatalf("db2 must fire independently: %v", ev)
	}
	if got := len(e.Active()); got != 2 {
		t.Fatalf("Active() = %d, want 2", got)
	}
}

func TestVanishedSeriesResolvesOnlyWhenCollectionComplete(t *testing.T) {
	e := newEngine(t, aboveRule(100, 1000, 0, 0), Options{})
	labels := map[string]string{"slot": "a"}
	e.Eval(at(0), "db", []model.Sample{sample("db", "m", 150, labels)}, true)

	// Partial / failed collection: the series is missing, but the alert must stay.
	if ev := e.Eval(at(1), "db", nil, false); len(ev) != 0 {
		t.Fatalf("incomplete collection must not resolve alerts: %v", ev)
	}
	if len(e.Active()) != 1 {
		t.Fatal("alert must remain active after an incomplete collection")
	}
	// Complete collection without the series (for example the slot was dropped): resolve.
	ev := e.Eval(at(2), "db", nil, true)
	if len(ev) != 1 || ev[0].State != model.StateResolved || !strings.Contains(ev[0].Summary, "no longer reported") {
		t.Fatalf("vanished series must resolve on a complete collection: %v", ev)
	}
	if len(e.Export()) != 0 {
		t.Error("state for a vanished series must be dropped")
	}
}

func TestIgnoresSamplesForOtherTargetsAndUnknownMetrics(t *testing.T) {
	e := newEngine(t, aboveRule(100, 1000, 0, 0), Options{})
	ev := e.Eval(at(0), "db", []model.Sample{
		sample("other", "m", 999, nil),
		sample("db", "unknown.metric", 999, nil),
	}, true)
	if len(ev) != 0 {
		t.Fatalf("unexpected events: %v", ev)
	}
}

func TestExportImportDoesNotRenotify(t *testing.T) {
	r := aboveRule(100, 1000, 0, 0)
	e1 := newEngine(t, r, Options{RepeatInterval: time.Hour})
	eval(e1, at(0), "db", 150)

	e2 := newEngine(t, r, Options{RepeatInterval: time.Hour})
	e2.Import(e1.Export())
	if ev := eval(e2, at(5), "db", 150); len(ev) != 0 {
		t.Fatalf("a restarted engine must not re-fire an active alert: %v", ev)
	}
	if ev := eval(e2, at(61), "db", 150); len(ev) != 1 || ev[0].State != model.StateReminder {
		t.Fatalf("reminder schedule must survive a restart: %v", ev)
	}
	if ev := eval(e2, at(62), "db", 10); len(ev) != 1 || ev[0].State != model.StateResolved {
		t.Fatalf("restored alert must be resolvable: %v", ev)
	}
}

func TestRuleValidation(t *testing.T) {
	if _, err := New([]Rule{aboveRule(200, 100, 0, 0)}, Options{}); err == nil {
		t.Error("warning above critical must be rejected for Above rules")
	}
	bad := Rule{Metric: "m", Op: Below, Levels: []Level{{model.SeverityWarning, 0.5, 0}, {model.SeverityCritical, 0.9, 0}}}
	if _, err := New([]Rule{bad}, Options{}); err == nil {
		t.Error("warning below critical must be rejected for Below rules")
	}
	if _, err := New([]Rule{{Metric: "m"}}, Options{}); err == nil {
		t.Error("a rule without levels must be rejected")
	}
	if _, err := New([]Rule{aboveRule(1, 2, 0, 0), aboveRule(1, 2, 0, 0)}, Options{}); err == nil {
		t.Error("duplicate metric must be rejected")
	}
}

func TestDefaultsAreValid(t *testing.T) {
	if _, err := New(Defaults(), Options{}); err != nil {
		t.Fatalf("default rules must be valid: %v", err)
	}
}

func TestApplyOverrides(t *testing.T) {
	thr := func(v float64) *config.Threshold { t := config.Threshold(v); return &t }
	dur := func(d time.Duration) *config.Duration { x := config.Duration(d); return &x }

	rs, err := ApplyOverrides(Defaults(), map[string]Override{
		MetricPGSlotRetainedWAL: {Warning: thr(1 << 30), ForWarning: dur(time.Minute)},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got Rule
	for _, r := range rs {
		if r.Metric == MetricPGSlotRetainedWAL {
			got = r
		}
	}
	w, _ := got.level(model.SeverityWarning)
	c, _ := got.level(model.SeverityCritical)
	if w.Threshold != 1<<30 || w.For != time.Minute {
		t.Errorf("warning override not applied: %+v", w)
	}
	if c.Threshold != 20*gib {
		t.Errorf("critical must keep its default: %+v", c)
	}

	// Defaults must not be mutated by an override.
	for _, r := range Defaults() {
		if r.Metric == MetricPGSlotRetainedWAL {
			if l, _ := r.level(model.SeverityWarning); l.Threshold != 5*gib {
				t.Error("ApplyOverrides mutated the shared defaults")
			}
		}
	}

	if _, err := ApplyOverrides(Defaults(), map[string]Override{"pg.typo": {Warning: thr(1)}}); err == nil || !strings.Contains(err.Error(), "unknown rule") {
		t.Errorf("typo in a rule name must be an error, got %v", err)
	}
	if _, err := ApplyOverrides(Defaults(), map[string]Override{MetricPGSlotRetainedWAL: {Warning: thr(100 * gib)}}); err == nil {
		t.Error("an override that inverts warning/critical must be rejected")
	}
}

func TestSummaryAndFormatting(t *testing.T) {
	cases := []struct {
		u    Unit
		v    float64
		want string
	}{
		{UnitRatio, 0.832, "83.2%"}, {UnitBytes, 5 * gib, "5.0 GiB"}, {UnitBytes, 512, "512 B"},
		{UnitSeconds, 302, "5m2s"}, {UnitSeconds, 0.25, "250 ms"}, {UnitFlag, 0, "down"}, {UnitFlag, 1, "up"},
		{UnitCount, 750e6, "750000000"}, {UnitCount, 1.5, "1.50"},
	}
	for _, c := range cases {
		if got := FormatValue(c.u, c.v); got != c.want {
			t.Errorf("FormatValue(%v,%v) = %q, want %q", c.u, c.v, got, c.want)
		}
	}
	e := newEngine(t, Rule{
		Metric: "m", Description: "WAL retained by slot", Op: Above, Unit: UnitBytes,
		Levels: []Level{{model.SeverityWarning, 5 * gib, 0}},
	}, Options{})
	ev := e.Eval(at(0), "rds-main", []model.Sample{sample("rds-main", "m", 7*gib, map[string]string{"slot": "lk_x"})}, true)
	want := "WAL retained by slot on rds-main [slot=lk_x]: 7.0 GiB (> 5.0 GiB)"
	if len(ev) != 1 || ev[0].Summary != want {
		t.Fatalf("summary = %q, want %q", ev[0].Summary, want)
	}
}
