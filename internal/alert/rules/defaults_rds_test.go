package rules

import (
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/model"
)

func rdsSample(metric string, labels map[string]string, v float64, at time.Time) []model.Sample {
	return []model.Sample{{Target: "rds-main", Metric: metric, Labels: labels, Value: v, At: at}}
}

func TestRDSDefaultsAreValidAndDistinct(t *testing.T) {
	if _, err := New(Defaults(), Options{}); err != nil {
		t.Fatalf("defaults do not build an engine: %v", err)
	}
	got := map[string]bool{}
	for _, r := range RDSDefaults() {
		got[r.Metric] = true
	}
	for _, want := range []string{MetricRDSFreeStorageRatio, MetricPGSlotRetainedWALFreeRatio} {
		if !got[want] {
			t.Errorf("missing default rule %s", want)
		}
	}
}

func TestFreeStorageRatioThresholdsAndHysteresis(t *testing.T) {
	e, err := New(RDSDefaults(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	eval := func(v float64) []model.Event {
		return e.Eval(now, "rds-main", rdsSample(MetricRDSFreeStorageRatio, nil, v, now), true)
	}
	step := func(d time.Duration) { now = now.Add(d) }

	if ev := eval(0.25); len(ev) != 0 {
		t.Fatalf("healthy value fired: %v", ev)
	}
	// 19% free is below the warning threshold, but only fires after 5 minutes.
	if ev := eval(0.19); len(ev) != 0 {
		t.Fatalf("fired before its duration: %v", ev)
	}
	step(5 * time.Minute)
	ev := eval(0.19)
	if len(ev) != 1 || ev[0].Severity != model.SeverityWarning || ev[0].Threshold != 0.20 {
		t.Fatalf("expected a warning at 19%%: %+v", ev)
	}
	// Hovering just above the threshold must not flap: it clears only past 21%.
	step(time.Minute)
	if ev := eval(0.205); len(ev) != 0 {
		t.Fatalf("cleared inside the hysteresis band: %+v", ev)
	}
	// 9% is critical after two minutes.
	step(time.Minute)
	eval(0.09)
	step(2 * time.Minute)
	ev = eval(0.09)
	if len(ev) != 1 || ev[0].Severity != model.SeverityCritical || ev[0].Threshold != 0.10 {
		t.Fatalf("expected critical at 9%%: %+v", ev)
	}
	step(time.Minute)
	if ev := eval(0.30); len(ev) != 1 || ev[0].State != model.StateResolved {
		t.Fatalf("expected a resolve: %+v", ev)
	}
}

func TestRetainedWALShareOfFreeStorageGuardrail(t *testing.T) {
	e, err := New(RDSDefaults(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	slot := map[string]string{"slot": "lk_x"}
	eval := func(v float64) []model.Event {
		return e.Eval(now, "rds-main", rdsSample(MetricPGSlotRetainedWALFreeRatio, slot, v, now), true)
	}
	if ev := eval(0.10); len(ev) != 0 {
		t.Fatalf("fired at 10%%: %v", ev)
	}
	ev := eval(0.30)
	if len(ev) != 1 || ev[0].Severity != model.SeverityWarning || ev[0].Labels["slot"] != "lk_x" {
		t.Fatalf("expected an immediate warning above 25%%: %+v", ev)
	}
	if ev := eval(0.60); len(ev) != 1 || ev[0].Severity != model.SeverityCritical {
		t.Fatalf("expected critical above 50%%: %+v", ev)
	}
	// Back to 45%: warning, not resolved.
	if ev := eval(0.45); len(ev) != 1 || ev[0].Severity != model.SeverityWarning {
		t.Fatalf("expected a downgrade to warning: %+v", ev)
	}
	if ev := eval(0.24); len(ev) != 0 { // inside the 5% hysteresis band below 0.25
		t.Fatalf("cleared inside the hysteresis band: %+v", ev)
	}
	if ev := eval(0.20); len(ev) != 1 || ev[0].State != model.StateResolved {
		t.Fatalf("expected a resolve: %+v", ev)
	}
}
