package prom

import (
	"math"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/model"
)

var at0 = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func smp(target, metric string, v float64, labels map[string]string) model.Sample {
	return model.Sample{Target: target, Metric: metric, Labels: labels, Value: v, At: at0}
}

// A strict-enough validator for the 0.0.4 text format: every line is a comment
// or `name{label="value",...} number`, with only \\, \" and \n escapes in values.
var (
	lineRe = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*` +
		`(\{[a-zA-Z_][a-zA-Z0-9_]*="(\\[\\"n]|[^"\\\n])*"(,[a-zA-Z_][a-zA-Z0-9_]*="(\\[\\"n]|[^"\\\n])*")*\})?` +
		` (NaN|[+-]Inf|-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?)$`)
	helpRe = regexp.MustCompile(`^# HELP [a-zA-Z_:][a-zA-Z0-9_:]* (\\[\\n]|[^\\\n])*$`)
	typeRe = regexp.MustCompile(`^# TYPE [a-zA-Z_:][a-zA-Z0-9_:]* gauge$`)
)

func requireValidExposition(t *testing.T, out string) {
	t.Helper()
	if out == "" {
		return
	}
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("output must end with a newline: %q", out)
	}
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "# HELP "):
			if !helpRe.MatchString(line) {
				t.Errorf("invalid HELP line: %q", line)
			}
		case strings.HasPrefix(line, "# TYPE "):
			if !typeRe.MatchString(line) {
				t.Errorf("invalid TYPE line: %q", line)
			}
		default:
			if !lineRe.MatchString(line) {
				t.Errorf("invalid sample line: %q", line)
			}
		}
	}
}

func TestRenderGolden(t *testing.T) {
	r := NewRegistry()
	r.UpdateTarget("rds-main", []model.Sample{
		smp("rds-main", "pg.up", 1, nil),
		smp("rds-main", "pg.connections.used_ratio", 0.25, nil),
		smp("rds-main", "pg.slot.retained_wal_bytes", 1.5e9, map[string]string{"slot": "s2", "type": "logical"}),
		smp("rds-main", "pg.slot.retained_wal_bytes", 0, map[string]string{"slot": "s1", "type": "physical"}),
	}, true, at0)
	r.UpdateTarget("ovh", []model.Sample{smp("ovh", "pg.up", 0, nil)}, false, at0)
	r.SetAlerts([]model.Event{{
		Rule: "pg.connections.used_ratio", Target: "rds-main", Severity: model.SeverityWarning,
		State: model.StateFiring, Labels: map[string]string{"database": "app"},
	}})

	want := `# HELP lockkeeper_alert_active 1 for each alert that is currently firing.
# TYPE lockkeeper_alert_active gauge
lockkeeper_alert_active{database="app",rule="pg.connections.used_ratio",severity="warning",target="rds-main"} 1
# HELP lockkeeper_collection_last_success_timestamp_seconds Unix time of the last collection that completed without error, per target.
# TYPE lockkeeper_collection_last_success_timestamp_seconds gauge
lockkeeper_collection_last_success_timestamp_seconds{target="rds-main"} 1.7939664e+09
# HELP lockkeeper_pg_connections_used_ratio Latest value of the Lockkeeper metric "pg.connections.used_ratio".
# TYPE lockkeeper_pg_connections_used_ratio gauge
lockkeeper_pg_connections_used_ratio{target="rds-main"} 0.25
# HELP lockkeeper_pg_slot_retained_wal_bytes Latest value of the Lockkeeper metric "pg.slot.retained_wal_bytes".
# TYPE lockkeeper_pg_slot_retained_wal_bytes gauge
lockkeeper_pg_slot_retained_wal_bytes{slot="s1",target="rds-main",type="physical"} 0
lockkeeper_pg_slot_retained_wal_bytes{slot="s2",target="rds-main",type="logical"} 1.5e+09
# HELP lockkeeper_pg_up Latest value of the Lockkeeper metric "pg.up".
# TYPE lockkeeper_pg_up gauge
lockkeeper_pg_up{target="ovh"} 0
lockkeeper_pg_up{target="rds-main"} 1
`
	got := string(r.Render())
	if got != want {
		t.Fatalf("unexpected output.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	requireValidExposition(t, got)
}

func TestLabelValueEscaping(t *testing.T) {
	r := NewRegistry()
	r.UpdateTarget("t", []model.Sample{
		smp("t", "pg.table.dead_tuple_ratio", 0.5, map[string]string{
			"table":  `we"ird\name` + "\nline2",
			"schema": `back\slash`,
			"extra":  "quote\"",
			"utf":    "café 中",
			"bad":    "x\xffy",
			"empty":  "",
		}),
	}, true, at0)
	out := string(r.Render())
	requireValidExposition(t, out)
	for _, want := range []string{
		`table="we\"ird\\name\nline2"`,
		`schema="back\\slash"`,
		`extra="quote\""`,
		"utf=\"café 中\"",
		"bad=\"x�y\"",
		`empty=""`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in:\n%s", want, out)
		}
	}
	// The label value must never break the line: the sample is exactly one line.
	if n := strings.Count(out, "lockkeeper_pg_table_dead_tuple_ratio{"); n != 1 {
		t.Errorf("sample lines = %d", n)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "line2") {
			t.Errorf("an unescaped newline split the line: %q", line)
		}
	}
}

func TestHelpEscaping(t *testing.T) {
	r := NewRegistry()
	// The metric id ends up in HELP text; it must not be able to inject a line.
	r.UpdateTarget("t", []model.Sample{smp("t", "evil\nlockkeeper_injected 1\\", 1, nil)}, true, at0)
	out := string(r.Render())
	requireValidExposition(t, out)
	if strings.Contains(out, "\nlockkeeper_injected") {
		t.Errorf("HELP injection: %s", out)
	}
	if !strings.Contains(out, "lockkeeper_evil_lockkeeper_injected_1_{target=\"t\"} 1") {
		t.Errorf("sanitised name missing: %s", out)
	}
}

func TestMetricAndLabelNameSanitising(t *testing.T) {
	for in, want := range map[string]string{
		"pg.up":                        "lockkeeper_pg_up",
		"pg.connections.used_ratio":    "lockkeeper_pg_connections_used_ratio",
		"my-sql metric:x":              "lockkeeper_my_sql_metric_x",
		"café":                         "lockkeeper_caf_",
		"":                             "lockkeeper_",
		"already_ok_123":               "lockkeeper_already_ok_123",
		"pg.autovacuum.last_age_s":     "lockkeeper_pg_autovacuum_last_age_s",
		"pg.statements.total_exec_s":   "lockkeeper_pg_statements_total_exec_s",
		"weird\"name{label=\"x\"}\\\n": "lockkeeper_weird_name_label__x____",
	} {
		if got := MetricName(in); got != want {
			t.Errorf("MetricName(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"table": "table", "my-label": "my_label", "9lives": "_9lives",
		"__reserved": "_reserved", "": "_", "a.b": "a_b",
	} {
		if got := labelName(in); got != want {
			t.Errorf("labelName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReservedLabelsAreRenamedNotOverwritten(t *testing.T) {
	r := NewRegistry()
	r.UpdateTarget("real", []model.Sample{
		smp("real", "m", 1, map[string]string{"target": "spoofed", "ok": "v"}),
	}, true, at0)
	r.SetAlerts([]model.Event{{
		Rule: "m", Target: "real", Severity: model.SeverityCritical,
		Labels: map[string]string{"rule": "x", "severity": "info", "target": "y"},
	}})
	out := string(r.Render())
	requireValidExposition(t, out)
	if !strings.Contains(out, `lockkeeper_m{exported_target="spoofed",ok="v",target="real"} 1`) {
		t.Errorf("sample label collision: %s", out)
	}
	want := `lockkeeper_alert_active{exported_rule="x",exported_severity="info",exported_target="y",rule="m",severity="critical",target="real"} 1`
	if !strings.Contains(out, want) {
		t.Errorf("alert label collision: %s", out)
	}
}

func TestSamplesCannotShadowLockkeeperSeries(t *testing.T) {
	r := NewRegistry()
	r.UpdateTarget("t", []model.Sample{
		smp("t", "alert.active", 7, nil),
		smp("t", "collection.last_success_timestamp_seconds", 7, nil),
		smp("t", "pg.up", 1, nil),
	}, true, at0)
	out := string(r.Render())
	requireValidExposition(t, out)
	if strings.Contains(out, "lockkeeper_alert_active") {
		t.Errorf("a collector metric shadowed the alert series: %s", out)
	}
	if strings.Count(out, "lockkeeper_collection_last_success_timestamp_seconds{") != 1 {
		t.Errorf("last-success series must come only from the registry: %s", out)
	}
}

func TestCollidingSanitisedNamesProduceNoDuplicateLines(t *testing.T) {
	r := NewRegistry()
	r.UpdateTarget("t", []model.Sample{
		smp("t", "a.b", 1, nil),
		smp("t", "a_b", 2, nil), // sanitises to the same exposition name
	}, true, at0)
	out := string(r.Render())
	requireValidExposition(t, out)
	if n := strings.Count(out, "lockkeeper_a_b{"); n != 1 {
		t.Errorf("duplicate series lines (%d): %s", n, out)
	}
	if !strings.Contains(out, "lockkeeper_a_b{target=\"t\"} 1\n") {
		t.Errorf("the winner must be deterministic (series key order): %s", out)
	}
}

func TestVanishedSeriesIsNotEmitted(t *testing.T) {
	r := NewRegistry()
	slotA := map[string]string{"slot": "a", "type": "logical"}
	slotB := map[string]string{"slot": "b", "type": "logical"}
	r.UpdateTarget("t", []model.Sample{
		smp("t", "pg.up", 1, nil),
		smp("t", "pg.slot.retained_wal_bytes", 10, slotA),
		smp("t", "pg.slot.retained_wal_bytes", 20, slotB),
	}, true, at0)
	r.SetAlerts([]model.Event{{Rule: "pg.slot.retained_wal_bytes", Target: "t", Severity: model.SeverityWarning, Labels: slotB}})
	out := string(r.Render())
	if !strings.Contains(out, `slot="a"`) || !strings.Contains(out, `slot="b"`) {
		t.Fatalf("both slots expected first: %s", out)
	}

	// Slot b is dropped; the alert for it resolved. Neither may appear any more.
	r.UpdateTarget("t", []model.Sample{
		smp("t", "pg.up", 1, nil),
		smp("t", "pg.slot.retained_wal_bytes", 11, slotA),
	}, true, at0.Add(time.Minute))
	r.SetAlerts(nil)
	out = string(r.Render())
	requireValidExposition(t, out)
	if strings.Contains(out, `slot="b"`) {
		t.Errorf("a vanished series is still exported:\n%s", out)
	}
	if strings.Contains(out, "lockkeeper_alert_active") {
		t.Errorf("a resolved alert is still exported:\n%s", out)
	}
	if !strings.Contains(out, `lockkeeper_pg_slot_retained_wal_bytes{slot="a",target="t",type="logical"} 11`) {
		t.Errorf("the remaining series must carry its latest value:\n%s", out)
	}

	// An outage collection returns only pg.up = 0: everything else vanishes, and the
	// last-success timestamp stays at the last complete collection.
	r.UpdateTarget("t", []model.Sample{smp("t", "pg.up", 0, nil)}, false, at0.Add(2*time.Minute))
	out = string(r.Render())
	requireValidExposition(t, out)
	if strings.Contains(out, "retained_wal") {
		t.Errorf("series from before the outage must not be exported:\n%s", out)
	}
	if !strings.Contains(out, `lockkeeper_pg_up{target="t"} 0`) {
		t.Errorf("pg.up=0 must be exported during an outage:\n%s", out)
	}
	wantTS := formatValue(unixSeconds(at0.Add(time.Minute)))
	if !strings.Contains(out, "lockkeeper_collection_last_success_timestamp_seconds{target=\"t\"} "+wantTS+"\n") {
		t.Errorf("last success must stay at the last complete collection (%s):\n%s", wantTS, out)
	}
}

func TestNeverSucceededTargetHasNoLastSuccessSeries(t *testing.T) {
	r := NewRegistry()
	r.UpdateTarget("t", []model.Sample{smp("t", "pg.up", 0, nil)}, false, at0)
	if out := string(r.Render()); strings.Contains(out, "last_success") {
		t.Errorf("no success yet, so no timestamp (0 would claim 1970): %s", out)
	}
}

func TestOutputIsDeterministicRegardlessOfInputOrder(t *testing.T) {
	samples := []model.Sample{
		smp("t", "pg.slot.active", 1, map[string]string{"slot": "b", "type": "logical"}),
		smp("t", "pg.up", 1, nil),
		smp("t", "pg.slot.active", 0, map[string]string{"slot": "a", "type": "physical"}),
		smp("t", "pg.xid.age", 5, map[string]string{"database": "z"}),
		smp("t", "pg.xid.age", 6, map[string]string{"database": "a"}),
	}
	alerts := []model.Event{
		{Rule: "r1", Target: "t", Severity: model.SeverityWarning},
		{Rule: "r2", Target: "t", Severity: model.SeverityCritical},
	}
	render := func(s []model.Sample, a []model.Event) string {
		r := NewRegistry()
		r.UpdateTarget("t", s, true, at0)
		r.UpdateTarget("u", []model.Sample{smp("u", "pg.up", 1, nil)}, true, at0)
		r.SetAlerts(a)
		return string(r.Render())
	}
	base := render(samples, alerts)
	rev := make([]model.Sample, len(samples))
	for i, s := range samples {
		rev[len(samples)-1-i] = s
	}
	if got := render(rev, []model.Event{alerts[1], alerts[0]}); got != base {
		t.Errorf("output depends on input order:\n%s\nvs\n%s", got, base)
	}
	for i := 0; i < 20; i++ {
		if got := render(samples, alerts); got != base {
			t.Fatal("output is not stable between runs")
		}
	}
	requireValidExposition(t, base)
}

func TestSpecialFloatValues(t *testing.T) {
	r := NewRegistry()
	r.UpdateTarget("t", []model.Sample{
		smp("t", "nan", math.NaN(), nil),
		smp("t", "pinf", math.Inf(1), nil),
		smp("t", "ninf", math.Inf(-1), nil),
		smp("t", "big", 123456789012, nil),
		smp("t", "small", 0.000001234, nil),
		smp("t", "neg", -42.5, nil),
	}, true, at0)
	out := string(r.Render())
	requireValidExposition(t, out)
	for _, want := range []string{
		`lockkeeper_nan{target="t"} NaN`,
		`lockkeeper_pinf{target="t"} +Inf`,
		`lockkeeper_ninf{target="t"} -Inf`,
		`lockkeeper_big{target="t"} 1.23456789012e+11`,
		`lockkeeper_small{target="t"} 1.234e-06`,
		`lockkeeper_neg{target="t"} -42.5`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestEmptyAndNilRegistries(t *testing.T) {
	if out := NewRegistry().Render(); len(out) != 0 {
		t.Errorf("an empty registry must render nothing, got %q", out)
	}
	var r *Registry
	r.UpdateTarget("t", []model.Sample{smp("t", "pg.up", 1, nil)}, true, at0) // must not panic
	r.SetAlerts(nil)
	if out := r.Render(); len(out) != 0 {
		t.Errorf("a nil registry must render nothing, got %q", out)
	}
}

func TestRegistryDoesNotAliasCallerData(t *testing.T) {
	r := NewRegistry()
	labels := map[string]string{"slot": "a"}
	r.UpdateTarget("t", []model.Sample{smp("t", "pg.slot.active", 1, labels)}, true, at0)
	labels["slot"] = "mutated"
	ev := model.Event{Rule: "x", Target: "t", Severity: model.SeverityWarning, Labels: map[string]string{"k": "v"}}
	r.SetAlerts([]model.Event{ev})
	ev.Labels["k"] = "mutated"
	out := string(r.Render())
	if strings.Contains(out, "mutated") {
		t.Errorf("registry shares maps with its caller:\n%s", out)
	}
}

func TestRegistryIsConcurrencySafe(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			target := string(rune('a' + w))
			for i := 0; i < 200; i++ {
				r.UpdateTarget(target, []model.Sample{
					smp(target, "pg.up", 1, nil),
					smp(target, "pg.xid.age", float64(i), map[string]string{"database": "d"}),
				}, i%2 == 0, at0.Add(time.Duration(i)*time.Second))
				r.SetAlerts([]model.Event{{Rule: "r", Target: target, Severity: model.SeverityWarning}})
			}
		}(w)
	}
	for rd := 0; rd < 4; rd++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				requireValidExposition(t, string(r.Render()))
			}
		}()
	}
	wg.Wait()
}
