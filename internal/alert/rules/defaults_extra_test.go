package rules

import (
	"testing"

	"github.com/wisnuvb/lockkeeper/internal/model"
)

func TestExtraPostgresDefaultsMatchSpec(t *testing.T) {
	want := map[string][2]float64{
		MetricPGTableDeadRatio:     {0.20, 0.40},
		MetricPGAutovacuumAge:      {3 * 86400, 14 * 86400},
		MetricPGCheckpointReqRatio: {0.30, 0.60},
	}
	got := map[string]Rule{}
	for _, r := range PostgresDefaults() {
		got[r.Metric] = r
	}
	for metric, thr := range want {
		r, ok := got[metric]
		if !ok {
			t.Errorf("no default rule for %s", metric)
			continue
		}
		if r.Op != Above || r.NeedsHistory {
			t.Errorf("%s: want an Above rule that does not need history", metric)
		}
		w, _ := r.level(model.SeverityWarning)
		c, _ := r.level(model.SeverityCritical)
		if w.Threshold != thr[0] || c.Threshold != thr[1] {
			t.Errorf("%s: thresholds = %v/%v, want %v/%v", metric, w.Threshold, c.Threshold, thr[0], thr[1])
		}
	}
	// Informational metrics must stay without a default rule.
	for _, metric := range []string{
		MetricPGTempBytesRate, MetricPGDBSize, MetricPGAutovacuumNeverVacuumed,
		MetricPGStatementsTime, MetricPGStatementsCalls, MetricPGStatementsRows,
	} {
		if _, ok := got[metric]; ok {
			t.Errorf("%s is informational and must have no default rule", metric)
		}
	}
}
