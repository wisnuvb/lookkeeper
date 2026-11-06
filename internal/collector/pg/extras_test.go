package pg

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/wisnuvb/lockkeeper/internal/model"
)

var base = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func snap(min float64, timed, req int64) ckptSnap {
	return ckptSnap{at: base.Add(time.Duration(min * float64(time.Minute))), timed: timed, req: req}
}

func approx(a, b float64) bool { return a > b-1e-9 && a < b+1e-9 }

func TestAdvanceCheckpoints(t *testing.T) {
	t.Run("first reading has no ratio", func(t *testing.T) {
		hist, _, ok := advanceCheckpoints(nil, snap(0, 10, 10))
		if ok || len(hist) != 1 {
			t.Fatalf("ok=%v hist=%d", ok, len(hist))
		}
	})
	t.Run("interval with enough checkpoints", func(t *testing.T) {
		hist := []ckptSnap{snap(0, 100, 50)}
		_, ratio, ok := advanceCheckpoints(hist, snap(1, 103, 54)) // 3 timed + 4 req
		if !ok || !approx(ratio, 4.0/7.0) {
			t.Fatalf("ratio=%v ok=%v", ratio, ok)
		}
	})
	t.Run("fewer than five checkpoints in total is not reported", func(t *testing.T) {
		hist := []ckptSnap{snap(0, 100, 50)}
		_, _, ok := advanceCheckpoints(hist, snap(1, 102, 52)) // 4
		if ok {
			t.Fatal("4 checkpoints must not produce a ratio")
		}
	})
	t.Run("window reaches back until five checkpoints are seen", func(t *testing.T) {
		var hist []ckptSnap
		var ok bool
		var ratio float64
		// One requested checkpoint per half minute: the ratio appears at the 5th.
		for i := 0; i <= 5; i++ {
			hist, ratio, ok = advanceCheckpoints(hist, snap(float64(i)/2, 100, int64(50+i)))
			if i < 5 && ok {
				t.Fatalf("reading %d: ratio before five checkpoints", i)
			}
		}
		if !ok || !approx(ratio, 1) {
			t.Fatalf("ratio=%v ok=%v", ratio, ok)
		}
		// It stays reported on the next reading (continuous series).
		_, ratio, ok = advanceCheckpoints(hist, snap(3, 100, 56))
		if !ok || !approx(ratio, 1) {
			t.Fatalf("series must stay continuous: ratio=%v ok=%v", ratio, ok)
		}
	})
	t.Run("recovers when timed checkpoints dominate again", func(t *testing.T) {
		hist := []ckptSnap{snap(0, 100, 50), snap(1, 100, 54)}
		_, ratio, ok := advanceCheckpoints(hist, snap(2, 106, 54)) // window from t=1: 6 timed, 0 req
		if !ok || !approx(ratio, 0) {
			t.Fatalf("ratio=%v ok=%v", ratio, ok)
		}
	})
	t.Run("counter going backwards is a reset", func(t *testing.T) {
		hist := []ckptSnap{snap(0, 1000, 500)}
		newHist, _, ok := advanceCheckpoints(hist, snap(1, 3, 1))
		if ok || len(newHist) != 1 || newHist[0].timed != 3 {
			t.Fatalf("reset must restart the history: ok=%v hist=%+v", ok, newHist)
		}
	})
	t.Run("changed stats_reset is a reset even if counters grew", func(t *testing.T) {
		prev := snap(0, 100, 50)
		prev.reset = base.Add(-time.Hour)
		cur := snap(1, 200, 150)
		cur.reset = base // statistics reset, then grew past the old value
		newHist, _, ok := advanceCheckpoints([]ckptSnap{prev}, cur)
		if ok || len(newHist) != 1 {
			t.Fatalf("ok=%v hist=%+v", ok, newHist)
		}
	})
	t.Run("history older than the lookback is dropped", func(t *testing.T) {
		hist := []ckptSnap{snap(0, 100, 50)}
		newHist, _, ok := advanceCheckpoints(hist, snap(90, 200, 150))
		if ok || len(newHist) != 1 {
			t.Fatalf("a 90-minute-old baseline must not be used: ok=%v hist=%d", ok, len(newHist))
		}
	})
}

func TestTempRate(t *testing.T) {
	reset := base.Add(-time.Hour)
	prev := tempCounters{at: base, bytes: 1000, reset: reset}
	cases := []struct {
		name string
		cur  tempCounters
		want float64
		ok   bool
	}{
		{"steady", tempCounters{at: base.Add(30 * time.Second), bytes: 31_000, reset: reset}, 1000, true},
		{"no temp files", tempCounters{at: base.Add(30 * time.Second), bytes: 1000, reset: reset}, 0, true},
		{"counter went backwards", tempCounters{at: base.Add(30 * time.Second), bytes: 10, reset: reset}, 0, false},
		{"stats_reset changed", tempCounters{at: base.Add(30 * time.Second), bytes: 99_000, reset: base}, 0, false},
		{"readings too close", tempCounters{at: base.Add(100 * time.Millisecond), bytes: 5000, reset: reset}, 0, false},
		{"clock went backwards", tempCounters{at: base.Add(-time.Minute), bytes: 5000, reset: reset}, 0, false},
	}
	for _, c := range cases {
		got, ok := tempRate(prev, c.cur)
		if ok != c.ok || (ok && !approx(got, c.want)) {
			t.Errorf("%s: got (%v,%v), want (%v,%v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestVersionDependentSQL(t *testing.T) {
	for _, v := range []int{120000, 140005, 160009} {
		if q := checkpointSQL(v); !strings.Contains(q, "pg_stat_bgwriter") || strings.Contains(q, "pg_stat_checkpointer") {
			t.Errorf("version %d must read pg_stat_bgwriter: %s", v, q)
		}
	}
	for _, v := range []int{170000, 170004, 180001} {
		if q := checkpointSQL(v); !strings.Contains(q, "pg_stat_checkpointer") || strings.Contains(q, "bgwriter") {
			t.Errorf("version %d must read pg_stat_checkpointer: %s", v, q)
		}
	}
	if q := statementsSQL(120012); !strings.Contains(q, "s.total_time") || strings.Contains(q, "total_exec_time") {
		t.Errorf("PG12 must use total_time: %s", q)
	}
	for _, v := range []int{130000, 140000, 170000} {
		if q := statementsSQL(v); !strings.Contains(q, "s.total_exec_time") || strings.Contains(q, "s.total_time") {
			t.Errorf("version %d must use total_exec_time: %s", v, q)
		}
	}
}

// The statements query must never read query text (threat T10).
func TestStatementsSQLNeverReadsQueryText(t *testing.T) {
	for _, v := range []int{120000, 170000} {
		q := strings.ToLower(statementsSQL(v))
		for _, bad := range []string{"s.query,", "s.query ", "s.query)", "s.query\n", "s.*", " * ", "query::"} {
			if strings.Contains(q, bad) {
				t.Errorf("version %d: statements SQL must not read query text (found %q):\n%s", v, bad, q)
			}
		}
	}
}

func TestStatementsErrSwallowsOnlyNotLoaded(t *testing.T) {
	if err := statementsErr(&pgconn.PgError{Code: "55000"}); err != nil {
		t.Errorf("55000 (extension not loaded) must be swallowed, got %v", err)
	}
	other := &pgconn.PgError{Code: "42501"}
	if err := statementsErr(other); !errors.Is(err, other) {
		t.Errorf("other errors must pass through, got %v", err)
	}
	if statementsErr(nil) != nil {
		t.Error("nil must stay nil")
	}
}

func TestSlowGroupRefreshesOnlyEveryInterval(t *testing.T) {
	c := New("t", nil, Options{})
	calls := 0
	fail := false
	fn := c.slow("g", func(_ context.Context, b *batch, _ serverInfo) error {
		calls++
		if fail {
			return errors.New("boom")
		}
		b.add("m", float64(calls), map[string]string{"k": "v"})
		return nil
	})
	run := func(at time.Time) ([]model.Sample, error) {
		b := &batch{target: "t", at: at}
		err := fn(context.Background(), b, serverInfo{})
		return b.samples, err
	}

	s, err := run(base)
	if err != nil || len(s) != 1 || s[0].Value != 1 || calls != 1 {
		t.Fatalf("first run: %v %v calls=%d", s, err, calls)
	}
	s, _ = run(base.Add(30 * time.Second))
	if calls != 1 || len(s) != 1 || s[0].Value != 1 || !s[0].At.Equal(base.Add(30*time.Second)) {
		t.Fatalf("within the interval the cache must be re-emitted with the new timestamp: %v calls=%d", s, calls)
	}
	s[0].Labels["k"] = "mutated"
	if s2, _ := run(base.Add(time.Minute)); s2[0].Labels["k"] != "v" {
		t.Fatal("cached labels must not be shared with emitted samples")
	}
	s, _ = run(base.Add(slowGroupEvery))
	if calls != 2 || s[0].Value != 2 {
		t.Fatalf("after the interval the group must refresh: %v calls=%d", s, calls)
	}

	// A failed refresh reports the error, emits nothing and drops the stale entry.
	fail = true
	s, err = run(base.Add(2 * slowGroupEvery))
	if err == nil || len(s) != 0 || calls != 3 {
		t.Fatalf("failed refresh: %v %v calls=%d", s, err, calls)
	}
	fail = false
	if _, err := run(base.Add(2*slowGroupEvery + time.Second)); err != nil || calls != 4 {
		t.Fatalf("after a failure the next run must query again: err=%v calls=%d", err, calls)
	}
}
