package pg

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
)

func TestCacheRatio(t *testing.T) {
	cases := []struct {
		name      string
		prev, cur cacheCounters
		want      float64
		ok        bool
	}{
		{"healthy", cacheCounters{0, 0}, cacheCounters{99_000, 1_000}, 0.99, true},
		{"poor", cacheCounters{1_000_000, 50_000}, cacheCounters{1_080_000, 70_000}, 0.8, true},
		{"too little traffic", cacheCounters{0, 0}, cacheCounters{500, 5}, 0, false},
		{"stats reset", cacheCounters{9_000_000, 1_000}, cacheCounters{10, 1}, 0, false},
		{"no change", cacheCounters{5, 5}, cacheCounters{5, 5}, 0, false},
	}
	for _, c := range cases {
		got, ok := cacheRatio(c.prev, c.cur)
		if ok != c.ok || (ok && (got < c.want-1e-9 || got > c.want+1e-9)) {
			t.Errorf("%s: got (%v,%v), want (%v,%v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestCollectReportsDownAsData(t *testing.T) {
	boom := errors.New("connection refused")
	c := New("rds-main", func(context.Context) (*pgx.Conn, error) { return nil, boom }, Options{
		Now: func() time.Time { return time.Unix(1_700_000_000, 0) },
	})
	samples, complete, err := c.Collect(context.Background())
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("expected the connect error to be wrapped, got %v", err)
	}
	if complete {
		t.Error("a failed collection must not be complete")
	}
	if len(samples) != 1 || samples[0].Metric != rules.MetricPGUp || samples[0].Value != 0 || samples[0].Target != "rds-main" {
		t.Fatalf("expected a single pg.up=0 sample, got %+v", samples)
	}
	if !samples[0].At.Equal(time.Unix(1_700_000_000, 0)) {
		t.Errorf("sample time not taken from the injected clock: %v", samples[0].At)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close without a connection must be a no-op: %v", err)
	}
}
