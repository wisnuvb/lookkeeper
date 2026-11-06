package service

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/model"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func scrape(addr string) (string, error) {
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + addr + "/metrics")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func TestMonitorRunExportsPrometheusMetricsWhenConfigured(t *testing.T) {
	ts := newTelegram(t)
	col := &fakeCollector{target: "db"}
	col.set(func() ([]model.Sample, bool, error) {
		return upSamples(
			sampleOf(rules.MetricPGIdleInTxAge, 400), // fires a warning at once (for: 0)
			model.Sample{Target: "db", Metric: rules.MetricPGSlotRetainedWAL, Value: 5, Labels: map[string]string{"slot": `q"s\1`}},
		), true, nil
	})
	addr := freeAddr(t)
	cfg := testConfig(t)
	cfg.Monitor.Interval = config.Duration(40 * time.Millisecond)
	cfg.Monitor.QueryTimeout = config.Duration(20 * time.Millisecond)
	cfg.Monitor.Metrics = &config.Metrics{Listen: addr}
	svc, err := New(cfg, testDeps(ts, col, nil, io.Discard))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.MonitorRun(ctx) }()

	var body string
	deadline := time.Now().Add(5 * time.Second)
	for {
		b, err := scrape(addr)
		if err == nil && strings.Contains(b, "lockkeeper_alert_active") {
			body = b
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no metrics with the alert within 5s (last body %q, err %v)", b, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, want := range []string{
		`lockkeeper_pg_up{target="db"} 1`,
		`lockkeeper_pg_idle_in_tx_max_age_s{target="db"} 400`,
		`lockkeeper_pg_slot_retained_wal_bytes{slot="q\"s\\1",target="db"} 5`,
		`lockkeeper_alert_active{rule="pg.idle_in_tx.max_age_s",severity="warning",target="db"} 1`,
		`lockkeeper_collection_last_success_timestamp_seconds{target="db"}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}

	// The alert resolves and a series vanishes: both must leave the endpoint.
	col.set(func() ([]model.Sample, bool, error) {
		return upSamples(sampleOf(rules.MetricPGIdleInTxAge, 0)), true, nil
	})
	deadline = time.Now().Add(5 * time.Second)
	for {
		b, err := scrape(addr)
		if err == nil && !strings.Contains(b, "alert_active") && !strings.Contains(b, "retained_wal") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("resolved alert or vanished series still exported:\n%s", b)
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("MonitorRun: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("MonitorRun did not shut down")
	}
	if _, err := scrape(addr); err == nil {
		t.Error("the endpoint must be closed after the monitor stops")
	}
}

func TestMonitorRunDoesNotListenWithoutMetricsConfig(t *testing.T) {
	ts := newTelegram(t)
	col := &fakeCollector{target: "db"}
	col.set(func() ([]model.Sample, bool, error) { return upSamples(), true, nil })
	cfg := testConfig(t) // Monitor.Metrics is nil
	cfg.Monitor.Interval = config.Duration(40 * time.Millisecond)
	cfg.Monitor.QueryTimeout = config.Duration(20 * time.Millisecond)
	svc, err := New(cfg, testDeps(ts, col, nil, io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	// With the endpoint off the monitor must run and stop cleanly, and the nil
	// registry must make the tick's registry calls harmless.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.MonitorRun(ctx) }()
	time.Sleep(150 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestMonitorRunFailsWhenMetricsAddressIsRefused(t *testing.T) {
	ts := newTelegram(t)
	col := &fakeCollector{target: "db"}
	col.set(func() ([]model.Sample, bool, error) { return upSamples(), true, nil })
	cfg := testConfig(t)
	// Bypasses config validation on purpose: the service must not trust it.
	cfg.Monitor.Metrics = &config.Metrics{Listen: "0.0.0.0:9187"}
	svc, err := New(cfg, testDeps(ts, col, nil, io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = svc.MonitorRun(ctx)
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("a non-loopback metrics address must stop the monitor, got %v", err)
	}
}
