//go:build integration

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/testutil"
)

const (
	metricsPassword = "CANARY-metrics-pw-5d27b1"
	queryCanary     = "CANARY-LITERAL-IN-QUERY-31337"
)

func scrapeMetrics(addr string) (string, error) {
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Get("http://" + addr + "/metrics")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return string(b), fmt.Errorf("status %d", resp.StatusCode)
	}
	return string(b), nil
}

// The real binary serves Prometheus metrics for a real server, the endpoint
// carries no secret and no query text, and it goes away with the daemon.
func TestPrometheusEndpointWithRealBinary(t *testing.T) {
	bin := buildBinary(t)
	p := testutil.StartPG(t, "shared_preload_libraries=pg_stat_statements")
	admin := p.Admin(t)
	ctx := context.Background()
	for _, q := range []string{
		"CREATE EXTENSION pg_stat_statements",
		"CREATE ROLE lk_mon LOGIN PASSWORD '" + metricsPassword + "'",
		"GRANT pg_monitor TO lk_mon",
		"SELECT pg_create_logical_replication_slot('lk_prom_slot','pgoutput')",
		"CREATE TABLE prom_dead (id int) WITH (autovacuum_enabled = false)",
		"INSERT INTO prom_dead SELECT g FROM generate_series(1, 150000) g",
		"DELETE FROM prom_dead WHERE id <= 120000",
		"SELECT count(*), '" + queryCanary + "' FROM prom_dead",
	} {
		if _, err := admin.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	_ = admin.Close(ctx) // flush this session's statistics now

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	metricsAddr := ln.Addr().String()
	_ = ln.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "lockkeeper.yaml")
	cfg := fmt.Sprintf(`
version: 1
databases:
  e2e:
    engine: postgres
    host: %s
    port: %d
    database: postgres
    user: lk_mon
    password: { env: LK_E2E_PASSWORD }
    tls: { mode: disable }
monitor:
  interval: 5s
  query_timeout: 2s
  metrics: { listen: "%s" }
alerts:
  rules:
    pg.slot.retained_wal_bytes:
      warning: 1B
store:
  path: %s
`, p.Host, p.Port, metricsAddr, filepath.Join(dir, "state", "lockkeeper.db"))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	var daemonOut, daemonErr bytes.Buffer
	daemon := exec.Command(bin, "-c", cfgPath, "monitor", "run")
	daemon.Env = append(os.Environ(), "LK_E2E_PASSWORD="+metricsPassword)
	daemon.Stdout, daemon.Stderr = &daemonOut, &daemonErr
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- daemon.Wait() }()
	t.Cleanup(func() { _ = daemon.Process.Kill() })

	var body string
	deadline := time.Now().Add(40 * time.Second)
	for {
		b, err := scrapeMetrics(metricsAddr)
		if err == nil && strings.Contains(b, "lockkeeper_pg_table_dead_tuple_ratio") &&
			strings.Contains(b, "lockkeeper_alert_active") && strings.Contains(b, "lockkeeper_pg_statements_calls") {
			body = b
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected metrics not served within 40s (err %v). Last body:\n%s\nstderr:\n%s", err, b, daemonErr.String())
		}
		time.Sleep(300 * time.Millisecond)
	}
	for _, want := range []string{
		`lockkeeper_pg_up{target="e2e"} 1`,
		`lockkeeper_pg_slot_retained_wal_bytes{slot="lk_prom_slot",target="e2e",type="logical"}`,
		`lockkeeper_pg_table_dead_tuple_ratio{database="postgres",schema="public",table="prom_dead",target="e2e"}`,
		`lockkeeper_pg_db_size_bytes{database="postgres",target="e2e"}`,
		`lockkeeper_alert_active{rule="pg.slot.retained_wal_bytes",severity="warning",slot="lk_prom_slot",target="e2e",type="logical"} 1`,
		`lockkeeper_collection_last_success_timestamp_seconds{target="e2e"}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	for _, secretValue := range []string{metricsPassword, queryCanary} {
		if strings.Contains(body, secretValue) {
			t.Errorf("the metrics endpoint leaks %q", secretValue)
		}
	}
	if strings.Contains(strings.ToLower(body), "select ") {
		t.Errorf("the metrics endpoint appears to carry query text:\n%s", body)
	}

	// Only GET /metrics exists.
	resp, err := http.Get("http://" + metricsAddr + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET / = %d, want 404", resp.StatusCode)
	}

	if err := daemon.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("daemon did not exit cleanly: %v\n%s", err, daemonErr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("daemon did not stop within 30s")
	}
	if _, err := scrapeMetrics(metricsAddr); err == nil {
		t.Error("the endpoint must be closed once the daemon has stopped")
	}
	for _, s := range []string{metricsPassword, queryCanary} {
		if strings.Contains(daemonOut.String()+daemonErr.String(), s) {
			t.Errorf("%q leaked into the daemon output", s)
		}
	}
}

// A non-loopback listen address must stop `config validate` and the daemon.
func TestPrometheusNonLoopbackIsRefusedByTheBinary(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "lockkeeper.yaml")
	cfg := `
version: 1
databases:
  x: { engine: postgres, host: 127.0.0.1, user: u, password: { env: LK_E2E_PASSWORD }, tls: { mode: disable } }
monitor:
  metrics: { listen: "0.0.0.0:9187" }
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-c", cfgPath, "config", "validate")
	cmd.Env = append(os.Environ(), "LK_E2E_PASSWORD=x")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "allow_non_loopback") {
		t.Fatalf("config validate must refuse a non-loopback metrics address, got err=%v\n%s", err, out)
	}
}
