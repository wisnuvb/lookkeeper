//go:build integration

// Package e2e runs the real lockkeeper binary against a real Postgres container
// and checks behaviour and secret hygiene from the outside, the way an operator
// would experience them.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/testutil"
)

const (
	monitorPassword = "CANARY-db-password-7c1e90"
	slackSecret     = "SLACK-CANARY-7731-webhook"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "lockkeeper")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/wisnuvb/lockkeeper/cmd/lockkeeper")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

type slackStub struct {
	*httptest.Server
	mu   sync.Mutex
	msgs []string
}

func newSlack(t *testing.T) *slackStub {
	s := &slackStub{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.mu.Lock()
		s.msgs = append(s.msgs, body["text"])
		s.mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *slackStub) messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.msgs...)
}

func (s *slackStub) waitFor(t *testing.T, substr string, d time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, m := range s.messages() {
			if strings.Contains(m, substr) {
				return m
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no Slack message containing %q within %v; got %v", substr, d, s.messages())
	return ""
}

func TestMonitorBinaryAgainstRealPostgres(t *testing.T) {
	bin := buildBinary(t)
	p := testutil.StartPG(t)
	admin := p.Admin(t)
	ctx := context.Background()
	for _, q := range []string{
		"CREATE ROLE lk_mon LOGIN PASSWORD '" + monitorPassword + "'",
		"GRANT pg_monitor TO lk_mon",
		"SELECT pg_create_logical_replication_slot('lk_e2e_slot','pgoutput')",
		"CREATE TABLE bulk (id serial primary key, payload text)",
		"INSERT INTO bulk (payload) SELECT repeat('x', 300) FROM generate_series(1, 60000)",
	} {
		if _, err := admin.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	slack := newSlack(t)
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state", "lockkeeper.db")
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
alerts:
  channels:
    slack:
      webhook_url: { env: LK_E2E_SLACK }
  rules:
    pg.slot.retained_wal_bytes:
      warning: 1MiB
store:
  path: %s
`, p.Host, p.Port, statePath)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(),
		"LK_E2E_PASSWORD="+monitorPassword,
		"LK_E2E_SLACK="+slack.URL+"/services/T0/B0/"+slackSecret,
		"PGPASSWORD=ambient-must-be-ignored",
	)

	runCLI := func(args ...string) (string, string, int) {
		cmd := exec.Command(bin, append([]string{"-c", cfgPath}, args...)...)
		cmd.Env = env
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("run %v: %v", args, err)
		}
		return out.String(), errb.String(), code
	}

	var allOutput strings.Builder
	collect := func(parts ...string) {
		for _, s := range parts {
			allOutput.WriteString(s)
		}
	}

	// config validate resolves every referenced secret without printing it.
	so, se, code := runCLI("config", "validate")
	collect(so, se)
	if code != 0 || !strings.Contains(so, "Configuration OK") {
		t.Fatalf("config validate: code=%d\n%s\n%s", code, so, se)
	}

	// check: exit 2 (warning) because the unread slot retains more than 1 MiB.
	so, se, code = runCLI("check")
	collect(so, se)
	if code != 2 || !strings.Contains(so, "WAL retained by replication slot") || !strings.Contains(so, "lk_e2e_slot") {
		t.Fatalf("check: want exit 2 with a WAL finding, got code=%d\n%s\n%s", code, so, se)
	}
	if strings.Contains(so, "superuser") {
		t.Errorf("the least-privilege role must not trigger a superuser warning:\n%s", so)
	}

	// slots list shows the slot and its retained WAL.
	so, se, code = runCLI("slots", "list")
	collect(so, se)
	if code != 0 || !strings.Contains(so, "lk_e2e_slot") || !strings.Contains(so, "pgoutput") || !strings.Contains(so, "false") {
		t.Fatalf("slots list: code=%d\n%s\n%s", code, so, se)
	}

	// alerts test reaches the Slack stub.
	so, se, code = runCLI("alerts", "test")
	collect(so, se)
	if code != 0 || !strings.Contains(so, "slack: sent") {
		t.Fatalf("alerts test: code=%d\n%s\n%s", code, so, se)
	}
	slack.waitFor(t, "Test alert from Lockkeeper", 5*time.Second)

	// Run the daemon.
	var daemonOut, daemonErr bytes.Buffer
	daemon := exec.Command(bin, "-c", cfgPath, "--log-level", "debug", "monitor", "run")
	daemon.Env = env
	daemon.Stdout, daemon.Stderr = &daemonOut, &daemonErr
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- daemon.Wait() }()
	t.Cleanup(func() { _ = daemon.Process.Kill() })

	msg := slack.waitFor(t, "WAL retained by replication slot", 30*time.Second)
	if !strings.Contains(msg, "[slot=lk_e2e_slot") || !strings.Contains(msg, "WARNING") {
		t.Errorf("unexpected alert text: %q", msg)
	}

	// The command line of the running process must not contain any secret.
	ps, err := exec.Command("ps", "-axo", "args").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{monitorPassword, slackSecret} {
		if bytes.Contains(ps, []byte(s)) {
			t.Errorf("a secret appears in the process list (ps): %q", s)
		}
	}

	// Let it run another cycle: the same alert must not be re-sent.
	before := len(slack.messages())
	time.Sleep(7 * time.Second)
	if after := len(slack.messages()); after != before {
		t.Errorf("an active alert must not be re-notified every tick: %d -> %d", before, after)
	}

	// Graceful shutdown on SIGTERM, exit status 0.
	if err := daemon.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("daemon did not exit cleanly: %v\nstderr:\n%s", err, daemonErr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("daemon did not stop within 30s\nstderr:\n%s", daemonErr.String())
	}
	collect(daemonOut.String(), daemonErr.String())
	if !strings.Contains(daemonErr.String(), "monitor stopped") {
		t.Errorf("expected a clean shutdown log line:\n%s", daemonErr.String())
	}

	// A restart must not repeat the notification (alert state was persisted).
	before = len(slack.messages())
	restart := exec.Command(bin, "-c", cfgPath, "monitor", "run")
	restart.Env = env
	var rErr bytes.Buffer
	restart.Stderr = &rErr
	if err := restart.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(8 * time.Second)
	_ = restart.Process.Signal(syscall.SIGTERM)
	_ = restart.Wait()
	collect(rErr.String())
	if after := len(slack.messages()); after != before {
		t.Errorf("a restart must not re-notify: %d -> %d", before, after)
	}

	// Canary scan: no secret may appear in any output nor in the state database.
	scan := func(name string, data []byte) {
		for _, s := range []string{monitorPassword, slackSecret, "ambient-must-be-ignored"} {
			if bytes.Contains(data, []byte(s)) {
				t.Errorf("secret %q leaked into %s", s, name)
			}
		}
	}
	scan("command output and logs", []byte(allOutput.String()))
	entries, _ := filepath.Glob(statePath + "*")
	if len(entries) == 0 {
		t.Fatal("expected a state database")
	}
	for _, f := range entries {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		scan(filepath.Base(f), b)
	}
	fi, _ := os.Stat(statePath)
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("state database must be 0600, got %v", fi.Mode().Perm())
	}
}
