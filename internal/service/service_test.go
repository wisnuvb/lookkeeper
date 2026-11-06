package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/alert/notify"
	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/collector"
	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/model"
	"github.com/wisnuvb/lockkeeper/internal/redact"
	"github.com/wisnuvb/lockkeeper/internal/secret"
	"github.com/wisnuvb/lockkeeper/internal/store"
)

const testYAML = `
version: 1
databases:
  db:
    engine: postgres
    host: 127.0.0.1
    user: mon
    password: { env: DB_PW }
    tls: { mode: disable }
alerts:
  channels:
    telegram:
      bot_token: { env: TG_TOKEN }
      chat_id: "42"
`

const (
	dbPassword = "DB-PASSWORD-canary-9f3a"
	tgToken    = "555:TELEGRAM-token-canary"
)

type fakeCollector struct {
	target string
	mu     sync.Mutex
	script func() ([]model.Sample, bool, error)
	closed bool
}

func (f *fakeCollector) Target() string { return f.target }
func (f *fakeCollector) Close() error   { f.mu.Lock(); f.closed = true; f.mu.Unlock(); return nil }
func (f *fakeCollector) Collect(context.Context) ([]model.Sample, bool, error) {
	f.mu.Lock()
	fn := f.script
	f.mu.Unlock()
	return fn()
}
func (f *fakeCollector) set(fn func() ([]model.Sample, bool, error)) {
	f.mu.Lock()
	f.script = fn
	f.mu.Unlock()
}

func sampleOf(metric string, v float64) model.Sample {
	return model.Sample{Target: "db", Metric: metric, Value: v, At: time.Now()}
}

func upSamples(extra ...model.Sample) []model.Sample {
	return append([]model.Sample{sampleOf(rules.MetricPGUp, 1)}, extra...)
}

type telegramServer struct {
	*httptest.Server
	mu   sync.Mutex
	msgs []string
}

func newTelegram(t *testing.T) *telegramServer {
	t.Helper()
	ts := &telegramServer{}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		ts.mu.Lock()
		ts.msgs = append(ts.msgs, fmt.Sprint(body["text"]))
		ts.mu.Unlock()
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func (ts *telegramServer) messages() []string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return append([]string(nil), ts.msgs...)
}

func (ts *telegramServer) waitFor(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m := ts.messages(); len(m) >= n {
			return m
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected %d Telegram messages, got %v", n, ts.messages())
	return nil
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, _, err := config.Parse([]byte(testYAML))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Store.Path = filepath.Join(t.TempDir(), "state", "lockkeeper.db")
	return cfg
}

func testDeps(ts *telegramServer, col *fakeCollector, red *redact.Redactor, logOut io.Writer) Deps {
	env := map[string]string{"DB_PW": dbPassword, "TG_TOKEN": tgToken}
	return Deps{
		Secrets:         secret.Resolver{Getenv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }},
		Log:             slog.New(slog.NewTextHandler(logOut, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Redactor:        red,
		HTTP:            ts.Client(),
		NewCollector:    func(string) collector.Collector { return col },
		RetrySleep:      func(context.Context, time.Duration) error { return nil },
		TelegramBaseURL: ts.URL,
	}
}

func TestCheckSeverityAndExitCodes(t *testing.T) {
	ts := newTelegram(t)
	cases := []struct {
		name     string
		samples  []model.Sample
		complete bool
		err      error
		wantCode int
		wantUp   bool
	}{
		{"healthy", upSamples(sampleOf(rules.MetricPGConnectionsRatio, 0.20)), true, nil, 0, true},
		// 85% would only fire after 5 minutes in the daemon, but a one-shot check ignores "for".
		{"warning", upSamples(sampleOf(rules.MetricPGConnectionsRatio, 0.85)), true, nil, 2, true},
		{"critical", upSamples(sampleOf(rules.MetricPGConnectionsRatio, 0.97)), true, nil, 3, true},
		{"unreachable", []model.Sample{sampleOf(rules.MetricPGUp, 0)}, false, errors.New("connect: refused"), 3, false},
	}
	for _, c := range cases {
		col := &fakeCollector{target: "db"}
		col.set(func() ([]model.Sample, bool, error) { return c.samples, c.complete, c.err })
		svc, err := New(testConfig(t), testDeps(ts, col, nil, io.Discard))
		if err != nil {
			t.Fatal(err)
		}
		res, err := svc.Check(context.Background(), nil, false)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if res.ExitCode() != c.wantCode || res.Targets[0].Up != c.wantUp {
			t.Errorf("%s: exit=%d up=%v, want exit=%d up=%v (%+v)", c.name, res.ExitCode(), res.Targets[0].Up, c.wantCode, c.wantUp, res.Targets[0])
		}
		if !col.closed {
			t.Errorf("%s: collector must be closed after the check", c.name)
		}
	}
}

func TestCheckRejectsUnknownTargetAndRedactsErrors(t *testing.T) {
	ts := newTelegram(t)
	red := redact.New()
	red.Add(dbPassword)
	col := &fakeCollector{target: "db"}
	col.set(func() ([]model.Sample, bool, error) {
		return []model.Sample{sampleOf(rules.MetricPGUp, 0)}, false,
			fmt.Errorf("auth failed: postgres://mon:%s@127.0.0.1/postgres", dbPassword)
	})
	svc, _ := New(testConfig(t), testDeps(ts, col, red, io.Discard))

	if _, err := svc.Check(context.Background(), []string{"nope"}, false); err == nil || !strings.Contains(err.Error(), `unknown database "nope"`) {
		t.Errorf("unknown target must be rejected, got %v", err)
	}
	res, err := svc.Check(context.Background(), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Targets[0].Error, dbPassword) || !strings.Contains(res.Targets[0].Error, "***") {
		t.Errorf("error must be redacted, got %q", res.Targets[0].Error)
	}
}

func TestConfigRuleOverrideTypoFailsFast(t *testing.T) {
	cfg := testConfig(t)
	thr := config.Threshold(1)
	cfg.Alerts.Rules = map[string]config.RuleOverride{"pg.slot.retained_wal_byte": {Warning: &thr}}
	if _, err := New(cfg, Deps{}); err == nil || !strings.Contains(err.Error(), "unknown rule") {
		t.Fatalf("a misspelled rule must fail at startup, got %v", err)
	}
}

func TestAlertsTest(t *testing.T) {
	ts := newTelegram(t)
	col := &fakeCollector{target: "db"}
	svc, _ := New(testConfig(t), testDeps(ts, col, nil, io.Discard))

	res, err := svc.AlertsTest(context.Background(), "")
	if err != nil || len(res) != 1 || res[0].Err != nil || res[0].Channel != "telegram" {
		t.Fatalf("results = %+v, err = %v", res, err)
	}
	if m := ts.messages(); len(m) != 1 || !strings.Contains(m[0], "Test alert from Lockkeeper") {
		t.Errorf("messages = %v", m)
	}
	if _, err := svc.AlertsTest(context.Background(), "pagerduty"); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Errorf("unknown channel must be rejected: %v", err)
	}
}

// newTestRunner wires a runner like MonitorRun does, with a controllable clock.
func newTestRunner(t *testing.T, svc *Service, st *store.Store, now *time.Time) (*runner, *notify.Dispatcher) {
	t.Helper()
	channels, err := svc.buildChannels(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	d := notify.NewDispatcher(svc.buildRoutes(channels), svc.log, 1, 64)
	engine, err := rules.New(svc.rules, svc.engineOptions())
	if err != nil {
		t.Fatal(err)
	}
	if snaps, err := st.LoadAlertState(context.Background()); err == nil {
		engine.Import(snaps)
	}
	return &runner{svc: svc, store: st, engine: engine, dispatcher: d}, d
}

func TestTickFullFlowWithRestartSafety(t *testing.T) {
	ts := newTelegram(t)
	col := &fakeCollector{target: "db"}
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	deps := testDeps(ts, col, nil, io.Discard)
	deps.Now = func() time.Time { return now }
	svc, err := New(testConfig(t), deps)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), svc.cfg.Store.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	r, d := newTestRunner(t, svc, st, &now)

	breach := func() ([]model.Sample, bool, error) {
		return upSamples(sampleOf(rules.MetricPGConnectionsRatio, 0.97)), true, nil
	}
	col.set(breach)
	ctx := context.Background()

	r.tick(ctx, col) // t=0: breaching, but the default rule needs 2m for critical
	now = now.Add(time.Minute)
	r.tick(ctx, col)
	if got := ts.messages(); len(got) != 0 {
		t.Fatalf("must not notify before the for-duration: %v", got)
	}
	now = now.Add(time.Minute) // t=2m
	r.tick(ctx, col)
	msgs := ts.waitFor(t, 1)
	if !strings.Contains(msgs[0], "CRITICAL") || !strings.Contains(msgs[0], "connection usage on db") {
		t.Errorf("unexpected message: %q", msgs[0])
	}
	now = now.Add(time.Minute)
	r.tick(ctx, col)

	// The alert state is persisted: a restarted monitor must not notify again.
	flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = d.Close(flushCtx)
	r2, d2 := newTestRunner(t, svc, st, &now)
	now = now.Add(time.Minute)
	r2.tick(ctx, col)
	_ = d2.Close(flushCtx)
	if got := ts.messages(); len(got) != 1 {
		t.Fatalf("restart must not re-notify, got %d messages: %v", len(got), got)
	}

	// Recovery produces exactly one RESOLVED message.
	col.set(func() ([]model.Sample, bool, error) {
		return upSamples(sampleOf(rules.MetricPGConnectionsRatio, 0.10)), true, nil
	})
	r3, d3 := newTestRunner(t, svc, st, &now)
	now = now.Add(time.Minute)
	r3.tick(ctx, col)
	_ = d3.Close(flushCtx)
	msgs = ts.messages()
	if len(msgs) != 2 || !strings.Contains(msgs[1], "RESOLVED") {
		t.Fatalf("expected a RESOLVED message, got %v", msgs)
	}

	events, err := st.RecentEvents(ctx, 10)
	if err != nil || len(events) != 2 {
		t.Fatalf("events stored = %+v, %v", events, err)
	}
	if latest, err := st.LatestSamples(ctx, "db"); err != nil || len(latest) == 0 {
		t.Errorf("samples must be stored: %v %v", latest, err)
	}
}

func TestTickSurvivesCollectorPanic(t *testing.T) {
	ts := newTelegram(t)
	col := &fakeCollector{target: "db"}
	svc, _ := New(testConfig(t), testDeps(ts, col, nil, io.Discard))
	st, _ := store.Open(context.Background(), svc.cfg.Store.Path)
	defer st.Close()
	now := time.Now()
	r, d := newTestRunner(t, svc, st, &now)
	defer d.Close(context.Background())

	col.set(func() ([]model.Sample, bool, error) { panic("boom") })
	r.tick(context.Background(), col) // must not panic out of tick
	if r.lastTick.Load() == 0 {
		t.Error("lastTick should still be updated after a recovered panic")
	}
}

func TestMonitorRunEndToEnd(t *testing.T) {
	ts := newTelegram(t)
	col := &fakeCollector{target: "db"}
	col.set(func() ([]model.Sample, bool, error) {
		// idle-in-transaction has a 0s for-duration: fires on the first tick.
		return upSamples(sampleOf(rules.MetricPGIdleInTxAge, 400)), true, nil
	})
	cfg := testConfig(t)
	cfg.Monitor.Interval = config.Duration(40 * time.Millisecond)
	cfg.Monitor.QueryTimeout = config.Duration(20 * time.Millisecond)

	var logs strings.Builder
	var logMu sync.Mutex
	red := redact.New()
	logW := lockedWriter{w: red.Writer(&logs), mu: &logMu}
	svc, err := New(cfg, testDeps(ts, col, red, logW))
	if err != nil {
		t.Fatal(err)
	}

	run := func() error {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- svc.MonitorRun(ctx) }()
		time.Sleep(400 * time.Millisecond) // several ticks
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatal("MonitorRun did not shut down")
			return nil
		}
	}

	if err := run(); err != nil {
		t.Fatalf("first run: %v", err)
	}
	msgs := ts.messages()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "WARNING") || !strings.Contains(msgs[0], "idle-in-transaction") {
		t.Fatalf("first run must send exactly one warning, got %v", msgs)
	}
	if !col.closed {
		t.Error("collector must be closed on shutdown")
	}

	// Graceful shutdown persisted the active alert, so a second run stays quiet.
	if err := run(); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if got := ts.messages(); len(got) != 1 {
		t.Fatalf("a restart must not re-notify an active alert, got %v", got)
	}

	logMu.Lock()
	out := logs.String()
	logMu.Unlock()
	for _, secretValue := range []string{dbPassword, tgToken, "TELEGRAM-token-canary"} {
		if strings.Contains(out, secretValue) {
			t.Errorf("log output leaks a secret (%q)", secretValue)
		}
	}
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
