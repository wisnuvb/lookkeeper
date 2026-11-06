package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/model"
	"github.com/wisnuvb/lockkeeper/internal/redact"
	"github.com/wisnuvb/lockkeeper/internal/secret"
)

const (
	botToken = "123456:SECRET-bot-token_xyz"
	hookPath = "/services/T000/B000/WEBHOOK-SECRET-abc"
)

var event = model.Event{
	Rule: "pg.slot.retained_wal_bytes", Target: "rds-main", Labels: map[string]string{"slot": "lk_x"},
	State: model.StateFiring, Severity: model.SeverityCritical, Value: 25 << 30, Threshold: 20 << 30,
	Since:   time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC),
	Summary: "WAL retained by replication slot on rds-main [slot=lk_x]: 25.0 GiB (> 20.0 GiB)",
}

func TestFormatEvent(t *testing.T) {
	got := FormatEvent(event)
	for _, want := range []string{"🔴 CRITICAL", event.Summary, "since 2026-11-06 12:00 UTC"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	resolved := event
	resolved.State = model.StateResolved
	if got := FormatEvent(resolved); !strings.Contains(got, "✅ RESOLVED") || strings.Contains(got, "since") {
		t.Errorf("resolved format wrong: %q", got)
	}
	rem := event
	rem.State, rem.Severity = model.StateReminder, model.SeverityWarning
	if got := FormatEvent(rem); !strings.Contains(got, "🟠 WARNING (reminder)") {
		t.Errorf("reminder format wrong: %q", got)
	}
}

func TestTelegramSendsExpectedRequest(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()
	tg := &Telegram{Token: secret.New(botToken), ChatID: "42", Client: srv.Client(), BaseURL: srv.URL}
	if err := tg.Send(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/bot"+botToken+"/sendMessage" {
		t.Errorf("path = %q", gotPath)
	}
	if gotBody["chat_id"] != "42" || !strings.Contains(gotBody["text"].(string), event.Summary) {
		t.Errorf("body = %v", gotBody)
	}
}

func TestSlackEscapesAndPosts(t *testing.T) {
	var body map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}))
	defer srv.Close()
	s := &Slack{Webhook: secret.New(srv.URL + hookPath), Client: srv.Client()}
	ev := event
	ev.Summary = "a <b> & c"
	if err := s.Send(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body["text"], "a &lt;b&gt; &amp; c") {
		t.Errorf("slack text not escaped: %q", body["text"])
	}
}

func TestErrorsNeverContainSecrets(t *testing.T) {
	// 1) HTTP error status with a body that echoes a secret-looking path.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"ok":false,"description":"Unauthorized"}`)
	}))
	// 2) A closed server: the transport error normally prints the full URL.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL, deadClient := dead.URL, dead.Client()
	dead.Close()

	cases := map[string]error{
		"status":     (&Telegram{Token: secret.New(botToken), ChatID: "1", Client: bad.Client(), BaseURL: bad.URL}).Send(context.Background(), event),
		"dial tg":    (&Telegram{Token: secret.New(botToken), ChatID: "1", Client: deadClient, BaseURL: deadURL}).Send(context.Background(), event),
		"dial slack": (&Slack{Webhook: secret.New(deadURL + hookPath), Client: deadClient}).Send(context.Background(), event),
		"heartbeat":  (&Heartbeat{URL: secret.New(deadURL + hookPath), Client: deadClient}).Ping(context.Background()),
		"bad url":    (&Slack{Webhook: secret.New("://bad" + hookPath), Client: deadClient}).Send(context.Background(), event),
	}
	bad.Close()
	for name, err := range cases {
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		for _, s := range []string{botToken, "SECRET-bot-token", "WEBHOOK-SECRET", "T000/B000"} {
			if strings.Contains(err.Error(), s) {
				t.Errorf("%s: error leaks %q: %v", name, s, err)
			}
		}
	}
}

type flaky struct {
	failures int
	err      error
	calls    atomic.Int32
}

func (f *flaky) Name() string { return "flaky" }
func (f *flaky) Send(context.Context, model.Event) error {
	n := int(f.calls.Add(1))
	if n <= f.failures {
		return f.err
	}
	return nil
}

func noSleep(context.Context, time.Duration) error { return nil }

func TestRetrying(t *testing.T) {
	ctx := context.Background()

	f := &flaky{failures: 2, err: errors.New("HTTP 503")}
	if err := (Retrying{Notifier: f, Sleep: noSleep}).Send(ctx, event); err != nil || f.calls.Load() != 3 {
		t.Errorf("transient failures should be retried: err=%v calls=%d", err, f.calls.Load())
	}

	f = &flaky{failures: 10, err: permanentError{errors.New("HTTP 401")}}
	if err := (Retrying{Notifier: f, Sleep: noSleep}).Send(ctx, event); err == nil || f.calls.Load() != 1 {
		t.Errorf("permanent failures must not be retried: err=%v calls=%d", err, f.calls.Load())
	}

	f = &flaky{failures: 10, err: errors.New("HTTP 500")}
	if err := (Retrying{Notifier: f, Attempts: 4, Sleep: noSleep}).Send(ctx, event); err == nil || f.calls.Load() != 4 {
		t.Errorf("attempts must be bounded: err=%v calls=%d", err, f.calls.Load())
	}

	var waited []time.Duration
	rec := func(_ context.Context, d time.Duration) error { waited = append(waited, d); return nil }
	f = &flaky{failures: 1, err: retryAfterError{err: errors.New("HTTP 429"), d: 30 * time.Second}}
	if err := (Retrying{Notifier: f, BaseDelay: time.Second, Sleep: rec}).Send(ctx, event); err != nil {
		t.Fatal(err)
	}
	if len(waited) != 1 || waited[0] != 30*time.Second {
		t.Errorf("Retry-After must be honoured, waited %v", waited)
	}

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	f = &flaky{failures: 10, err: errors.New("HTTP 500")}
	if err := (Retrying{Notifier: f, Sleep: noSleep}).Send(cctx, event); err == nil || f.calls.Load() != 1 {
		t.Errorf("a cancelled context must stop retries: calls=%d", f.calls.Load())
	}
}

func TestStatusMapping(t *testing.T) {
	mk := func(code int, hdr string) error {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hdr != "" {
				w.Header().Set("Retry-After", hdr)
			}
			w.WriteHeader(code)
		}))
		defer srv.Close()
		return (&Slack{Webhook: secret.New(srv.URL), Client: srv.Client()}).Send(context.Background(), event)
	}
	var perm permanentError
	if err := mk(400, ""); !errors.As(err, &perm) {
		t.Errorf("400 should be permanent: %v", err)
	}
	if err := mk(500, ""); err == nil || errors.As(err, &perm) {
		t.Errorf("500 should be retryable: %v", err)
	}
	var ra retryAfterError
	if err := mk(429, "7"); !errors.As(err, &ra) || ra.d != 7*time.Second {
		t.Errorf("429 should carry Retry-After: %v", err)
	}
	if got := parseRetryAfter("9999"); got != 60*time.Second {
		t.Errorf("Retry-After must be capped at 60s, got %v", got)
	}
}

type recorder struct {
	name string
	mu   sync.Mutex
	got  []model.Event
	err  error
	gate chan struct{}
}

func (r *recorder) Name() string { return r.name }
func (r *recorder) Send(_ context.Context, e model.Event) error {
	if r.gate != nil {
		<-r.gate
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, e)
	return r.err
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestRoutingBySeverityAndDedupe(t *testing.T) {
	pager, chat := &recorder{name: "telegram"}, &recorder{name: "slack"}
	routes := []Route{
		{Severities: []model.Severity{model.SeverityCritical}, Notifiers: []Notifier{pager, chat}},
		{Severities: []model.Severity{model.SeverityWarning}, Notifiers: []Notifier{chat}},
		{Notifiers: []Notifier{chat}}, // catch-all: must not cause a duplicate to slack
	}
	crit, warn := event, event
	warn.Severity = model.SeverityWarning
	if got := Targets(routes, crit); len(got) != 2 {
		t.Errorf("critical goes to both channels once, got %d", len(got))
	}
	if got := Targets(routes, warn); len(got) != 1 || got[0].Name() != "slack" {
		t.Errorf("warning goes to slack only, got %v", got)
	}
}

func TestDispatcherDeliversAndDrains(t *testing.T) {
	rec := &recorder{name: "slack"}
	d := NewDispatcher([]Route{{Notifiers: []Notifier{rec}}}, discard(), 2, 16)
	for i := 0; i < 10; i++ {
		d.Dispatch(event)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if sent, failed, dropped := d.Stats(); sent != 10 || failed != 0 || dropped != 0 {
		t.Errorf("stats sent=%d failed=%d dropped=%d", sent, failed, dropped)
	}
	d.Dispatch(event) // after Close: must not panic
	if err := d.Close(ctx); err != nil {
		t.Errorf("Close must be idempotent: %v", err)
	}
}

func TestDispatcherNeverBlocksAndCountsDrops(t *testing.T) {
	gate := make(chan struct{})
	rec := &recorder{name: "slack", gate: gate}
	d := NewDispatcher([]Route{{Notifiers: []Notifier{rec}}}, discard(), 1, 2)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 20; i++ {
			d.Dispatch(event)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Dispatch blocked on a stuck channel")
	}
	if _, _, dropped := d.Stats(); dropped == 0 {
		t.Error("expected dropped events when the queue is full")
	}
	close(gate)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDispatcherLogsFailuresWithoutSecrets(t *testing.T) {
	var sb strings.Builder
	r := redact.New()
	logger := slog.New(slog.NewTextHandler(r.Writer(&sb), nil))
	failing := &recorder{name: "telegram", err: errors.New("telegram: HTTP 401: Unauthorized")}
	d := NewDispatcher([]Route{{Notifiers: []Notifier{failing}}}, logger, 1, 4)
	d.Dispatch(event)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = d.Close(ctx)
	if _, failed, _ := d.Stats(); failed != 1 {
		t.Errorf("failed = %d", failed)
	}
	if !strings.Contains(sb.String(), "alert delivery failed") {
		t.Errorf("failure not logged: %q", sb.String())
	}
}
