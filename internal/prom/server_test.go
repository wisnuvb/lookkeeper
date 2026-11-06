package prom

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/model"
)

// freeLoopbackAddr returns a 127.0.0.1 address that was free a moment ago. The
// config rules (and so Start) refuse port 0, hence the detour.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func startTestServer(t *testing.T, reg *Registry) *Server {
	t.Helper()
	s, err := Start(reg, ServerOptions{Listen: freeLoopbackAddr(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	return s
}

func get(t *testing.T, method, url, host string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestServerServesMetricsOnLoopback(t *testing.T) {
	reg := NewRegistry()
	reg.UpdateTarget("db", []model.Sample{smp("db", "pg.up", 1, nil)}, true, at0)
	reg.SetAlerts([]model.Event{{Rule: "pg.up", Target: "db", Severity: model.SeverityCritical, Labels: map[string]string{"table": "a\"b"}}})
	s := startTestServer(t, reg)
	base := "http://" + s.Addr()

	resp, body := get(t, http.MethodGet, base+"/metrics", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("content type = %q", ct)
	}
	for _, want := range []string{
		`lockkeeper_pg_up{target="db"} 1`,
		`lockkeeper_alert_active{rule="pg.up",severity="critical",table="a\"b",target="db"} 1`,
		`lockkeeper_collection_last_success_timestamp_seconds{target="db"}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	requireValidExposition(t, body)

	// The endpoint follows the registry: a scrape after an update sees the update.
	reg.UpdateTarget("db", []model.Sample{smp("db", "pg.up", 0, nil)}, false, at0)
	reg.SetAlerts(nil)
	_, body = get(t, http.MethodGet, base+"/metrics", "")
	if !strings.Contains(body, `lockkeeper_pg_up{target="db"} 0`) || strings.Contains(body, "alert_active") {
		t.Errorf("scrape does not reflect the update:\n%s", body)
	}
}

func TestServerServesOnlyGetMetrics(t *testing.T) {
	s := startTestServer(t, NewRegistry())
	base := "http://" + s.Addr()
	for _, path := range []string{"/", "/metrics/", "/metric", "/debug/pprof/", "/api/v1/targets", "//metrics"} {
		if resp, _ := get(t, http.MethodGet, base+path, ""); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, resp.StatusCode)
		}
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodHead, http.MethodOptions} {
		resp, body := get(t, m, base+"/metrics", "")
		if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "GET" {
			t.Errorf("%s /metrics = %d (Allow %q), want 405", m, resp.StatusCode, resp.Header.Get("Allow"))
		}
		if strings.Contains(body, "lockkeeper_") {
			t.Errorf("%s must not return metrics", m)
		}
	}
	// A query string does not change the answer.
	if resp, _ := get(t, http.MethodGet, base+"/metrics?x=1", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("query string: %d", resp.StatusCode)
	}
}

// A browser tricked by DNS rebinding talks to 127.0.0.1 but sends the attacker's
// host name; the loopback-only endpoint must refuse it.
func TestServerRefusesNonLoopbackHostHeader(t *testing.T) {
	s := startTestServer(t, NewRegistry())
	url := "http://" + s.Addr() + "/metrics"
	for _, host := range []string{"evil.example.com", "evil.example.com:9187", "10.0.0.5:9187", "localhost.evil.com"} {
		if resp, _ := get(t, http.MethodGet, url, host); resp.StatusCode != http.StatusForbidden {
			t.Errorf("Host %q = %d, want 403", host, resp.StatusCode)
		}
	}
	for _, host := range []string{"localhost", "localhost:9187", "127.0.0.1", "127.0.0.1:9187", "[::1]:9187", "LOCALHOST"} {
		if resp, _ := get(t, http.MethodGet, url, host); resp.StatusCode != http.StatusOK {
			t.Errorf("Host %q = %d, want 200", host, resp.StatusCode)
		}
	}
}

func TestStartRefusesNonLoopbackUnlessAllowed(t *testing.T) {
	port := strconv.Itoa(9187)
	for _, listen := range []string{"0.0.0.0:" + port, ":" + port, "[::]:" + port, "10.1.2.3:" + port, "example.com:" + port} {
		s, err := Start(NewRegistry(), ServerOptions{Listen: listen})
		if err == nil {
			_ = s.Shutdown(context.Background())
			t.Errorf("Start(%q) must be refused without allow_non_loopback", listen)
			continue
		}
		if !strings.Contains(err.Error(), "loopback") {
			t.Errorf("Start(%q): unhelpful error %v", listen, err)
		}
	}
	for _, listen := range []string{"", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:abc"} {
		if s, err := Start(NewRegistry(), ServerOptions{Listen: listen}); err == nil {
			_ = s.Shutdown(context.Background())
			t.Errorf("Start(%q) must be refused: malformed address", listen)
		}
	}
}

func TestStartFailsFastWhenThePortIsBusy(t *testing.T) {
	first := startTestServer(t, NewRegistry())
	if s, err := Start(NewRegistry(), ServerOptions{Listen: first.Addr()}); err == nil {
		_ = s.Shutdown(context.Background())
		t.Fatal("a second server on the same address must fail at Start, not later")
	}
}

func TestServerHasTimeoutsAndShutsDownGracefully(t *testing.T) {
	s := startTestServer(t, NewRegistry())
	for name, d := range map[string]time.Duration{
		"ReadHeaderTimeout": s.srv.ReadHeaderTimeout, "ReadTimeout": s.srv.ReadTimeout,
		"WriteTimeout": s.srv.WriteTimeout, "IdleTimeout": s.srv.IdleTimeout,
	} {
		if d <= 0 {
			t.Errorf("%s is not set", name)
		}
	}
	if s.srv.MaxHeaderBytes <= 0 {
		t.Error("MaxHeaderBytes is not set")
	}

	// A slow client (headers never finished) must not block shutdown beyond the
	// grace period, and a finished server must refuse new connections.
	conn, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\n")) // no terminating blank line

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if err := s.Shutdown(ctx); err != nil {
		t.Logf("Shutdown returned %v after the grace period (connection was force-closed)", err)
	}
	if time.Since(start) > 4*time.Second {
		t.Errorf("Shutdown took %v", time.Since(start))
	}
	if c, err := net.DialTimeout("tcp", s.Addr(), time.Second); err == nil {
		_ = c.Close()
		t.Error("the port must be closed after Shutdown")
	}
}
