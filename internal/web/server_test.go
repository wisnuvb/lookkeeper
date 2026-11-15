package web

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func testUI() fstest.MapFS {
	return fstest.MapFS{
		"index.html":         {Data: []byte(`<!doctype html><meta name="csp-nonce" content="__CSP_NONCE__"><title>app</title><div id=root></div>`)},
		"assets/app-abc.js":  {Data: []byte("console.log(1)")},
		"assets/app-abc.css": {Data: []byte("body{}")},
		"favicon.svg":        {Data: []byte("<svg xmlns='http://www.w3.org/2000/svg'/>")},
		".gitkeep":           {Data: []byte("")},
		"assets/.hidden":     {Data: []byte("hidden-secret")},
	}
}

type harness struct {
	s   *Server
	log *bytes.Buffer
}

func newHarness(t *testing.T, mutate ...func(*Config)) harness {
	t.Helper()
	buf := &bytes.Buffer{}
	cfg := Config{UI: testUI(), Logger: slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	for _, m := range mutate {
		m(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return harness{s: s, log: buf}
}

func (h harness) do(method, target string, mut ...func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.Host = "127.0.0.1:8443"
	for _, m := range mut {
		m(r)
	}
	w := httptest.NewRecorder()
	h.s.Handler().ServeHTTP(w, r)
	return w
}

func host(v string) func(*http.Request) { return func(r *http.Request) { r.Host = v } }

var requiredHeaders = []string{
	"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
	"Permissions-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
}

// An attacker picks the URL, so the protective headers must be on EVERY response, including errors.
func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	h := newHarness(t)
	reqs := []struct {
		name, method, target string
		mut                  []func(*http.Request)
	}{
		{"index", "GET", "/", nil},
		{"client route", "GET", "/servers/rds-main", nil},
		{"asset", "GET", "/assets/app-abc.js", nil},
		{"missing file", "GET", "/missing.js", nil},
		{"dotfile", "GET", "/.gitkeep", nil},
		{"health", "GET", "/api/v1/health", nil},
		{"unknown api", "GET", "/api/v1/nope", nil},
		{"api root", "GET", "/api/", nil},
		{"wrong method on api", "POST", "/api/v1/health", nil},
		{"wrong method on ui", "POST", "/", nil},
		{"bad host", "GET", "/", []func(*http.Request){host("evil.example")}},
		{"redirecting path", "GET", "//a//b", nil},
	}
	for _, c := range reqs {
		t.Run(c.name, func(t *testing.T) {
			w := h.do(c.method, c.target, c.mut...)
			for _, name := range requiredHeaders {
				if w.Header().Get(name) == "" {
					t.Errorf("%s missing (status %d)", name, w.Code)
				}
			}
			if w.Header().Get("X-Request-Id") == "" {
				t.Error("X-Request-Id missing")
			}
			if w.Header().Get("Strict-Transport-Security") != "" {
				t.Error("HSTS must not be sent over plain HTTP")
			}
		})
	}
}

func TestCSPIsStrict(t *testing.T) {
	csp := newHarness(t).do("GET", "/").Header().Get("Content-Security-Policy")
	for _, bad := range []string{"unsafe-inline", "unsafe-eval", "http:", "https:", "*", "data:", "blob:", "strict-dynamic"} {
		if strings.Contains(csp, bad) {
			t.Errorf("CSP must not contain %q: %s", bad, csp)
		}
	}
	for _, want := range []string{"default-src 'none'", "script-src 'self';", "frame-ancestors 'none'", "object-src 'none'", "base-uri 'none'", "form-action 'self'", "connect-src 'self'", "style-src 'self' 'nonce-"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP must contain %q: %s", want, csp)
		}
	}
	// The nonce is for STYLES only. A nonce on script-src would let any injected <script nonce=...> run.
	if strings.Contains(strings.SplitN(csp, "style-src", 2)[0], "nonce-") {
		t.Errorf("no nonce may appear before style-src (script-src must stay 'self' only): %s", csp)
	}
	w := newHarness(t).do("GET", "/")
	if w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("framing, referrer and sniffing headers wrong")
	}
}

var nonceInCSP = regexp.MustCompile(`style-src 'self' 'nonce-([A-Za-z0-9+/=]+)'`)
var nonceInHTML = regexp.MustCompile(`<meta name="csp-nonce" content="([^"]*)">`)

// The nonce is what lets Radix's scroll-lock <style> pass a strict CSP. It must be unguessable, fresh
// for every response, identical in the header and in the page, and never a leftover placeholder.
func TestCSPNonce(t *testing.T) {
	h := newHarness(t)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		w := h.do("GET", "/servers/rds-main")
		hm := nonceInCSP.FindStringSubmatch(w.Header().Get("Content-Security-Policy"))
		bm := nonceInHTML.FindStringSubmatch(w.Body.String())
		if hm == nil || bm == nil {
			t.Fatalf("nonce missing: header %q body %q", w.Header().Get("Content-Security-Policy"), w.Body.String())
		}
		if hm[1] != bm[1] {
			t.Fatalf("the page and the header must carry the same nonce: %q vs %q", bm[1], hm[1])
		}
		if len(hm[1]) != 24 { // 16 random bytes, base64
			t.Fatalf("nonce must be 128 bits, got %q", hm[1])
		}
		if seen[hm[1]] {
			t.Fatal("a nonce was reused across responses")
		}
		seen[hm[1]] = true
		if strings.Contains(w.Body.String(), "__CSP_NONCE__") {
			t.Fatal("the placeholder must never reach the client")
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("a page with a nonce must not be cacheable")
		}
	}

	// Every response gets its own nonce in the header, but only the app shell embeds it.
	asset := h.do("GET", "/assets/app-abc.js")
	if strings.Contains(asset.Body.String(), "nonce") || asset.Body.String() != "console.log(1)" {
		t.Errorf("assets must be served untouched, got %q", asset.Body.String())
	}
	api := h.do("GET", "/api/v1/health")
	if strings.Contains(api.Body.String(), "nonce") {
		t.Error("the nonce must not appear in API bodies")
	}
	if nonceInCSP.FindStringSubmatch(api.Header().Get("Content-Security-Policy")) == nil {
		t.Error("API responses carry the CSP too")
	}
	// HEAD must not break the shell either.
	if w := h.do("HEAD", "/"); w.Code != 200 || w.Body.Len() != 0 {
		t.Errorf("HEAD /: %d with %d body bytes", w.Code, w.Body.Len())
	}
}

func TestHSTSOnlyOverTLS(t *testing.T) {
	h := newHarness(t)
	w := h.do("GET", "/", func(r *http.Request) { r.TLS = &tls.ConnectionState{} })
	if !strings.Contains(w.Header().Get("Strict-Transport-Security"), "max-age=") {
		t.Fatal("HSTS expected over TLS")
	}
}

// DNS rebinding: the browser sends the attacker's NAME in Host even though it connected to us.
func TestHostGuard(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.AllowedHosts = []string{"lockkeeper.example.net", "Proxy.Example.Org:8443"} })
	cases := []struct {
		host string
		ok   bool
	}{
		{"127.0.0.1:8443", true},
		{"127.0.0.1", true},
		{"localhost:8443", true},
		{"LOCALHOST", true},
		{"localhost.", true},
		{"[::1]:8443", true},
		{"[::1]", true},
		{"10.1.2.3:8443", true}, // an IP literal is not a rebinding vector (no DNS name involved)
		{"lockkeeper.example.net", true},
		{"lockkeeper.example.net:8443", true},
		{"LockKeeper.Example.NET", true},
		{"proxy.example.org", true},

		{"attacker.example", false},
		{"attacker.example:8443", false},
		{"127.0.0.1.attacker.example", false},
		{"localhost.attacker.example", false},
		{"lockkeeper.example.net.attacker.example", false},
		{"xlockkeeper.example.net", false},
		{"", false},
		{"   ", false},
		{"@", false},
	}
	for _, c := range cases {
		w := h.do("GET", "/api/v1/health", host(c.host))
		if c.ok && w.Code != http.StatusOK {
			t.Errorf("Host %q should be served, got %d", c.host, w.Code)
		}
		if !c.ok && w.Code != http.StatusMisdirectedRequest {
			t.Errorf("Host %q must be refused with 421, got %d", c.host, w.Code)
		}
	}
	// The refusal must not leak anything about the server.
	body := h.do("GET", "/", host("attacker.example")).Body.String()
	if strings.Contains(body, "app") || strings.Contains(body, "127.0.0.1") {
		t.Errorf("refusal body leaks: %q", body)
	}
}

func TestSPAServing(t *testing.T) {
	h := newHarness(t)

	for _, p := range []string{"/", "/servers", "/servers/rds-main", "/migrations/new", "/some/deep/client/route", "/index.html"} {
		w := h.do("GET", p)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "<div id=root>") {
			t.Errorf("%s: want index.html, got %d %q", p, w.Code, w.Body.String())
		}
		if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s: the app shell carries a per-response nonce and must never be cached, Cache-Control=%q", p, cc)
		}
	}

	w := h.do("GET", "/assets/app-abc.js")
	if w.Code != 200 || w.Body.String() != "console.log(1)" {
		t.Fatalf("asset: %d %q", w.Code, w.Body.String())
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("hashed assets are cacheable forever, got %q", cc)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("js content type %q", ct)
	}
	if ct := h.do("GET", "/assets/app-abc.css").Header().Get("Content-Type"); !strings.Contains(ct, "text/css") {
		t.Errorf("css content type %q", ct)
	}
	if ct := h.do("GET", "/favicon.svg").Header().Get("Content-Type"); !strings.Contains(ct, "svg") {
		t.Errorf("svg content type %q", ct)
	}

	// Something that looks like a file but is not there is a 404, never the app shell.
	for _, p := range []string{"/missing.js", "/assets/gone.css", "/robots.txt", "/x.map"} {
		if w := h.do("GET", p); w.Code != 404 || strings.Contains(w.Body.String(), "<div id=root>") {
			t.Errorf("%s: want 404, got %d", p, w.Code)
		}
	}

	// HEAD works and has no body; other methods are refused.
	if w := h.do("HEAD", "/"); w.Code != 200 || w.Body.Len() != 0 {
		t.Errorf("HEAD /: %d, %d body bytes", w.Code, w.Body.Len())
	}
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		w := h.do(m, "/")
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") == "" {
			t.Errorf("%s /: want 405 with Allow, got %d", m, w.Code)
		}
	}
}

func TestStaticServerNeverEscapesOrServesDotfiles(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{
		"/.gitkeep", "/assets/.hidden", "/.git/config", "/..%2f..%2fetc%2fpasswd", "/%2e%2e/%2e%2e/etc/passwd",
		"/assets/../../../etc/passwd", "/assets/%2e%2e/.gitkeep", "/..;/x", "/assets/..%5c..%5cx",
	} {
		w := h.do("GET", p)
		body := w.Body.String()
		if strings.Contains(body, "hidden-secret") || strings.Contains(body, "root:") {
			t.Errorf("%s leaked content: %q", p, body)
		}
		if w.Code == 200 && !strings.Contains(body, "<div id=root>") {
			t.Errorf("%s: a 200 may only be the app shell, got %q", p, body)
		}
	}
	if w := h.do("GET", "/.gitkeep"); w.Code != 404 {
		t.Errorf("dotfile must be 404, got %d", w.Code)
	}
}

func TestAPIRoutes(t *testing.T) {
	h := newHarness(t)
	w := h.do("GET", "/api/v1/health")
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("health: %d %q", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content type %q", ct)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("API responses must not be cached")
	}
	if w := h.do("HEAD", "/api/v1/health"); w.Code != 200 {
		t.Errorf("HEAD health: %d", w.Code)
	}

	w = h.do("POST", "/api/v1/health")
	if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" || !strings.Contains(w.Body.String(), `"method_not_allowed"`) {
		t.Errorf("POST health: %d allow=%q body=%q", w.Code, w.Header().Get("Allow"), w.Body.String())
	}

	// A mistyped API path is a JSON 404, never the HTML app shell with status 200.
	for _, p := range []string{"/api/v1/nope", "/api/", "/api/v2/health", "/api/v1/health/extra", "/api/v1"} {
		w := h.do("GET", p)
		if w.Code != 404 || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") || strings.Contains(w.Body.String(), "<div id=root>") {
			t.Errorf("%s: want JSON 404, got %d %q %q", p, w.Code, w.Header().Get("Content-Type"), w.Body.String())
		}
	}
	// The health response reveals nothing about the build or the host.
	for _, leak := range []string{"version", "uptime", "go1", "lockkeeper", "127.0.0.1"} {
		if strings.Contains(strings.ToLower(h.do("GET", "/api/v1/health").Body.String()), leak) {
			t.Errorf("health leaks %q", leak)
		}
	}
}

func TestRequestBodyIsBounded(t *testing.T) {
	h := newHarness(t)
	h.s.Handle("/api/v1/echo", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "Request body too large.")
			return
		}
		writeJSON(w, 200, map[string]string{"ok": "yes"})
	}))
	big := func(n int) func(*http.Request) {
		return func(r *http.Request) {
			r.Body = io.NopCloser(bytes.NewReader(make([]byte, n)))
			r.ContentLength = int64(n)
		}
	}
	if w := h.do("POST", "/api/v1/echo", big(MaxBodyBytes-10)); w.Code != 200 {
		t.Errorf("a body under the limit must pass, got %d", w.Code)
	}
	if w := h.do("POST", "/api/v1/echo", big(MaxBodyBytes+1)); w.Code != 413 {
		t.Errorf("a body over the limit must get 413, got %d", w.Code)
	}
	if w := h.do("POST", "/api/v1/echo", big(50<<20)); w.Code != 413 {
		t.Errorf("a 50 MiB body must get 413, got %d", w.Code)
	}
}

func TestPanicBecomesGenericErrorAndLeaksNothing(t *testing.T) {
	h := newHarness(t)
	const canary = "SECRET-IN-PANIC-s3cr3t"
	h.s.Handle("/api/v1/boom", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("db password is " + canary) }))
	w := h.do("GET", "/api/v1/boom")
	if w.Code != 500 || !strings.Contains(w.Body.String(), `"internal"`) {
		t.Fatalf("want JSON 500, got %d %q", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), canary) || strings.Contains(w.Body.String(), "goroutine") {
		t.Fatalf("panic detail reached the client: %q", w.Body.String())
	}
	if strings.Contains(h.log.String(), canary) {
		t.Fatalf("panic VALUE must not be logged (it can embed secrets): %s", h.log.String())
	}
	if !strings.Contains(h.log.String(), "panic_type=string") {
		t.Fatalf("the panic must be logged by type: %s", h.log.String())
	}
	for _, name := range requiredHeaders {
		if w.Header().Get(name) == "" {
			t.Errorf("%s missing on the 500", name)
		}
	}
	// And the server keeps working.
	if w := h.do("GET", "/api/v1/health"); w.Code != 200 {
		t.Fatal("server must survive a handler panic")
	}
}

func TestAccessLogHasNoSecrets(t *testing.T) {
	h := newHarness(t)
	h.do("GET", "/api/v1/health?token=QUERY-CANARY&password=QUERY-CANARY2", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer HEADER-CANARY")
		r.Header.Set("Cookie", "lk_session=COOKIE-CANARY")
		r.Header.Set("X-Csrf-Token", "CSRF-CANARY")
	})
	out := h.log.String()
	for _, c := range []string{"QUERY-CANARY", "HEADER-CANARY", "COOKIE-CANARY", "CSRF-CANARY"} {
		if strings.Contains(out, c) {
			t.Errorf("the access log leaked %s: %s", c, out)
		}
	}
	for _, want := range []string{"method=GET", "path=/api/v1/health", "status=200", "request_id="} {
		if !strings.Contains(out, want) {
			t.Errorf("access log should contain %q: %s", want, out)
		}
	}
}

func TestUINotBuilt(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.UI = fstest.MapFS{".gitkeep": {}} })
	w := h.do("GET", "/")
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "make web-build") {
		t.Fatalf("want 503 with build instructions, got %d %q", w.Code, w.Body.String())
	}
	if w := h.do("GET", "/api/v1/health"); w.Code != 200 {
		t.Fatal("the API must work without the UI")
	}
}

func TestNewValidatesConfiguration(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := New(Config{Listen: "0.0.0.0:8443", Logger: log}); err == nil {
		t.Error("wildcard without opt-in must be refused")
	}
	if _, err := New(Config{Listen: "0.0.0.0:8443", AllowNonLoopback: true, AuthEnabled: true, Logger: log}); err == nil {
		t.Error("non-loopback without TLS must be refused")
	}
	if _, err := New(Config{TLSCertFile: "cert.pem", Logger: log}); err == nil {
		t.Error("a certificate without a key must be refused")
	}
	if _, err := New(Config{TLSKeyFile: "key.pem", Logger: log}); err == nil {
		t.Error("a key without a certificate must be refused")
	}
	if _, err := New(Config{Logger: log, UI: testUI()}); err != nil {
		t.Errorf("the default configuration (loopback) must be valid: %v", err)
	}
	if DefaultListen != "127.0.0.1:8443" {
		t.Error("the default must stay loopback")
	}
}

func TestServeAndGracefulShutdown(t *testing.T) {
	h := newHarness(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.s.Serve(ctx, ln) }()

	resp, err := http.Get("http://" + ln.Addr().String() + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "ok") {
		t.Fatalf("live request: %d %s", resp.StatusCode, body)
	}
	// Over a real socket the Host header is "127.0.0.1:port", which the guard accepts.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down")
	}
	if _, err := http.Get("http://" + ln.Addr().String() + "/api/v1/health"); err == nil {
		t.Fatal("the port must be closed after shutdown")
	}
}

func selfSigned(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	kb, _ := x509.MarshalECPrivateKey(key)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	cert, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, pool
}

func TestServeTLS(t *testing.T) {
	certFile, keyFile, pool := selfSigned(t)
	h := newHarness(t, func(c *Config) { c.TLSCertFile, c.TLSKeyFile = certFile, keyFile })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.s.Serve(ctx, ln) }()

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Strict-Transport-Security") == "" {
		t.Fatalf("TLS: %d, HSTS %q", resp.StatusCode, resp.Header.Get("Strict-Transport-Security"))
	}
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Fatal("TLS 1.2 or newer expected")
	}
	// Plain HTTP to the TLS port must not be answered with content.
	plain := &http.Client{Timeout: 2 * time.Second}
	if r, err := plain.Get("http://" + ln.Addr().String() + "/api/v1/health"); err == nil {
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if strings.Contains(string(b), `"ok"`) {
			t.Fatal("plain HTTP was served on the TLS port")
		}
	}
}
