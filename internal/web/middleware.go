package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// MaxBodyBytes bounds every request body. Nothing the API accepts is larger (a CA certificate is the
// biggest field); a hostile client cannot make the server buffer more.
const MaxBodyBytes = 1 << 20

// cspBase is deliberately tight: scripts, fonts, images and connections only from this origin, no
// inline script, no eval, no framing, no plugins, no <base>. The UI is built to satisfy it.
//
// Styles are 'self' plus ONE per-response nonce. Radix UI (menus, dialogs) injects a <style> element to
// compensate for the scrollbar when it locks page scroll; without a nonce a strict CSP blocks it. The
// nonce is random for every response, is placed in index.html as <meta name="csp-nonce"> and handed to
// Radix by the app, so no 'unsafe-inline' is needed and an injected <style> without the nonce is still
// refused. Inline style ATTRIBUTES stay blocked; the UI sets styles through the DOM, which CSP allows.
const cspBase = "default-src 'none'; script-src 'self'; img-src 'self'; font-src 'self'; " +
	"connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"

type ctxKey int

const nonceKey ctxKey = iota

// nonceFrom returns the CSP nonce chosen for this request ("" if the middleware did not run).
func nonceFrom(ctx context.Context) string {
	n, _ := ctx.Value(nonceKey).(string)
	return n
}

func newNonce() string {
	b := make([]byte, 16) // 128 bits
	if _, err := rand.Read(b); err != nil {
		panic("web: random source failed: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(b)
}

func buildCSP(nonce string) string {
	return cspBase + "; style-src 'self' 'nonce-" + nonce + "'"
}

// securityHeaders sets the response headers that protect the browser. They go on EVERY response,
// including errors, redirects and 404s, because an attacker chooses which URL to open.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := newNonce()
		r = r.WithContext(context.WithValue(r.Context(), nonceKey, nonce))
		h := w.Header()
		h.Set("Content-Security-Policy", buildCSP(nonce))
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// hostGuard rejects requests whose Host header is not one of ours. This is the defence against DNS
// rebinding: a malicious page makes the browser resolve attacker.example to 127.0.0.1 and then talk to
// the local server as if it were same-origin. The browser still sends "Host: attacker.example", so
// refusing unknown names stops it. IP-literal hosts are allowed (a rebinding attack needs a NAME; an
// address typed or linked directly is an ordinary cross-origin request, which CSRF and SameSite
// handle). A name must be "localhost" or in the operator's allow-list.
type hostGuard struct{ names map[string]struct{} }

func newHostGuard(extra []string) *hostGuard {
	g := &hostGuard{names: map[string]struct{}{"localhost": {}}}
	for _, n := range extra {
		if n = normaliseHost(n); n != "" {
			g.names[n] = struct{}{}
		}
	}
	return g
}

func normaliseHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	return strings.TrimSuffix(h, ".")
}

func (g *hostGuard) allowed(hostHeader string) bool {
	h := normaliseHost(hostHeader)
	if h == "" {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	_, ok := g.names[h]
	return ok
}

func (g *hostGuard) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.allowed(r.Host) {
			writeError(w, http.StatusMisdirectedRequest, "bad_host", "This host name is not served here.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// limitBody bounds the request body for every route.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}
func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status, w.wrote = http.StatusOK, true
	}
	return w.ResponseWriter.Write(b)
}
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func requestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// recoverer turns a panic into a generic 500. The panic value and stack go to the log only (never to
// the client), and only its type is logged, because a panic message can embed request data.
func recoverer(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if v := recover(); v != nil {
					if v == http.ErrAbortHandler {
						panic(v)
					}
					log.Error("handler panicked", "request_id", w.Header().Get("X-Request-Id"), "panic_type", typeName(v), "path", r.URL.Path)
					writeError(w, http.StatusInternalServerError, "internal", "Something went wrong.")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// accessLog logs method, path (never the query string: it could carry tokens), status and duration.
// It logs no headers, cookies or bodies.
func accessLog(log *slog.Logger, now func() time.Time) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := requestID()
			w.Header().Set("X-Request-Id", id)
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			start := now()
			next.ServeHTTP(sw, r)
			log.Info("http", "request_id", id, "method", r.Method, "path", r.URL.Path, "status", sw.status, "ms", now().Sub(start).Milliseconds())
		})
	}
}
