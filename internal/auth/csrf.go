package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// CSRF issues and checks per-session tokens: HMAC-SHA256(serverKey, sessionID). Nothing is stored. The
// key is random per process, so after a restart clients fetch a fresh token (the UI does this on a
// 403 "csrf" response). Combined with SameSite=Strict cookies and the Origin check below, a forged
// cross-site request needs three independent protections to fail.
type CSRF struct{ key []byte }

// NewCSRF creates a CSRF helper with a fresh random key.
func NewCSRF() (*CSRF, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("auth: random source failed: %w", err)
	}
	return &CSRF{key: k}, nil
}

// Token returns the CSRF token for a session.
func (c *CSRF) Token(sessionID string) string {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte("lockkeeper-csrf\x00"))
	m.Write([]byte(sessionID))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Valid reports whether token is the token for sessionID, in constant time.
func (c *CSRF) Valid(sessionID, token string) bool {
	if token == "" || sessionID == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Token(sessionID)), []byte(token)) == 1
}

// ErrCrossSite is returned for a state-changing request that did not come from this site.
var ErrCrossSite = errors.New("auth: cross-site request refused")

// IsUnsafeMethod reports whether a method can change state and therefore needs CSRF protection.
func IsUnsafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	}
	return true
}

// CheckOrigin enforces the same-origin rule for state-changing requests:
//   - an Origin header, when present, must name the host the request was sent to AND use the scheme the
//     deployment is served with (https is true when TLS ends here or at a proxy the operator declared;
//     an "http://" origin must not pass on an HTTPS site, where a network attacker controls it);
//     "null" never passes;
//   - without Origin, Sec-Fetch-Site must be "same-origin" (or "none" for a user-typed navigation);
//   - with neither header the request is refused. Browsers always send at least one on a cross-site
//     write, and a non-browser client has no business using a cookie session.
//
// Safe methods are not checked.
func CheckOrigin(r *http.Request, https bool) error {
	if !IsUnsafeMethod(r.Method) {
		return nil
	}
	return CheckSameOrigin(r, https)
}

// CheckSameOrigin applies the same-origin rule whatever the method. Use it for requests that change
// nothing but still must not be driven from another site: a Server-Sent Events stream or a WebSocket
// upgrade is a GET, so CheckOrigin would wave it through, and an attacker page could otherwise open it
// with the victim's cookie and read the live data.
func CheckSameOrigin(r *http.Request, https bool) error {
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" || strings.EqualFold(origin, "null") {
			return ErrCrossSite
		}
		want := "http"
		if https {
			want = "https"
		}
		if !strings.EqualFold(u.Scheme, want) || !strings.EqualFold(u.Host, r.Host) {
			return ErrCrossSite
		}
		return nil
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return nil
	}
	return ErrCrossSite
}
