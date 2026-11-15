package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)} }
func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// ---- Limiter ------------------------------------------------------------------------------------

func TestLimiterLocksAfterThresholdAndBacksOff(t *testing.T) {
	c := newClock()
	l := &Limiter{Threshold: 3, BaseLock: 10 * time.Second, MaxLock: 60 * time.Second, Now: c.Now}
	for i := 0; i < 2; i++ {
		l.Fail("k")
		if ok, _ := l.Allow("k"); !ok {
			t.Fatalf("must not lock before the threshold (after %d failures)", i+1)
		}
	}
	l.Fail("k") // 3rd: locked 10 s
	ok, wait := l.Allow("k")
	if ok || wait != 10*time.Second {
		t.Fatalf("after 3 failures: ok=%v wait=%v, want locked for 10s", ok, wait)
	}
	c.Add(10 * time.Second)
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("must be allowed again once the lock has passed")
	}
	l.Fail("k") // 4th failure: doubles to 20 s
	if _, wait := l.Allow("k"); wait != 20*time.Second {
		t.Fatalf("backoff should double to 20s, got %v", wait)
	}
	c.Add(20 * time.Second)
	l.Fail("k") // 5th: 40 s
	if _, wait := l.Allow("k"); wait != 40*time.Second {
		t.Fatalf("want 40s, got %v", wait)
	}
	c.Add(40 * time.Second)
	for i := 0; i < 5; i++ { // far past the cap
		l.Fail("k")
		c.Add(time.Hour)
	}
	l.Fail("k")
	if _, wait := l.Allow("k"); wait != 60*time.Second {
		t.Fatalf("lock must be capped at MaxLock, got %v", wait)
	}
}

func TestLimiterSuccessClearsAndKeysAreIndependent(t *testing.T) {
	c := newClock()
	l := &Limiter{Threshold: 2, BaseLock: time.Minute, Now: c.Now}
	l.Fail("alice")
	l.Fail("alice")
	if ok, _ := l.Allow("alice"); ok {
		t.Fatal("alice should be locked")
	}
	if ok, _ := l.Allow("bob"); !ok {
		t.Fatal("bob must be unaffected")
	}
	l.Succeed("alice")
	if ok, _ := l.Allow("alice"); !ok {
		t.Fatal("success must clear the lock")
	}
}

func TestLimiterMemoryIsBounded(t *testing.T) {
	c := newClock()
	l := &Limiter{Threshold: 3, MaxKeys: 50, Now: c.Now}
	for i := 0; i < 5000; i++ {
		l.Fail(strings.Repeat("k", 1) + string(rune('a'+i%26)) + strings.Repeat("x", i%7) + time.Duration(i).String())
		c.Add(time.Millisecond)
	}
	l.mu.Lock()
	n := len(l.entries)
	l.mu.Unlock()
	if n > 50 {
		t.Fatalf("limiter kept %d keys, want at most 50", n)
	}
}

func TestLoginGuard(t *testing.T) {
	c := newClock()
	g := NewLoginGuard(c.Now)
	for i := 0; i < 5; i++ {
		if ok, _ := g.Check("Alice", "203.0.113.9"); !ok {
			t.Fatalf("attempt %d must be allowed", i+1)
		}
		g.Failure("Alice", "203.0.113.9")
	}
	if ok, wait := g.Check("alice", "198.51.100.1"); ok || wait <= 0 {
		t.Fatalf("username lock must apply from any address and ignore case: ok=%v wait=%v", ok, wait)
	}
	if ok, _ := g.Check("bob", "198.51.100.1"); !ok {
		t.Fatal("another user from another address must be fine")
	}
	g.Success("alice")
	if ok, _ := g.Check("alice", "198.51.100.1"); !ok {
		t.Fatal("success clears the username counter")
	}

	// One address guessing many different usernames is stopped by the address limiter.
	g2 := NewLoginGuard(c.Now)
	for i := 0; i < 20; i++ {
		g2.Failure("user"+time.Duration(i).String(), "192.0.2.77")
	}
	if ok, _ := g2.Check("someone-new", "192.0.2.77"); ok {
		t.Fatal("an address with 20 failures must be locked even for a fresh username")
	}
	if ok, _ := g2.Check("someone-new", "192.0.2.78"); !ok {
		t.Fatal("other addresses are unaffected")
	}
	// Unknown usernames are throttled exactly like known ones.
	g3 := NewLoginGuard(c.Now)
	for i := 0; i < 5; i++ {
		g3.Failure("does-not-exist", "192.0.2.1")
	}
	if ok, _ := g3.Check("does-not-exist", "192.0.2.2"); ok {
		t.Fatal("a nonexistent username must be throttled the same way")
	}
}

// ---- CSRF ---------------------------------------------------------------------------------------

func TestCSRFToken(t *testing.T) {
	c, err := NewCSRF()
	if err != nil {
		t.Fatal(err)
	}
	tok := c.Token("session-1")
	if !c.Valid("session-1", tok) {
		t.Fatal("token must validate for its own session")
	}
	if c.Valid("session-2", tok) {
		t.Fatal("token must not validate for another session")
	}
	for _, bad := range []string{"", tok + "A", tok[:len(tok)-1], "AAAA", strings.ToUpper(tok)} {
		if c.Valid("session-1", bad) {
			t.Fatalf("tampered token %q accepted", bad)
		}
	}
	if c.Valid("", tok) || c.Valid("", "") {
		t.Fatal("empty session id must never validate")
	}
	other, _ := NewCSRF()
	if other.Valid("session-1", tok) {
		t.Fatal("a token from another process key must not validate")
	}
}

func req(method, host string, h map[string]string) *http.Request {
	r := httptest.NewRequest(method, "http://"+host+"/api/v1/x", nil)
	r.Host = host
	for k, v := range h {
		r.Header.Set(k, v)
	}
	return r
}

func TestCheckOrigin(t *testing.T) {
	host := "127.0.0.1:8443"
	cases := []struct {
		name   string
		method string
		hdr    map[string]string
		ok     bool
	}{
		{"GET needs nothing", "GET", nil, true},
		{"HEAD needs nothing", "HEAD", nil, true},
		{"POST same origin", "POST", map[string]string{"Origin": "http://127.0.0.1:8443"}, true},
		{"POST same origin https", "POST", map[string]string{"Origin": "https://127.0.0.1:8443"}, true},
		{"POST same origin host case", "POST", map[string]string{"Origin": "http://127.0.0.1:8443"}, true},
		{"POST evil origin", "POST", map[string]string{"Origin": "https://evil.example"}, false},
		{"POST other port", "POST", map[string]string{"Origin": "http://127.0.0.1:9999"}, false},
		{"POST suffix trick", "POST", map[string]string{"Origin": "http://127.0.0.1:8443.evil.example"}, false},
		{"POST origin null", "POST", map[string]string{"Origin": "null"}, false},
		{"POST garbage origin", "POST", map[string]string{"Origin": "::::"}, false},
		{"POST origin wins over fetch metadata", "POST", map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "same-origin"}, false},
		{"POST fetch metadata same-origin", "POST", map[string]string{"Sec-Fetch-Site": "same-origin"}, true},
		{"POST fetch metadata none", "POST", map[string]string{"Sec-Fetch-Site": "none"}, true},
		{"POST fetch metadata cross-site", "POST", map[string]string{"Sec-Fetch-Site": "cross-site"}, false},
		{"POST fetch metadata same-site is not enough", "POST", map[string]string{"Sec-Fetch-Site": "same-site"}, false},
		{"POST no headers", "POST", nil, false},
		{"PUT no headers", "PUT", nil, false},
		{"PATCH no headers", "PATCH", nil, false},
		{"DELETE no headers", "DELETE", nil, false},
	}
	for _, c := range cases {
		err := CheckOrigin(req(c.method, host, c.hdr))
		if c.ok && err != nil {
			t.Errorf("%s: want allowed, got %v", c.name, err)
		}
		if !c.ok && err != ErrCrossSite {
			t.Errorf("%s: want ErrCrossSite, got %v", c.name, err)
		}
	}
}

// ---- Sessions -----------------------------------------------------------------------------------

func newManager(c *clock) *Manager {
	return &Manager{Store: &MemStore{}, Idle: 30 * time.Minute, Absolute: 12 * time.Hour, Now: c.Now}
}

func TestSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	m := newManager(c)

	tok, s, err := m.Create(ctx, "u1")
	if err != nil || tok == "" || s.UserID != "u1" {
		t.Fatalf("create: %v", err)
	}
	if string(s.TokenHash) == tok {
		t.Fatal("the store must hold a digest, never the token")
	}
	got, err := m.Authenticate(ctx, tok)
	if err != nil || got.UserID != "u1" {
		t.Fatalf("authenticate: %v", err)
	}
	if got.ID() == "" || got.ID() == tok {
		t.Fatal("session id for CSRF binding must exist and differ from the token")
	}

	// Idle timeout.
	c.Add(31 * time.Minute)
	if _, err := m.Authenticate(ctx, tok); err != ErrNoSession {
		t.Fatalf("idle timeout: want ErrNoSession, got %v", err)
	}
	if _, ok, _ := m.Store.Get(ctx, HashToken(tok)); ok {
		t.Fatal("an expired session must be deleted when seen")
	}
}

func TestSessionSlidesButNeverPastTheAbsoluteLimit(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	m := newManager(c)
	tok, _, _ := m.Create(ctx, "u1")

	// Active every 20 minutes: stays alive past the 30 minute idle window.
	for i := 0; i < 30; i++ { // 10 hours
		c.Add(20 * time.Minute)
		if _, err := m.Authenticate(ctx, tok); err != nil {
			t.Fatalf("an active session must stay alive (step %d): %v", i, err)
		}
	}
	// ...but the absolute limit (12 h) still ends it, however active it is.
	for i := 0; i < 10; i++ {
		c.Add(20 * time.Minute)
		_, err := m.Authenticate(ctx, tok)
		if c.Now().Sub(time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)) >= 12*time.Hour {
			if err != ErrNoSession {
				t.Fatalf("past 12 h the session must be dead, got %v", err)
			}
			return
		}
	}
	t.Fatal("test did not reach the absolute limit")
}

func TestSessionTokensAreFreshAndUnknownLooksLikeExpired(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	m := newManager(c)
	a, _, _ := m.Create(ctx, "u1")
	b, _, _ := m.Create(ctx, "u1")
	if a == b {
		t.Fatal("every login must mint a new token (no session fixation)")
	}
	_, e1 := m.Authenticate(ctx, "never-issued")
	c.Add(time.Hour)
	_, e2 := m.Authenticate(ctx, a)
	if e1 != ErrNoSession || e2 != ErrNoSession {
		t.Fatalf("unknown and expired must both be ErrNoSession, got %v / %v", e1, e2)
	}
	for _, bad := range []string{"", strings.Repeat("x", 129)} {
		if _, err := m.Authenticate(ctx, bad); err != ErrNoSession {
			t.Errorf("token %q: %v", bad, err)
		}
	}
}

func TestRevoke(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	m := newManager(c)
	a, _, _ := m.Create(ctx, "u1")
	b, _, _ := m.Create(ctx, "u1")
	o, _, _ := m.Create(ctx, "u2")
	if err := m.Revoke(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Authenticate(ctx, a); err != ErrNoSession {
		t.Fatal("revoked session must be dead")
	}
	if _, err := m.Authenticate(ctx, b); err != nil {
		t.Fatal("other sessions of the user survive a single logout")
	}
	if err := m.RevokeUser(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Authenticate(ctx, b); err != ErrNoSession {
		t.Fatal("RevokeUser must end all of the user's sessions")
	}
	if _, err := m.Authenticate(ctx, o); err != nil {
		t.Fatal("RevokeUser must not touch other users")
	}
}

func TestDeleteExpired(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	m := newManager(c)
	m.Create(ctx, "u1")
	m.Create(ctx, "u2")
	c.Add(time.Hour)
	live, _, _ := m.Create(ctx, "u3")
	n, err := m.Store.DeleteExpired(ctx, c.Now())
	if err != nil || n != 2 {
		t.Fatalf("deleted %d, err %v; want 2", n, err)
	}
	if _, err := m.Authenticate(ctx, live); err != nil {
		t.Fatal("the live session must survive")
	}
}

func TestSessionCookie(t *testing.T) {
	exp := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	secure := NewSessionCookie("tok", exp, true)
	if secure.Name != "__Host-lk_session" || !secure.Secure || !secure.HttpOnly || secure.SameSite != http.SameSiteStrictMode || secure.Path != "/" || secure.Domain != "" {
		t.Fatalf("TLS cookie must be __Host-, Secure, HttpOnly, SameSite=Strict, Path=/, no Domain: %+v", secure)
	}
	plain := NewSessionCookie("tok", exp, false)
	if plain.Name != "lk_session" || plain.Secure || !plain.HttpOnly || plain.SameSite != http.SameSiteStrictMode || plain.Domain != "" {
		t.Fatalf("loopback cookie: %+v", plain)
	}
	for _, s := range []bool{true, false} {
		clear := ClearSessionCookie(s)
		if clear.MaxAge >= 0 || clear.Value != "" || clear.Name != SessionCookieName(s) {
			t.Fatalf("clear cookie: %+v", clear)
		}
	}
}

// ---- Bootstrap ----------------------------------------------------------------------------------

func TestBootstrapIsSingleUseAndExpires(t *testing.T) {
	c := newClock()
	b, tok, err := NewBootstrap(c.Now)
	if err != nil {
		t.Fatal(err)
	}
	if !b.Active() {
		t.Fatal("fresh token must be active")
	}
	if b.Consume("wrong") || b.Consume("") || b.Consume(tok+"x") {
		t.Fatal("wrong guesses must fail")
	}
	if !b.Active() {
		t.Fatal("a wrong guess must not burn the token (or anyone could invalidate it)")
	}
	if !b.Consume(tok) {
		t.Fatal("the right token must work once")
	}
	if b.Consume(tok) || b.Active() {
		t.Fatal("the token is single use")
	}

	b2, tok2, _ := NewBootstrap(c.Now)
	c.Add(BootstrapLifetime)
	if b2.Consume(tok2) || b2.Active() {
		t.Fatal("an expired token must not work")
	}
}
