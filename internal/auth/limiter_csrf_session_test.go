package auth

import (
	"context"
	"fmt"
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
	for i := 1; i <= 3; i++ { // the attempt that reaches the threshold still runs; the next one does not
		if ok, _ := l.Acquire("k"); !ok {
			t.Fatalf("attempt %d must be allowed", i)
		}
	}
	ok, wait := l.Acquire("k")
	if ok || wait != 10*time.Second {
		t.Fatalf("4th attempt: ok=%v wait=%v, want locked for 10s", ok, wait)
	}
	c.Add(10 * time.Second)
	if ok, _ := l.Acquire("k"); !ok { // counted as the 4th: lock doubles
		t.Fatal("must be allowed again once the lock has passed")
	}
	if _, wait := l.Acquire("k"); wait != 20*time.Second {
		t.Fatalf("backoff should double to 20s, got %v", wait)
	}
	c.Add(20 * time.Second)
	l.Acquire("k") // 5th counted: 40 s
	if _, wait := l.Acquire("k"); wait != 40*time.Second {
		t.Fatalf("want 40s, got %v", wait)
	}
	for i := 0; i < 6; i++ { // far past the cap
		c.Add(time.Hour)
		l.Acquire("k")
	}
	if _, wait := l.Acquire("k"); wait != 60*time.Second {
		t.Fatalf("lock must be capped at MaxLock, got %v", wait)
	}
}

// Review finding 1: with "check, then record the failure later", every concurrent request passed the
// check. Reserving in Acquire makes exactly Threshold of them run.
func TestLimiterConcurrentAttemptsCannotBypassTheThreshold(t *testing.T) {
	l := &Limiter{Threshold: 5, BaseLock: time.Hour, MaxLock: time.Hour}
	var wg sync.WaitGroup
	var mu sync.Mutex
	passed := 0
	start := make(chan struct{})
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if ok, _ := l.Acquire("admin"); ok {
				mu.Lock()
				passed++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if passed != 5 {
		t.Fatalf("%d of 200 concurrent attempts ran against a threshold of 5; want exactly 5", passed)
	}
}

func TestLimiterSuccessClearsAndKeysAreIndependent(t *testing.T) {
	c := newClock()
	l := &Limiter{Threshold: 2, BaseLock: time.Minute, Now: c.Now}
	l.Acquire("alice")
	l.Acquire("alice")
	if ok, _ := l.Acquire("alice"); ok {
		t.Fatal("alice should be locked")
	}
	if ok, _ := l.Acquire("bob"); !ok {
		t.Fatal("bob must be unaffected")
	}
	l.Reset("alice")
	if ok, _ := l.Acquire("alice"); !ok {
		t.Fatal("Reset must clear the lock")
	}
}

func TestLimiterReleaseGivesAnAttemptBackButNeverUnlocks(t *testing.T) {
	c := newClock()
	l := &Limiter{Threshold: 3, BaseLock: time.Minute, Now: c.Now}
	l.Acquire("k")
	l.Acquire("k")
	l.Release("k") // a database error, not a wrong password
	l.Acquire("k")
	if ok, _ := l.Acquire("k"); !ok { // 1 + 1 + (released) + 1 = 3 counted so far, not 4
		t.Fatal("a released attempt must not count toward the lock")
	}
	if locked, _ := l.Locked("k"); !locked {
		t.Fatal("the third counted attempt locks")
	}
	l.Release("k")
	if locked, _ := l.Locked("k"); !locked {
		t.Fatal("releasing an attempt must never lift a lock that is already active")
	}
	// Releasing an unknown key is harmless.
	l.Release("never-seen")
}

func TestLimiterCountersDecayWhenQuiet(t *testing.T) {
	c := newClock()
	l := &Limiter{Threshold: 5, BaseLock: time.Minute, DecayAfter: time.Hour, Now: c.Now}
	for i := 0; i < 4; i++ {
		l.Acquire("typo-prone")
	}
	c.Add(2 * time.Hour) // quiet for longer than the decay window
	for i := 0; i < 4; i++ {
		if ok, _ := l.Acquire("typo-prone"); !ok {
			t.Fatalf("old typos must not add up to a lock (attempt %d)", i+1)
		}
	}
	if locked, _ := l.Locked("typo-prone"); locked {
		t.Fatal("8 typos spread over two hours must not lock the account")
	}
	// But a burst inside the window still does.
	for i := 0; i < 2; i++ {
		l.Acquire("typo-prone")
	}
	if locked, _ := l.Locked("typo-prone"); !locked {
		t.Fatal("a burst inside the decay window must still lock")
	}
}

// Review finding 2: flooding the table with junk keys evicted the oldest key, locked or not, which
// erased the administrator's lock.
func TestLimiterNeverEvictsALockedKeyAndFailsClosedWhenFullOfLocks(t *testing.T) {
	c := newClock()
	l := &Limiter{Threshold: 3, BaseLock: time.Hour, MaxLock: time.Hour, MaxKeys: 50, Now: c.Now}
	for i := 0; i < 3; i++ {
		l.Acquire("admin")
	}
	if locked, _ := l.Locked("admin"); !locked {
		t.Fatal("setup: admin should be locked")
	}
	c.Add(time.Second)
	for i := 0; i < 5000; i++ { // a flood of distinct junk keys
		l.Acquire("junk-" + time.Duration(i).String())
		c.Add(time.Millisecond)
	}
	if locked, _ := l.Locked("admin"); !locked {
		t.Fatal("a locked key must survive a flood of junk keys")
	}
	l.mu.Lock()
	n := len(l.entries)
	l.mu.Unlock()
	if n > 50 {
		t.Fatalf("limiter kept %d keys, want at most 50", n)
	}

	// If EVERY slot is a lock, a new key is refused (fail closed) rather than evicting a lock.
	full := &Limiter{Threshold: 1, BaseLock: time.Hour, MaxLock: time.Hour, MaxKeys: 10, Now: c.Now}
	for i := 0; i < 10; i++ {
		full.Acquire("locked-" + time.Duration(i).String())
	}
	ok, wait := full.Acquire("newcomer")
	if ok || wait <= 0 {
		t.Fatalf("a table full of locks must refuse a new key: ok=%v wait=%v", ok, wait)
	}
	for i := 0; i < 10; i++ {
		if locked, _ := full.Locked("locked-" + time.Duration(i).String()); !locked {
			t.Fatalf("lock %d was evicted", i)
		}
	}
	c.Add(2 * time.Hour) // locks expire, room appears
	if ok, _ := full.Acquire("newcomer"); !ok {
		t.Fatal("once locks expire a new key must be accepted again")
	}
}

func TestCanonicalUsernameAndAddrKey(t *testing.T) {
	same := []string{"alice", "ALICE", "  Alice  ", "ａｌｉｃｅ", "ＡＬＩＣＥ", "alice\u00a0"}
	want := CanonicalUsername("alice")
	for _, u := range same {
		if got := CanonicalUsername(u); got != want {
			t.Errorf("CanonicalUsername(%q) = %q, want %q", u, got, want)
		}
	}
	if CanonicalUsername("\u212a") != "k" { // Kelvin sign
		t.Errorf("the Kelvin sign must fold to k, got %q", CanonicalUsername("\u212a"))
	}
	if CanonicalUsername("alice") == CanonicalUsername("alice2") {
		t.Error("different names must stay different")
	}

	k := AddrKey
	if k("203.0.113.9") != k("203.0.113.9:51234") || k("203.0.113.9") != k("::ffff:203.0.113.9") {
		t.Error("port and IPv4-mapped form must not create new keys")
	}
	if k("2001:db8:1:2::1") != k("2001:db8:1:2:ffff:ffff:ffff:ffff") || k("[2001:db8:1:2::1]:443") != k("2001:db8:1:2::1") {
		t.Error("addresses in one /64 must share a key")
	}
	if k("2001:db8:1:2::1") == k("2001:db8:1:3::1") {
		t.Error("different /64s must differ")
	}
	if k("fe80::1%eth0") != k("fe80::1") {
		t.Error("an IPv6 zone must not create a new key")
	}
	if k("not an ip") != k("another junk") || k("") != k("junk") {
		t.Error("unparseable input must share one bucket, not create unbounded keys")
	}
}

func TestLoginGuard(t *testing.T) {
	c := newClock()
	g := NewLoginGuard(c.Now)

	for i := 0; i < 5; i++ { // five wrong passwords: each Begin reserves, none calls Succeeded
		if _, _, ok := g.Begin("Alice", "203.0.113.9"); !ok {
			t.Fatalf("attempt %d must be allowed", i+1)
		}
	}
	if _, wait, ok := g.Begin("alice", "198.51.100.1"); ok || wait <= 0 {
		t.Fatalf("username lock applies from any address and ignores case: ok=%v wait=%v", ok, wait)
	}
	if _, _, ok := g.Begin("ａｌｉｃｅ", "198.51.100.2"); ok {
		t.Fatal("a fullwidth spelling of the same username must hit the same lock")
	}
	if _, _, ok := g.Begin("bob", "198.51.100.1"); !ok {
		t.Fatal("another user from another address must be fine")
	}

	g.Unlock("alice") // the administrator console
	a, _, ok := g.Begin("alice", "198.51.100.1")
	if !ok {
		t.Fatal("Unlock must clear the username lock")
	}
	a.Succeeded()

	// One address guessing many usernames is stopped by the address limiter.
	g2 := NewLoginGuard(c.Now)
	for i := 0; i < 20; i++ {
		if _, _, ok := g2.Begin("user"+time.Duration(i).String(), "192.0.2.77"); !ok {
			t.Fatalf("attempt %d from the address must be allowed", i+1)
		}
	}
	if _, _, ok := g2.Begin("someone-new", "192.0.2.77"); ok {
		t.Fatal("an address with 20 attempts must be locked even for a fresh username")
	}
	if _, _, ok := g2.Begin("someone-new", "192.0.2.78"); !ok {
		t.Fatal("other addresses are unaffected")
	}
	// Spreading over an IPv6 /64 does not help the attacker.
	g3 := NewLoginGuard(c.Now)
	for i := 0; i < 20; i++ {
		g3.Begin(fmt.Sprintf("u%d", i), fmt.Sprintf("2001:db8:5:5::%x", i+1))
	}
	if _, _, ok := g3.Begin("x", "2001:db8:5:5:dead:beef::1"); ok {
		t.Fatal("addresses of one /64 must share the address limiter")
	}
	// Unknown usernames are throttled exactly like known ones.
	g4 := NewLoginGuard(c.Now)
	for i := 0; i < 5; i++ {
		g4.Begin("does-not-exist", "192.0.2.1")
	}
	if _, _, ok := g4.Begin("does-not-exist", "192.0.2.2"); ok {
		t.Fatal("a nonexistent username must be throttled the same way")
	}
}

func TestAttemptOutcomes(t *testing.T) {
	c := newClock()
	g := NewLoginGuard(c.Now)

	// Success clears the user's counter and refunds the address's attempt.
	for i := 0; i < 4; i++ {
		g.Begin("alice", "203.0.113.9")
	}
	a, _, ok := g.Begin("alice", "203.0.113.9") // 5th: allowed, locks after it
	if !ok {
		t.Fatal("5th attempt allowed")
	}
	a.Succeeded()
	if _, _, ok := g.Begin("alice", "203.0.113.9"); !ok {
		t.Fatal("a correct password must clear the username counter")
	}

	// Cancel (a database error) refunds both.
	g2 := NewLoginGuard(c.Now)
	for i := 0; i < 10; i++ {
		at, _, ok := g2.Begin("bob", "203.0.113.9")
		if !ok {
			t.Fatalf("attempt %d: cancelled attempts must not count (%d)", i+1, i)
		}
		at.Cancel()
	}
	// Succeeded and Cancel are idempotent: a second call must not refund twice.
	g3 := NewLoginGuard(c.Now)
	at, _, _ := g3.Begin("carol", "203.0.113.9")
	at.Cancel()
	at.Cancel()
	at.Succeeded()
	for i := 0; i < 5; i++ {
		g3.Begin("carol", "203.0.113.9")
	}
	if _, _, ok := g3.Begin("carol", "203.0.113.9"); ok {
		t.Fatal("double Cancel/Succeeded must not give extra attempts")
	}
}

// A username that is blocked must not burn the caller's address budget.
func TestBlockedByUsernameDoesNotChargeTheAddress(t *testing.T) {
	c := newClock()
	g := NewLoginGuard(c.Now)
	for i := 0; i < 5; i++ {
		g.Begin("victim", "198.51.100.1")
	}
	for i := 0; i < 50; i++ { // a legitimate user behind the same NAT keeps hitting the locked name
		g.Begin("victim", "203.0.113.50")
	}
	if _, _, ok := g.Begin("someone-else", "203.0.113.50"); !ok {
		t.Fatal("attempts refused because of the username must not be charged to the address")
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
		err := CheckOrigin(req(c.method, host, c.hdr), false)
		if c.ok && err != nil {
			t.Errorf("%s: want allowed, got %v", c.name, err)
		}
		if !c.ok && err != ErrCrossSite {
			t.Errorf("%s: want ErrCrossSite, got %v", c.name, err)
		}
	}
}

// Review finding 4: the scheme was ignored, so "http://host" passed on an HTTPS deployment.
func TestCheckOriginChecksTheScheme(t *testing.T) {
	const host = "lk.example.com"
	cases := []struct {
		name   string
		origin string
		https  bool
		ok     bool
	}{
		{"https origin on an https deployment", "https://lk.example.com", true, true},
		{"http origin on an https deployment", "http://lk.example.com", true, false},
		{"http origin on a plain http deployment", "http://lk.example.com", false, true},
		{"https origin on a plain http deployment", "https://lk.example.com", false, false},
		{"scheme is case-insensitive", "HTTPS://lk.example.com", true, true},
		{"other scheme", "ftp://lk.example.com", true, false},
		{"javascript scheme", "javascript://lk.example.com", false, false},
		{"https with a different host", "https://evil.example", true, false},
	}
	for _, c := range cases {
		err := CheckOrigin(req("POST", host, map[string]string{"Origin": c.origin}), c.https)
		if c.ok && err != nil {
			t.Errorf("%s: want allowed, got %v", c.name, err)
		}
		if !c.ok && err != ErrCrossSite {
			t.Errorf("%s: want ErrCrossSite, got %v", c.name, err)
		}
	}
}

// Review note 14: an SSE stream or WebSocket upgrade is a GET; it must still be same-origin.
func TestCheckSameOriginAppliesToGET(t *testing.T) {
	const host = "127.0.0.1:8443"
	if err := CheckSameOrigin(req("GET", host, map[string]string{"Origin": "https://evil.example"}), false); err != ErrCrossSite {
		t.Errorf("a cross-origin GET stream must be refused, got %v", err)
	}
	if err := CheckSameOrigin(req("GET", host, nil), false); err != ErrCrossSite {
		t.Errorf("a GET with no origin evidence must be refused, got %v", err)
	}
	if err := CheckSameOrigin(req("GET", host, map[string]string{"Origin": "http://127.0.0.1:8443"}), false); err != nil {
		t.Errorf("a same-origin stream must pass: %v", err)
	}
	if err := CheckSameOrigin(req("GET", host, map[string]string{"Sec-Fetch-Site": "same-origin"}), false); err != nil {
		t.Errorf("fetch metadata same-origin must pass: %v", err)
	}
	// CheckOrigin itself still leaves plain page loads alone.
	if err := CheckOrigin(req("GET", host, nil), false); err != nil {
		t.Errorf("CheckOrigin must not block ordinary GETs: %v", err)
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
	// Valid never burns: validate the new admin's password first, create the account, then Consume.
	if b.Valid("wrong") || !b.Valid(tok) || !b.Valid(tok) || !b.Active() {
		t.Fatal("Valid must check without consuming")
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

func TestJanitorRemovesSessionsThatAreNeverPresentedAgain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newClock()
	m := newManager(c)
	m.Create(ctx, "u1")
	m.Create(ctx, "u2")
	c.Add(2 * time.Hour) // both are now long expired, and nobody will ever present them
	done := make(chan struct{})
	go func() { m.RunJanitor(ctx, 5*time.Millisecond); close(done) }()

	deadline := time.After(3 * time.Second)
	for {
		ms := m.Store.(*MemStore)
		ms.mu.Lock()
		n := len(ms.m)
		ms.mu.Unlock()
		if n == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("%d expired sessions were never removed", n)
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the janitor must stop when its context is cancelled")
	}
}
