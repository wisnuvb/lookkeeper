package auth

import (
	"strings"
	"sync"
	"time"
)

// Limiter slows down password guessing with exponential backoff. It tracks failures per key; after
// Threshold consecutive failures the key is locked for BaseLock, doubling with each further failure up
// to MaxLock. A success clears the key. The map is bounded so an attacker cannot exhaust memory by
// inventing keys.
//
// Trade-off, stated plainly: a per-username lock lets an attacker who knows a username keep that
// account locked (a lockout attack). The lock is capped at MaxLock and a per-IP limiter with a higher
// threshold runs beside it; the admin can always reach the server console to reset a password.
type Limiter struct {
	Threshold int
	BaseLock  time.Duration
	MaxLock   time.Duration
	MaxKeys   int
	Now       func() time.Time

	mu      sync.Mutex
	entries map[string]*entry
}

type entry struct {
	failures    int
	lockedUntil time.Time
	lastSeen    time.Time
}

func (l *Limiter) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

func (l *Limiter) init() {
	if l.entries == nil {
		l.entries = make(map[string]*entry)
	}
	if l.Threshold <= 0 {
		l.Threshold = 5
	}
	if l.BaseLock <= 0 {
		l.BaseLock = 30 * time.Second
	}
	if l.MaxLock <= 0 {
		l.MaxLock = 15 * time.Minute
	}
	if l.MaxKeys <= 0 {
		l.MaxKeys = 10_000
	}
}

// Allow reports whether the key may try now, and if not, how long to wait.
func (l *Limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.init()
	e := l.entries[key]
	if e == nil {
		return true, 0
	}
	if now := l.now(); now.Before(e.lockedUntil) {
		return false, e.lockedUntil.Sub(now)
	}
	return true, 0
}

// Fail records a failed attempt.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.init()
	now := l.now()
	e := l.entries[key]
	if e == nil {
		l.evict(now)
		e = &entry{}
		l.entries[key] = e
	}
	e.failures++
	e.lastSeen = now
	if e.failures >= l.Threshold {
		lock := l.BaseLock
		for i := l.Threshold; i < e.failures && lock < l.MaxLock; i++ {
			lock *= 2
		}
		if lock > l.MaxLock {
			lock = l.MaxLock
		}
		e.lockedUntil = now.Add(lock)
	}
}

// Succeed clears the key after a successful login.
func (l *Limiter) Succeed(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// evict makes room: first drop entries that are no longer locked and are stale, then the oldest.
func (l *Limiter) evict(now time.Time) {
	if len(l.entries) < l.MaxKeys {
		return
	}
	var oldestKey string
	var oldest time.Time
	for k, e := range l.entries {
		if now.After(e.lockedUntil) && now.Sub(e.lastSeen) > l.MaxLock {
			delete(l.entries, k)
			continue
		}
		if oldestKey == "" || e.lastSeen.Before(oldest) {
			oldestKey, oldest = k, e.lastSeen
		}
	}
	if len(l.entries) >= l.MaxKeys && oldestKey != "" {
		delete(l.entries, oldestKey)
	}
}

// LoginGuard combines a per-username and a per-client-address limiter.
type LoginGuard struct {
	byUser *Limiter
	byAddr *Limiter
}

// NewLoginGuard builds a guard with sensible defaults: 5 failures lock a username, 20 lock an address.
func NewLoginGuard(now func() time.Time) *LoginGuard {
	return &LoginGuard{
		byUser: &Limiter{Threshold: 5, BaseLock: 30 * time.Second, MaxLock: 15 * time.Minute, Now: now},
		byAddr: &Limiter{Threshold: 20, BaseLock: 30 * time.Second, MaxLock: 15 * time.Minute, Now: now},
	}
}

func userKey(username string) string { return "u:" + strings.ToLower(strings.TrimSpace(username)) }
func addrKey(addr string) string     { return "a:" + addr }

// Check returns ok=false and the wait time if either the username or the address is locked.
func (g *LoginGuard) Check(username, addr string) (bool, time.Duration) {
	okU, wU := g.byUser.Allow(userKey(username))
	okA, wA := g.byAddr.Allow(addrKey(addr))
	if okU && okA {
		return true, 0
	}
	if wA > wU {
		return false, wA
	}
	return false, wU
}

// Failure records a failed login for both keys. An unknown username is recorded too, so the throttle
// behaves identically whether or not the account exists.
func (g *LoginGuard) Failure(username, addr string) {
	g.byUser.Fail(userKey(username))
	g.byAddr.Fail(addrKey(addr))
}

// Success clears the username's counter (the address counter keeps counting: one address that
// succeeds once should not erase evidence of guessing against other accounts).
func (g *LoginGuard) Success(username string) { g.byUser.Succeed(userKey(username)) }
