package auth

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/text/unicode/norm"
)

// Limiter slows down password guessing with exponential backoff.
//
// The model is RESERVE BEFORE VERIFY. Acquire checks the lock and, in the same critical section, counts
// the attempt as a failure in advance. Only a success (Reset) or a non-credential error (Release) takes
// it back. A separate "check, verify, then record" sequence would let any number of concurrent requests
// pass the check before the first failure is recorded (the independent review proved 200 of 200 passing
// a threshold of 5).
//
// After Threshold counted attempts the key is locked for BaseLock, doubling with each further counted
// attempt up to MaxLock. Counters decay: a key that has been quiet for DecayAfter starts from zero, so
// typos spread over months never add up to a lock.
//
// The table is bounded and fails SAFE. When it is full the oldest key that is NOT locked is evicted; a
// currently locked key is never evicted (otherwise flooding the table with junk keys would erase a lock),
// and if every key is locked a new key is refused until one expires.
//
// Trade-off, stated plainly: a per-username lock lets an attacker who knows a username keep that
// account locked. The lock is capped at MaxLock, the address limiter runs beside it, and Reset (wired to
// an administrator console command) clears it.
type Limiter struct {
	Threshold  int
	BaseLock   time.Duration
	MaxLock    time.Duration
	MaxKeys    int
	DecayAfter time.Duration
	Now        func() time.Time

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
	if l.DecayAfter <= 0 {
		l.DecayAfter = time.Hour
	}
}

// Acquire is called BEFORE the password is verified. It returns ok=false (and how long to wait) if the
// key is locked or the table is saturated with locks; otherwise it counts this attempt and returns
// ok=true. The attempt that reaches the threshold is still allowed to run; the next one is not.
func (l *Limiter) Acquire(key string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.init()
	now := l.now()
	e := l.entries[key]
	if e != nil {
		if now.Before(e.lockedUntil) {
			return false, e.lockedUntil.Sub(now)
		}
		if now.Sub(e.lastSeen) > l.DecayAfter {
			e.failures = 0 // quiet for a long time: start again
		}
	} else {
		if wait, full := l.makeRoom(now); full {
			return false, wait
		}
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
	return true, 0
}

// Release takes back one counted attempt: used when an attempt turned out not to be a credential
// failure (a database error, a cancelled request) and for the address counter after a success. It never
// clears a lock that is currently active.
func (l *Limiter) Release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.entries[key]; e != nil && e.failures > 0 {
		e.failures--
		if e.failures == 0 && !l.now().Before(e.lockedUntil) {
			delete(l.entries, key)
		}
	}
}

// Reset clears a key completely: after a successful login, and for an administrator's unlock.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// Locked reports whether the key is locked now, without counting an attempt.
func (l *Limiter) Locked(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.entries[key]; e != nil {
		if now := l.now(); now.Before(e.lockedUntil) {
			return true, e.lockedUntil.Sub(now)
		}
	}
	return false, 0
}

// makeRoom frees space for one new key. It never evicts a locked key. If every entry is locked it
// reports full=true with the shortest remaining lock, and the caller refuses the new key.
func (l *Limiter) makeRoom(now time.Time) (wait time.Duration, full bool) {
	if len(l.entries) < l.MaxKeys {
		return 0, false
	}
	var oldestKey string
	var oldest time.Time
	shortest := time.Duration(-1)
	for k, e := range l.entries {
		if now.Before(e.lockedUntil) {
			if r := e.lockedUntil.Sub(now); shortest < 0 || r < shortest {
				shortest = r
			}
			continue
		}
		if now.Sub(e.lastSeen) > l.DecayAfter { // decayed: it would start from zero anyway
			delete(l.entries, k)
			continue
		}
		if oldestKey == "" || e.lastSeen.Before(oldest) {
			oldestKey, oldest = k, e.lastSeen
		}
	}
	if len(l.entries) < l.MaxKeys {
		return 0, false
	}
	if oldestKey != "" {
		delete(l.entries, oldestKey)
		return 0, false
	}
	if shortest < 0 {
		shortest = l.BaseLock
	}
	return shortest, true
}

// CanonicalUsername is the ONE normal form of a username, used by the limiter and (when it exists) by
// the user store, so that an attacker cannot spread guesses over spellings of one account (fullwidth
// letters, the Kelvin sign, trailing spaces...). NFKC, lower case, trimmed.
func CanonicalUsername(s string) string {
	return strings.ToLower(norm.NFKC.String(strings.TrimSpace(s)))
}

// AddrKey is the limiter key for a client address. IPv6 clients are grouped by /64, because one
// subscriber normally controls a whole /64 and would otherwise have 2^64 distinct keys. IPv4-mapped
// IPv6 is treated as IPv4. Anything unparseable shares one bucket instead of creating unbounded keys.
func AddrKey(addr string) string {
	addr = strings.TrimSpace(addr)
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		addr = ap.Addr().String()
	}
	ip, err := netip.ParseAddr(strings.Trim(addr, "[]"))
	if err != nil {
		return "a:unparsed"
	}
	ip = ip.WithZone("").Unmap()
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return "a:" + p.String()
	}
	return "a:" + ip.String()
}

// LoginGuard combines a per-username and a per-client-address limiter.
type LoginGuard struct {
	byUser *Limiter
	byAddr *Limiter
}

// NewLoginGuard builds a guard with sensible defaults: 5 attempts lock a username, 20 lock an address.
func NewLoginGuard(now func() time.Time) *LoginGuard {
	return &LoginGuard{
		byUser: &Limiter{Threshold: 5, BaseLock: 30 * time.Second, MaxLock: 15 * time.Minute, Now: now},
		byAddr: &Limiter{Threshold: 20, BaseLock: 30 * time.Second, MaxLock: 15 * time.Minute, Now: now},
	}
}

func userKey(username string) string { return "u:" + CanonicalUsername(username) }

// Attempt is one reserved login attempt. Unless Succeeded or Cancel is called, it counts as a failure.
type Attempt struct {
	g          *LoginGuard
	uKey, aKey string
	once       sync.Once
}

// Begin reserves an attempt BEFORE the password is checked. ok=false means the username or the address
// is locked (or the table is saturated): answer 429 with wait as Retry-After and do not verify. Unknown
// usernames are reserved exactly like known ones, so the throttle reveals nothing about which exist.
func (g *LoginGuard) Begin(username, addr string) (a *Attempt, wait time.Duration, ok bool) {
	aKey, uKey := AddrKey(addr), userKey(username)
	okA, wA := g.byAddr.Acquire(aKey)
	if !okA {
		return nil, wA, false
	}
	okU, wU := g.byUser.Acquire(uKey)
	if !okU {
		g.byAddr.Release(aKey) // blocked by the username: do not charge the address for it
		return nil, wU, false
	}
	return &Attempt{g: g, uKey: uKey, aKey: aKey}, 0, true
}

// Succeeded records a correct password: the username's counter is cleared and the address gets its
// attempt back (it keeps counting failures against other usernames).
func (a *Attempt) Succeeded() {
	a.once.Do(func() {
		a.g.byUser.Reset(a.uKey)
		a.g.byAddr.Release(a.aKey)
	})
}

// Cancel gives both attempts back: the request failed for a reason that is not a wrong password (a
// database error, a client that went away).
func (a *Attempt) Cancel() {
	a.once.Do(func() {
		a.g.byUser.Release(a.uKey)
		a.g.byAddr.Release(a.aKey)
	})
}

// Unlock clears a username's lock. It is for the administrator console (a locked-out administrator
// resets from the server, not from the web).
func (g *LoginGuard) Unlock(username string) { g.byUser.Reset(userKey(username)) }
