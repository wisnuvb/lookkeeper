package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"
)

// Session is a logged-in browser. It carries only the user id: the user's CURRENT role and disabled
// flag are read on every request, so demoting or disabling a user takes effect immediately instead of
// when their session happens to expire.
type Session struct {
	TokenHash []byte
	UserID    string
	CreatedAt time.Time
	LastSeen  time.Time
	// ExpiresAt is the absolute deadline; IdleUntil is the sliding one.
	ExpiresAt time.Time
	IdleUntil time.Time
}

// SessionID is the stable identifier used to bind CSRF tokens (the hex-free digest, base64url).
func (s Session) ID() string { return base64.RawURLEncoding.EncodeToString(s.TokenHash) }

// SessionStore persists sessions by token digest. The SQLite implementation arrives with the state
// schema; MemStore below serves tests.
type SessionStore interface {
	Put(ctx context.Context, s Session) error
	Get(ctx context.Context, tokenHash []byte) (Session, bool, error)
	Touch(ctx context.Context, tokenHash []byte, lastSeen, idleUntil time.Time) error
	Delete(ctx context.Context, tokenHash []byte) error
	DeleteUser(ctx context.Context, userID string) error
	// DeleteExpired removes sessions past their absolute or idle deadline; it returns how many.
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}

var (
	// ErrNoSession covers a missing, unknown and expired token alike, so a caller cannot tell them apart.
	ErrNoSession = errors.New("auth: no valid session")
)

// Manager enforces session lifetime rules.
type Manager struct {
	Store    SessionStore
	Idle     time.Duration // sliding timeout, default 30 minutes
	Absolute time.Duration // hard limit regardless of activity, default 12 hours
	Now      func() time.Time
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}
func (m *Manager) idle() time.Duration {
	if m.Idle > 0 {
		return m.Idle
	}
	return 30 * time.Minute
}
func (m *Manager) absolute() time.Duration {
	if m.Absolute > 0 {
		return m.Absolute
	}
	return 12 * time.Hour
}

// Create starts a new session with a fresh random token. Because every login mints a new token there
// is nothing an attacker can plant beforehand (no session fixation).
func (m *Manager) Create(ctx context.Context, userID string) (token string, s Session, err error) {
	token, digest, err := NewToken()
	if err != nil {
		return "", Session{}, err
	}
	now := m.now()
	s = Session{TokenHash: digest, UserID: userID, CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(m.absolute()), IdleUntil: now.Add(m.idle())}
	if err := m.Store.Put(ctx, s); err != nil {
		return "", Session{}, err
	}
	return token, s, nil
}

// Authenticate resolves a cookie token to a live session and slides the idle deadline (never past the
// absolute one). Expired sessions are deleted on sight.
func (m *Manager) Authenticate(ctx context.Context, token string) (Session, error) {
	if token == "" || len(token) > 128 {
		return Session{}, ErrNoSession
	}
	digest := HashToken(token)
	s, ok, err := m.Store.Get(ctx, digest)
	if err != nil {
		return Session{}, err
	}
	if !ok {
		return Session{}, ErrNoSession
	}
	now := m.now()
	if !now.Before(s.ExpiresAt) || !now.Before(s.IdleUntil) {
		_ = m.Store.Delete(ctx, digest)
		return Session{}, ErrNoSession
	}
	idleUntil := now.Add(m.idle())
	if idleUntil.After(s.ExpiresAt) {
		idleUntil = s.ExpiresAt
	}
	// Writing on every request would hammer SQLite; slide only when at least a minute has passed.
	if now.Sub(s.LastSeen) >= time.Minute {
		if err := m.Store.Touch(ctx, digest, now, idleUntil); err != nil {
			return Session{}, err
		}
		s.LastSeen, s.IdleUntil = now, idleUntil
	}
	return s, nil
}

// Revoke ends one session (logout).
func (m *Manager) Revoke(ctx context.Context, token string) error {
	return m.Store.Delete(ctx, HashToken(token))
}

// RevokeUser ends every session of a user (password change, account disabled, role change).
func (m *Manager) RevokeUser(ctx context.Context, userID string) error {
	return m.Store.DeleteUser(ctx, userID)
}

// Cookie names. The __Host- prefix makes the browser refuse the cookie unless it is Secure, has
// Path=/ and no Domain, which blocks a sibling subdomain from planting one.
const (
	cookieSecure = "__Host-lk_session"
	cookiePlain  = "lk_session"
)

// SessionCookieName is the cookie to read for a request. When the connection is not TLS (loopback
// during local use) the __Host- form cannot be used.
func SessionCookieName(secure bool) string {
	if secure {
		return cookieSecure
	}
	return cookiePlain
}

// Known limit on plain-HTTP loopback: cookies are scoped by host, not by port, so another service the same
// browser reaches on http://127.0.0.1:<other port> is sent this cookie. The Origin check stops that
// service from WRITING through the session, but it could read the cookie. Serving the UI over TLS under
// its own host name (which also selects the __Host- form) removes the exposure.
//
// NewSessionCookie builds the session cookie: HttpOnly (no script access), SameSite=Strict, Path=/,
// Secure whenever the request arrived over TLS. A non-TLS cookie is only possible on loopback because
// the server refuses to listen elsewhere without TLS.
func NewSessionCookie(token string, expires time.Time, secure bool) *http.Cookie {
	return &http.Cookie{
		Name: SessionCookieName(secure), Value: token, Path: "/", Expires: expires,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode,
	}
}

// ClearSessionCookie expires the cookie in the browser.
func ClearSessionCookie(secure bool) *http.Cookie {
	return &http.Cookie{Name: SessionCookieName(secure), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode}
}

// MemStore is an in-memory SessionStore for tests.
type MemStore struct {
	mu sync.Mutex
	m  map[string]Session
}

func (s *MemStore) key(h []byte) string { return string(h) }

func (s *MemStore) Put(_ context.Context, x Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]Session{}
	}
	s.m[s.key(x.TokenHash)] = x
	return nil
}
func (s *MemStore) Get(_ context.Context, h []byte) (Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.m[s.key(h)]
	return x, ok, nil
}
func (s *MemStore) Touch(_ context.Context, h []byte, seen, idle time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if x, ok := s.m[s.key(h)]; ok {
		x.LastSeen, x.IdleUntil = seen, idle
		s.m[s.key(h)] = x
	}
	return nil
}
func (s *MemStore) Delete(_ context.Context, h []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, s.key(h))
	return nil
}
func (s *MemStore) DeleteUser(_ context.Context, user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if v.UserID == user {
			delete(s.m, k)
		}
	}
	return nil
}
func (s *MemStore) DeleteExpired(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, v := range s.m {
		if !now.Before(v.ExpiresAt) || !now.Before(v.IdleUntil) {
			delete(s.m, k)
			n++
		}
	}
	return n, nil
}

// RunJanitor deletes expired sessions every interval until ctx is cancelled. Without it, sessions that
// are never presented again (a closed laptop, a lost cookie) stay in the database for good. It blocks;
// run it in a goroutine owned by the server.
func (m *Manager) RunJanitor(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 10 * time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = m.Store.DeleteExpired(ctx, m.now())
		}
	}
}
