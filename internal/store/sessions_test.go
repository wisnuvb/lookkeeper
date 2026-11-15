package store

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/auth"
)

func newSessionFixture(t *testing.T) (*Store, string, *auth.Manager, *time.Time) {
	t.Helper()
	s, _ := openTemp(t)
	u, err := s.CreateFirstAdmin(context.Background(), "admin", fakeHash, base)
	if err != nil {
		t.Fatal(err)
	}
	now := base
	m := &auth.Manager{Store: s.Sessions(), Now: func() time.Time { return now }}
	return s, u.ID, m, &now
}

// The real auth.Manager drives the SQLite store: create, authenticate, slide, expire, revoke.
func TestSessionLifecycleThroughManager(t *testing.T) {
	ctx := context.Background()
	_, uid, m, now := newSessionFixture(t)

	tok, sess, err := m.Create(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Authenticate(ctx, tok)
	if err != nil || got.UserID != uid || !got.ExpiresAt.Equal(sess.ExpiresAt) {
		t.Fatalf("authenticate: %+v %v", got, err)
	}

	// Activity slides the idle deadline but never past the absolute one.
	*now = now.Add(20 * time.Minute)
	if got, err = m.Authenticate(ctx, tok); err != nil || !got.IdleUntil.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("idle deadline must slide: %+v %v", got, err)
	}
	stored, ok, _ := m.Store.Get(ctx, auth.HashToken(tok))
	if !ok || !stored.IdleUntil.Equal(got.IdleUntil) {
		t.Fatalf("the slide must be persisted: %+v ok=%v", stored, ok)
	}

	// Idle expiry.
	*now = now.Add(31 * time.Minute)
	if _, err := m.Authenticate(ctx, tok); err != auth.ErrNoSession {
		t.Fatalf("idle session must be refused, got %v", err)
	}
	if _, ok, _ := m.Store.Get(ctx, auth.HashToken(tok)); ok {
		t.Fatal("an expired session is deleted when presented")
	}
}

func TestSessionAbsoluteLimitHoldsDespiteActivity(t *testing.T) {
	ctx := context.Background()
	_, uid, m, now := newSessionFixture(t)
	tok, _, _ := m.Create(ctx, uid)
	for i := 0; i < 13*4; i++ { // active every 15 minutes for 13 hours
		*now = now.Add(15 * time.Minute)
		if _, err := m.Authenticate(ctx, tok); err != nil {
			if i < 12*4-1 {
				t.Fatalf("session died too early at step %d: %v", i, err)
			}
			return
		}
	}
	t.Fatal("a session must not outlive its 12 hour absolute limit")
}

func TestRevokeAndRevokeUser(t *testing.T) {
	ctx := context.Background()
	s, uid, m, _ := newSessionFixture(t)
	other, err := s.CreateUser(ctx, "other", auth.Viewer, fakeHash, base)
	if err != nil {
		t.Fatal(err)
	}
	a, _, _ := m.Create(ctx, uid)
	b, _, _ := m.Create(ctx, uid)
	c, _, _ := m.Create(ctx, other.ID)

	if err := m.Revoke(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Authenticate(ctx, a); err != auth.ErrNoSession {
		t.Fatal("a revoked token must stop working")
	}
	if _, err := m.Authenticate(ctx, b); err != nil {
		t.Fatal("revoking one session must not touch another")
	}
	if err := m.RevokeUser(ctx, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Authenticate(ctx, b); err != auth.ErrNoSession {
		t.Fatal("RevokeUser must end every session of that user")
	}
	if _, err := m.Authenticate(ctx, c); err != nil {
		t.Fatal("RevokeUser must not end another user's session")
	}
}

func TestDeleteExpiredKeepsLiveSessions(t *testing.T) {
	ctx := context.Background()
	_, uid, m, now := newSessionFixture(t)
	live, _, _ := m.Create(ctx, uid)
	*now = now.Add(10 * time.Minute)
	young, _, _ := m.Create(ctx, uid) // still idle-valid when `live` is not
	*now = now.Add(25 * time.Minute)  // live: idle since +0 → 35 min > 30; young: 25 min
	n, err := m.Store.DeleteExpired(ctx, *now)
	if err != nil || n != 1 {
		t.Fatalf("want exactly the idle one removed, got n=%d err=%v", n, err)
	}
	if _, err := m.Authenticate(ctx, live); err != auth.ErrNoSession {
		t.Fatal("the idle session must be gone")
	}
	if _, err := m.Authenticate(ctx, young); err != nil {
		t.Fatalf("the live session must survive: %v", err)
	}
}

// Disabling or removing the account must take its sessions with it at the database level too.
func TestSessionsCascadeWhenUserRowIsRemoved(t *testing.T) {
	ctx := context.Background()
	s, uid, m, _ := newSessionFixture(t)
	if _, _, err := m.Create(ctx, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, uid); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT count(*) FROM sessions`).Scan(&n)
	if n != 0 {
		t.Fatalf("foreign keys must cascade, %d sessions left", n)
	}
}

// Only the digest of a token reaches the disk, never the token itself.
func TestStateFileNeverContainsTheSessionToken(t *testing.T) {
	ctx := context.Background()
	s, path := openTemp(t)
	u, _ := s.CreateFirstAdmin(ctx, "admin", fakeHash, base)
	m := &auth.Manager{Store: s.Sessions(), Now: func() time.Time { return base }}
	tok, _, err := m.Create(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{path, path + "-wal"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if strings.Contains(string(b), tok) {
			t.Fatalf("session token found in %s", f)
		}
	}
}
