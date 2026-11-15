package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/auth"
)

// Sessions returns the SQLite-backed auth.SessionStore. It is a separate type, not methods on Store,
// so "Get" and "Delete" do not read as if they were about the whole state database.
func (s *Store) Sessions() auth.SessionStore { return sessionStore{db: s.db} }

type sessionStore struct{ db *sql.DB }

var _ auth.SessionStore = sessionStore{}

func (s sessionStore) Put(ctx context.Context, x auth.Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (token_hash, user_id, created_at, last_seen, expires_at, idle_until)
		VALUES (?, ?, ?, ?, ?, ?)`,
		x.TokenHash, x.UserID, x.CreatedAt.UnixMilli(), x.LastSeen.UnixMilli(), x.ExpiresAt.UnixMilli(), x.IdleUntil.UnixMilli())
	if err != nil {
		return fmt.Errorf("store session: %w", err)
	}
	return nil
}

func (s sessionStore) Get(ctx context.Context, tokenHash []byte) (auth.Session, bool, error) {
	var created, seen, exp, idle int64
	x := auth.Session{TokenHash: tokenHash}
	err := s.db.QueryRowContext(ctx, `SELECT user_id, created_at, last_seen, expires_at, idle_until FROM sessions WHERE token_hash = ?`, tokenHash).
		Scan(&x.UserID, &created, &seen, &exp, &idle)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.Session{}, false, nil
	}
	if err != nil {
		return auth.Session{}, false, fmt.Errorf("read session: %w", err)
	}
	x.CreatedAt, x.LastSeen = time.UnixMilli(created).UTC(), time.UnixMilli(seen).UTC()
	x.ExpiresAt, x.IdleUntil = time.UnixMilli(exp).UTC(), time.UnixMilli(idle).UTC()
	return x, true, nil
}

func (s sessionStore) Touch(ctx context.Context, tokenHash []byte, lastSeen, idleUntil time.Time) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen = ?, idle_until = ? WHERE token_hash = ?`,
		lastSeen.UnixMilli(), idleUntil.UnixMilli(), tokenHash); err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

func (s sessionStore) Delete(ctx context.Context, tokenHash []byte) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s sessionStore) DeleteUser(ctx context.Context, userID string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("delete user sessions: %w", err)
	}
	return nil
}

func (s sessionStore) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ? OR idle_until <= ?`, now.UnixMilli(), now.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
