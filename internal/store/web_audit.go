package store

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// WebAuditOutcome is how a web action ended.
type WebAuditOutcome string

const (
	AuditOK     WebAuditOutcome = "ok"
	AuditDenied WebAuditOutcome = "denied" // authenticated but not permitted, or a failed login
	AuditError  WebAuditOutcome = "error"
)

// WebAuditEvent is one thing a person did through the web interface. Detail is a short, already
// scrubbed note (never a password, token, DSN or SQL); it is truncated here as a last line of defence
// against a runaway value, not as a substitute for scrubbing.
type WebAuditEvent struct {
	ID      int64
	At      time.Time
	ActorID string // user id; empty for an unauthenticated attempt
	Actor   string // username as it was at the time
	Action  string // e.g. "login", "connection.create"
	Target  string
	Outcome WebAuditOutcome
	Remote  string // client address as seen by the server (after the trusted-proxy policy)
	Detail  string
}

const (
	maxAuditField  = 256
	maxAuditDetail = 512
)

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) { // never cut a multi-byte character in half
		s = s[:len(s)-1]
	}
	return s
}

// AppendWebAudit records an event. The table is append-only (triggers refuse UPDATE and DELETE).
func (s *Store) AppendWebAudit(ctx context.Context, e WebAuditEvent) error {
	switch e.Outcome {
	case AuditOK, AuditDenied, AuditError:
	default:
		return fmt.Errorf("web audit: unknown outcome %q", e.Outcome)
	}
	if strings.TrimSpace(e.Action) == "" {
		return fmt.Errorf("web audit: action is required")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO web_audit (ts, actor_id, actor, action, target, outcome, remote, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.At.UnixMilli(), clip(e.ActorID, maxAuditField), clip(e.Actor, maxAuditField), clip(e.Action, maxAuditField),
		clip(e.Target, maxAuditField), string(e.Outcome), clip(e.Remote, maxAuditField), clip(e.Detail, maxAuditDetail))
	if err != nil {
		return fmt.Errorf("append web audit: %w", err)
	}
	return nil
}

// ListWebAudit returns the newest events first. beforeID > 0 pages backwards from that id; limit is
// capped at 500.
func (s *Store) ListWebAudit(ctx context.Context, beforeID int64, limit int) ([]WebAuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id, ts, actor_id, actor, action, target, outcome, remote, detail FROM web_audit`
	args := []any{}
	if beforeID > 0 {
		q += ` WHERE id < ?`
		args = append(args, beforeID)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list web audit: %w", err)
	}
	defer rows.Close()
	var out []WebAuditEvent
	for rows.Next() {
		var (
			e  WebAuditEvent
			ts int64
			oc string
		)
		if err := rows.Scan(&e.ID, &ts, &e.ActorID, &e.Actor, &e.Action, &e.Target, &oc, &e.Remote, &e.Detail); err != nil {
			return nil, fmt.Errorf("scan web audit: %w", err)
		}
		e.At, e.Outcome = time.UnixMilli(ts).UTC(), WebAuditOutcome(oc)
		out = append(out, e)
	}
	return out, rows.Err()
}
