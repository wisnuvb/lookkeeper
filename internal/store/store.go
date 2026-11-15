// Package store persists Lockkeeper's local state in a single SQLite file: a
// bounded metrics history, the alert engine's state (so restarts do not
// re-notify) and an event log.
//
// The file holds no secrets. It is created with mode 0600 and refused if it is
// accessible to group or others.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo)

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/model"
)

// migrations are applied in order; index+1 is the schema version. Never edit an
// existing entry: append a new one.
var migrations = []string{
	`CREATE TABLE metrics (
		id     INTEGER PRIMARY KEY,
		ts     INTEGER NOT NULL,
		target TEXT NOT NULL,
		metric TEXT NOT NULL,
		labels TEXT NOT NULL,
		value  REAL NOT NULL
	);
	CREATE INDEX metrics_series ON metrics (target, metric, labels, ts);
	CREATE INDEX metrics_ts ON metrics (ts);

	CREATE TABLE alert_state (
		target TEXT NOT NULL,
		metric TEXT NOT NULL,
		labels TEXT NOT NULL,
		state  TEXT NOT NULL,
		PRIMARY KEY (target, metric, labels)
	);

	CREATE TABLE events (
		id        INTEGER PRIMARY KEY,
		ts        INTEGER NOT NULL,
		target    TEXT NOT NULL,
		rule      TEXT NOT NULL,
		labels    TEXT NOT NULL,
		state     TEXT NOT NULL,
		severity  TEXT NOT NULL,
		value     REAL NOT NULL,
		threshold REAL NOT NULL,
		summary   TEXT NOT NULL
	);
	CREATE INDEX events_ts ON events (ts);`,
	migrationSchemaV2, // migration state model (schema_migrate.go)
	webSchemaV3,       // users, sessions, web audit (schema_web.go)
}

// Store is a handle to the state database.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens (creating if needed) the database at path and applies migrations.
// Before upgrading an existing database it writes a consistent backup next to it.
func Open(ctx context.Context, path string) (*Store, error) {
	return open(ctx, path, migrations)
}

func open(ctx context.Context, path string, migs []string) (*Store, error) {
	if err := prepareFile(path); err != nil {
		return nil, err
	}
	dsn := "file:" + strings.NewReplacer("?", "%3F", "#", "%23").Replace(path) +
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite has a single writer; serialising avoids SQLITE_BUSY
	s := &Store{db: db, path: path}
	if err := s.migrate(ctx, migs); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// prepareFile creates the directory (0700) and file (0600) if missing and
// refuses a file that group or others can access.
func prepareFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("create state database: %w", err)
	}
	_ = f.Close()
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat state database: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state database %s has mode %#o; it must not be accessible by group or others (chmod 600)", path, fi.Mode().Perm())
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

func (s *Store) migrate(ctx context.Context, migs []string) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("init schema_migrations: %w", err)
	}
	var cur int
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&cur); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if cur > len(migs) {
		return fmt.Errorf("state database is schema version %d but this build only knows %d: refusing to downgrade; use a newer lockkeeper", cur, len(migs))
	}
	if cur == len(migs) {
		return nil
	}
	if cur > 0 { // an existing database is about to change shape: back it up first
		if err := s.backup(ctx, cur); err != nil {
			return err
		}
	}
	for v := cur + 1; v <= len(migs); v++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", v, err)
		}
		if _, err := tx.ExecContext(ctx, migs[v-1]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %d: %w", v, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, v, time.Now().Unix()); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d: %w", v, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", v, err)
		}
	}
	return nil
}

// backup writes a transactionally consistent copy with VACUUM INTO.
func (s *Store) backup(ctx context.Context, fromVersion int) error {
	dst := fmt.Sprintf("%s.bak-v%d", s.path, fromVersion)
	if _, err := os.Stat(dst); err == nil {
		_ = os.Remove(dst) // VACUUM INTO refuses to overwrite
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, dst); err != nil {
		return fmt.Errorf("back up state database before upgrade: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dst, 0o600); err != nil {
			return fmt.Errorf("restrict backup permissions: %w", err)
		}
	}
	return nil
}

func labelsJSON(l map[string]string) string {
	if len(l) == 0 {
		return "{}"
	}
	b, _ := json.Marshal(l) // map keys are sorted: canonical form
	return string(b)
}

func parseLabels(s string) map[string]string {
	if s == "" || s == "{}" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil
	}
	return m
}

// AppendSamples stores samples in one transaction.
func (s *Store) AppendSamples(ctx context.Context, samples []model.Sample) error {
	if len(samples) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO metrics (ts, target, metric, labels, value) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()
	for _, sm := range samples {
		if _, err := stmt.ExecContext(ctx, sm.At.UnixMilli(), sm.Target, sm.Metric, labelsJSON(sm.Labels), sm.Value); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("insert sample: %w", err)
		}
	}
	return tx.Commit()
}

// LatestSamples returns the most recent sample of every series of target.
func (s *Store) LatestSamples(ctx context.Context, target string) ([]model.Sample, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT m.ts, m.target, m.metric, m.labels, m.value
		FROM metrics m
		JOIN (SELECT metric, labels, MAX(ts) AS ts FROM metrics WHERE target = ? GROUP BY metric, labels) l
		  ON l.metric = m.metric AND l.labels = m.labels AND l.ts = m.ts
		WHERE m.target = ?
		GROUP BY m.metric, m.labels
		ORDER BY m.metric, m.labels`, target, target)
	if err != nil {
		return nil, fmt.Errorf("query latest samples: %w", err)
	}
	defer rows.Close()
	var out []model.Sample
	for rows.Next() {
		var ts int64
		var sm model.Sample
		var labels string
		if err := rows.Scan(&ts, &sm.Target, &sm.Metric, &labels, &sm.Value); err != nil {
			return nil, err
		}
		sm.At, sm.Labels = time.UnixMilli(ts).UTC(), parseLabels(labels)
		out = append(out, sm)
	}
	return out, rows.Err()
}

// PruneSamples deletes samples older than before and returns how many were removed.
func (s *Store) PruneSamples(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM metrics WHERE ts < ?`, before.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("prune samples: %w", err)
	}
	return res.RowsAffected()
}

// PruneEvents deletes events older than before.
func (s *Store) PruneEvents(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, before.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("prune events: %w", err)
	}
	return res.RowsAffected()
}

// SaveAlertState replaces the persisted alert engine state.
func (s *Store) SaveAlertState(ctx context.Context, snaps []rules.Snapshot) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM alert_state`); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("clear alert state: %w", err)
	}
	for _, sn := range snaps {
		b, err := json.Marshal(sn)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("encode alert state: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO alert_state (target, metric, labels, state) VALUES (?, ?, ?, ?)`,
			sn.Target, sn.Metric, labelsJSON(sn.Labels), string(b)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("save alert state: %w", err)
		}
	}
	return tx.Commit()
}

// LoadAlertState returns the persisted alert engine state.
func (s *Store) LoadAlertState(ctx context.Context) ([]rules.Snapshot, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT state FROM alert_state`)
	if err != nil {
		return nil, fmt.Errorf("load alert state: %w", err)
	}
	defer rows.Close()
	var out []rules.Snapshot
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var sn rules.Snapshot
		if err := json.Unmarshal([]byte(raw), &sn); err != nil {
			continue // a corrupt row must not stop Lockkeeper from starting
		}
		out = append(out, sn)
	}
	return out, rows.Err()
}

// AppendEvent records an alert event.
func (s *Store) AppendEvent(ctx context.Context, e model.Event) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO events (ts, target, rule, labels, state, severity, value, threshold, summary)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.At.UnixMilli(), e.Target, e.Rule, labelsJSON(e.Labels), string(e.State), string(e.Severity), e.Value, e.Threshold, e.Summary)
	if err != nil {
		return fmt.Errorf("append event: %w", err)
	}
	return nil
}

// RecentEvents returns the newest events first.
func (s *Store) RecentEvents(ctx context.Context, limit int) ([]model.Event, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT ts, target, rule, labels, state, severity, value, threshold, summary
		FROM events ORDER BY ts DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()
	var out []model.Event
	for rows.Next() {
		var ts int64
		var e model.Event
		var labels, state, sev string
		if err := rows.Scan(&ts, &e.Target, &e.Rule, &labels, &state, &sev, &e.Value, &e.Threshold, &e.Summary); err != nil {
			return nil, err
		}
		e.At, e.Labels, e.State, e.Severity = time.UnixMilli(ts).UTC(), parseLabels(labels), model.EventState(state), model.Severity(sev)
		out = append(out, e)
	}
	return out, rows.Err()
}
