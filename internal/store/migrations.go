package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/action"
)

// Errors of the migration store.
var (
	// ErrNotFound means no such migration.
	ErrNotFound = errors.New("migration not found")
	// ErrStateConflict means a compare-and-swap lost: the migration is not in
	// the state the caller expected.
	ErrStateConflict = errors.New("migration is not in the expected state")
	// ErrLeaseHeld means another driver holds the migration.
	ErrLeaseHeld = errors.New("migration is driven by another process")
)

// Migration is one row of the migrations table.
type Migration struct {
	ID    string
	State string
	// FailedFrom is the state the migration was in when it failed; FailedStep,
	// FailedResumable and FailedReason describe the failure. Empty unless
	// State is "failed".
	FailedFrom      string
	FailedStep      string
	FailedResumable bool
	FailedReason    string

	SourceName   string
	TargetName   string
	Databases    []string
	PlanHash     string
	PlanJSON     string
	InputJSON    string
	ApprovedHash string

	LeaseOwner string
	LeaseUntil time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

const migrationColumns = `id, state, failed_from, failed_step, failed_resumable, failed_reason,
	source_name, target_name, databases, plan_hash, plan_json, input_json, approved_hash,
	lease_owner, lease_until, created_at, updated_at`

type scanner interface{ Scan(dest ...any) error }

func scanMigration(r scanner) (Migration, error) {
	var m Migration
	var dbs string
	var resumable int
	var lease, created, updated int64
	if err := r.Scan(&m.ID, &m.State, &m.FailedFrom, &m.FailedStep, &resumable, &m.FailedReason,
		&m.SourceName, &m.TargetName, &dbs, &m.PlanHash, &m.PlanJSON, &m.InputJSON, &m.ApprovedHash,
		&m.LeaseOwner, &lease, &created, &updated); err != nil {
		return Migration{}, err
	}
	if err := json.Unmarshal([]byte(dbs), &m.Databases); err != nil {
		return Migration{}, fmt.Errorf("decode databases of %s: %w", m.ID, err)
	}
	m.FailedResumable = resumable != 0
	m.LeaseUntil = time.UnixMilli(lease).UTC()
	m.CreatedAt, m.UpdatedAt = time.UnixMilli(created).UTC(), time.UnixMilli(updated).UTC()
	return m, nil
}

// CreateMigration inserts a new migration in state "draft". Creating the same
// plan twice returns the existing row (plans are deterministic, so planning
// again is idempotent) with created=false.
func (s *Store) CreateMigration(ctx context.Context, m Migration, now time.Time) (Migration, bool, error) {
	if m.ID == "" || m.PlanHash == "" || m.PlanJSON == "" {
		return Migration{}, false, errors.New("migration needs an id, a plan hash and the plan")
	}
	dbs, _ := json.Marshal(m.Databases)
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO migrations (id, state, source_name, target_name, databases, plan_hash, plan_json, input_json, created_at, updated_at)
		VALUES (?, 'draft', ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`,
		m.ID, m.SourceName, m.TargetName, string(dbs), m.PlanHash, m.PlanJSON, m.InputJSON, now.UnixMilli(), now.UnixMilli())
	if err != nil {
		return Migration{}, false, fmt.Errorf("create migration: %w", err)
	}
	n, _ := res.RowsAffected()
	got, err := s.GetMigration(ctx, m.ID)
	if err != nil {
		return Migration{}, false, err
	}
	if got.PlanHash != m.PlanHash {
		return Migration{}, false, fmt.Errorf("migration id %s already exists for a different plan", m.ID)
	}
	return got, n == 1, nil
}

// GetMigration loads a migration by id.
func (s *Store) GetMigration(ctx context.Context, id string) (Migration, error) {
	m, err := scanMigration(s.db.QueryRowContext(ctx, `SELECT `+migrationColumns+` FROM migrations WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Migration{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return Migration{}, fmt.Errorf("load migration: %w", err)
	}
	return m, nil
}

// FindMigrationByPlanHash returns the migration created from a plan hash.
func (s *Store) FindMigrationByPlanHash(ctx context.Context, hash string) (Migration, error) {
	m, err := scanMigration(s.db.QueryRowContext(ctx, `SELECT `+migrationColumns+` FROM migrations WHERE plan_hash = ?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return Migration{}, fmt.Errorf("%w: no migration was planned with hash %s", ErrNotFound, hash)
	}
	if err != nil {
		return Migration{}, fmt.Errorf("find migration: %w", err)
	}
	return m, nil
}

// ListMigrations returns all migrations, newest first.
func (s *Store) ListMigrations(ctx context.Context) ([]Migration, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+migrationColumns+` FROM migrations ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	defer rows.Close()
	var out []Migration
	for rows.Next() {
		m, err := scanMigration(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Transition moves a migration from one state to another with compare-and-swap
// on (id, from). It returns ErrStateConflict if the migration is not in `from`.
// The transition and its audit event are written in one transaction. Leaving
// "failed" clears the failure columns.
func (s *Store) Transition(ctx context.Context, id, from, to, why, actor string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transition: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `
		UPDATE migrations SET state = ?, updated_at = ?,
			failed_from = CASE WHEN ? = 'failed' THEN failed_from ELSE '' END,
			failed_step = CASE WHEN ? = 'failed' THEN failed_step ELSE '' END,
			failed_resumable = CASE WHEN ? = 'failed' THEN failed_resumable ELSE 0 END,
			failed_reason = CASE WHEN ? = 'failed' THEN failed_reason ELSE '' END
		WHERE id = ? AND state = ?`, to, now.UnixMilli(), to, to, to, to, id, from)
	if err != nil {
		return fmt.Errorf("transition %s: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		var cur string
		if err := tx.QueryRowContext(ctx, `SELECT state FROM migrations WHERE id = ?`, id).Scan(&cur); errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		return fmt.Errorf("%w: %s is %q, expected %q", ErrStateConflict, id, cur, from)
	}
	if err := appendAuditTx(ctx, tx, action.Event{At: now, MigrationID: id, Actor: actor, Kind: "state.transition", Detail: from + " -> " + to + ": " + why}); err != nil {
		return err
	}
	return tx.Commit()
}

// MarkFailed moves a migration from `from` to "failed", recording the failed
// step and whether `resume` may continue it. CAS on (id, from).
func (s *Store) MarkFailed(ctx context.Context, id, from, step string, resumable bool, reason, actor string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `
		UPDATE migrations SET state = 'failed', failed_from = ?, failed_step = ?, failed_resumable = ?, failed_reason = ?, updated_at = ?
		WHERE id = ? AND state = ?`, from, step, boolInt(resumable), reason, now.UnixMilli(), id, from)
	if err != nil {
		return fmt.Errorf("mark failed: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: %s is not %q", ErrStateConflict, id, from)
	}
	if err := appendAuditTx(ctx, tx, action.Event{At: now, MigrationID: id, Actor: actor, Kind: "state.failed",
		Detail: fmt.Sprintf("%s -> failed at step %s (resumable=%v): %s", from, step, resumable, reason)}); err != nil {
		return err
	}
	return tx.Commit()
}

// SetApprovedHash records the plan hash the operator approved for source changes.
func (s *Store) SetApprovedHash(ctx context.Context, id, hash string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE migrations SET approved_hash = ?, updated_at = ? WHERE id = ?`, hash, now.UnixMilli(), id)
	if err != nil {
		return fmt.Errorf("record approved plan: %w", err)
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// AcquireLease takes the single-driver lease on a migration for owner until
// now+ttl. It succeeds if the lease is free, expired or already owned by owner.
// With takeOver it succeeds regardless (used after the local lock file proved
// that the previous holder is dead).
func (s *Store) AcquireLease(ctx context.Context, id, owner string, ttl time.Duration, now time.Time, takeOver bool) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE migrations SET lease_owner = ?, lease_until = ?
		WHERE id = ? AND (? = 1 OR lease_owner = '' OR lease_owner = ? OR lease_until < ?)`,
		owner, now.Add(ttl).UnixMilli(), id, boolInt(takeOver), owner, now.UnixMilli())
	if err != nil {
		return fmt.Errorf("acquire lease: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		m, gerr := s.GetMigration(ctx, id)
		if gerr != nil {
			return gerr
		}
		return fmt.Errorf("%w: %s holds %s until %s", ErrLeaseHeld, m.LeaseOwner, id, m.LeaseUntil.Format(time.RFC3339))
	}
	return nil
}

// RenewLease extends owner's lease; it fails if someone else took it.
func (s *Store) RenewLease(ctx context.Context, id, owner string, ttl time.Duration, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE migrations SET lease_until = ? WHERE id = ? AND lease_owner = ?`, now.Add(ttl).UnixMilli(), id, owner)
	if err != nil {
		return fmt.Errorf("renew lease: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: lease of %s was lost", ErrLeaseHeld, id)
	}
	return nil
}

// ReleaseLease frees owner's lease. Releasing a lease owned by someone else is a no-op.
func (s *Store) ReleaseLease(ctx context.Context, id, owner string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE migrations SET lease_owner = '', lease_until = 0 WHERE id = ? AND lease_owner = ?`, id, owner)
	if err != nil {
		return fmt.Errorf("release lease: %w", err)
	}
	return nil
}

// Step is one attempt at one step of a migration for one database. A step is
// written with status "intent" before its effect and finished afterwards.
type Step struct {
	ID          int64
	MigrationID string
	Database    string
	Name        string
	Attempt     int
	// Status is "intent", "done", "failed" or "skipped".
	Status     string
	Detail     string
	Error      string
	StartedAt  time.Time
	FinishedAt time.Time
}

// BeginStep records the intent of a step and returns its id.
func (s *Store) BeginStep(ctx context.Context, st Step, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO steps (migration_id, db, name, attempt, status, detail, started_at) VALUES (?, ?, ?, ?, 'intent', ?, ?)`,
		st.MigrationID, st.Database, st.Name, st.Attempt, st.Detail, now.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("record step intent: %w", err)
	}
	return res.LastInsertId()
}

// FinishStep records the result of a step.
func (s *Store) FinishStep(ctx context.Context, id int64, status, detail, errText string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE steps SET status = ?, detail = CASE WHEN ? = '' THEN detail ELSE ? END, error = ?, finished_at = ? WHERE id = ?`,
		status, detail, detail, errText, now.UnixMilli(), id)
	if err != nil {
		return fmt.Errorf("record step result: %w", err)
	}
	return nil
}

// Steps lists the steps of a migration in the order they were started.
func (s *Store) Steps(ctx context.Context, id string) ([]Step, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, migration_id, db, name, attempt, status, detail, error, started_at, finished_at FROM steps WHERE migration_id = ? ORDER BY id`, id)
	if err != nil {
		return nil, fmt.Errorf("list steps: %w", err)
	}
	defer rows.Close()
	var out []Step
	for rows.Next() {
		var st Step
		var a, b int64
		if err := rows.Scan(&st.ID, &st.MigrationID, &st.Database, &st.Name, &st.Attempt, &st.Status, &st.Detail, &st.Error, &a, &b); err != nil {
			return nil, err
		}
		st.StartedAt, st.FinishedAt = time.UnixMilli(a).UTC(), time.UnixMilli(b).UTC()
		out = append(out, st)
	}
	return out, rows.Err()
}

// SetCheckpoint stores a value for (migration, database, key), replacing any
// earlier one. Checkpoints hold facts such as the slot name, the consistent
// LSN and whether a copy finished. Never a secret.
func (s *Store) SetCheckpoint(ctx context.Context, id, db, key, value string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO checkpoints (migration_id, db, key, value, updated_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (migration_id, db, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		id, db, key, value, now.UnixMilli())
	if err != nil {
		return fmt.Errorf("set checkpoint: %w", err)
	}
	return nil
}

// Checkpoint reads one checkpoint.
func (s *Store) Checkpoint(ctx context.Context, id, db, key string) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM checkpoints WHERE migration_id = ? AND db = ? AND key = ?`, id, db, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read checkpoint: %w", err)
	}
	return v, true, nil
}

// DeleteCheckpoint removes a checkpoint (used when a database starts a fresh attempt).
func (s *Store) DeleteCheckpoint(ctx context.Context, id, db, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM checkpoints WHERE migration_id = ? AND db = ? AND key = ?`, id, db, key)
	if err != nil {
		return fmt.Errorf("delete checkpoint: %w", err)
	}
	return nil
}

// Checkpoints returns all checkpoints of a migration as db -> key -> value.
func (s *Store) Checkpoints(ctx context.Context, id string) (map[string]map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT db, key, value FROM checkpoints WHERE migration_id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("list checkpoints: %w", err)
	}
	defer rows.Close()
	out := map[string]map[string]string{}
	for rows.Next() {
		var db, k, v string
		if err := rows.Scan(&db, &k, &v); err != nil {
			return nil, err
		}
		if out[db] == nil {
			out[db] = map[string]string{}
		}
		out[db][k] = v
	}
	return out, rows.Err()
}

// RecordAction implements action.ActionRecorder.
func (s *Store) RecordAction(ctx context.Context, r action.ActionRecord) error {
	ep, _ := json.Marshal(r.Endpoint)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO actions (migration_id, plan_hash, action_id, phase, endpoint, sql_text, mutates, status, method, approver, at, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.MigrationID, r.PlanHash, r.ActionID, string(r.Phase), string(ep), r.SQL, boolInt(r.Mutates), r.Status, r.Method, r.Approver, r.At.UnixMilli(), r.Error)
	if err != nil {
		return fmt.Errorf("record action: %w", err)
	}
	return nil
}

// Actions lists the recorded actions of a migration in order.
func (s *Store) Actions(ctx context.Context, id string) ([]action.ActionRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT migration_id, plan_hash, action_id, phase, endpoint, sql_text, mutates, status, method, approver, at, error
		FROM actions WHERE migration_id = ? ORDER BY id`, id)
	if err != nil {
		return nil, fmt.Errorf("list actions: %w", err)
	}
	defer rows.Close()
	var out []action.ActionRecord
	for rows.Next() {
		var r action.ActionRecord
		var ph, ep string
		var mut int
		var at int64
		if err := rows.Scan(&r.MigrationID, &r.PlanHash, &r.ActionID, &ph, &ep, &r.SQL, &mut, &r.Status, &r.Method, &r.Approver, &at, &r.Error); err != nil {
			return nil, err
		}
		r.Phase, r.Mutates, r.At = action.Phase(ph), mut != 0, time.UnixMilli(at).UTC()
		_ = json.Unmarshal([]byte(ep), &r.Endpoint)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Append implements action.AuditLog. The table is append-only (triggers).
func (s *Store) Append(ctx context.Context, e action.Event) error {
	return appendAuditTx(ctx, s.db, e)
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func appendAuditTx(ctx context.Context, x execer, e action.Event) error {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	_, err := x.ExecContext(ctx, `
		INSERT INTO audit_events (ts, migration_id, actor, kind, action_id, plan_hash, method, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.At.UnixMilli(), e.MigrationID, e.Actor, e.Kind, e.ActionID, e.PlanHash, e.Method, e.Detail)
	if err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	return nil
}

// AuditEvents returns the audit trail of a migration (all migrations if id is
// empty), oldest first.
func (s *Store) AuditEvents(ctx context.Context, id string, limit int) ([]action.Event, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT ts, migration_id, actor, kind, action_id, plan_hash, method, detail FROM audit_events
		WHERE (? = '' OR migration_id = ?) ORDER BY id LIMIT ?`, id, id, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()
	var out []action.Event
	for rows.Next() {
		var e action.Event
		var ts int64
		if err := rows.Scan(&ts, &e.MigrationID, &e.Actor, &e.Kind, &e.ActionID, &e.PlanHash, &e.Method, &e.Detail); err != nil {
			return nil, err
		}
		e.At = time.UnixMilli(ts).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}
