package machine

import (
	"context"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/action"
	"github.com/wisnuvb/lockkeeper/internal/store"
)

// SQLStore adapts the SQLite state database to the machine's Store.
type SQLStore struct {
	DB    *store.Store
	Actor string
	Now   func() time.Time
}

func (s SQLStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Load implements Store.
func (s SQLStore) Load(ctx context.Context, id string) (Record, error) {
	m, err := s.DB.GetMigration(ctx, id)
	if err != nil {
		return Record{}, err
	}
	return RecordOf(m), nil
}

// RecordOf converts a stored migration.
func RecordOf(m store.Migration) Record {
	return Record{
		ID: m.ID, State: State(m.State), FailedFrom: State(m.FailedFrom), FailedStep: m.FailedStep,
		FailedResumable: m.FailedResumable, FailedReason: m.FailedReason,
		PlanHash: m.PlanHash, ApprovedHash: m.ApprovedHash, Databases: m.Databases,
		LeaseOwner: m.LeaseOwner, LeaseUntil: m.LeaseUntil,
	}
}

// Transition implements Store.
func (s SQLStore) Transition(ctx context.Context, id string, from, to State, why string) error {
	return s.DB.Transition(ctx, id, string(from), string(to), why, s.Actor, s.now())
}

// MarkFailed implements Store.
func (s SQLStore) MarkFailed(ctx context.Context, id string, from State, step string, resumable bool, reason string) error {
	return s.DB.MarkFailed(ctx, id, string(from), step, resumable, reason, s.Actor, s.now())
}

// BeginStep implements Store.
func (s SQLStore) BeginStep(ctx context.Context, id, db, name string, attempt int, detail string) (int64, error) {
	return s.DB.BeginStep(ctx, store.Step{MigrationID: id, Database: db, Name: name, Attempt: attempt, Detail: detail}, s.now())
}

// FinishStep implements Store.
func (s SQLStore) FinishStep(ctx context.Context, stepID int64, status, detail, errText string) error {
	return s.DB.FinishStep(ctx, stepID, status, detail, errText, s.now())
}

// SetCheckpoint implements Store.
func (s SQLStore) SetCheckpoint(ctx context.Context, id, db, key, value string) error {
	return s.DB.SetCheckpoint(ctx, id, db, key, value, s.now())
}

// Checkpoint implements Store.
func (s SQLStore) Checkpoint(ctx context.Context, id, db, key string) (string, bool, error) {
	return s.DB.Checkpoint(ctx, id, db, key)
}

// DeleteCheckpoint implements Store.
func (s SQLStore) DeleteCheckpoint(ctx context.Context, id, db, key string) error {
	return s.DB.DeleteCheckpoint(ctx, id, db, key)
}

// AcquireLease implements Store.
func (s SQLStore) AcquireLease(ctx context.Context, id, owner string, ttl time.Duration, takeOver bool) error {
	return s.DB.AcquireLease(ctx, id, owner, ttl, s.now(), takeOver)
}

// RenewLease implements Store.
func (s SQLStore) RenewLease(ctx context.Context, id, owner string, ttl time.Duration) error {
	return s.DB.RenewLease(ctx, id, owner, ttl, s.now())
}

// ReleaseLease implements Store.
func (s SQLStore) ReleaseLease(ctx context.Context, id, owner string) error {
	return s.DB.ReleaseLease(ctx, id, owner)
}

// Audit implements Store.
func (s SQLStore) Audit(ctx context.Context, id, kind, detail string) error {
	return s.DB.Append(ctx, action.Event{At: s.now(), MigrationID: id, Actor: s.Actor, Kind: kind, Detail: detail})
}
