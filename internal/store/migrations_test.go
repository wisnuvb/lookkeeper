package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/action"
	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/model"
)

func newMigration(t *testing.T, s *Store, id, hash string) Migration {
	t.Helper()
	m, created, err := s.CreateMigration(context.Background(), Migration{
		ID: id, SourceName: "a", TargetName: "b", Databases: []string{"app", "billing"}, PlanHash: hash, PlanJSON: `{"x":1}`,
	}, base)
	if err != nil || !created {
		t.Fatalf("create: %v created=%v", err, created)
	}
	return m
}

func TestCreateMigrationIsIdempotentPerPlan(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	m := newMigration(t, s, "m1", "h1")
	if m.State != "draft" || strings.Join(m.Databases, ",") != "app,billing" {
		t.Fatalf("%+v", m)
	}
	again, created, err := s.CreateMigration(ctx, Migration{ID: "m1", SourceName: "a", TargetName: "b", Databases: []string{"app"}, PlanHash: "h1", PlanJSON: "{}"}, base)
	if err != nil || created || again.ID != "m1" {
		t.Fatalf("planning the same plan again must return the existing draft: %v %v", err, created)
	}
	if _, _, err := s.CreateMigration(ctx, Migration{ID: "m1", SourceName: "a", TargetName: "b", Databases: nil, PlanHash: "other", PlanJSON: "{}"}, base); err == nil {
		t.Fatal("an id that exists for a different plan must be refused")
	}
	got, err := s.FindMigrationByPlanHash(ctx, "h1")
	if err != nil || got.ID != "m1" {
		t.Fatalf("find by hash: %v %v", got, err)
	}
	if _, err := s.FindMigrationByPlanHash(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := s.GetMigration(ctx, "zzz"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestTransitionIsCompareAndSwapAndAudited(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	newMigration(t, s, "m1", "h1")
	if err := s.Transition(ctx, "m1", "draft", "preflight_ok", "checked", "op", base); err != nil {
		t.Fatal(err)
	}
	// The same transition again loses the race.
	err := s.Transition(ctx, "m1", "draft", "preflight_ok", "again", "op", base)
	if !errors.Is(err, ErrStateConflict) {
		t.Fatalf("want ErrStateConflict, got %v", err)
	}
	if err := s.Transition(ctx, "nope", "draft", "x", "", "op", base); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	ev, err := s.AuditEvents(ctx, "m1", 10)
	if err != nil || len(ev) != 1 || ev[0].Kind != "state.transition" || !strings.Contains(ev[0].Detail, "draft -> preflight_ok") {
		t.Fatalf("a transition is audited exactly once, and a lost CAS is not: %v %v", ev, err)
	}
}

func TestFailureColumnsAndResume(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	newMigration(t, s, "m1", "h1")
	_ = s.Transition(ctx, "m1", "draft", "copying", "x", "op", base)
	if err := s.MarkFailed(ctx, "m1", "copying", "copy:app", true, "connection reset", "op", base); err != nil {
		t.Fatal(err)
	}
	m, _ := s.GetMigration(ctx, "m1")
	if m.State != "failed" || m.FailedFrom != "copying" || m.FailedStep != "copy:app" || !m.FailedResumable || m.FailedReason != "connection reset" {
		t.Fatalf("%+v", m)
	}
	if err := s.MarkFailed(ctx, "m1", "copying", "x", true, "y", "op", base); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("failing a migration that is not in `from` must conflict: %v", err)
	}
	if err := s.Transition(ctx, "m1", "failed", "copying", "resume", "op", base); err != nil {
		t.Fatal(err)
	}
	m, _ = s.GetMigration(ctx, "m1")
	if m.State != "copying" || m.FailedFrom != "" || m.FailedStep != "" || m.FailedResumable || m.FailedReason != "" {
		t.Fatalf("leaving failed must clear the failure columns: %+v", m)
	}
}

func TestLeaseSingleDriver(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	newMigration(t, s, "m1", "h1")
	ttl := time.Minute
	if err := s.AcquireLease(ctx, "m1", "A", ttl, base, false); err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireLease(ctx, "m1", "B", ttl, base.Add(10*time.Second), false); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("a second driver must be refused: %v", err)
	}
	if err := s.AcquireLease(ctx, "m1", "A", ttl, base.Add(10*time.Second), false); err != nil {
		t.Fatalf("the owner may re-acquire: %v", err)
	}
	if err := s.RenewLease(ctx, "m1", "B", ttl, base); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("a non-owner cannot renew: %v", err)
	}
	if err := s.AcquireLease(ctx, "m1", "B", ttl, base.Add(2*time.Minute), false); err != nil {
		t.Fatalf("an expired lease can be taken: %v", err)
	}
	if err := s.AcquireLease(ctx, "m1", "C", ttl, base.Add(2*time.Minute), false); !errors.Is(err, ErrLeaseHeld) {
		t.Fatal("B holds it now")
	}
	if err := s.AcquireLease(ctx, "m1", "C", ttl, base.Add(2*time.Minute), true); err != nil {
		t.Fatalf("take over after the lock file proved the holder dead: %v", err)
	}
	_ = s.ReleaseLease(ctx, "m1", "B") // not the owner: no-op
	if m, _ := s.GetMigration(ctx, "m1"); m.LeaseOwner != "C" {
		t.Fatalf("release by a non-owner must be a no-op, owner is %q", m.LeaseOwner)
	}
	_ = s.ReleaseLease(ctx, "m1", "C")
	if m, _ := s.GetMigration(ctx, "m1"); m.LeaseOwner != "" {
		t.Fatal("lease not released")
	}
}

func TestStepsCheckpointsActions(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	newMigration(t, s, "m1", "h1")
	id, err := s.BeginStep(ctx, Step{MigrationID: "m1", Database: "app", Name: "copy", Attempt: 1, Detail: "intent"}, base)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinishStep(ctx, id, "done", "", "", base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	steps, _ := s.Steps(ctx, "m1")
	if len(steps) != 1 || steps[0].Status != "done" || steps[0].Detail != "intent" || steps[0].FinishedAt.IsZero() {
		t.Fatalf("%+v", steps)
	}

	if _, ok, _ := s.Checkpoint(ctx, "m1", "app", "slot"); ok {
		t.Fatal("no checkpoint yet")
	}
	_ = s.SetCheckpoint(ctx, "m1", "app", "slot", "lk_a", base)
	_ = s.SetCheckpoint(ctx, "m1", "app", "slot", "lk_b", base)
	_ = s.SetCheckpoint(ctx, "m1", "billing", "slot", "lk_c", base)
	if v, ok, _ := s.Checkpoint(ctx, "m1", "app", "slot"); !ok || v != "lk_b" {
		t.Fatalf("checkpoint replaced: %q %v", v, ok)
	}
	all, _ := s.Checkpoints(ctx, "m1")
	if all["app"]["slot"] != "lk_b" || all["billing"]["slot"] != "lk_c" {
		t.Fatalf("%v", all)
	}
	_ = s.DeleteCheckpoint(ctx, "m1", "app", "slot")
	if _, ok, _ := s.Checkpoint(ctx, "m1", "app", "slot"); ok {
		t.Fatal("checkpoint not deleted")
	}

	rec := action.ActionRecord{MigrationID: "m1", PlanHash: "h1", ActionID: "source.create-publication", Phase: action.PhaseSource,
		Endpoint: action.Endpoint{Role: "source", Name: "a", Host: "h", Port: 5432, Database: "app", User: "u"},
		SQL:      "CREATE PUBLICATION p;", Mutates: true, Status: "applied", Method: "plan-hash", Approver: "op", At: base}
	if err := s.RecordAction(ctx, rec); err != nil {
		t.Fatal(err)
	}
	acts, _ := s.Actions(ctx, "m1")
	if len(acts) != 1 || acts[0].Endpoint.Host != "h" || acts[0].Phase != action.PhaseSource || !acts[0].Mutates {
		t.Fatalf("%+v", acts)
	}
}

func TestAuditEventsAreAppendOnly(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if err := s.Append(ctx, action.Event{At: base, MigrationID: "m1", Actor: "op", Kind: "action.intent", ActionID: "a", PlanHash: "h", Method: "typed", Detail: "d"}); err != nil {
		t.Fatal(err)
	}
	for name, q := range map[string]string{
		"update":      `UPDATE audit_events SET detail = 'rewritten'`,
		"update-id":   `UPDATE audit_events SET id = id + 100`,
		"delete":      `DELETE FROM audit_events`,
		"delete-some": `DELETE FROM audit_events WHERE kind = 'action.intent'`,
	} {
		_, err := s.db.ExecContext(ctx, q)
		if err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s must be refused by the trigger, got %v", name, err)
		}
	}
	ev, err := s.AuditEvents(ctx, "", 10)
	if err != nil || len(ev) != 1 || ev[0].Detail != "d" {
		t.Fatalf("history must be intact: %v %v", ev, err)
	}
	// Alert-event retention does not touch the audit trail.
	if _, err := s.PruneEvents(ctx, base.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if ev, _ := s.AuditEvents(ctx, "", 10); len(ev) != 1 {
		t.Fatal("PruneEvents must not delete audit events")
	}
}

// TestUpgradeFromSchemaV1PreservesDataAndBacksUp opens a database that only has
// the first schema version, fills it, and upgrades it with the real migration
// list: data must survive, the pre-upgrade backup must exist and hold the old
// shape, and the new tables must be usable.
func TestUpgradeFromSchemaV1PreservesDataAndBacksUp(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "lockkeeper.db")
	old, err := open(ctx, path, migrations[:1])
	if err != nil {
		t.Fatal(err)
	}
	samples := []model.Sample{{Target: "db", Metric: "m1", Value: 42, At: base}, {Target: "db", Metric: "m2", Labels: map[string]string{"slot": "s"}, Value: 7, At: base}}
	if err := old.AppendSamples(ctx, samples); err != nil {
		t.Fatal(err)
	}
	if err := old.AppendEvent(ctx, model.Event{Target: "db", Rule: "r", State: model.EventState("firing"), Severity: model.Severity("warning"), Summary: "alert", At: base}); err != nil {
		t.Fatal(err)
	}
	if err := old.SaveAlertState(ctx, []rules.Snapshot{{Target: "db", Metric: "m1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := old.db.ExecContext(ctx, `SELECT count(*) FROM migrations`); err == nil {
		t.Fatal("the v1 database must not have the migration tables")
	}
	_ = old.Close()

	s, err := Open(ctx, path) // upgrades to the current version
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer s.Close()

	var ver int
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&ver); err != nil || ver != len(migrations) {
		t.Fatalf("schema version %d (%v), want %d", ver, err, len(migrations))
	}
	got, err := s.LatestSamples(ctx, "db")
	if err != nil || len(got) != 2 || got[0].Value != 42 || got[1].Value != 7 {
		t.Fatalf("metrics lost in the upgrade: %v %v", got, err)
	}
	if ev, err := s.RecentEvents(ctx, 10); err != nil || len(ev) != 1 || ev[0].Summary != "alert" {
		t.Fatalf("alert events lost in the upgrade: %v %v", ev, err)
	}
	if st, err := s.LoadAlertState(ctx); err != nil || len(st) != 1 {
		t.Fatalf("alert state lost in the upgrade: %v %v", st, err)
	}

	bak := path + ".bak-v1"
	fi, err := os.Stat(bak)
	if err != nil {
		t.Fatalf("pre-upgrade backup missing: %v", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("backup must be 0600, is %v", fi.Mode().Perm())
	}
	bs, err := open(ctx, bak, migrations[:1])
	if err != nil {
		t.Fatalf("the backup must be a valid v1 database: %v", err)
	}
	defer bs.Close()
	if got, _ := bs.LatestSamples(ctx, "db"); len(got) != 2 {
		t.Fatal("the backup must hold the pre-upgrade data")
	}

	newMigration(t, s, "m1", "h1") // the new tables work
	// Reopening an up-to-date database is a no-op (no second backup, no error).
	_ = s.Close()
	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s2.Close()
}

func TestOpenRefusesDowngrade(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "lockkeeper.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err := open(ctx, path, migrations[:1]); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("an older build must refuse a newer schema: %v", err)
	}
}
