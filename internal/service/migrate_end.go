package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/wisnuvb/lockkeeper/internal/action"
	"github.com/wisnuvb/lockkeeper/internal/migrate/machine"
	"github.com/wisnuvb/lockkeeper/internal/migrate/pgnative"
)

// lockMigration takes the driver lock so that abort and cleanup cannot run
// while `migrate start` is driving the same migration.
func (s *Service) lockMigration(id string) (*machine.Lock, error) {
	mdir, err := s.migrationDir(id)
	if err != nil {
		return nil, err
	}
	lock, _, err := machine.AcquireLock(filepath.Join(mdir, "driver.lock"), s.deps.Now())
	if err != nil {
		return nil, fmt.Errorf("%w: stop the running `lockkeeper migrate start`/`resume` first (Ctrl-C is safe)", err)
	}
	return lock, nil
}

// AbortMigration stops our consumption: it disables the subscriptions (see
// abortOnce). Applying takes the driver lock FIRST and only then reads the
// state and builds the plan again, so the plan that is approved and run is the
// one for the state that holds while nobody else can move the migration.
func (s *Service) AbortMigration(ctx context.Context, o EndOptions) (*EndResult, error) {
	if !o.Apply {
		return s.abortOnce(ctx, o, false)
	}
	id, err := s.resolveMigrationID(ctx, o)
	if err != nil {
		return nil, err
	}
	lock, err := s.lockMigration(id)
	if err != nil {
		return nil, err
	}
	defer lock.Release()
	return s.abortOnce(ctx, o, true)
}

// resolveMigrationID finds which migration a command is about, without reading
// anything else, so that the lock can be taken before the state is looked at.
func (s *Service) resolveMigrationID(ctx context.Context, o EndOptions) (string, error) {
	st, err := s.openState(ctx)
	if err != nil {
		return "", err
	}
	defer st.Close()
	m, err := findMigration(ctx, st, o.PlanHash, o.MigrationID)
	if err != nil {
		return "", err
	}
	return m.ID, nil
}

// CleanupMigration drops exactly this migration's objects (see cleanupOnce),
// with the same lock-first ordering as AbortMigration.
func (s *Service) CleanupMigration(ctx context.Context, o EndOptions) (*EndResult, error) {
	if !o.Apply {
		return s.cleanupOnce(ctx, o, false)
	}
	id, err := s.resolveMigrationID(ctx, o)
	if err != nil {
		return nil, err
	}
	lock, err := s.lockMigration(id)
	if err != nil {
		return nil, err
	}
	defer lock.Release()
	return s.cleanupOnce(ctx, o, true)
}

// abortOnce does the work of AbortMigration: it disables the subscriptions on the
// target and marks the migration aborted. It leaves the source's slots and
// publications exactly as they are (dropping them is `cleanup`, a separate
// confirmed step) and never touches data. Dry run unless Apply.
func (s *Service) abortOnce(ctx context.Context, o EndOptions, apply bool) (*EndResult, error) {
	st, err := s.openState(ctx)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	m, err := findMigration(ctx, st, o.PlanHash, o.MigrationID)
	if err != nil {
		return nil, err
	}
	cur := machine.State(m.State)
	from := cur
	if cur == machine.Failed {
		from = machine.State(m.FailedFrom)
	}
	if !(from.InProgress()) {
		return nil, fmt.Errorf("migration %s is %s: only a migration that is in progress (or failed) can be aborted", m.ID, m.State)
	}
	l, err := s.loadMigration(ctx, st, m, o.Tools)
	if err != nil {
		return nil, err
	}
	withSubs := from == machine.Copying || from == machine.Following || from == machine.CaughtUp
	plan, err := pgnative.BuildAbortPlan(l.in, m.ID, withSubs)
	if err != nil {
		return nil, err
	}
	res := &EndResult{MigrationID: m.ID, Plan: plan, DryRun: !apply, Lines: action.DryRun(plan, action.PhaseAbort), State: cur}
	if !apply {
		return res, nil
	}
	if o.Approver == nil {
		return res, ErrNoApproval
	}
	approval, err := o.Approver(plan)
	if err != nil {
		return res, err
	}
	auth, err := s.executor(st).Authorize(plan, plan.Hash(), approval)
	if err != nil {
		return res, err
	}
	conns, err := s.newMigrateConns(ctx, l.in.Source.Name, l.in.Target.Name)
	if err != nil {
		return res, err
	}
	if _, err := auth.Run(ctx, action.PhaseAbort, conns.actionConns()); err != nil {
		return res, s.redactErr(err)
	}
	ss := machine.SQLStore{DB: st, Actor: actor(), Now: s.deps.Now}
	if err := machine.Move(ctx, ss, m.ID, machine.Aborted, "aborted by the operator ("+approval.Method+"); the source's slots and publications were left in place", machine.Facts{}); err != nil {
		return res, err
	}
	res.State = machine.Aborted
	return res, nil
}

// cleanupOnce does the work of CleanupMigration: it drops exactly what this migration created: subscriptions on
// the target, then slots, publications and the role on the source, each only if
// it carries the migration's name and marker. It refuses unless the migration
// was aborted (Phase 4 adds the verified-cutover path), needs the exact plan
// hash or a typed phrase, and never touches user data. Dry run unless Apply.
func (s *Service) cleanupOnce(ctx context.Context, o EndOptions, apply bool) (*EndResult, error) {
	st, err := s.openState(ctx)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	m, err := findMigration(ctx, st, o.PlanHash, o.MigrationID)
	if err != nil {
		return nil, err
	}
	cur := machine.State(m.State)
	ok := cur == machine.Aborted || cur == machine.CleanupPending || (cur == machine.Failed && machine.State(m.FailedFrom) == machine.CleanupPending)
	if !ok {
		return nil, fmt.Errorf("migration %s is %s: cleanup is only allowed after `lockkeeper migrate abort` (the replication slot is the only copy of the change stream; dropping it ends the migration)", m.ID, m.State)
	}
	l, err := s.loadMigration(ctx, st, m, o.Tools)
	if err != nil {
		return nil, err
	}
	conns, err := s.newMigrateConns(ctx, l.in.Source.Name, l.in.Target.Name)
	if err != nil {
		return nil, err
	}
	slots := map[int][]string{}
	for i, d := range l.in.DBs {
		src, err := conns.Source(ctx, d.Database)
		if err != nil {
			return nil, fmt.Errorf("connect to the source database %s: %w", d.Database, err)
		}
		list, err := pgnative.SlotsWithPrefix(ctx, src, fmt.Sprintf("lk_%s_d%d_a", m.ID, i+1))
		_ = src.Close(ctx)
		if err != nil {
			return nil, err
		}
		slots[i+1] = list
	}
	plan, err := pgnative.BuildCleanupPlan(pgnative.CleanupInput{PlanInput: l.in, MigrationID: m.ID, Slots: slots})
	if err != nil {
		return nil, err
	}
	res := &EndResult{MigrationID: m.ID, Plan: plan, DryRun: !apply, Lines: action.DryRun(plan, action.PhaseCleanup), State: cur}
	if !apply {
		return res, nil
	}
	if o.Approver == nil {
		return res, ErrNoApproval
	}
	approval, err := o.Approver(plan)
	if err != nil {
		return res, err
	}
	auth, err := s.executor(st).Authorize(plan, plan.Hash(), approval)
	if err != nil {
		return res, err
	}
	ss := machine.SQLStore{DB: st, Actor: actor(), Now: s.deps.Now}
	switch cur {
	case machine.Aborted:
		f := machine.Facts{CleanupApprovedHash: plan.Hash(), CleanupPlanHash: plan.Hash()}
		if err := machine.Move(ctx, ss, m.ID, machine.CleanupPending, "cleanup approved ("+approval.Method+") with plan "+plan.Hash()[:12], f); err != nil {
			return res, err
		}
	case machine.Failed:
		if err := machine.Move(ctx, ss, m.ID, machine.CleanupPending, "resume cleanup", machine.Facts{}); err != nil {
			return res, err
		}
	}
	if _, err := auth.Run(ctx, action.PhaseCleanup, conns.actionConns()); err != nil {
		merr := ss.MarkFailed(context.WithoutCancel(ctx), m.ID, machine.CleanupPending, "cleanup", true, s.redactErr(err).Error())
		return res, errors.Join(s.redactErr(err), merr)
	}
	if err := machine.Move(ctx, ss, m.ID, machine.Cleaned, "every cleanup action is satisfied", machine.Facts{CleanupDone: true}); err != nil {
		return res, err
	}
	res.State = machine.Cleaned
	// The generated password and the tool work directories are of no use any more.
	root, _ := s.migrationsRoot()
	if root != "" {
		_ = pgnative.PasswordFileFor(root, m.ID).Remove()
		// The tools' raw logs can quote table rows (see runner.ToolError).
		_ = os.RemoveAll(filepath.Join(root, m.ID, "logs"))
		_ = os.RemoveAll(filepath.Join(root, m.ID, "work"))
	}
	return res, nil
}
