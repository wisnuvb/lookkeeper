package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/wisnuvb/lockkeeper/internal/action"
	"github.com/wisnuvb/lockkeeper/internal/migrate/machine"
	"github.com/wisnuvb/lockkeeper/internal/migrate/pgnative"
	"github.com/wisnuvb/lockkeeper/internal/store"
)

// Actor is the operator identity recorded in the audit log (user@host).
func Actor() string { return actor() }

func (s *Service) executor(st *store.Store) *action.Executor {
	return &action.Executor{Audit: st, Recorder: st, Now: s.deps.Now, Actor: actor(), Scrub: s.deps.Redactor.String}
}

// verifyReady is the last look before anything changes: the schema still
// matches the plan (see driftCheck) and the connected roles still have the
// privileges. It reads only.
func (s *Service) verifyReady(ctx context.Context, l *loaded, preApply bool) error {
	if err := s.driftCheck(ctx, l, preApply); err != nil {
		return err
	}
	src, err := s.openInventoryDB(ctx, l.in.Source.Name, "")
	if err != nil {
		return fmt.Errorf("connect to the source %s: %w", l.in.Source.Name, err)
	}
	defer pfCloseConn(src)
	sf, err := pgnative.DiscoverSource(ctx, src)
	if err != nil {
		return s.redactErr(err)
	}
	tgt, err := s.openInventoryDB(ctx, l.in.Target.Name, "")
	if err != nil {
		return fmt.Errorf("connect to the target %s: %w", l.in.Target.Name, err)
	}
	defer pfCloseConn(tgt)
	tf, err := pgnative.DiscoverTarget(ctx, tgt)
	if err != nil {
		return s.redactErr(err)
	}
	// The server behind the configured address must still be the one that was planned.
	if sf.Version != l.in.Source.Version || tf.Version != l.in.Target.Version {
		return fmt.Errorf("the servers are not the ones this migration was planned against: source was PostgreSQL %s and is %s, target was %s and is %s. The configuration may point at a different server, or a server was upgraded; nothing was changed. Abort and plan again", l.in.Source.Version, sf.Version, l.in.Target.Version, tf.Version)
	}
	var problems []string
	if preApply {
		// Before the source was changed the slot and sender budget is checked as
		// planned; afterwards the slots of this very migration use it up.
		var dbs []pgnative.DBFacts
		for _, d := range l.in.DBs {
			live, err := s.discoverDB(ctx, l.in.Source.Name, d.Database)
			if err != nil {
				return err
			}
			dbs = append(dbs, live)
		}
		problems = append(problems, pgnative.CheckSource(sf, dbs)...)
	} else {
		switch {
		case sf.WALLevel != "logical":
			problems = append(problems, fmt.Sprintf("source wal_level is %q, not logical", sf.WALLevel))
		case sf.InRecovery:
			problems = append(problems, "the source is a standby")
		case !(sf.Superuser || sf.Replication || sf.RDSReplicate):
			problems = append(problems, fmt.Sprintf("source role %q cannot create a replication slot (REPLICATION / rds_replication)", sf.User))
		}
	}
	names := make([]string, 0, len(l.in.DBs))
	for _, d := range l.in.DBs {
		names = append(names, d.Database)
	}
	problems = append(problems, pgnative.CheckTarget(tf, sf, names)...)
	if len(problems) > 0 {
		return &PrivilegeError{Problems: problems}
	}
	return nil
}

// ApplySourceChanges applies the source-side actions of an approved plan: the
// per-migration role, REPLICA IDENTITY FULL where needed, and the publications.
// It is a dry run unless Apply is set, and applying needs an approval that
// matches the plan hash exactly. Every action is audited before and after.
func (s *Service) ApplySourceChanges(ctx context.Context, o ApplyOptions, tools ToolOptions) (*ApplyResult, error) {
	st, err := s.openState(ctx)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	m, err := findMigration(ctx, st, o.PlanHash, o.MigrationID)
	if err != nil {
		return nil, err
	}
	switch machine.State(m.State) {
	case machine.PreflightOK:
	case machine.SourceChangesApproved, machine.Copying, machine.Following, machine.CaughtUp:
		return nil, fmt.Errorf("the source changes of %s were already applied (state %s); run `lockkeeper migrate start`", m.ID, m.State)
	default:
		return nil, fmt.Errorf("migration %s is %s: source changes can only be applied from preflight_ok", m.ID, m.State)
	}
	l, err := s.loadMigration(ctx, st, m, tools)
	if err != nil {
		return nil, err
	}
	res := &ApplyResult{MigrationID: m.ID, Plan: l.plan, DryRun: !o.Apply, Lines: action.DryRun(l.plan, action.PhaseSource)}
	if !o.Apply {
		return res, nil
	}
	if o.Approver == nil {
		return res, ErrNoApproval
	}
	approval, err := o.Approver(l.plan)
	if err != nil {
		return res, err
	}
	if err := s.verifyReady(ctx, l, true); err != nil {
		return res, err
	}
	auth, err := s.executor(st).Authorize(l.plan, m.PlanHash, approval)
	if err != nil {
		return res, err
	}
	conns, err := s.newMigrateConns(ctx, l.in.Source.Name, l.in.Target.Name)
	if err != nil {
		return res, err
	}
	rep, err := auth.Run(ctx, action.PhaseSource, conns.actionConns())
	res.Report = rep
	if err != nil {
		return res, s.redactErr(err)
	}
	if err := st.SetApprovedHash(ctx, m.ID, m.PlanHash, s.deps.Now()); err != nil {
		return res, err
	}
	if err := st.Append(ctx, action.Event{At: s.deps.Now(), MigrationID: m.ID, Actor: approval.Approver, Kind: "plan.approved",
		PlanHash: m.PlanHash, Method: approval.Method, Detail: "source changes applied: " + fmt.Sprint(len(rep.Applied)) + " applied, " + fmt.Sprint(len(rep.Satisfied)) + " already in place"}); err != nil {
		return res, err
	}
	ss := machine.SQLStore{DB: st, Actor: actor(), Now: s.deps.Now}
	if err := machine.Move(ctx, ss, m.ID, machine.SourceChangesApproved, "source changes applied under the approved plan "+m.PlanHash[:12], machine.Facts{}); err != nil {
		return res, err
	}
	return res, nil
}

// approvalOf recovers who approved the plan and how, from the audit log.
func approvalOf(ctx context.Context, st *store.Store, m store.Migration) (action.Approval, error) {
	evs, err := st.AuditEvents(ctx, m.ID, 100000)
	if err != nil {
		return action.Approval{}, err
	}
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Kind == "plan.approved" && evs[i].PlanHash == m.PlanHash {
			return action.Approval{Method: evs[i].Method, Approver: evs[i].Actor}, nil
		}
	}
	return action.Approval{}, errors.New("this plan has no recorded approval: run `lockkeeper migrate apply-source-changes` first")
}
