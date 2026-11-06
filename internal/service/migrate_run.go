package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/action"
	"github.com/wisnuvb/lockkeeper/internal/migrate"
	"github.com/wisnuvb/lockkeeper/internal/migrate/machine"
	"github.com/wisnuvb/lockkeeper/internal/migrate/pgnative"
	"github.com/wisnuvb/lockkeeper/internal/store"
)

const (
	defaultMaxLag      = 4 << 20
	defaultCaughtUpFor = 2 * time.Minute
	defaultPoll        = 10 * time.Second
)

// recoveryRecord is persisted (as a checkpoint) before a recovery plan runs, so
// that a later process can rebuild exactly that plan and the authorisation of
// the copy attempts that follow it.
type recoveryRecord struct {
	Attempts     map[int]int
	OldSlots     map[int][]string
	TargetCreate map[int]string
	PlanHash     string
	Method       string
	Approver     string
}

type recovery struct {
	plan *action.Plan
	auth *action.Authorization
}

func ownerID() string {
	host, _ := os.Hostname()
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s:%d:%s", host, os.Getpid(), hex.EncodeToString(b[:]))
}

// loadRecoveries rebuilds the recovery plans recorded for a migration.
func (s *Service) loadRecoveries(ctx context.Context, st *store.Store, l *loaded, exec *action.Executor) ([]recovery, error) {
	cps, err := st.Checkpoints(ctx, l.m.ID)
	if err != nil {
		return nil, err
	}
	var keys []string
	for k := range cps[""] {
		if strings.HasPrefix(k, "recovery.") {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		a, _ := strconv.Atoi(strings.TrimPrefix(keys[i], "recovery."))
		b, _ := strconv.Atoi(strings.TrimPrefix(keys[j], "recovery."))
		return a < b
	})
	var out []recovery
	for _, k := range keys {
		var rr recoveryRecord
		if err := json.Unmarshal([]byte(cps[""][k]), &rr); err != nil {
			return nil, fmt.Errorf("stored recovery %s is unreadable: %w", k, err)
		}
		plan, err := pgnative.BuildRecoverPlan(pgnative.RecoverInput{PlanInput: l.in, MigrationID: l.m.ID, Attempts: rr.Attempts, OldSlots: rr.OldSlots, TargetCreate: rr.TargetCreate})
		if err != nil {
			return nil, err
		}
		if plan.Hash() != rr.PlanHash {
			return nil, fmt.Errorf("stored recovery %s no longer matches its hash: the state database was altered", k)
		}
		auth, err := exec.Authorize(plan, rr.PlanHash, action.Approval{Method: rr.Method, Approver: rr.Approver})
		if err != nil {
			return nil, err
		}
		out = append(out, recovery{plan: plan, auth: auth})
	}
	return out, nil
}

// RunMigration is `migrate start` and `migrate resume`: it drives the migration
// from source_changes_approved (or a resumable failure) through copying and
// following, and with Wait until caught up. It reconciles with the real servers
// first, so it is safe to run again after any interruption. When a new copy is
// needed (an interrupted copy leaves a slot and a partial target) it returns the
// recovery plan instead of acting.
func (s *Service) RunMigration(ctx context.Context, o RunOptions) (*RunResult, error) {
	st, err := s.openState(ctx)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	m, err := findMigration(ctx, st, o.PlanHash, o.MigrationID)
	if err != nil {
		return nil, err
	}
	res := &RunResult{MigrationID: m.ID, State: machine.State(m.State)}
	switch machine.State(m.State) {
	case machine.SourceChangesApproved, machine.Copying, machine.Following, machine.CaughtUp, machine.Failed:
	case machine.Draft, machine.PreflightOK:
		return res, fmt.Errorf("migration %s is %s: apply the source changes first (`lockkeeper migrate apply-source-changes --plan-hash %s --apply`)", m.ID, m.State, m.PlanHash)
	default:
		return res, fmt.Errorf("migration %s is %s: there is nothing to start or resume", m.ID, m.State)
	}
	l, err := s.loadMigration(ctx, st, m, o.Tools)
	if err != nil {
		return res, err
	}
	if m.ApprovedHash != m.PlanHash {
		return res, errors.New("the plan was never approved")
	}
	approval, err := approvalOf(ctx, st, m)
	if err != nil {
		return res, err
	}

	mdir, err := s.migrationDir(m.ID)
	if err != nil {
		return res, err
	}
	lock, stale, err := machine.AcquireLock(filepath.Join(mdir, "driver.lock"), s.deps.Now())
	if err != nil {
		return res, fmt.Errorf("%w: another `lockkeeper migrate` is running this migration", err)
	}
	defer lock.Release()
	if stale != nil && o.Notify != nil {
		o.Notify("warn", fmt.Sprintf("the previous driver (pid %d, started %s) died without releasing the lock; taking over", stale.PID, stale.Started.Format(time.RFC3339)))
	}

	// Nothing is changed before these checks pass.
	if err := l.in.Copier.Check(ctx, l.in.Source.Major); err != nil {
		return res, s.redactErr(err)
	}
	if err := s.verifyReady(ctx, l, false); err != nil {
		return res, err
	}

	conns, err := s.newMigrateConns(ctx, l.in.Source.Name, l.in.Target.Name)
	if err != nil {
		return res, err
	}
	exec := s.executor(st)
	mainAuth, err := exec.Authorize(l.plan, m.ApprovedHash, approval)
	if err != nil {
		return res, err
	}
	recs, err := s.loadRecoveries(ctx, st, l, exec)
	if err != nil {
		return res, err
	}
	authFor := func(db, attempt int) (*action.Authorization, error) {
		if attempt <= 1 {
			return mainAuth, nil
		}
		for i := len(recs) - 1; i >= 0; i-- {
			if recs[i].plan.Settings[fmt.Sprintf("attempt.%d", db)] == strconv.Itoa(attempt) {
				return recs[i].auth, nil
			}
		}
		return nil, fmt.Errorf("no approved recovery plan covers attempt %d of database #%d", attempt, db)
	}

	ss := machine.SQLStore{DB: st, Actor: actor(), Now: s.deps.Now}
	engine := &pgnative.Engine{
		Conns: conns, Names: migrate.Names{MigrationID: m.ID}, DBs: append([]string(nil), l.plan.Databases...), Copier: l.in.Copier, AuthFor: authFor,
		WorkRoot: filepath.Join(mdir, "work"), SourceMajor: l.in.Source.Major, TableJobs: l.in.TableJobs, IndexJobs: l.in.IndexJobs, NoOwner: l.in.NoOwner,
		SlotTimeout: o.SlotTimeout,
		Record: func(ctx context.Context, db int, key, value string) {
			if db >= 1 && db <= len(l.plan.Databases) {
				_ = st.SetCheckpoint(ctx, m.ID, l.plan.Databases[db-1], key, value, s.deps.Now())
			}
		},
		Log: func(format string, args ...any) { s.log.Info(fmt.Sprintf(format, args...)) },
	}
	th := s.slotThresholds()
	maxLag, hold, poll := o.MaxLagBytes, o.CaughtUpFor, o.PollInterval
	if maxLag <= 0 {
		maxLag = defaultMaxLag
	}
	if hold <= 0 {
		hold = defaultCaughtUpFor
	}
	if poll <= 0 {
		poll = defaultPoll
	}
	drv := machine.NewDriver(ss, engine, machine.Options{
		Owner: ownerID(), LeaseTTL: 60 * time.Second, TakeOver: stale != nil,
		Policy: machine.CaughtUpPolicy{MaxLagBytes: maxLag, Hold: hold, PollInterval: poll},
		Guard:  machine.Guardrail{Warn: th.SlotWarnBytes, Critical: th.SlotBlockerBytes},
		Wait:   o.Wait, Now: s.deps.Now, Notify: o.Notify,
	})

	for round := 0; ; round++ {
		rec, err := drv.Run(ctx, m.ID)
		res.State = rec.State
		var need *machine.RecoveryRequiredError
		if !errors.As(err, &need) {
			return res, s.redactErr(err)
		}
		if round >= 3 {
			return res, fmt.Errorf("recovery did not converge after %d rounds: %w", round, err)
		}
		plan, rr, perr := s.buildRecoveryPlan(ctx, l, conns, drv, need)
		if perr != nil {
			return res, perr
		}
		res.RecoveryPlan, res.RecoveryWhy = plan, need.Error()
		if !o.ApplyRecovery {
			return res, ErrRecoveryPlanNeeded
		}
		if o.Approver == nil {
			return res, ErrNoApproval
		}
		ap, err := o.Approver(plan)
		if err != nil {
			return res, err
		}
		auth, err := exec.Authorize(plan, plan.Hash(), ap)
		if err != nil {
			return res, err
		}
		// Intent first: record the plan and its approval, move to the next
		// attempt, then run the actions (all idempotent).
		rr.PlanHash, rr.Method, rr.Approver = plan.Hash(), ap.Method, ap.Approver
		blob, _ := json.Marshal(rr)
		cps, err := st.Checkpoints(ctx, m.ID)
		if err != nil {
			return res, err
		}
		n := 1
		for k := range cps[""] {
			if strings.HasPrefix(k, "recovery.") {
				if v, _ := strconv.Atoi(strings.TrimPrefix(k, "recovery.")); v >= n {
					n = v + 1
				}
			}
		}
		if err := st.SetCheckpoint(ctx, m.ID, "", fmt.Sprintf("recovery.%d", n), string(blob), s.deps.Now()); err != nil {
			return res, err
		}
		for _, db := range need.DBs() {
			if err := drv.BumpAttempt(ctx, m.ID, db); err != nil {
				return res, err
			}
		}
		if _, err := auth.Run(ctx, action.PhaseRecover, conns.actionConns()); err != nil {
			return res, s.redactErr(err)
		}
		recs = append(recs, recovery{plan: plan, auth: auth})
		res.RecoveryPlan = nil
		if o.Notify != nil {
			o.Notify("info", "recovery plan applied; copying again under new slot(s)")
		}
	}
}

// buildRecoveryPlan reads what only the live servers know (old slots, the
// target database properties) and builds the recovery plan for the databases
// that need a new copy.
func (s *Service) buildRecoveryPlan(ctx context.Context, l *loaded, conns *migrateConns, drv *machine.Driver, need *machine.RecoveryRequiredError) (*action.Plan, *recoveryRecord, error) {
	rr := &recoveryRecord{Attempts: map[int]int{}, OldSlots: map[int][]string{}, TargetCreate: map[int]string{}}
	for _, db := range need.DBs() {
		a, err := drv.Attempt(ctx, l.m.ID, db)
		if err != nil {
			return nil, nil, err
		}
		rr.Attempts[db] = a
		name := l.in.DBs[db-1].Database
		src, err := conns.Source(ctx, name)
		if err != nil {
			return nil, nil, fmt.Errorf("connect to the source database %s: %w", name, err)
		}
		slots, err := pgnative.SlotsWithPrefix(ctx, src, fmt.Sprintf("lk_%s_d%d_a", l.m.ID, db))
		_ = src.Close(ctx)
		if err != nil {
			return nil, nil, err
		}
		rr.OldSlots[db] = slots
		tgt, err := conns.Target(ctx, name)
		if err != nil {
			return nil, nil, fmt.Errorf("connect to the target database %s: %w", name, err)
		}
		create, err := pgnative.CreateStatementFor(ctx, tgt, name)
		_ = tgt.Close(ctx)
		if err != nil {
			return nil, nil, err
		}
		rr.TargetCreate[db] = create
	}
	plan, err := pgnative.BuildRecoverPlan(pgnative.RecoverInput{PlanInput: l.in, MigrationID: l.m.ID, Attempts: rr.Attempts, OldSlots: rr.OldSlots, TargetCreate: rr.TargetCreate})
	return plan, rr, err
}
