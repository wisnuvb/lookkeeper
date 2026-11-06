package machine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Store is the persistence the machine needs. internal/store implements it
// (see SQLStore); tests use an in-memory one.
type Store interface {
	Load(ctx context.Context, id string) (Record, error)
	// Transition is a compare-and-swap on (id, from).
	Transition(ctx context.Context, id string, from, to State, why string) error
	MarkFailed(ctx context.Context, id string, from State, step string, resumable bool, reason string) error
	BeginStep(ctx context.Context, id, db, name string, attempt int, detail string) (int64, error)
	FinishStep(ctx context.Context, stepID int64, status, detail, errText string) error
	SetCheckpoint(ctx context.Context, id, db, key, value string) error
	Checkpoint(ctx context.Context, id, db, key string) (string, bool, error)
	DeleteCheckpoint(ctx context.Context, id, db, key string) error
	AcquireLease(ctx context.Context, id, owner string, ttl time.Duration, takeOver bool) error
	RenewLease(ctx context.Context, id, owner string, ttl time.Duration) error
	ReleaseLease(ctx context.Context, id, owner string) error
	// Audit appends an audit event (kind, detail) for the migration.
	Audit(ctx context.Context, id, kind, detail string) error
}

// DBState is what the real servers say about one database right now.
type DBState struct {
	SlotExists bool
	SlotActive bool
	// SlotWALStatus is pg_replication_slots.wal_status ("lost" means the slot
	// can no longer be used).
	SlotWALStatus   string
	SubExists       bool
	SubEnabled      bool
	TargetHasTables bool
}

// Progress is a database's replication progress.
type Progress struct {
	LagBytes      int64
	RetainedBytes int64
	WALStatus     string
	SubEnabled    bool
	WorkerRunning bool
}

// World is every effect on and observation of the real servers. Databases are
// addressed by their 1-based index in the migration; attempt numbers a copy
// (every attempt uses a new slot). All methods are idempotent or read-only.
type World interface {
	Databases() []string
	Observe(ctx context.Context, db, attempt int) (DBState, error)
	// Copy creates the slot with an exported snapshot, copies the database inside
	// it, removes what the schema copy brought along, and releases the snapshot.
	// It returns only after all of that finished successfully.
	Copy(ctx context.Context, db, attempt int) error
	CreateSubscription(ctx context.Context, db, attempt int) error
	EnableSubscription(ctx context.Context, db, attempt int) error
	Progress(ctx context.Context, db, attempt int) (Progress, error)
}

// CaughtUpPolicy decides when replication counts as caught up.
type CaughtUpPolicy struct {
	// MaxLagBytes: a database is within threshold at or below this lag.
	MaxLagBytes int64
	// Hold: every database must stay within threshold for this long.
	Hold time.Duration
	// PollInterval is the delay between observations while waiting.
	PollInterval time.Duration
}

// Guardrail holds the retained-WAL thresholds (the monitor rule's).
type Guardrail struct {
	Warn, Critical int64
}

// Level returns "ok", "warning" or "critical" for a slot's retained WAL; a slot
// whose WAL was lost is always critical.
func (g Guardrail) Level(retained int64, walStatus string) string {
	switch {
	case walStatus == "lost", g.Critical > 0 && retained >= g.Critical:
		return "critical"
	case g.Warn > 0 && retained >= g.Warn:
		return "warning"
	default:
		return "ok"
	}
}

// ErrSimulatedCrash lets tests kill the "process" at a boundary: when the hook
// returns it, the driver stops at once and writes nothing more, exactly like a
// SIGKILL would. Production code never returns it.
var ErrSimulatedCrash = errors.New("simulated crash")

// ErrNotRunnable means the migration is in a state that has nothing to drive.
var ErrNotRunnable = errors.New("nothing to run in this state")

// RecoveryRequiredError is returned when a database cannot continue without a
// new copy: its slot or snapshot is gone, or a partial copy is on the target.
// The operator approves a recovery plan (drop the old slot, reset the target
// database, copy again under a new slot).
type RecoveryRequiredError struct {
	// Reasons maps database index to why.
	Reasons map[int]string
}

func (e *RecoveryRequiredError) Error() string {
	idx := e.DBs()
	parts := make([]string, 0, len(idx))
	for _, i := range idx {
		parts = append(parts, fmt.Sprintf("database #%d: %s", i, e.Reasons[i]))
	}
	return "a new copy is required before this migration can continue (" + strings.Join(parts, "; ") + "): run `lockkeeper migrate resume` to see the recovery plan"
}

// DBs returns the affected database indexes in order.
func (e *RecoveryRequiredError) DBs() []int {
	idx := make([]int, 0, len(e.Reasons))
	for i := range e.Reasons {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	return idx
}

// Options configure a Driver.
type Options struct {
	// Owner identifies this process in the lease (host:pid:random).
	Owner    string
	LeaseTTL time.Duration
	// TakeOver takes the lease even if it is still held: set only after the
	// local lock file proved that the previous holder is dead.
	TakeOver bool
	Policy   CaughtUpPolicy
	Guard    Guardrail
	// Wait keeps running in `following` until caught up.
	Wait bool
	Now  func() time.Time
	// Sleep waits d or until ctx ends (default: a real timer).
	Sleep func(ctx context.Context, d time.Duration) error
	// Hook is called at every persistence boundary with its name. Tests use it
	// to observe the boundaries and to inject ErrSimulatedCrash.
	Hook func(point string) error
	// Notify receives progress and warning lines (never secrets).
	Notify func(level, msg string)
}

// Driver advances one migration.
type Driver struct {
	store Store
	world World
	opt   Options
}

// NewDriver builds a Driver.
func NewDriver(s Store, w World, o Options) *Driver {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	if o.LeaseTTL <= 0 {
		o.LeaseTTL = 60 * time.Second
	}
	if o.Policy.PollInterval <= 0 {
		o.Policy.PollInterval = 10 * time.Second
	}
	return &Driver{store: s, world: w, opt: o}
}

func (d *Driver) hook(point string) error {
	if d.opt.Hook == nil {
		return nil
	}
	return d.opt.Hook(point)
}

func (d *Driver) say(level, format string, args ...any) {
	if d.opt.Notify != nil {
		d.opt.Notify(level, fmt.Sprintf(format, args...))
	}
}

func isCrash(err error) bool { return errors.Is(err, ErrSimulatedCrash) }

// Run drives the migration as far as it can go: from source_changes_approved
// (or a resumable failure) through copying to following and, with Options.Wait,
// to caught_up. It holds the single-driver lease for the whole call. It returns
// the record as it ends.
func (d *Driver) Run(ctx context.Context, id string) (Record, error) {
	if err := d.store.AcquireLease(ctx, id, d.opt.Owner, d.opt.LeaseTTL, d.opt.TakeOver); err != nil {
		return Record{}, err
	}
	runCtx, cancel := context.WithCancelCause(ctx)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(d.opt.LeaseTTL / 3)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if err := d.store.RenewLease(runCtx, id, d.opt.Owner, d.opt.LeaseTTL); err != nil && !errors.Is(err, context.Canceled) {
					cancel(fmt.Errorf("lost the driver lease: %w", err))
					return
				}
			}
		}
	}()
	rec, err := d.run(runCtx, id)
	close(stop)
	<-done
	if cause := context.Cause(runCtx); err != nil && cause != nil && !errors.Is(cause, context.Canceled) {
		err = cause
	}
	cancel(nil)
	relCtx, relCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer relCancel()
	if !isCrash(err) { // a killed process releases nothing
		_ = d.store.ReleaseLease(relCtx, id, d.opt.Owner)
	}
	return rec, err
}

func (d *Driver) run(ctx context.Context, id string) (Record, error) {
	rec, err := d.store.Load(ctx, id)
	if err != nil {
		return rec, err
	}
	// A resumable failure returns to the state it failed in.
	if rec.State == Failed {
		if !rec.FailedResumable {
			return rec, fmt.Errorf("%w: the migration failed at %s and is not resumable: %s", ErrNotRunnable, rec.FailedStep, rec.FailedReason)
		}
		if err := d.move(ctx, rec, rec.FailedFrom, "resume after failure at "+rec.FailedStep, Facts{}); err != nil {
			return rec, err
		}
		if rec, err = d.store.Load(ctx, id); err != nil {
			return rec, err
		}
	}
	switch rec.State {
	case SourceChangesApproved:
		if err := d.move(ctx, rec, Copying, "start", Facts{}); err != nil {
			return rec, err
		}
	case Copying, Following:
	case CaughtUp:
		return rec, nil
	default:
		return rec, fmt.Errorf("%w: %s (run apply-source-changes first, or the migration was aborted or cleaned)", ErrNotRunnable, rec.State)
	}
	if rec, err = d.store.Load(ctx, id); err != nil {
		return rec, err
	}

	if err := d.reconcileAll(ctx, rec); err != nil {
		return d.fail(ctx, id, rec, err)
	}
	rec, _ = d.store.Load(ctx, id)
	if rec.State == Copying {
		enabled, err := d.countEnabled(ctx, rec)
		if err != nil {
			return d.fail(ctx, id, rec, err)
		}
		f := rec.Facts()
		f.SubscriptionsEnabled = enabled
		if err := d.move(ctx, rec, Following, "every subscription is enabled", f); err != nil {
			return d.fail(ctx, id, rec, err)
		}
		rec, _ = d.store.Load(ctx, id)
	}
	if d.opt.Wait && rec.State == Following {
		if err := d.waitCaughtUp(ctx, id); err != nil {
			return d.fail(ctx, id, rec, err)
		}
		rec, _ = d.store.Load(ctx, id)
	}
	return rec, nil
}

// fail records a failure unless the process was stopped (cancellation) or
// "killed" (crash injection), in which case the state is left as it is and
// resume reconciles.
func (d *Driver) fail(ctx context.Context, id string, rec Record, err error) (Record, error) {
	if isCrash(err) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return rec, err
	}
	cur, lerr := d.store.Load(context.WithoutCancel(ctx), id)
	if lerr != nil {
		return rec, err
	}
	step := "reconcile"
	var sf *stepFailure
	if errors.As(err, &sf) {
		step = sf.step
	}
	var rr *RecoveryRequiredError
	resumable := true
	if errors.As(err, &rr) {
		step = "recovery-required"
	}
	if cur.State.InProgress() {
		if merr := d.store.MarkFailed(context.WithoutCancel(ctx), id, cur.State, step, resumable, err.Error()); merr != nil {
			return cur, fmt.Errorf("%w (and recording the failure failed: %v)", err, merr)
		}
		cur.State = Failed
	}
	return cur, err
}

type stepFailure struct {
	step string
	err  error
}

func (e *stepFailure) Error() string { return e.err.Error() }
func (e *stepFailure) Unwrap() error { return e.err }

// move transitions after checking the guard. A crash can be injected on both
// sides of the compare-and-swap.
func (d *Driver) move(ctx context.Context, rec Record, to State, why string, observed Facts) error {
	f := rec.Facts()
	f.SubscriptionsEnabled, f.CaughtUp = observed.SubscriptionsEnabled, observed.CaughtUp
	if err := Check(f, to); err != nil {
		return err
	}
	if err := d.hook(fmt.Sprintf("before-transition:%s->%s", rec.State, to)); err != nil {
		return err
	}
	if err := d.store.Transition(ctx, rec.ID, rec.State, to, why); err != nil {
		return err
	}
	return d.hook(fmt.Sprintf("after-transition:%s->%s", rec.State, to))
}

func (d *Driver) attempt(ctx context.Context, id, db string) (int, error) {
	v, ok, err := d.store.Checkpoint(ctx, id, db, "attempt")
	if err != nil || !ok {
		return 1, err
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 1, nil
	}
	return n, nil
}

func (d *Driver) copyDone(ctx context.Context, id, db string, attempt int) (bool, error) {
	v, ok, err := d.store.Checkpoint(ctx, id, db, "copy_done")
	if err != nil || !ok {
		return false, err
	}
	return v == strconv.Itoa(attempt), nil
}

// needsRecovery decides, from the recorded copy status and what the servers
// say, whether a database cannot continue without a new copy.
func needsRecovery(copyDone bool, o DBState) (string, bool) {
	switch {
	case copyDone && (!o.SlotExists || o.SlotWALStatus == "lost"):
		return "the replication slot is missing or lost its WAL, so the change stream has a gap", true
	case !copyDone && o.SubExists:
		return "a subscription exists although the copy was never recorded as finished", true
	case !copyDone && o.SlotExists:
		return "a replication slot from an interrupted copy exists (its snapshot is gone and a slot cannot be reused for a new copy)", true
	case !copyDone && o.TargetHasTables:
		return "the target database already holds tables from an interrupted copy", true
	}
	return "", false
}

// reconcileAll observes every database first and refuses to start anything if
// one needs recovery, then advances each database: copy, subscription, enable.
func (d *Driver) reconcileAll(ctx context.Context, rec Record) error {
	names := d.world.Databases()
	need := &RecoveryRequiredError{Reasons: map[int]string{}}
	for i, name := range names {
		db := i + 1
		attempt, err := d.attempt(ctx, rec.ID, name)
		if err != nil {
			return err
		}
		cd, err := d.copyDone(ctx, rec.ID, name, attempt)
		if err != nil {
			return err
		}
		o, err := d.world.Observe(ctx, db, attempt)
		if err != nil {
			return fmt.Errorf("observe %s: %w", name, err)
		}
		if why, bad := needsRecovery(cd, o); bad {
			need.Reasons[db] = why
		}
	}
	if len(need.Reasons) > 0 {
		return need
	}
	for i := range names {
		if err := d.advance(ctx, rec.ID, i+1, names[i]); err != nil {
			return err
		}
	}
	return nil
}

func (d *Driver) advance(ctx context.Context, id string, db int, name string) error {
	attempt, err := d.attempt(ctx, id, name)
	if err != nil {
		return err
	}
	cd, err := d.copyDone(ctx, id, name, attempt)
	if err != nil {
		return err
	}
	o, err := d.world.Observe(ctx, db, attempt)
	if err != nil {
		return fmt.Errorf("observe %s: %w", name, err)
	}
	if why, bad := needsRecovery(cd, o); bad {
		return &RecoveryRequiredError{Reasons: map[int]string{db: why}}
	}
	if !cd {
		// The completion marker is written right after the copy returns and before
		// the step result: the only window in which a crash loses the fact that
		// the copy finished is between Copy returning and this single write, and
		// that case is handled conservatively (a new copy, see needsRecovery).
		err := d.effect(ctx, id, name, "copy", attempt, func() error {
			if err := d.world.Copy(ctx, db, attempt); err != nil {
				return err
			}
			if err := d.hook("after-copy:" + name); err != nil {
				return err
			}
			return d.store.SetCheckpoint(ctx, id, name, "copy_done", strconv.Itoa(attempt))
		})
		if err != nil {
			return err
		}
		if o, err = d.world.Observe(ctx, db, attempt); err != nil {
			return fmt.Errorf("observe %s: %w", name, err)
		}
	}
	if !o.SubExists {
		if err := d.effect(ctx, id, name, "subscription_create", attempt, func() error { return d.world.CreateSubscription(ctx, db, attempt) }); err != nil {
			return err
		}
		o.SubExists = true
	}
	if !o.SubEnabled {
		if err := d.effect(ctx, id, name, "subscription_enable", attempt, func() error { return d.world.EnableSubscription(ctx, db, attempt) }); err != nil {
			return err
		}
	}
	return nil
}

// effect runs fn with its intent persisted first and its result after.
func (d *Driver) effect(ctx context.Context, id, db, name string, attempt int, fn func() error) error {
	label := name + ":" + db
	if err := d.hook("before-intent:" + label); err != nil {
		return err
	}
	sid, err := d.store.BeginStep(ctx, id, db, name, attempt, "intent")
	if err != nil {
		return fmt.Errorf("record intent of %s: %w", label, err)
	}
	if err := d.hook("intent:" + label); err != nil {
		return err
	}
	ferr := fn()
	if isCrash(ferr) {
		return ferr // a killed process records nothing
	}
	if err := d.hook("effect:" + label); err != nil {
		return err
	}
	fctx := context.WithoutCancel(ctx)
	if ferr != nil {
		_ = d.store.FinishStep(fctx, sid, "failed", "", ferr.Error())
		return &stepFailure{step: label, err: fmt.Errorf("%s: %w", label, ferr)}
	}
	if err := d.store.FinishStep(fctx, sid, "done", "", ""); err != nil {
		return fmt.Errorf("record result of %s: %w", label, err)
	}
	return d.hook("done:" + label)
}

func (d *Driver) countEnabled(ctx context.Context, rec Record) (int, error) {
	n := 0
	for i, name := range d.world.Databases() {
		attempt, err := d.attempt(ctx, rec.ID, name)
		if err != nil {
			return 0, err
		}
		o, err := d.world.Observe(ctx, i+1, attempt)
		if err != nil {
			return 0, err
		}
		if o.SubEnabled {
			n++
		}
	}
	return n, nil
}

// waitCaughtUp polls progress until every database stayed within the lag
// threshold for the hold period, evaluating the WAL guardrail on the way.
func (d *Driver) waitCaughtUp(ctx context.Context, id string) error {
	names := d.world.Databases()
	for {
		allOK := true
		for i, name := range names {
			attempt, err := d.attempt(ctx, id, name)
			if err != nil {
				return err
			}
			p, err := d.world.Progress(ctx, i+1, attempt)
			if err != nil {
				return fmt.Errorf("progress of %s: %w", name, err)
			}
			d.guard(ctx, id, name, p)
			if !(p.SubEnabled && p.WorkerRunning && p.LagBytes <= d.opt.Policy.MaxLagBytes && p.WALStatus != "lost") {
				allOK = false
			}
		}
		now := d.opt.Now()
		since, have, err := d.store.Checkpoint(ctx, id, "", "caught_since")
		if err != nil {
			return err
		}
		switch {
		case !allOK:
			if have {
				if err := d.store.DeleteCheckpoint(ctx, id, "", "caught_since"); err != nil {
					return err
				}
			}
		case !have:
			if err := d.store.SetCheckpoint(ctx, id, "", "caught_since", strconv.FormatInt(now.UnixMilli(), 10)); err != nil {
				return err
			}
			d.say("info", "every database is within the lag threshold; holding for %s", d.opt.Policy.Hold)
		default:
			ms, _ := strconv.ParseInt(since, 10, 64)
			if now.Sub(time.UnixMilli(ms)) >= d.opt.Policy.Hold {
				rec, err := d.store.Load(ctx, id)
				if err != nil {
					return err
				}
				f := rec.Facts()
				f.CaughtUp = true
				return d.move(ctx, rec, CaughtUp, fmt.Sprintf("within %d bytes of the source for %s", d.opt.Policy.MaxLagBytes, d.opt.Policy.Hold), f)
			}
		}
		if err := d.opt.Sleep(ctx, d.opt.Policy.PollInterval); err != nil {
			return err
		}
	}
}

// guard evaluates the retained-WAL guardrail for one database. It only alerts
// (an audit event and a notification when the level changes); it never drops a
// slot or pauses anything.
func (d *Driver) guard(ctx context.Context, id, db string, p Progress) {
	level := d.opt.Guard.Level(p.RetainedBytes, p.WALStatus)
	prev, _, _ := d.store.Checkpoint(ctx, id, db, "guardrail")
	if prev == "" {
		prev = "ok"
	}
	if level == prev {
		return
	}
	_ = d.store.SetCheckpoint(ctx, id, db, "guardrail", level)
	msg := fmt.Sprintf("database %s: the source retains %d bytes of WAL for this migration's slot (wal_status %q): guardrail is now %s", db, p.RetainedBytes, p.WALStatus, level)
	_ = d.store.Audit(ctx, id, "guardrail."+level, msg)
	switch level {
	case "ok":
		d.say("info", "%s", strings.Replace(msg, "guardrail is now ok", "guardrail resolved", 1))
	case "warning":
		d.say("warn", "%s. Nothing is done automatically; see docs/runbooks/wal-slot-full.md", msg)
	default:
		d.say("critical", "%s. The source disk can fill up. Nothing is done automatically; see docs/runbooks/wal-slot-full.md", msg)
	}
}

// BumpAttempt records that database db (1-based) was recovered: the next copy
// is a new attempt with a new slot, and the old completion marker no longer
// counts. The caller applies the recovery plan first.
func (d *Driver) BumpAttempt(ctx context.Context, id string, db int) error {
	names := d.world.Databases()
	if db < 1 || db > len(names) {
		return fmt.Errorf("no database #%d", db)
	}
	name := names[db-1]
	cur, err := d.attempt(ctx, id, name)
	if err != nil {
		return err
	}
	if err := d.store.SetCheckpoint(ctx, id, name, "attempt", strconv.Itoa(cur+1)); err != nil {
		return err
	}
	return d.store.DeleteCheckpoint(ctx, id, name, "copy_done")
}

// Attempt returns the current copy attempt of database db (1-based).
func (d *Driver) Attempt(ctx context.Context, id string, db int) (int, error) {
	names := d.world.Databases()
	if db < 1 || db > len(names) {
		return 0, fmt.Errorf("no database #%d", db)
	}
	return d.attempt(ctx, id, names[db-1])
}

// Move performs a guarded compare-and-swap transition on behalf of the commands
// that are not the driver loop (preflight_ok, approval, abort, cleanup).
func Move(ctx context.Context, s Store, id string, to State, why string, observed Facts) error {
	rec, err := s.Load(ctx, id)
	if err != nil {
		return err
	}
	f := rec.Facts()
	f.SubscriptionsEnabled, f.CaughtUp = observed.SubscriptionsEnabled, observed.CaughtUp
	f.PreflightBlockers = observed.PreflightBlockers
	f.CleanupApprovedHash, f.CleanupPlanHash, f.CleanupDone = observed.CleanupApprovedHash, observed.CleanupPlanHash, observed.CleanupDone
	if err := Check(f, to); err != nil {
		return err
	}
	return s.Transition(ctx, id, rec.State, to, why)
}
