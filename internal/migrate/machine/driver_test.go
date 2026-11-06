package machine

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/store"
)

var t0 = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

// fakeClock is a manual clock; Sleep advances it.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
	return nil
}

// fakeWorld is an in-memory pair of servers that is as strict as the real ones:
// creating a slot or a subscription that exists, or copying into a target that
// already has tables, is an error, so any duplicated effect fails the test.
type fakeWorld struct {
	mu    sync.Mutex
	names []string

	slots  map[int]map[int]bool // db -> attempt -> exists
	subs   map[int]*fakeSub
	tables map[int]bool
	lost   map[int]bool

	copies, slotCreates, subCreates, enables, recoveries map[int]int

	// crashMidCopy makes the next Copy of that database die after the slot and a
	// partial target exist (the process "is killed" inside the copy).
	crashMidCopy map[int]bool
	// failCopy returns this error from the next Copy of that database.
	failCopy map[int]error
	progress func(db, attempt int, w *fakeWorld) Progress
}

type fakeSub struct {
	attempt int
	enabled bool
}

func newFakeWorld(names ...string) *fakeWorld {
	w := &fakeWorld{
		names: names, slots: map[int]map[int]bool{}, subs: map[int]*fakeSub{}, tables: map[int]bool{}, lost: map[int]bool{},
		copies: map[int]int{}, slotCreates: map[int]int{}, subCreates: map[int]int{}, enables: map[int]int{}, recoveries: map[int]int{},
		crashMidCopy: map[int]bool{}, failCopy: map[int]error{},
	}
	return w
}

func (w *fakeWorld) Databases() []string { return w.names }

func (w *fakeWorld) Observe(_ context.Context, db, _ int) (DBState, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := DBState{TargetHasTables: w.tables[db]}
	if len(w.slots[db]) > 0 {
		st.SlotExists = true
		st.SlotWALStatus = "reserved"
		if w.lost[db] {
			st.SlotWALStatus = "lost"
		}
	}
	if s := w.subs[db]; s != nil {
		st.SubExists, st.SubEnabled, st.SlotActive = true, s.enabled, s.enabled
	}
	return st, nil
}

func (w *fakeWorld) Copy(_ context.Context, db, attempt int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.slots[db][attempt] {
		return fmt.Errorf("fake: slot for database %d attempt %d already exists", db, attempt)
	}
	if w.tables[db] {
		return fmt.Errorf("fake: target database %d is not empty", db)
	}
	if w.slots[db] == nil {
		w.slots[db] = map[int]bool{}
	}
	w.slots[db][attempt] = true
	w.slotCreates[db]++
	w.copies[db]++
	if err := w.failCopy[db]; err != nil {
		delete(w.failCopy, db)
		w.tables[db] = true // a partial copy is left behind
		return err
	}
	if w.crashMidCopy[db] {
		delete(w.crashMidCopy, db)
		w.tables[db] = true
		return ErrSimulatedCrash
	}
	w.tables[db] = true
	return nil
}

func (w *fakeWorld) CreateSubscription(_ context.Context, db, attempt int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.subs[db] != nil {
		return fmt.Errorf("fake: subscription for database %d already exists", db)
	}
	w.subs[db] = &fakeSub{attempt: attempt}
	w.subCreates[db]++
	return nil
}

func (w *fakeWorld) EnableSubscription(_ context.Context, db int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.subs[db] == nil {
		return fmt.Errorf("fake: no subscription for database %d", db)
	}
	w.subs[db].enabled = true
	w.enables[db]++
	return nil
}

func (w *fakeWorld) Progress(_ context.Context, db, attempt int) (Progress, error) {
	if w.progress != nil {
		return w.progress(db, attempt, w), nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	en := w.subs[db] != nil && w.subs[db].enabled
	return Progress{SubEnabled: en, WorkerRunning: en, WALStatus: "reserved"}, nil
}

// Recover is what the confirmed recovery plan does to the real servers.
func (w *fakeWorld) Recover(db int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.slots, db)
	delete(w.subs, db)
	w.tables[db] = false
	delete(w.lost, db)
	w.recoveries[db]++
}

type env struct {
	t     *testing.T
	db    *store.Store
	ss    SQLStore
	clock *fakeClock
	id    string
}

func newEnv(t *testing.T, dbs ...string) *env {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "state", "lockkeeper.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	e := &env{t: t, db: s, clock: &fakeClock{t: t0}, id: "m1"}
	e.ss = SQLStore{DB: s, Actor: "test", Now: e.clock.Now}
	if _, _, err := s.CreateMigration(ctx, store.Migration{ID: e.id, SourceName: "a", TargetName: "b", Databases: dbs, PlanHash: "h", PlanJSON: "{}"}, t0); err != nil {
		t.Fatal(err)
	}
	return e
}

// approve moves the migration to source_changes_approved through the guarded path.
func (e *env) approve() {
	e.t.Helper()
	ctx := context.Background()
	if err := Move(ctx, e.ss, e.id, PreflightOK, "pre-flight clean", Facts{}); err != nil {
		e.t.Fatal(err)
	}
	if err := e.db.SetApprovedHash(ctx, e.id, "h", t0); err != nil {
		e.t.Fatal(err)
	}
	if err := Move(ctx, e.ss, e.id, SourceChangesApproved, "approved", Facts{}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) opts(owner string, wait bool) Options {
	return Options{
		Owner: owner, LeaseTTL: time.Hour, Wait: wait, Now: e.clock.Now, Sleep: e.clock.Sleep,
		Policy: CaughtUpPolicy{MaxLagBytes: 1000, Hold: 2 * time.Minute, PollInterval: 30 * time.Second},
		Guard:  Guardrail{Warn: 5000, Critical: 20000},
	}
}

func (e *env) state() State {
	e.t.Helper()
	rec, err := e.ss.Load(context.Background(), e.id)
	if err != nil {
		e.t.Fatal(err)
	}
	return rec.State
}

func TestHappyPathReachesFollowingWithEveryEffectOnce(t *testing.T) {
	e := newEnv(t, "app", "billing")
	e.approve()
	w := newFakeWorld("app", "billing")
	rec, err := NewDriver(e.ss, w, e.opts("A", false)).Run(context.Background(), e.id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != Following {
		t.Fatalf("state %s", rec.State)
	}
	for db := 1; db <= 2; db++ {
		if w.copies[db] != 1 || w.slotCreates[db] != 1 || w.subCreates[db] != 1 || w.enables[db] != 1 {
			t.Errorf("database %d: effects copies=%d slots=%d subs=%d enables=%d, want 1 each", db, w.copies[db], w.slotCreates[db], w.subCreates[db], w.enables[db])
		}
	}
	steps, _ := e.db.Steps(context.Background(), e.id)
	var names []string
	for _, s := range steps {
		if s.Status != "done" {
			t.Errorf("step %+v must be done", s)
		}
		names = append(names, s.Database+"/"+s.Name)
	}
	want := "app/copy app/subscription_create app/subscription_enable billing/copy billing/subscription_create billing/subscription_enable"
	if strings.Join(names, " ") != want {
		t.Fatalf("steps:\n got %v\nwant %s", names, want)
	}
	// Resuming a finished run changes nothing and creates nothing.
	if _, err := NewDriver(e.ss, w, e.opts("B", false)).Run(context.Background(), e.id); err != nil {
		t.Fatal(err)
	}
	if w.copies[1] != 1 || w.subCreates[1] != 1 {
		t.Fatal("a second run duplicated an effect")
	}
}

func TestRunRefusesStatesWithNothingToDrive(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "app")
	w := newFakeWorld("app")
	if _, err := NewDriver(e.ss, w, e.opts("A", false)).Run(ctx, e.id); !errors.Is(err, ErrNotRunnable) {
		t.Fatalf("draft: %v", err)
	}
	e.approve()
	if err := Move(ctx, e.ss, e.id, Aborted, "stop", Facts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDriver(e.ss, w, e.opts("A", false)).Run(ctx, e.id); !errors.Is(err, ErrNotRunnable) {
		t.Fatalf("aborted: %v", err)
	}
	if len(w.copies) != 0 {
		t.Fatal("nothing may be copied for an aborted migration")
	}
}

func TestSecondDriverIsRefusedWhileTheLeaseIsHeld(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "app")
	e.approve()
	if err := e.ss.AcquireLease(ctx, e.id, "other-process", time.Hour, false); err != nil {
		t.Fatal(err)
	}
	w := newFakeWorld("app")
	_, err := NewDriver(e.ss, w, e.opts("A", false)).Run(ctx, e.id)
	if !errors.Is(err, store.ErrLeaseHeld) {
		t.Fatalf("want ErrLeaseHeld, got %v", err)
	}
	if len(w.copies) != 0 {
		t.Fatal("a refused driver must not touch anything")
	}
	// After the lock file proved the holder dead the lease can be taken over.
	o := e.opts("A", false)
	o.TakeOver = true
	if _, err := NewDriver(e.ss, w, o).Run(ctx, e.id); err != nil {
		t.Fatalf("takeover: %v", err)
	}
	if rec, _ := e.ss.Load(ctx, e.id); rec.LeaseOwner != "" {
		t.Fatalf("the lease must be released after a clean run, owner %q", rec.LeaseOwner)
	}
}

func TestResumableFailureResumesWithoutDuplicatingTheCopy(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "app")
	e.approve()
	w := newFakeWorld("app")
	w.failCopy[1] = errors.New("connection reset by peer")
	rec, err := NewDriver(e.ss, w, e.opts("A", false)).Run(ctx, e.id)
	if err == nil || rec.State != Failed {
		t.Fatalf("want failed, got %v / %v", rec.State, err)
	}
	rec, _ = e.ss.Load(ctx, e.id)
	if rec.FailedFrom != Copying || !rec.FailedResumable || !strings.Contains(rec.FailedStep, "copy") || !strings.Contains(rec.FailedReason, "connection reset") {
		t.Fatalf("%+v", rec)
	}
	// The partial copy and the slot are left behind: resume must not blindly
	// copy again into them but ask for a recovery.
	_, err = NewDriver(e.ss, w, e.opts("B", false)).Run(ctx, e.id)
	var rr *RecoveryRequiredError
	if !errors.As(err, &rr) || len(rr.DBs()) != 1 || rr.DBs()[0] != 1 {
		t.Fatalf("want a RecoveryRequiredError for database 1, got %v", err)
	}
	if w.copies[1] != 1 {
		t.Fatalf("no second copy may start before the recovery plan is applied (copies=%d)", w.copies[1])
	}
	// The recovery plan is applied (the fake does what the plan's actions do),
	// the attempt is bumped, and the migration continues.
	w.Recover(1)
	d := NewDriver(e.ss, w, e.opts("C", false))
	if err := d.BumpAttempt(ctx, e.id, 1); err != nil {
		t.Fatal(err)
	}
	if n, _ := d.Attempt(ctx, e.id, 1); n != 2 {
		t.Fatalf("attempt = %d, want 2", n)
	}
	rec, err = d.Run(ctx, e.id)
	if err != nil || rec.State != Following {
		t.Fatalf("after recovery: %v %v", rec.State, err)
	}
	if !w.slots[1][2] || w.slots[1][1] || len(w.slots[1]) != 1 {
		t.Fatalf("the new copy must use a new slot and the old one must be gone: %v", w.slots[1])
	}
}

func TestReconcileDecisions(t *testing.T) {
	ctx := context.Background()
	t.Run("copy finished, subscription missing: create and enable only", func(t *testing.T) {
		e := newEnv(t, "app")
		e.approve()
		w := newFakeWorld("app")
		w.slots[1] = map[int]bool{1: true}
		w.tables[1] = true
		if err := e.ss.SetCheckpoint(ctx, e.id, "app", "copy_done", "1"); err != nil {
			t.Fatal(err)
		}
		if _, err := NewDriver(e.ss, w, e.opts("A", false)).Run(ctx, e.id); err != nil {
			t.Fatal(err)
		}
		if w.copies[1] != 0 || w.subCreates[1] != 1 || w.enables[1] != 1 {
			t.Fatalf("copies=%d subs=%d enables=%d", w.copies[1], w.subCreates[1], w.enables[1])
		}
	})
	t.Run("subscription exists but disabled: only enable", func(t *testing.T) {
		e := newEnv(t, "app")
		e.approve()
		w := newFakeWorld("app")
		w.slots[1] = map[int]bool{1: true}
		w.tables[1] = true
		w.subs[1] = &fakeSub{attempt: 1}
		_ = e.ss.SetCheckpoint(ctx, e.id, "app", "copy_done", "1")
		if _, err := NewDriver(e.ss, w, e.opts("A", false)).Run(ctx, e.id); err != nil {
			t.Fatal(err)
		}
		if w.subCreates[1] != 0 || w.enables[1] != 1 {
			t.Fatalf("subs=%d enables=%d", w.subCreates[1], w.enables[1])
		}
	})
	t.Run("slot dropped behind our back after the copy", func(t *testing.T) {
		e := newEnv(t, "app")
		e.approve()
		w := newFakeWorld("app")
		w.tables[1] = true
		_ = e.ss.SetCheckpoint(ctx, e.id, "app", "copy_done", "1")
		_, err := NewDriver(e.ss, w, e.opts("A", false)).Run(ctx, e.id)
		var rr *RecoveryRequiredError
		if !errors.As(err, &rr) || !strings.Contains(rr.Reasons[1], "slot") {
			t.Fatalf("want recovery for a missing slot, got %v", err)
		}
		if w.subCreates[1] != 0 {
			t.Fatal("a subscription must not be created on a slot that no longer exists")
		}
	})
	t.Run("slot lost its WAL while following", func(t *testing.T) {
		e := newEnv(t, "app")
		e.approve()
		w := newFakeWorld("app")
		if _, err := NewDriver(e.ss, w, e.opts("A", false)).Run(ctx, e.id); err != nil {
			t.Fatal(err)
		}
		w.lost[1] = true
		_, err := NewDriver(e.ss, w, e.opts("B", false)).Run(ctx, e.id)
		var rr *RecoveryRequiredError
		if !errors.As(err, &rr) {
			t.Fatalf("want recovery for a lost slot, got %v", err)
		}
		if st := e.state(); st != Failed {
			t.Fatalf("state %s", st)
		}
	})
}

// TestCrashAtEveryBoundary kills the driver at every persistence boundary (and
// inside the copy) and checks that resume reaches the same end state without
// duplicating any effect. The fake servers fail any duplicated create, so a
// duplicate is both counted and refused.
func TestCrashAtEveryBoundary(t *testing.T) {
	ctx := context.Background()
	script := func(db, attempt int, w *fakeWorld) Progress {
		// Lag falls below the threshold on the third poll.
		w.mu.Lock()
		defer w.mu.Unlock()
		w.copies[-1]++ // poll counter
		lag := int64(0)
		if w.copies[-1] <= 4 {
			lag = 50000
		}
		en := w.subs[db] != nil && w.subs[db].enabled
		return Progress{LagBytes: lag, SubEnabled: en, WorkerRunning: en, WALStatus: "reserved"}
	}

	// Dry run: list the boundaries.
	var points []string
	{
		e := newEnv(t, "app", "billing")
		e.approve()
		w := newFakeWorld("app", "billing")
		w.progress = script
		o := e.opts("A", true)
		o.Hook = func(p string) error { points = append(points, p); return nil }
		rec, err := NewDriver(e.ss, w, o).Run(ctx, e.id)
		if err != nil || rec.State != CaughtUp {
			t.Fatalf("dry run: %v %v", rec.State, err)
		}
	}
	if len(points) < 25 {
		t.Fatalf("only %d boundaries: the driver is not exposing them", len(points))
	}
	for _, want := range []string{"before-intent:copy:app", "intent:copy:app", "after-copy:app", "effect:copy:app", "done:copy:app",
		"before-intent:subscription_create:billing", "effect:subscription_enable:billing", "before-transition:source_changes_approved->copying",
		"after-transition:copying->following", "before-transition:following->caught_up", "after-transition:following->caught_up"} {
		found := false
		for _, p := range points {
			found = found || p == want
		}
		if !found {
			t.Errorf("boundary %q was never exposed", want)
		}
	}

	finish := func(e *env, w *fakeWorld) Record {
		t.Helper()
		for i := 0; i < 6; i++ {
			d := NewDriver(e.ss, w, func() Options { o := e.opts(fmt.Sprintf("restart-%d", i), true); o.TakeOver = true; return o }())
			rec, err := d.Run(ctx, e.id)
			var rr *RecoveryRequiredError
			if errors.As(err, &rr) {
				for _, db := range rr.DBs() {
					w.Recover(db) // what the approved recovery plan does
					if err := d.BumpAttempt(ctx, e.id, db); err != nil {
						t.Fatal(err)
					}
				}
				continue
			}
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			return rec
		}
		t.Fatal("resume did not converge")
		return Record{}
	}

	check := func(t *testing.T, e *env, w *fakeWorld, rec Record, wantRecoveries map[int]int) {
		t.Helper()
		if rec.State != CaughtUp {
			t.Fatalf("end state %s, want caught_up", rec.State)
		}
		for db := 1; db <= 2; db++ {
			rc := w.recoveries[db]
			if rc != wantRecoveries[db] {
				t.Errorf("database %d: %d recoveries, want %d", db, rc, wantRecoveries[db])
			}
			if got := w.copies[db]; got != 1+rc {
				t.Errorf("database %d: copied %d times, want %d (one per attempt)", db, got, 1+rc)
			}
			if got := w.slotCreates[db]; got != 1+rc {
				t.Errorf("database %d: %d slots created, want %d", db, got, 1+rc)
			}
			// Recoveries only happen before a subscription existed, so there is
			// exactly one subscription, created and enabled once.
			if got := w.subCreates[db]; got != 1 {
				t.Errorf("database %d: %d subscriptions created, want 1", db, got)
			}
			if got := w.enables[db]; got != 1 {
				t.Errorf("database %d: subscription enabled %d times, want 1", db, got)
			}
			if len(w.slots[db]) != 1 || w.subs[db] == nil || !w.subs[db].enabled {
				t.Errorf("database %d: end state slots=%v sub=%v, want one slot and one enabled subscription", db, w.slots[db], w.subs[db])
			}
		}
		// The audit trail's transitions form one unbroken chain.
		evs, _ := e.db.AuditEvents(ctx, e.id, 1000)
		cur := "draft"
		for _, ev := range evs {
			if ev.Kind != "state.transition" && ev.Kind != "state.failed" {
				continue
			}
			from, rest, _ := strings.Cut(ev.Detail, " -> ")
			to, _, _ := strings.Cut(rest, ":")
			if ev.Kind == "state.failed" {
				to, _, _ = strings.Cut(rest, " ")
			}
			if from != cur {
				t.Errorf("transition chain broken: %q after state %s", ev.Detail, cur)
			}
			cur = to
		}
		if cur != "caught_up" {
			t.Errorf("transition chain ends in %s", cur)
		}
		if rec2, _ := e.ss.Load(ctx, e.id); rec2.LeaseOwner != "" {
			t.Errorf("lease left behind: %q", rec2.LeaseOwner)
		}
	}

	recoveryFor := func(p string) map[int]int {
		switch p {
		case "after-copy:app":
			return map[int]int{1: 1}
		case "after-copy:billing":
			return map[int]int{2: 1}
		}
		return nil
	}

	for k := 1; k <= len(points); k++ {
		point := points[k-1]
		t.Run(fmt.Sprintf("%02d %s", k, point), func(t *testing.T) {
			e := newEnv(t, "app", "billing")
			e.approve()
			w := newFakeWorld("app", "billing")
			w.progress = script
			n := 0
			o := e.opts("victim", true)
			o.Hook = func(p string) error {
				n++
				if n == k {
					return ErrSimulatedCrash
				}
				return nil
			}
			_, err := NewDriver(e.ss, w, o).Run(ctx, e.id)
			if !errors.Is(err, ErrSimulatedCrash) {
				t.Fatalf("the crash at boundary %d (%s) did not happen: %v", k, point, err)
			}
			rec := finish(e, w)
			check(t, e, w, rec, recoveryFor(point))
		})
	}

	// A crash inside the copy itself (the process dies with the slot and a
	// partial copy on the target): the one case that needs a recovery.
	for db := 1; db <= 2; db++ {
		t.Run(fmt.Sprintf("killed inside the copy of database %d", db), func(t *testing.T) {
			e := newEnv(t, "app", "billing")
			e.approve()
			w := newFakeWorld("app", "billing")
			w.progress = script
			w.crashMidCopy[db] = true
			_, err := NewDriver(e.ss, w, e.opts("victim", true)).Run(ctx, e.id)
			if !errors.Is(err, ErrSimulatedCrash) {
				t.Fatalf("expected the simulated kill, got %v", err)
			}
			if st := e.state(); st != Copying {
				t.Fatalf("a killed process leaves the state as it was (copying), got %s", st)
			}
			rec := finish(e, w)
			check(t, e, w, rec, map[int]int{db: 1})
		})
	}
}

func TestGuardrailOnlyAlertsAndDedupesLevels(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "app")
	e.approve()
	w := newFakeWorld("app")
	polls := 0
	retained := []int64{0, 6000, 25000, 100, 0} // hold 2 min at 30 s polls: five polls
	w.progress = func(db, attempt int, w *fakeWorld) Progress {
		w.mu.Lock()
		defer w.mu.Unlock()
		r := retained[min(polls, len(retained)-1)]
		polls++
		return Progress{LagBytes: 0, RetainedBytes: r, SubEnabled: true, WorkerRunning: true, WALStatus: "extended"}
	}
	var notes []string
	o := e.opts("A", true)
	o.Notify = func(level, msg string) { notes = append(notes, level) }
	rec, err := NewDriver(e.ss, w, o).Run(ctx, e.id)
	if err != nil || rec.State != CaughtUp {
		t.Fatalf("%v %v", rec.State, err)
	}
	evs, _ := e.db.AuditEvents(ctx, e.id, 100)
	var kinds []string
	for _, ev := range evs {
		if strings.HasPrefix(ev.Kind, "guardrail.") {
			kinds = append(kinds, ev.Kind)
		}
	}
	if got := strings.Join(kinds, ","); got != "guardrail.warning,guardrail.critical,guardrail.ok" {
		t.Fatalf("one event per level change, got %s", got)
	}
	joined := strings.Join(notes, ",")
	if !strings.Contains(joined, "warn") || !strings.Contains(joined, "critical") {
		t.Fatalf("notifications: %s", joined)
	}
	// Alert-only: the guardrail never changed the world.
	if w.recoveries[1] != 0 || len(w.slots[1]) != 1 || !w.subs[1].enabled {
		t.Fatal("the guardrail must never act on the source or the target")
	}
}

func TestCaughtUpNeedsTheLagHeldForTheWholePeriod(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "app", "billing")
	e.approve()
	w := newFakeWorld("app", "billing")
	var seq []string
	step := 0
	w.progress = func(db, attempt int, w *fakeWorld) Progress {
		// Database 2 spikes at poll 3 (30 s apart, hold 2 min): the timer restarts.
		w.mu.Lock()
		defer w.mu.Unlock()
		if db == 1 {
			step++
		}
		lag := int64(0)
		if db == 2 && step == 3 {
			lag = 5000
		}
		seq = append(seq, fmt.Sprintf("%d:%d", db, lag))
		return Progress{LagBytes: lag, SubEnabled: true, WorkerRunning: true, WALStatus: "reserved"}
	}
	start := e.clock.Now()
	rec, err := NewDriver(e.ss, w, e.opts("A", true)).Run(ctx, e.id)
	if err != nil || rec.State != CaughtUp {
		t.Fatalf("%v %v", rec.State, err)
	}
	// First all-ok poll is #1 (t0+0). The spike at poll 3 resets it; the next ok
	// poll #4 starts a new hold, which ends 2 minutes later: 4 + 4 polls.
	if elapsed := e.clock.Now().Sub(start); elapsed < 2*time.Minute+90*time.Second {
		t.Fatalf("caught up after only %s: a lag spike must restart the hold timer", elapsed)
	}
	if _, ok, _ := e.ss.Checkpoint(ctx, e.id, "", "caught_since"); !ok {
		// the marker may remain after success; presence is not required
		_ = ok
	}
}

func TestStuckSubscriptionNeverCountsAsCaughtUp(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "app")
	e.approve()
	w := newFakeWorld("app")
	polls := 0
	w.progress = func(db, attempt int, w *fakeWorld) Progress {
		polls++
		// The apply worker is down (crash loop) although lag shows 0.
		return Progress{LagBytes: 0, SubEnabled: true, WorkerRunning: false, WALStatus: "reserved"}
	}
	ctx2, cancel := context.WithCancel(ctx)
	o := e.opts("A", true)
	o.Sleep = func(c context.Context, d time.Duration) error {
		if polls >= 12 {
			cancel()
		}
		return e.clock.Sleep(c, d)
	}
	rec, err := NewDriver(e.ss, w, o).Run(ctx2, e.id)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want cancellation, got %v (state %s)", err, rec.State)
	}
	if st := e.state(); st != Following {
		t.Fatalf("a worker that is down must keep the migration in following, got %s", st)
	}
}
