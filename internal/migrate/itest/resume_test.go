//go:build integration

package itest

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"
)

var recoveryHashRe = regexp.MustCompile(`--recovery-plan-hash ([0-9a-f]{64})`)

func waitFor(t testing.TB, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", within, what)
}

// TestKillMidCopyThenResume interrupts the bulk copy in two ways (the copy tool
// is killed; the whole driver is cancelled the way a SIGKILLed process would
// leave things) and checks that resume refuses to reuse the slot, shows a
// recovery plan, applies it only with its hash, and ends with identical rows.
func TestKillMidCopyThenResume(t *testing.T) {
	for _, mode := range []string{"copy tool killed", "driver cancelled"} {
		t.Run(mode, func(t *testing.T) {
			r := newRig(t, copierKinds()[0], rigOptions{})
			// A bigger table makes the copy last long enough to interrupt.
			exec(t, r.src.AdminDB(t, "app"), `INSERT INTO ledger (account_id, amount) SELECT 1 + g % 2000, g FROM generate_series(1, 600000) g`)
			hash, id := r.plan()
			if o := r.apply(hash); o.code != 0 {
				t.Fatalf("apply: %s", o.all())
			}
			w := startWriters(t, r)

			slotUp := func() bool {
				return count(t, r, "app", `SELECT count(*) FROM pg_replication_slots WHERE slot_name LIKE 'lk\_`+id+`\_d1\_a%'`) > 0
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan output, 1)
			go func() { done <- r.runCtx(ctx, r.startArgs(id, "--no-wait")...) }()
			waitFor(t, 2*time.Minute, "the slot of the first database", slotUp)
			switch mode {
			case "copy tool killed":
				waitFor(t, time.Minute, "a copy tool container", func() bool { return r.launcher.KillToolContainers() > 0 })
			default:
				time.Sleep(1500 * time.Millisecond) // let the copy get going
				cancel()
			}
			var o output
			select {
			case o = <-done:
			case <-time.After(3 * time.Minute):
				t.Fatal("start did not return after the interruption")
			}
			if o.code == 0 {
				t.Fatalf("an interrupted copy must not look successful:\n%s", o.all())
			}
			want := map[string]string{"copy tool killed": "failed", "driver cancelled": "copying"}[mode]
			if got := r.state(id); got != want {
				t.Fatalf("state after the interruption = %s, want %s\n%s", got, want, o.all())
			}
			if !slotUp() {
				t.Fatal("the interrupted copy must leave its slot behind (it still retains WAL)")
			}

			// resume without --apply: shows the recovery plan, changes nothing.
			fp := r.sourceFingerprint()
			tablesBefore := targetCount(t, r, "app", `SELECT count(*) FROM pg_class WHERE relkind = 'r' AND relnamespace = 'public'::regnamespace`)
			dry := r.run("migrate", "resume", "--migration", id, "--allow-untested-pgcopydb")
			rh := recoveryHashRe.FindStringSubmatch(dry.stdout)
			if dry.code != 2 || rh == nil {
				t.Fatalf("resume must show a recovery plan and exit 2 (%d):\n%s", dry.code, dry.all())
			}
			for _, want := range []string{"pg_drop_replication_slot", "DROP DATABASE", "CREATE_REPLICATION_SLOT", "_a2", "slot cannot be reused"} {
				if !strings.Contains(dry.stdout, want) && !strings.Contains(strings.ToLower(dry.stdout), strings.ToLower(want)) {
					t.Errorf("the recovery plan lacks %q:\n%s", want, dry.stdout)
				}
			}
			if r.sourceFingerprint() != fp || targetCount(t, r, "app", `SELECT count(*) FROM pg_class WHERE relkind = 'r' AND relnamespace = 'public'::regnamespace`) != tablesBefore {
				t.Fatal("showing the recovery plan changed a server")
			}

			// Refusals: no confirmation, wrong hash.
			r.stdin = ""
			if o := r.run("migrate", "resume", "--migration", id, "--apply", "--allow-untested-pgcopydb"); o.code == 0 {
				t.Fatalf("applying a recovery needs a confirmation:\n%s", o.all())
			}
			if o := r.run("migrate", "resume", "--migration", id, "--apply", "--recovery-plan-hash", strings.Repeat("b", 64), "--allow-untested-pgcopydb"); o.code == 0 {
				t.Fatalf("a wrong recovery plan hash must be refused:\n%s", o.all())
			}
			if !slotUp() {
				t.Fatal("a refused recovery dropped the slot")
			}

			// Approve it, under writers; the migration completes.
			o = r.run("migrate", "resume", "--migration", id, "--apply", "--recovery-plan-hash", rh[1],
				"--allow-untested-pgcopydb", "--max-lag", "8MiB", "--caught-up-for", "3s", "--poll-interval", "1s")
			if o.code != 0 {
				t.Fatalf("resume with the recovery plan failed (%d):\n%s", o.code, o.all())
			}
			if got := r.state(id); got != "caught_up" {
				t.Fatalf("state = %s", got)
			}
			time.Sleep(time.Second)
			w.Stop()
			waitDrained(t, r.src, 90*time.Second)
			assertSameRows(t, r.src, r.tgt)

			// One live slot per database; the first database's is attempt 2.
			if n := count(t, r, "app", `SELECT count(*) FROM pg_replication_slots WHERE slot_name LIKE 'lk\_`+id+`\_%'`); n != 2 {
				t.Errorf("expected exactly one slot per database after recovery, got %d", n)
			}
			if n := count(t, r, "app", `SELECT count(*) FROM pg_replication_slots WHERE slot_name LIKE 'lk\_`+id+`\_d1\_a2'`); n != 1 {
				t.Error("the recovered database must use a new slot (attempt 2)")
			}
			if n := count(t, r, "app", `SELECT count(*) FROM pg_replication_slots WHERE slot_name LIKE 'lk\_`+id+`\_d1\_a1'`); n != 0 {
				t.Error("the old slot must have been dropped by the recovery plan")
			}
			// Everything the recovery did is in the audit trail.
			st := r.run("migrate", "status", "--migration", id, "--json", "--allow-untested-pgcopydb")
			if !strings.Contains(st.stdout, `"attempt": 2`) {
				t.Errorf("status must show attempt 2:\n%s", st.stdout)
			}
		})
	}
}

// TestKillDuringFollowingThenResume cancels the driver while it waits in
// following (replication keeps running on the target by itself), breaks the
// replication connection once, keeps writing, and resumes to caught_up.
func TestKillDuringFollowingThenResume(t *testing.T) {
	r := newRig(t, copierKinds()[0], rigOptions{})
	hash, id := r.plan()
	if o := r.apply(hash); o.code != 0 {
		t.Fatalf("apply: %s", o.all())
	}
	w := startWriters(t, r)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan output, 1)
	// A long hold keeps the driver waiting in following.
	go func() {
		done <- r.runCtx(ctx, r.startArgs(id, "--caught-up-for", "10m")...)
	}()
	waitFor(t, 3*time.Minute, "state following", func() bool { return r.state(id) == "following" })
	time.Sleep(time.Second)
	cancel() // the driver "dies"
	select {
	case <-done:
	case <-time.After(time.Minute):
		t.Fatal("start did not return after cancellation")
	}
	if got := r.state(id); got != "following" {
		t.Fatalf("a killed driver must leave the state at following, got %s", got)
	}

	// Replication does not need the driver: break its connection; the worker reconnects.
	exec(t, r.src.Admin(t), `SELECT pg_terminate_backend(pid) FROM pg_stat_replication`)
	time.Sleep(2 * time.Second)
	// The lock and lease were released: resume can take over.
	o := r.run("migrate", "resume", "--migration", id, "--allow-untested-pgcopydb", "--max-lag", "8MiB", "--caught-up-for", "3s", "--poll-interval", "1s")
	if o.code != 0 {
		t.Fatalf("resume (%d):\n%s", o.code, o.all())
	}
	if got := r.state(id); got != "caught_up" {
		t.Fatalf("state = %s", got)
	}
	w.Stop()
	waitDrained(t, r.src, 90*time.Second)
	assertSameRows(t, r.src, r.tgt)
	if n := count(t, r, "app", `SELECT count(*) FROM pg_replication_slots WHERE slot_name LIKE 'lk\_`+id+`\_%'`); n != 2 {
		t.Errorf("resume must not create another slot: %d slots", n)
	}
}
