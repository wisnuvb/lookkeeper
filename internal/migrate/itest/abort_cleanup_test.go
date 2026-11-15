//go:build integration

package itest

import (
	"context"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var hashInOutput = regexp.MustCompile(`--plan-hash ([0-9a-f]{64})`)

func count(t testing.TB, r *rig, db, sql string) int {
	t.Helper()
	var n int
	if err := r.src.AdminDB(t, db).QueryRow(context.Background(), sql).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func targetCount(t testing.TB, r *rig, db, sql string) int {
	t.Helper()
	var n int
	if err := r.tgt.AdminDB(t, db).QueryRow(context.Background(), sql).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

// TestAbortLeavesTheSourceAloneAndCleanupRemovesExactlyWhatWasCreated runs a
// migration to following, aborts it, and cleans it up, with decoy objects on the
// source that must survive and a snapshot of the source's rows that must not move.
func TestAbortLeavesTheSourceAloneAndCleanupRemovesExactlyWhatWasCreated(t *testing.T) {
	r := newRig(t, copierKinds()[0], rigOptions{})

	// Decoys: a slot of another migration (our naming scheme, other id), an
	// unrelated slot, a publication and a role that are not ours.
	admin := r.src.Admin(t)
	app := r.src.AdminDB(t, "app")
	mustExec(t, app, `SELECT pg_create_logical_replication_slot('lk_mdeadbeef_d1_a1', 'pgoutput')`)
	mustExec(t, app, `SELECT pg_create_logical_replication_slot('analytics_slot', 'pgoutput')`)
	mustExec(t, app, `CREATE PUBLICATION analytics_pub FOR TABLE accounts`)
	mustExec(t, admin, `CREATE ROLE analytics_role LOGIN`)

	hash, id := r.plan()
	if o := r.apply(hash); o.code != 0 {
		t.Fatalf("apply: %s", o.all())
	}
	// Cleanup is refused while the migration is not aborted.
	if o := r.run("migrate", "cleanup", "--migration", id); o.code == 0 || !strings.Contains(o.all(), "abort") {
		t.Fatalf("cleanup before abort must be refused (%d):\n%s", o.code, o.all())
	}
	if o := r.run(r.startArgs(id, "--no-wait")...); o.code != 0 {
		t.Fatalf("start: %s", o.all())
	}
	if got := r.state(id); got != "following" {
		t.Fatalf("state = %s", got)
	}
	rowsBefore := rowFingerprints(t, r.src)
	catalogBefore := r.sourceFingerprint()
	ourSlots := count(t, r, "app", `SELECT count(*) FROM pg_replication_slots WHERE slot_name LIKE 'lk\_`+id+`\_%'`)
	if ourSlots != 2 {
		t.Fatalf("expected one slot per database (2), got %d", ourSlots)
	}

	// --- abort ---
	dry := r.run("migrate", "abort", "--migration", id)
	if dry.code != 0 || !strings.Contains(dry.stdout, "DRY RUN") || !strings.Contains(dry.stdout, "leaves the source") && !strings.Contains(dry.stdout, "does NOT drop") {
		t.Fatalf("abort dry run (%d):\n%s", dry.code, dry.all())
	}
	if r.sourceFingerprint() != catalogBefore || r.state(id) != "following" {
		t.Fatal("the abort dry run changed something")
	}
	r.stdin = ""
	if o := r.run("migrate", "abort", "--migration", id, "--apply"); o.code == 0 {
		t.Fatalf("abort --apply without confirmation must be refused:\n%s", o.all())
	}
	if o := r.run("migrate", "abort", "--migration", id, "--apply", "--plan-hash", strings.Repeat("a", 64)); o.code == 0 {
		t.Fatalf("abort with a wrong hash must be refused:\n%s", o.all())
	}
	if r.state(id) != "following" {
		t.Fatal("a refused abort changed the state")
	}
	h := hashInOutput.FindStringSubmatch(dry.stdout)
	if h == nil {
		t.Fatalf("no abort plan hash in:\n%s", dry.stdout)
	}
	if o := r.run("migrate", "abort", "--migration", id, "--apply", "--plan-hash", h[1]); o.code != 0 {
		t.Fatalf("abort: %s", o.all())
	}
	if got := r.state(id); got != "aborted" {
		t.Fatalf("state = %s", got)
	}

	// The source's slot and publication are still there; its data and catalog are untouched.
	if !reflect.DeepEqual(rowFingerprints(t, r.src), rowsBefore) {
		t.Fatal("abort changed rows on the source")
	}
	if r.sourceFingerprint() != catalogBefore {
		t.Fatalf("abort changed the source catalog:\nbefore:\n%s\nafter:\n%s", catalogBefore, r.sourceFingerprint())
	}
	if n := count(t, r, "app", `SELECT count(*) FROM pg_replication_slots WHERE slot_name LIKE 'lk\_`+id+`\_%'`); n != 2 {
		t.Fatalf("abort must leave the slots in place (one per database), found %d", n)
	}
	if n := count(t, r, "app", `SELECT count(*) FROM pg_publication WHERE pubname LIKE 'lk\_`+id+`\_%'`); n != 1 {
		t.Fatalf("abort must leave the publication in place, found %d", n)
	}
	// The target stopped consuming: the subscription is disabled.
	if n := targetCount(t, r, "app", `SELECT count(*) FROM pg_subscription WHERE subenabled`); n != 0 {
		t.Fatalf("abort must disable the subscription, %d still enabled", n)
	}
	st := r.run("migrate", "status", "--migration", id)
	if !strings.Contains(st.stdout, "still retains") {
		t.Fatalf("status of an aborted migration must warn that the slot still retains WAL:\n%s", st.stdout)
	}
	if o := r.run(r.startArgs(id)...); o.code == 0 {
		t.Fatalf("an aborted migration cannot be started again:\n%s", o.all())
	}

	// --- cleanup ---
	cdry := r.run("migrate", "cleanup", "--migration", id)
	ch := hashInOutput.FindStringSubmatch(cdry.stdout)
	if cdry.code != 0 || ch == nil || !strings.Contains(cdry.stdout, "DRY RUN") {
		t.Fatalf("cleanup dry run (%d):\n%s", cdry.code, cdry.all())
	}
	if r.sourceFingerprint() != catalogBefore {
		t.Fatal("the cleanup dry run changed the source")
	}
	if o := r.run("migrate", "cleanup", "--migration", id, "--apply"); o.code == 0 {
		t.Fatalf("cleanup --apply without confirmation must be refused:\n%s", o.all())
	}
	if o := r.run("migrate", "cleanup", "--migration", id, "--apply", "--plan-hash", h[1]); o.code == 0 {
		t.Fatalf("the hash of the abort plan must not approve the cleanup plan:\n%s", o.all())
	}
	if r.state(id) != "aborted" {
		t.Fatal("a refused cleanup changed the state")
	}
	if o := r.run("migrate", "cleanup", "--migration", id, "--apply", "--plan-hash", ch[1]); o.code != 0 {
		t.Fatalf("cleanup: %s", o.all())
	}
	if got := r.state(id); got != "cleaned" {
		t.Fatalf("state = %s", got)
	}

	// Exactly ours is gone; the decoys and every row are still there.
	for _, tc := range []struct {
		what, db, sql string
		want          int
	}{
		{"slots of this migration", "app", `SELECT count(*) FROM pg_replication_slots WHERE slot_name LIKE 'lk\_` + id + `\_%'`, 0},
		{"publications of this migration", "app", `SELECT count(*) FROM pg_publication WHERE pubname LIKE 'lk\_` + id + `\_%'`, 0},
		{"publications of this migration (billing)", "billing", `SELECT count(*) FROM pg_publication WHERE pubname LIKE 'lk\_` + id + `\_%'`, 0},
		{"roles of this migration", "postgres", `SELECT count(*) FROM pg_roles WHERE rolname = 'lk_` + id + `'`, 0},
		{"decoy slot of another migration", "app", `SELECT count(*) FROM pg_replication_slots WHERE slot_name = 'lk_mdeadbeef_d1_a1'`, 1},
		{"decoy unrelated slot", "app", `SELECT count(*) FROM pg_replication_slots WHERE slot_name = 'analytics_slot'`, 1},
		{"decoy publication", "app", `SELECT count(*) FROM pg_publication WHERE pubname = 'analytics_pub'`, 1},
		{"decoy role", "postgres", `SELECT count(*) FROM pg_roles WHERE rolname = 'analytics_role'`, 1},
	} {
		if got := count(t, r, tc.db, tc.sql); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.what, got, tc.want)
		}
	}
	if n := targetCount(t, r, "app", `SELECT count(*) FROM pg_subscription`); n != 0 {
		t.Errorf("the subscription must be dropped, %d left", n)
	}
	if !reflect.DeepEqual(rowFingerprints(t, r.src), rowsBefore) {
		t.Fatal("cleanup changed rows on the source")
	}
	if !reflect.DeepEqual(rowFingerprints(t, r.tgt), rowsBefore) {
		t.Fatal("cleanup must not touch the target's copy of the data")
	}
	// REPLICA IDENTITY FULL, set by the migration, is a change to a user table's
	// metadata and is deliberately left alone (the cleanup plan says so).
	if !strings.Contains(cdry.stdout, "REPLICA IDENTITY") {
		t.Errorf("the cleanup plan must say that REPLICA IDENTITY is left in place:\n%s", cdry.stdout)
	}
	if n := count(t, r, "app", `SELECT count(*) FROM pg_class WHERE relname = 'events' AND relreplident = 'f'`); n != 1 {
		t.Error("cleanup must not revert REPLICA IDENTITY")
	}
}
