//go:build integration

package itest

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func (r *rig) stateSQL(query string, args ...any) {
	r.t.Helper()
	db, err := sql.Open("sqlite", "file:"+r.stateDB+"?_pragma=busy_timeout(5000)")
	if err != nil {
		r.t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(query, args...); err != nil {
		r.t.Fatalf("%s: %v", query, err)
	}
}

// TestPlanTamperDriftAndTypedConfirmation covers what must stop an apply:
// a state database that no longer matches the approved hash, a schema that
// changed after planning, a wrong typed phrase; and that the exact typed phrase
// works.
func TestPlanTamperDriftAndTypedConfirmation(t *testing.T) {
	r := newRig(t, copierKinds()[0], rigOptions{})
	before := r.sourceFingerprint()

	// 1. The stored plan input is edited behind Lockkeeper's back (NoOwner false -> true).
	hash, id := r.plan()
	r.stateSQL(`UPDATE migrations SET input_json = replace(input_json, '"NoOwner":false', '"NoOwner":true') WHERE id = ?`, id)
	o := r.apply(hash)
	if o.code == 0 || !strings.Contains(o.all(), "no longer matches its hash") {
		t.Fatalf("a tampered state database must be refused (%d):\n%s", o.code, o.all())
	}
	if r.sourceFingerprint() != before {
		t.Fatal("a refused apply changed the source")
	}
	r.stateSQL(`UPDATE migrations SET input_json = replace(input_json, '"NoOwner":true', '"NoOwner":false') WHERE id = ?`, id)

	// 2. A table is created after the plan: the schema freeze was not respected.
	mustExec(t, r.src.AdminDB(t, "app"), `CREATE TABLE surprise (id int PRIMARY KEY)`)
	o = r.apply(hash)
	if o.code == 0 || !strings.Contains(o.all(), "surprise") || !strings.Contains(o.all(), "schema") {
		t.Fatalf("schema drift after the plan must be refused and name the table (%d):\n%s", o.code, o.all())
	}
	if strings.Contains(r.sourceFingerprint(), "role:lk_") {
		t.Fatal("a refused apply created the role")
	}
	mustExec(t, r.src.AdminDB(t, "app"), `DROP TABLE surprise`)

	// 3. Typed confirmation: a wrong phrase is refused, the exact phrase works.
	r.stdin = "yes\n"
	if o := r.run("migrate", "apply-source-changes", "--migration", id, "--apply", "--allow-untested-pgcopydb"); o.code == 0 {
		t.Fatalf("\"yes\" must not approve:\n%s", o.all())
	}
	if r.sourceFingerprint() != before {
		t.Fatal("a refused typed confirmation changed the source")
	}
	r.stdin = "approve " + hash[:12] + "\n"
	o = r.run("migrate", "apply-source-changes", "--migration", id, "--apply", "--allow-untested-pgcopydb")
	if o.code != 0 || !strings.Contains(o.stdout, fmt.Sprintf("To approve this plan, type exactly: approve %s", hash[:12])) {
		t.Fatalf("the typed phrase must approve (%d):\n%s", o.code, o.all())
	}
	if got := r.state(id); got != "source_changes_approved" {
		t.Fatalf("state = %s", got)
	}

	// The audit trail records who approved it and how.
	db, err := sql.Open("sqlite", "file:"+r.stateDB+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var method, plans string
	if err := db.QueryRow(`SELECT method, plan_hash FROM audit_events WHERE kind = 'plan.approved' AND migration_id = ?`, id).Scan(&method, &plans); err != nil || method != "typed" || plans != hash {
		t.Fatalf("audit of the approval: %q %q %v", method, plans, err)
	}
	var applied int
	_ = db.QueryRow(`SELECT count(*) FROM actions WHERE migration_id = ? AND status = 'applied' AND mutates = 1`, id).Scan(&applied)
	if applied < 4 { // role, replica identity, two publications
		t.Fatalf("every mutating action must be recorded in the actions table, found %d", applied)
	}
	// The audit table is append-only even for someone with the file.
	rw, _ := sql.Open("sqlite", "file:"+r.stateDB)
	defer rw.Close()
	if _, err := rw.Exec(`DELETE FROM audit_events`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("audit_events must refuse deletes: %v", err)
	}
}

// A table that appears on the target after the plan was made is not the partial
// copy of a migration: start must refuse and must not offer a recovery plan
// (which would DROP the target database).
func TestTargetThatIsNotEmptyIsNeverRecovered(t *testing.T) {
	r := newRig(t, copierKinds()[0], rigOptions{})
	hash, id := r.plan()
	if o := r.apply(hash); o.code != 0 {
		t.Fatalf("apply: %s", o.all())
	}
	mustExec(t, r.tgt.AdminDB(t, "app"), `CREATE TABLE precious (id int)`)
	mustExec(t, r.tgt.AdminDB(t, "app"), `INSERT INTO precious VALUES (1)`)
	o := r.run(r.startArgs(id, "--no-wait")...)
	if o.code == 0 || !strings.Contains(o.all(), "refusing to plan a DROP DATABASE") {
		t.Fatalf("start must refuse (%d):\n%s", o.code, o.all())
	}
	if strings.Contains(o.all(), "Recovery plan") || strings.Contains(o.all(), "recovery-plan-hash") {
		t.Fatalf("a recovery plan must not be offered:\n%s", o.all())
	}
	if n := targetCount(t, r, "app", `SELECT count(*) FROM precious`); n != 1 {
		t.Fatal("the target's own table must be untouched")
	}
	if n := count(t, r, "app", `SELECT count(*) FROM pg_replication_slots WHERE slot_name LIKE 'lk\_`+id+`\_%'`); n != 0 {
		t.Fatalf("no slot may be created: %d", n)
	}
}

// TestRolesWithoutPrivilegesFailBeforeAnyChange uses a source role that cannot
// replicate: planning must fail with a clear message and change nothing.
func TestRolesWithoutPrivilegesFailBeforeAnyChange(t *testing.T) {
	r := newRig(t, copierKinds()[0], rigOptions{})
	mustExec(t, r.src.Admin(t), `CREATE ROLE limited LOGIN PASSWORD 'limited-pw-not-a-secret'`)
	before := r.sourceFingerprint()
	cfg, _ := os.ReadFile(r.cfg)
	limited := strings.Replace(string(cfg), "    user: postgres\n    password: { env: LK_SRC_PW }", "    user: limited\n    password: { env: LK_SRC_PW }", 1)
	if limited == string(cfg) {
		t.Fatal("test bug: config not rewritten")
	}
	if err := os.WriteFile(r.cfg, []byte(limited), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := r.src.Password
	r.src.Password = "limited-pw-not-a-secret"
	defer func() { r.src.Password = orig }()

	o := r.run(r.planArgs()...)
	if o.code == 0 {
		t.Fatalf("planning with a role that cannot replicate must fail:\n%s", o.all())
	}
	text := strings.ToLower(o.all())
	if !strings.Contains(text, "replication") {
		t.Fatalf("the message must say what is missing:\n%s", o.all())
	}
	r.src.Password = orig
	if r.sourceFingerprint() != before {
		t.Fatal("a failed plan changed the source")
	}
	// And no draft was created.
	st := r.run("migrate", "status", "--json")
	if st.code == 0 {
		t.Fatalf("no migration may exist after a refused plan:\n%s", st.all())
	}
}
