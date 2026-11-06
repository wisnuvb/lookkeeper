package pgnative

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wisnuvb/lockkeeper/internal/action"
	"github.com/wisnuvb/lockkeeper/internal/migrate"
)

type fakeCopier struct{}

func (fakeCopier) Name() string { return "pgcopydb" }
func (fakeCopier) Check(context.Context, int) error {
	return nil
}
func (fakeCopier) Describe(in migrate.CopyInput) []string {
	return []string{"pgcopydb clone --source " + in.Source.Database + " --snapshot " + in.SnapshotID}
}
func (fakeCopier) Copy(context.Context, migrate.CopyInput) error { return nil }

func testInput(t *testing.T) PlanInput {
	t.Helper()
	return PlanInput{
		LockkeeperVersion: "test",
		Source:            Side{Name: "rds", Host: "db.example.com", Port: 5432, User: "lk", Database: "postgres", TLSMode: "verify-full", Version: "17.2", Major: 17},
		Target:            Side{Name: "ovh", Host: "203.0.113.10", Port: 5432, User: "admin", Database: "postgres", TLSMode: "verify-full", Version: "17.2", Major: 17},
		TargetFacts:       TargetFacts{Superuser: true},
		Peer:              Peer{Host: "db.example.com", Port: 5432, SSLMode: "verify-full", SSLRootCert: "/etc/ssl/rds.pem"},
		DBs: []DBFacts{
			{Database: "app", Publish: []Table{{"public", "accounts"}, {"public", "events"}}, NeedFull: []Table{{"public", "events"}}},
			{Database: "billing", Publish: []Table{{"public", "invoices"}}},
		},
		Copier: fakeCopier{}, CopierKind: "pgcopydb", TableJobs: 4, IndexJobs: 4,
		Password: PasswordFileFor(t.TempDir(), "x"),
	}
}

func TestPlanIsDeterministicAndOrdered(t *testing.T) {
	a, err := BuildPlan(testInput(t))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := BuildPlan(testInput(t))
	if a.Hash() != b.Hash() || a.MigrationID != b.MigrationID {
		t.Fatal("the same input must give the same plan")
	}
	if !strings.HasPrefix(a.MigrationID, "m") || len(a.MigrationID) != 9 {
		t.Fatalf("migration id %q", a.MigrationID)
	}
	var ids []string
	for _, x := range a.Actions {
		ids = append(ids, x.ID())
	}
	want := []string{
		"source.create-role", "source.replica-identity.1.1", "source.create-publication.1", "source.create-publication.2",
		"start.slot-snapshot.1", "start.copy.1", "start.drop-copied-publication.1", "start.create-subscription.1", "start.enable-subscription.1",
		"start.slot-snapshot.2", "start.copy.2", "start.drop-copied-publication.2", "start.create-subscription.2", "start.enable-subscription.2",
	}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("action order:\n got %v\nwant %v", ids, want)
	}
	// The publication must exist before the slot: changes made in between would be lost otherwise.
	for i, x := range a.Actions {
		if x.ID() == "start.slot-snapshot.1" {
			for _, y := range a.Actions[:i] {
				if y.ID() == "source.create-publication.1" {
					goto ok
				}
			}
			t.Fatal("the publication must be created before the slot")
		}
	}
ok:
	// Any change of the input changes the id and the hash.
	in := testInput(t)
	in.DBs[0].Publish = append(in.DBs[0].Publish, Table{"public", "late"})
	c, _ := BuildPlan(in)
	if c.Hash() == a.Hash() || c.MigrationID == a.MigrationID {
		t.Fatal("a different table set must be a different plan with different names")
	}
}

func TestPlanSQLHasNoSecretsAndExactNames(t *testing.T) {
	p, _ := BuildPlan(testInput(t))
	text := p.Summary() + string(p.DisplayJSON())
	for _, bad := range []string{"SCRAM-SHA-256$", "password=84", "S3CR3T"} {
		if strings.Contains(text, bad) {
			t.Fatalf("plan text contains %q", bad)
		}
	}
	role := "lk_" + p.MigrationID
	for _, want := range []string{
		`CREATE ROLE "` + role + `" WITH LOGIN REPLICATION NOSUPERUSER NOCREATEDB NOCREATEROLE CONNECTION LIMIT 6 PASSWORD ***`,
		`COMMENT ON ROLE "` + role + `" IS 'lockkeeper:` + p.MigrationID + `'`,
		`SET lock_timeout = '10s'`,
		`ALTER TABLE "public"."events" REPLICA IDENTITY FULL`,
		`CREATE PUBLICATION "lk_` + p.MigrationID + `_d1" FOR TABLE "public"."accounts", "public"."events"`,
		`CREATE_REPLICATION_SLOT "lk_` + p.MigrationID + `_d1_a1" LOGICAL pgoutput (SNAPSHOT 'export')`,
		`SET log_statement = 'none'`, `SET log_min_error_statement = 'panic'`,
		`password=***`, `slot_name = 'lk_` + p.MigrationID + `_d1_a1', copy_data = false, enabled = false`,
		`sslrootcert=''/etc/ssl/rds.pem''`,
	} {
		if !strings.Contains(p.Summary(), want) {
			t.Errorf("plan lacks %q\n%s", want, p.Summary())
		}
	}
	for _, x := range p.Actions {
		for _, bad := range []string{"--follow", "--restart", "--resume"} {
			if strings.Contains(x.SQL(), bad) {
				t.Errorf("%s contains %s", x.ID(), bad)
			}
		}
	}
	// Mutating source actions are all in the source phase or are steps of start.
	for _, x := range p.Actions {
		if x.Target().Role == "source" && x.Mutates() && x.Phase() != action.PhaseSource && x.Phase() != action.PhaseStart {
			t.Errorf("%s changes the source in phase %s", x.ID(), x.Phase())
		}
	}
}

func TestRealStatementsCarryTheSecretsOnlyAtApplyTime(t *testing.T) {
	in := testInput(t)
	p, _ := BuildPlan(in)
	pw, err := in.Password.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range p.Actions {
		st, ok := x.(*action.Statement)
		if !ok || st.Secrets == nil {
			continue
		}
		sec, err := st.Secrets()
		if err != nil {
			t.Fatalf("%s: %v", x.ID(), err)
		}
		real, err := st.Main.Render(sec)
		if err != nil {
			t.Fatal(err)
		}
		switch x.ID() {
		case "source.create-role":
			if !strings.Contains(real, "PASSWORD 'SCRAM-SHA-256$4096:") || strings.Contains(real, pw.Reveal()) {
				t.Errorf("the role statement must carry a SCRAM verifier and never the clear password: %s", real)
			}
		case "start.create-subscription.1":
			if !strings.Contains(real, "password="+pw.Reveal()+" ") {
				t.Errorf("the subscription statement needs the clear password: %s", real)
			}
			if strings.Contains(st.SQL(), pw.Reveal()) {
				t.Error("the displayed SQL must mask the password")
			}
		}
	}
}

// A database, table or host whose name contains a secret placeholder must never
// be planned: rendering the template would put the real password where the name
// is (CREATE SUBSCRIPTION ... dbname='x{{password}}').
func TestNamesThatLookLikePlaceholdersAreRefused(t *testing.T) {
	for name, mut := range map[string]func(*PlanInput){
		"database":      func(in *PlanInput) { in.DBs[0].Database = "x{{password}}" },
		"database }}":   func(in *PlanInput) { in.DBs[0].Database = "x}}" },
		"table":         func(in *PlanInput) { in.DBs[0].Publish[0].Name = "t{{verifier}}" },
		"schema":        func(in *PlanInput) { in.DBs[0].NeedFull[0].Schema = "{{password}}" },
		"peer host":     func(in *PlanInput) { in.Peer.Host = "h{{password}}" },
		"root cert":     func(in *PlanInput) { in.Peer.SSLRootCert = "/x/{{password}}" },
		"source user":   func(in *PlanInput) { in.Source.User = "u{{password}}" },
		"target config": func(in *PlanInput) { in.Target.Database = "{{password}}" },
	} {
		t.Run(name, func(t *testing.T) {
			in := testInput(t)
			mut(&in)
			if _, err := BuildPlan(in); err == nil || !strings.Contains(err.Error(), "reserved for secret placeholders") {
				t.Fatalf("BuildPlan must refuse: %v", err)
			}
			if _, err := BuildAbortPlan(in, "m1", true); err == nil {
				t.Fatal("BuildAbortPlan must refuse")
			}
			if _, err := BuildCleanupPlan(CleanupInput{PlanInput: in, MigrationID: "m1"}); err == nil {
				t.Fatal("BuildCleanupPlan must refuse")
			}
			if _, err := BuildRecoverPlan(RecoverInput{PlanInput: in, MigrationID: "m1", Attempts: map[int]int{1: 1}}); err == nil {
				t.Fatal("BuildRecoverPlan must refuse")
			}
		})
	}
	in := testInput(t)
	if _, err := BuildCleanupPlan(CleanupInput{PlanInput: in, MigrationID: "m1", Slots: map[int][]string{1: {"lk_{{password}}"}}}); err == nil {
		t.Fatal("a slot name with a placeholder must be refused")
	}
	if _, err := BuildRecoverPlan(RecoverInput{PlanInput: in, MigrationID: "m1", Attempts: map[int]int{1: 1}, TargetCreate: map[int]string{1: `CREATE DATABASE "{{password}}"`}}); err == nil {
		t.Fatal("a CREATE DATABASE with a placeholder must be refused")
	}
}

func TestScramVerifierShapeAndDeterminism(t *testing.T) {
	salt := []byte("0123456789abcdef")
	a, err := ScramVerifier("pencil", salt)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := ScramVerifier("pencil", salt)
	c, _ := ScramVerifier("pencil2", salt)
	if a != b || a == c {
		t.Fatal("verifier must be deterministic in (password, salt) and depend on the password")
	}
	parts := strings.Split(a, "$")
	if len(parts) != 3 || parts[0] != "SCRAM-SHA-256" || !strings.HasPrefix(parts[1], "4096:") || strings.Count(parts[2], ":") != 1 {
		t.Fatalf("not the PostgreSQL SCRAM format: %s", a)
	}
	if strings.Contains(a, "pencil") {
		t.Fatal("the verifier must not contain the password")
	}
	r1, _ := RandomVerifier("pencil")
	r2, _ := RandomVerifier("pencil")
	if r1 == r2 {
		t.Fatal("a random salt per verifier")
	}
}

func TestPasswordFileModesAndReuse(t *testing.T) {
	root := t.TempDir()
	pf := PasswordFileFor(root, "m1")
	if pf.Exists() {
		t.Fatal("no file yet")
	}
	a, err := pf.Ensure()
	if err != nil || len(a.Reveal()) != 48 {
		t.Fatalf("password: %v %d", err, len(a.Reveal()))
	}
	b, _ := pf.Ensure()
	if a.Reveal() != b.Reveal() {
		t.Fatal("Ensure must return the stored password, not generate another (the role was created with it)")
	}
	if fi, _ := os.Stat(pf.Path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if fi, _ := os.Stat(filepath.Dir(pf.Path)); fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", fi.Mode())
	}
	if err := os.Chmod(pf.Path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := pf.Read(); err == nil {
		t.Fatal("a group-readable password file must be refused")
	}
	_ = os.Chmod(pf.Path, 0o600)
	if err := pf.Remove(); err != nil || pf.Exists() {
		t.Fatalf("remove: %v", err)
	}
	if err := pf.Remove(); err != nil {
		t.Fatal("removing twice is fine")
	}
}

func TestCleanupPlanDropsOnlyNamedObjectsInSafeOrder(t *testing.T) {
	in := testInput(t)
	p, _ := BuildPlan(in)
	cp, err := BuildCleanupPlan(CleanupInput{PlanInput: in, MigrationID: p.MigrationID, Slots: map[int][]string{
		1: {"lk_" + p.MigrationID + "_d1_a1", "lk_" + p.MigrationID + "_d1_a2"}, 2: {"lk_" + p.MigrationID + "_d2_a1"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, a := range cp.Actions {
		ids = append(ids, a.ID())
		if a.Phase() != action.PhaseCleanup {
			t.Errorf("%s has phase %s", a.ID(), a.Phase())
		}
	}
	// Subscriptions first (they must stop reading), the role last.
	if ids[0] != "cleanup.drop-subscription.1" || ids[1] != "cleanup.drop-subscription.2" || ids[len(ids)-1] != "cleanup.drop-role" {
		t.Fatalf("order: %v", ids)
	}
	text := cp.Summary()
	for _, want := range []string{"SET (slot_name = NONE)", "pg_drop_replication_slot('lk_" + p.MigrationID + "_d1_a2')", "REPLICA IDENTITY FULL, which the migration set"} {
		if !strings.Contains(text, want) {
			t.Errorf("cleanup plan lacks %q", want)
		}
	}
	// Nothing in it can match a name that is not this migration's.
	for _, a := range cp.Actions {
		if strings.Contains(a.SQL(), "DROP") || strings.Contains(a.SQL(), "pg_drop_replication_slot") {
			if !strings.Contains(a.SQL(), "lk_"+p.MigrationID) {
				t.Errorf("%s drops something without this migration's name: %s", a.ID(), a.SQL())
			}
		}
	}
}

func TestRecoverPlanUsesANewSlotAndNeverReusesTheOld(t *testing.T) {
	in := testInput(t)
	p, _ := BuildPlan(in)
	old := "lk_" + p.MigrationID + "_d1_a1"
	rp, err := BuildRecoverPlan(RecoverInput{PlanInput: in, MigrationID: p.MigrationID, Attempts: map[int]int{1: 1},
		OldSlots: map[int][]string{1: {old}}, TargetCreate: map[int]string{1: `CREATE DATABASE "app" WITH TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C' OWNER "postgres"`}})
	if err != nil {
		t.Fatal(err)
	}
	text := rp.Summary()
	for _, want := range []string{"pg_drop_replication_slot('" + old + "')", `DROP DATABASE IF EXISTS "app" WITH (FORCE)`, "CREATE DATABASE", `CREATE_REPLICATION_SLOT "lk_` + p.MigrationID + `_d1_a2"`, "slot_name = 'lk_" + p.MigrationID + "_d1_a2'"} {
		if !strings.Contains(text, want) {
			t.Errorf("recovery plan lacks %q\n%s", want, text)
		}
	}
	if strings.Contains(text, `CREATE_REPLICATION_SLOT "`+old+`"`) {
		t.Error("the old slot name must not be created again")
	}
	if rp.Hash() == p.Hash() {
		t.Fatal("a recovery plan is a different plan")
	}
	// Only the interrupted database is in it.
	if len(rp.Databases) != 1 || rp.Databases[0] != "app" {
		t.Fatalf("databases: %v", rp.Databases)
	}
}

func TestAbortPlanOnlyDisablesSubscriptions(t *testing.T) {
	in := testInput(t)
	p, _ := BuildPlan(in)
	ap, err := BuildAbortPlan(in, p.MigrationID, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range ap.Actions {
		if a.Target().Role != "target" || !strings.Contains(a.SQL(), "DISABLE") || strings.Contains(a.SQL(), "DROP") {
			t.Errorf("abort must only disable subscriptions on the target: %s %s", a.ID(), a.SQL())
		}
	}
	if len(ap.Actions) != 2 {
		t.Fatalf("one per database: %d", len(ap.Actions))
	}
	early, _ := BuildAbortPlan(in, p.MigrationID, false)
	if len(early.Actions) != 0 {
		t.Fatal("before copying there is no subscription to stop")
	}
}

func TestChecksReportEveryMissingPrivilegeClearly(t *testing.T) {
	good := SourceFacts{User: "lk", WALLevel: "logical", Replication: true, CreateRole: true, MaxSlots: 10, MaxSenders: 10, Major: 17}
	dbs := []DBFacts{{Database: "app", Publish: []Table{{"public", "t"}}, CanCreate: true}}
	if p := CheckSource(good, dbs); len(p) != 0 {
		t.Fatalf("unexpected problems: %v", p)
	}
	bad := SourceFacts{User: "lk", WALLevel: "replica", MaxSlots: 1, SlotsUsed: 1, MaxSenders: 1, SendersUsed: 1, InRecovery: true, Major: 17}
	probs := strings.Join(CheckSource(bad, []DBFacts{{Database: "app", Publish: nil, NotOwned: []Table{{"public", "t"}}}}), "\n")
	for _, want := range []string{"standby", "wal_level", "REPLICATION", "CREATEROLE", "free replication slot", "WAL sender", "CREATE privilege", "does not own", "no ordinary table"} {
		if !strings.Contains(probs, want) {
			t.Errorf("missing problem %q in:\n%s", want, probs)
		}
	}
	// RDS roles and superusers are accepted.
	if p := CheckSource(SourceFacts{User: "rdsadmin2", WALLevel: "logical", RDSReplicate: true, RDSSuperuser: true, MaxSlots: 5, MaxSenders: 5}, dbs); len(p) != 0 {
		t.Fatalf("rds roles: %v", p)
	}
	tp := CheckTarget(TargetFacts{User: "u", Major: 16, MaxWorkers: 1}, SourceFacts{Major: 17}, []string{"a", "b"})
	joined := strings.Join(tp, "\n")
	for _, want := range []string{"cannot create subscriptions", "older than the source", "max_logical_replication_workers"} {
		if !strings.Contains(joined, want) {
			t.Errorf("target problem %q missing in:\n%s", want, joined)
		}
	}
	if p := CheckTarget(TargetFacts{User: "u", Major: 17, CreateSubscription: true, MaxWorkers: 4}, SourceFacts{Major: 14}, []string{"a"}); len(p) != 0 {
		t.Fatalf("a capable target: %v", p)
	}
}

func TestServerMajorAndLSN(t *testing.T) {
	for in, want := range map[string]int{"14.24": 14, "17.11": 17, "17beta1": 17, "": 0, "x": 0} {
		if got := serverMajor(in); got != want {
			t.Errorf("serverMajor(%q) = %d, want %d", in, got, want)
		}
	}
	l, err := migrate.ParseLSN("1A/2B3C4D5E")
	if err != nil || l.String() != "1A/2B3C4D5E" {
		t.Fatalf("%v %v", l, err)
	}
	for _, bad := range []string{"", "1", "x/y", "1/zz"} {
		if _, err := migrate.ParseLSN(bad); err == nil {
			t.Errorf("%q must not parse", bad)
		}
	}
}
