package action

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type execCall struct{ sql string }

// fakeConn records executed SQL.
type fakeConn struct {
	calls  []execCall
	failOn string
}

func (f *fakeConn) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	f.calls = append(f.calls, execCall{sql})
	if f.failOn != "" && strings.Contains(sql, f.failOn) {
		return pgconn.CommandTag{}, errors.New("boom")
	}
	return pgconn.CommandTag{}, nil
}

func (f *fakeConn) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

type memAudit struct {
	events  []Event
	records []ActionRecord
	failAt  int // fail the n-th Append (1-based); 0 never
}

func (m *memAudit) Append(_ context.Context, e Event) error {
	if m.failAt > 0 && len(m.events)+1 == m.failAt {
		return errors.New("audit disk full")
	}
	m.events = append(m.events, e)
	return nil
}

func (m *memAudit) RecordAction(_ context.Context, r ActionRecord) error {
	m.records = append(m.records, r)
	return nil
}

func testPlan() *Plan {
	src := Endpoint{Role: "source", Name: "rds-main", Host: "db.example.com", Port: 5432, Database: "app", User: "lk"}
	tgt := Endpoint{Role: "target", Name: "ovh", Host: "203.0.113.10", Port: 5432, Database: "app", User: "lk"}
	return &Plan{
		Kind: KindMigrate, LockkeeperVer: "test", MigrationID: "m1234abcd",
		Source:    Identity{Name: "rds-main", Host: "db.example.com", Port: 5432, User: "lk", ServerVersion: "17.2"},
		Target:    Identity{Name: "ovh", Host: "203.0.113.10", Port: 5432, User: "lk", ServerVersion: "17.2"},
		Databases: []string{"app", "billing"},
		Settings:  map[string]string{"copier": "pgcopydb", "peer": "db.example.com:5432"},
		Notices:   []string{"target logs statements"},
		Actions: []Action{
			&Statement{Key: "source.create-role", Summary: "create the migration role", At: PhaseSource, Where: src, Changes: true,
				Main:    "CREATE ROLE lk_m1 LOGIN REPLICATION PASSWORD {{role-password}}",
				Secrets: func() (map[string]string, error) { return map[string]string{"role-password": "'S3CR3T-VALUE'"}, nil }},
			&Statement{Key: "source.create-publication", Summary: "create the publication", At: PhaseSource, Where: src, Changes: true,
				Main: "CREATE PUBLICATION lk_m1 FOR TABLE public.accounts"},
			&Statement{Key: "target.check", Summary: "read-only check", At: PhaseStart, Where: tgt, Changes: false,
				Main: "SELECT 1"},
			&Step{Key: "start.copy", Summary: "copy", At: PhaseStart, Where: tgt, Changes: true, Display: "pgcopydb clone ..."},
		},
	}
}

func TestHashIsDeterministicAndIndependentOfMapOrder(t *testing.T) {
	a, b := testPlan(), testPlan()
	if a.Hash() != b.Hash() {
		t.Fatal("equal plans must have equal hashes")
	}
	if len(a.Hash()) != 64 {
		t.Fatalf("want a hex SHA-256, got %q", a.Hash())
	}
	if string(a.CanonicalJSON()) != string(b.CanonicalJSON()) {
		t.Fatal("canonical JSON must be byte-identical")
	}
	// Rebuilding settings in another insertion order changes nothing.
	b.Settings = map[string]string{"peer": "db.example.com:5432", "copier": "pgcopydb"}
	if a.Hash() != b.Hash() {
		t.Fatal("hash depends on map insertion order")
	}
	if strings.Contains(string(a.CanonicalJSON()), "S3CR3T-VALUE") || strings.Contains(string(a.DisplayJSON()), "S3CR3T-VALUE") || strings.Contains(a.Summary(), "S3CR3T-VALUE") {
		t.Fatal("a secret leaked into the plan JSON or summary")
	}
	if !strings.Contains(a.Summary(), "PASSWORD ***") {
		t.Fatalf("the secret must be shown masked:\n%s", a.Summary())
	}
}

func TestTamperChangesHashAndApplyRefuses(t *testing.T) {
	base := testPlan()
	approved := base.Hash()
	tamper := map[string]func(p *Plan){
		"one SQL character": func(p *Plan) {
			p.Actions[1].(*Statement).Main = "CREATE PUBLICATION lk_m1 FOR TABLE public.accountz"
		},
		"one endpoint field": func(p *Plan) {
			p.Actions[0].(*Statement).Where.Host = "db.example.org"
		},
		"endpoint role": func(p *Plan) {
			p.Actions[0].(*Statement).Where.Role = "target"
		},
		"one database entry": func(p *Plan) { p.Databases[1] = "billing2" },
		"database order":     func(p *Plan) { p.Databases[0], p.Databases[1] = p.Databases[1], p.Databases[0] },
		"action order":       func(p *Plan) { p.Actions[0], p.Actions[1] = p.Actions[1], p.Actions[0] },
		"mutates flag":       func(p *Plan) { p.Actions[1].(*Statement).Changes = false },
		"added action":       func(p *Plan) { p.Actions = append(p.Actions, &Statement{Key: "x", At: PhaseSource, Main: "SELECT 1"}) },
		"setting":            func(p *Plan) { p.Settings["copier"] = "pgdump" },
		"notice":             func(p *Plan) { p.Notices = nil },
		"lockkeeper version": func(p *Plan) { p.LockkeeperVer = "other" },
		"identity":           func(p *Plan) { p.Target.ServerVersion = "17.3" },
		"session statement": func(p *Plan) {
			p.Actions[0].(*Statement).Session = []Template{"SET log_statement = 'all'"}
		},
	}
	for name, mut := range tamper {
		t.Run(name, func(t *testing.T) {
			p := testPlan()
			mut(p)
			if p.Hash() == approved {
				t.Fatalf("tampering with %s did not change the plan hash", name)
			}
			audit := &memAudit{}
			x := &Executor{Audit: audit, Recorder: audit}
			_, err := x.Authorize(p, approved, Approval{Method: MethodPlanHash, Approver: "op"})
			if err == nil {
				t.Fatal("apply must refuse a plan that changed after approval")
			}
			if len(audit.events) != 0 {
				t.Fatal("nothing may be audited as applied for a refused plan")
			}
		})
	}
}

func TestConfirmHash(t *testing.T) {
	p := testPlan()
	if _, err := ConfirmHash(p, p.Hash(), "op"); err != nil {
		t.Fatalf("the exact hash approves: %v", err)
	}
	if _, err := ConfirmHash(p, strings.ToUpper(p.Hash()), "op"); err != nil {
		t.Fatalf("case does not matter: %v", err)
	}
	for _, bad := range []string{"", p.Hash()[:12], p.Hash()[:63] + "0", "deadbeef"} {
		if _, err := ConfirmHash(p, bad, "op"); err == nil {
			t.Errorf("hash %q must not approve", bad)
		}
	}
}

func TestConfirmTyped(t *testing.T) {
	p := testPlan()
	var out strings.Builder
	if _, err := ConfirmTyped(strings.NewReader(TypedPhrase(p)+"\n"), &out, p, "op"); err != nil {
		t.Fatalf("typed phrase approves: %v", err)
	}
	if !strings.Contains(out.String(), TypedPhrase(p)) {
		t.Fatal("the prompt must show the phrase to type")
	}
	for name, in := range map[string]string{
		"empty":    "\n",
		"yes":      "yes\n",
		"y":        "y\n",
		"wrong":    "approve 000000000000\n",
		"eof":      "",
		"case":     strings.ToUpper(TypedPhrase(p)) + "\n",
		"suffixed": TypedPhrase(p) + " now\n",
	} {
		if _, err := ConfirmTyped(strings.NewReader(in), &strings.Builder{}, p, "op"); err == nil {
			t.Errorf("%s must not approve", name)
		}
	}
}

func TestTemplate(t *testing.T) {
	tpl := Template("CREATE ROLE r PASSWORD {{pw}} -- {{pw}}")
	if got := tpl.Text(); got != "CREATE ROLE r PASSWORD *** -- ***" {
		t.Fatalf("masked text: %q", got)
	}
	got, err := tpl.Render(map[string]string{"pw": "'x'"})
	if err != nil || got != "CREATE ROLE r PASSWORD 'x' -- 'x'" {
		t.Fatalf("render: %q %v", got, err)
	}
	if _, err := tpl.Render(nil); err == nil {
		t.Fatal("a missing secret must be an error, not an empty string")
	}
	if QuoteLiteral("a'b") != "'a''b'" || QuoteIdent(`a"b`) != `"a""b"` {
		t.Fatal("quoting")
	}
}

func TestExecutorRunOrderIntentBeforeEffectAndNoSecretInAudit(t *testing.T) {
	p := testPlan()
	audit := &memAudit{}
	conn := &fakeConn{}
	x := &Executor{Audit: audit, Recorder: audit, Actor: "op@host", Now: func() time.Time { return time.Unix(1, 0) }}
	auth, err := x.Authorize(p, p.Hash(), Approval{Method: MethodPlanHash, Approver: "op"})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := auth.Run(context.Background(), PhaseSource, func(context.Context, Endpoint) (Conn, func(), error) { return conn, func() {}, nil })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rep.Applied, ",") != "source.create-role,source.create-publication" {
		t.Fatalf("applied: %v", rep.Applied)
	}
	if len(conn.calls) != 2 || !strings.Contains(conn.calls[0].sql, "'S3CR3T-VALUE'") {
		t.Fatalf("the real statement must carry the secret: %v", conn.calls)
	}
	var kinds []string
	for _, e := range audit.events {
		kinds = append(kinds, e.Kind+":"+e.ActionID)
		if strings.Contains(e.Detail, "S3CR3T-VALUE") || e.PlanHash != p.Hash() {
			t.Fatalf("bad audit event %+v", e)
		}
	}
	want := "action.intent:source.create-role,action.applied:source.create-role,action.intent:source.create-publication,action.applied:source.create-publication"
	if strings.Join(kinds, ",") != want {
		t.Fatalf("audit order:\n got %v\nwant %s", kinds, want)
	}
	for _, r := range audit.records {
		if strings.Contains(r.SQL, "S3CR3T-VALUE") {
			t.Fatal("the actions table must hold the masked SQL")
		}
	}
	if audit.records[0].Status != "intent" || audit.records[1].Status != "applied" || audit.records[0].Approver != "op" {
		t.Fatalf("records: %+v", audit.records)
	}
}

func TestExecutorStopsAtFailureAndRecordsIt(t *testing.T) {
	p := testPlan()
	audit := &memAudit{}
	conn := &fakeConn{failOn: "CREATE ROLE"}
	x := &Executor{Audit: audit, Recorder: audit}
	auth, _ := x.Authorize(p, p.Hash(), Approval{Method: MethodTyped, Approver: "op"})
	_, err := auth.Run(context.Background(), PhaseSource, func(context.Context, Endpoint) (Conn, func(), error) { return conn, func() {}, nil })
	if err == nil {
		t.Fatal("expected failure")
	}
	if len(conn.calls) != 1 {
		t.Fatalf("must stop at the first failure, ran %d statements", len(conn.calls))
	}
	last := audit.events[len(audit.events)-1]
	if last.Kind != "action.failed" || last.Method != MethodTyped {
		t.Fatalf("last event %+v", last)
	}
}

func TestNoEffectWhenIntentCannotBeRecorded(t *testing.T) {
	p := testPlan()
	audit := &memAudit{failAt: 1}
	conn := &fakeConn{}
	x := &Executor{Audit: audit, Recorder: audit}
	auth, _ := x.Authorize(p, p.Hash(), Approval{Method: MethodPlanHash, Approver: "op"})
	if _, err := auth.Run(context.Background(), PhaseSource, func(context.Context, Endpoint) (Conn, func(), error) { return conn, func() {}, nil }); err == nil {
		t.Fatal("expected an error")
	}
	if len(conn.calls) != 0 {
		t.Fatal("an effect must never happen without its intent being recorded first")
	}
}

func TestSatisfiedActionIsSkippedAndRecorded(t *testing.T) {
	p := testPlan()
	p.Actions[1].(*Statement).Satisfied = func(context.Context, Conn) (bool, error) { return true, nil }
	audit := &memAudit{}
	conn := &fakeConn{}
	x := &Executor{Audit: audit, Recorder: audit}
	auth, _ := x.Authorize(p, p.Hash(), Approval{Method: MethodPlanHash, Approver: "op"})
	rep, err := auth.Run(context.Background(), PhaseSource, func(context.Context, Endpoint) (Conn, func(), error) { return conn, func() {}, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Satisfied) != 1 || rep.Satisfied[0] != "source.create-publication" || len(conn.calls) != 1 {
		t.Fatalf("report %+v, calls %d", rep, len(conn.calls))
	}
}

func TestAuthorizeRequiresAuditAndApprover(t *testing.T) {
	p := testPlan()
	if _, err := (&Executor{}).Authorize(p, p.Hash(), Approval{Method: MethodPlanHash, Approver: "op"}); err == nil {
		t.Fatal("no audit log must refuse")
	}
	x := &Executor{Audit: &memAudit{}}
	if _, err := x.Authorize(p, p.Hash(), Approval{Method: MethodPlanHash}); err == nil {
		t.Fatal("no approver must refuse")
	}
	if _, err := x.Authorize(p, p.Hash(), Approval{Method: "yes", Approver: "op"}); err == nil {
		t.Fatal("unknown method must refuse")
	}
}

func TestDoRejectsActionOutsideThePlanAndStepsAreNotSQL(t *testing.T) {
	p := testPlan()
	audit := &memAudit{}
	x := &Executor{Audit: audit, Recorder: audit}
	auth, _ := x.Authorize(p, p.Hash(), Approval{Method: MethodPlanHash, Approver: "op"})
	if err := auth.Do(context.Background(), "source.drop-everything", func(context.Context) error { return nil }); err == nil {
		t.Fatal("an action that is not in the approved plan must be refused")
	}
	ran := false
	if err := auth.Do(context.Background(), "start.copy", func(context.Context) error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("a step runs through Do: %v", err)
	}
	if err := (&Step{}).Apply(context.Background(), &fakeConn{}); !errors.Is(err, ErrNotSQL) {
		t.Fatal("a Step is not plain SQL")
	}
}

func TestDryRunConnectsNowhere(t *testing.T) {
	p := testPlan()
	lines := DryRun(p, PhaseStart)
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "read-only") || !strings.HasPrefix(lines[1], "would run") {
		t.Fatalf("%v", lines)
	}
}

func TestValidate(t *testing.T) {
	p := testPlan()
	p.Actions = append(p.Actions, &Statement{Key: "source.create-role", At: PhaseSource})
	if p.Validate() == nil {
		t.Fatal("duplicate ids must be refused")
	}
	p = testPlan()
	p.Actions[0].(*Statement).At = "weird"
	if p.Validate() == nil {
		t.Fatal("unknown phase must be refused")
	}
}
