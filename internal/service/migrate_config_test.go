package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/wisnuvb/lockkeeper/internal/action"
	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/dbconn"
	"github.com/wisnuvb/lockkeeper/internal/migrate/machine"
	"github.com/wisnuvb/lockkeeper/internal/migrate/pgnative"
	"github.com/wisnuvb/lockkeeper/internal/secret"
	"github.com/wisnuvb/lockkeeper/internal/store"
)

const migrateCfgYAML = `
version: 1
databases:
  src:
    engine: postgres
    host: 127.0.0.1
    port: 15432
    database: postgres
    user: admin
    password: { env: DB_PW }
    tls: { mode: disable }
  tgt:
    engine: postgres
    host: 127.0.0.1
    port: 15433
    database: postgres
    user: admin
    password: { env: DB_PW }
    tls: { mode: disable }
store:
  path: %s
`

// migrateFixture is a service plus a stored migration that was planned against
// the configuration in migrateCfgYAML, with every database connection counted.
type migrateFixture struct {
	t        *testing.T
	statePth string
	attempts *int
	id       string
}

func (f *migrateFixture) service(yaml string) *Service {
	f.t.Helper()
	cfg, _, err := config.Parse([]byte(fmt.Sprintf(yaml, f.statePth)))
	if err != nil {
		f.t.Fatal(err)
	}
	svc, err := New(cfg, Deps{
		Secrets: secret.Resolver{Getenv: func(string) (string, bool) { return "pw", true }},
		OpenPG: func(context.Context, dbconn.PGSpec) (*pgx.Conn, error) {
			*f.attempts++
			return nil, errors.New("no database in this test")
		},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return svc
}

func newMigrateFixture(t *testing.T, state machine.State) *migrateFixture {
	t.Helper()
	f := &migrateFixture{t: t, statePth: filepath.Join(t.TempDir(), "state", "lockkeeper.db"), attempts: new(int)}
	svc := f.service(migrateCfgYAML)
	cfg := svc.cfg
	in := pgnative.PlanInput{
		LockkeeperVersion: "test",
		Source:            sideOf("src", cfg.Databases["src"], "17.2", 17),
		Target:            sideOf("tgt", cfg.Databases["tgt"], "17.2", 17),
		Peer:              pgnative.Peer{Host: "127.0.0.1", Port: 15432, SSLMode: "disable"},
		DBs:               []pgnative.DBFacts{{Database: "app", Publish: []pgnative.Table{{Schema: "public", Name: "t"}}}},
		CopierKind:        "pgcopydb", TableJobs: 4, IndexJobs: 4,
	}
	if err := svc.finishInput(&in, "m00000000", ToolOptions{}); err != nil {
		t.Fatal(err)
	}
	plan, err := pgnative.BuildPlan(in)
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(in)
	st, err := svc.openState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, _, err := st.CreateMigration(context.Background(), store.Migration{
		ID: plan.MigrationID, SourceName: "src", TargetName: "tgt", Databases: plan.Databases,
		PlanHash: plan.Hash(), PlanJSON: string(plan.DisplayJSON()), InputJSON: string(blob),
	}, svc.deps.Now()); err != nil {
		t.Fatal(err)
	}
	f.id = plan.MigrationID
	ss := machine.SQLStore{DB: st}
	steps := []machine.State{machine.PreflightOK, machine.SourceChangesApproved}
	if state == machine.Aborted {
		steps = append(steps, machine.Aborted)
	}
	cur := machine.Draft
	for _, to := range steps {
		if err := st.Transition(context.Background(), f.id, string(cur), string(to), "test", "test", svc.deps.Now()); err != nil {
			t.Fatal(err)
		}
		cur = to
	}
	_ = ss
	if err := st.SetApprovedHash(context.Background(), f.id, plan.Hash(), svc.deps.Now()); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestConfigEditedAfterApprovalIsRefusedBeforeAnyConnection: execution connects
// through the live configuration, so an edit of the host, port, user, database,
// TLS mode or CA file of the source or the target after the plan was approved
// must stop every command that would act on the migration, before it connects.
func TestConfigEditedAfterApprovalIsRefusedBeforeAnyConnection(t *testing.T) {
	edits := map[string]string{
		"target host":  strings.Replace(migrateCfgYAML, "host: 127.0.0.1\n    port: 15433", "host: 127.0.0.2\n    port: 15433", 1),
		"target port":  strings.Replace(migrateCfgYAML, "15433", "15434", 1),
		"source user":  strings.Replace(migrateCfgYAML, "user: admin", "user: mallory", 1),
		"source db":    strings.Replace(migrateCfgYAML, "database: postgres", "database: other", 1),
		"source tls":   strings.Replace(migrateCfgYAML, "    tls: { mode: disable }", "    tls: { mode: require }", 1),
		"source ca":    strings.Replace(migrateCfgYAML, "    tls: { mode: disable }", "    tls: { mode: disable, ca_file: /etc/other-ca.pem }", 1),
		"target gone":  strings.Replace(migrateCfgYAML, "  tgt:", "  tgt-renamed:", 1),
		"source gone":  strings.Replace(migrateCfgYAML, "  src:", "  src-renamed:", 1),
		"target alias": strings.Replace(migrateCfgYAML, "port: 15433", "port: 15432", 1),
	}
	for name, yaml := range edits {
		t.Run(name, func(t *testing.T) {
			f := newMigrateFixture(t, machine.SourceChangesApproved)
			svc := f.service(yaml)
			ctx := context.Background()
			check := func(what string, err error) {
				t.Helper()
				if err == nil || !strings.Contains(err.Error(), "configuration was edited after") {
					t.Fatalf("%s must refuse with a message about the edited configuration, got: %v", what, err)
				}
			}
			_, err := svc.RunMigration(ctx, RunOptions{MigrationID: f.id})
			check("start/resume", err)
			_, err = svc.AbortMigration(ctx, EndOptions{MigrationID: f.id})
			check("abort", err)
			_, err = svc.ApplySourceChanges(ctx, ApplyOptions{MigrationID: f.id}, ToolOptions{})
			// apply refuses the state first (already applied): any refusal is fine,
			// but it must not have connected.
			_ = err
			_, err = svc.MigrationStatus(ctx, "", f.id, ToolOptions{})
			check("status", err)
			if *f.attempts != 0 {
				t.Fatalf("a connection was attempted %d time(s) before the refusal", *f.attempts)
			}
		})
	}

	t.Run("cleanup", func(t *testing.T) {
		f := newMigrateFixture(t, machine.Aborted)
		svc := f.service(strings.Replace(migrateCfgYAML, "15433", "15434", 1))
		_, err := svc.CleanupMigration(context.Background(), EndOptions{MigrationID: f.id})
		if err == nil || !strings.Contains(err.Error(), "configuration was edited after") {
			t.Fatalf("cleanup must refuse with a message about the edited configuration, got: %v", err)
		}
		if *f.attempts != 0 {
			t.Fatalf("a connection was attempted %d time(s)", *f.attempts)
		}
	})

	t.Run("unchanged configuration is accepted by the check", func(t *testing.T) {
		f := newMigrateFixture(t, machine.SourceChangesApproved)
		svc := f.service(migrateCfgYAML)
		st, err := svc.openState(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		m, _ := st.GetMigration(context.Background(), f.id)
		if _, err := svc.loadMigration(context.Background(), st, m, ToolOptions{}); err != nil {
			t.Fatalf("the unchanged configuration must pass: %v", err)
		}
	})
	_ = os.Remove
}

// Abort and cleanup take the driver lock before they read the state and build
// the plan: while another process holds the lock, nobody is asked to approve
// anything and nothing is connected.
func TestAbortAndCleanupTakeTheLockBeforePlanningAndApproving(t *testing.T) {
	for _, name := range []string{"abort", "cleanup"} {
		t.Run(name, func(t *testing.T) {
			state := machine.SourceChangesApproved
			if name == "cleanup" {
				state = machine.Aborted
			}
			f := newMigrateFixture(t, state)
			svc := f.service(migrateCfgYAML)
			mdir, err := svc.migrationDir(f.id)
			if err != nil {
				t.Fatal(err)
			}
			held, _, err := machine.AcquireLock(filepath.Join(mdir, "driver.lock"), svc.deps.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer held.Release()
			asked := 0
			o := EndOptions{MigrationID: f.id, Apply: true, Approver: func(*action.Plan) (action.Approval, error) {
				asked++
				return action.Approval{}, errors.New("must not be asked")
			}}
			var runErr error
			if name == "abort" {
				_, runErr = svc.AbortMigration(context.Background(), o)
			} else {
				_, runErr = svc.CleanupMigration(context.Background(), o)
			}
			if !errors.Is(runErr, machine.ErrLocked) {
				t.Fatalf("want the lock error, got %v", runErr)
			}
			if asked != 0 {
				t.Fatalf("the operator was asked to approve a plan %d time(s) before the lock was held", asked)
			}
		})
	}
}

// The CA file the tools use is part of what the plan shows and hashes.
func TestCAFileIsPartOfThePlan(t *testing.T) {
	mk := func(ca string) string {
		in := pgnative.PlanInput{
			Source:     pgnative.Side{Name: "a", Host: "h", Port: 5432, User: "u", TLSMode: "verify-full", CAFile: ca},
			Target:     pgnative.Side{Name: "b", Host: "t", Port: 5432, User: "u", TLSMode: "verify-full"},
			Peer:       pgnative.Peer{Host: "h", Port: 5432, SSLMode: "verify-full"},
			DBs:        []pgnative.DBFacts{{Database: "app", Publish: []pgnative.Table{{Schema: "public", Name: "t"}}}},
			CopierKind: "pgcopydb", TableJobs: 1, IndexJobs: 1,
		}
		svc := &Service{deps: Deps{Version: "t"}}
		cp, err := svc.newCopier("pgcopydb", nil, ToolOptions{})
		if err != nil {
			t.Fatal(err)
		}
		in.Copier = cp
		p, err := pgnative.BuildPlan(in)
		if err != nil {
			t.Fatal(err)
		}
		return p.Hash()
	}
	if mk("/etc/a.pem") == mk("/etc/b.pem") {
		t.Fatal("a different CA file must give a different plan hash")
	}
}
