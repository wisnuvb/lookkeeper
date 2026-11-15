//go:build integration

// Package itest holds the end-to-end tests of the Phase 3 orchestrator. They run
// the real CLI in-process against throwaway PostgreSQL containers on a private
// Docker network, with the bulk-copy tools in containers too. Nothing here can
// reach a server that the test did not start itself.
package itest

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/wisnuvb/lockkeeper/internal/cli"
	"github.com/wisnuvb/lockkeeper/internal/service"
	"github.com/wisnuvb/lockkeeper/internal/testutil"
)

type rigOptions struct {
	sourceArgs, targetArgs []string
}

// rig is a source and a target server, a Lockkeeper configuration pointing at
// them, and a launcher that runs the copy tools next to them.
type rig struct {
	t        *testing.T
	net      *testutil.Net
	src, tgt *testutil.NetPG
	launcher *testutil.DockerLauncher
	dir      string
	cfg      string
	stateDB  string
	copier   string
	stdin    string
}

func copierKinds() []string {
	if k := os.Getenv("LK_TEST_COPIER"); k != "" {
		return []string{k}
	}
	return []string{"pgcopydb"}
}

func newRig(t *testing.T, copier string, ro rigOptions) *rig {
	t.Helper()
	n := testutil.StartNet(t)
	src, tgt := testutil.StartPairNet(t, n, testutil.PairOptions{SourceArgs: ro.sourceArgs, TargetArgs: ro.targetArgs})
	r := &rig{t: t, net: n, src: src, tgt: tgt, dir: t.TempDir(), copier: copier}
	r.launcher = testutil.NewDockerLauncher(t, n, src, tgt)
	r.stateDB = filepath.Join(r.dir, "state", "lockkeeper.db")
	r.cfg = filepath.Join(r.dir, "lockkeeper.yaml")
	yaml := fmt.Sprintf(`version: 1
databases:
  src:
    engine: postgres
    host: %s
    port: %d
    database: postgres
    user: postgres
    password: { env: LK_SRC_PW }
    tls: { mode: disable, allow_insecure: true }
  tgt:
    engine: postgres
    host: %s
    port: %d
    database: postgres
    user: postgres
    password: { env: LK_TGT_PW }
    tls: { mode: disable }
store:
  path: %s
`, src.Host, src.Port, tgt.Host, tgt.Port, r.stateDB)
	if err := os.WriteFile(r.cfg, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	r.seed()
	return r
}

func mustExec(t testing.TB, c *pgx.Conn, sql string) {
	t.Helper()
	if _, err := c.Exec(context.Background(), sql); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// seed creates databases app and billing on both servers and fills the source.
// The target databases are empty. events has no primary key and the default
// replica identity: the plan must fix that.
func (r *rig) seed() {
	t := r.t
	for _, db := range []string{"app", "billing"} {
		mustExec(t, r.src.Admin(t), "CREATE DATABASE "+db)
		mustExec(t, r.tgt.Admin(t), "CREATE DATABASE "+db)
	}
	app := r.src.AdminDB(t, "app")
	for _, q := range []string{
		`CREATE TABLE accounts (id bigserial PRIMARY KEY, balance int NOT NULL DEFAULT 0, note text)`,
		`CREATE TABLE ledger (id bigserial PRIMARY KEY, account_id bigint NOT NULL, amount int NOT NULL)`,
		`CREATE TABLE events (payload text NOT NULL, n int NOT NULL DEFAULT 0)`,
		`INSERT INTO accounts (balance, note) SELECT g, 'seed' || g FROM generate_series(1, 2000) g`,
		`INSERT INTO ledger (account_id, amount) SELECT 1 + g % 2000, g FROM generate_series(1, 5000) g`,
		`INSERT INTO events (payload) SELECT 'seed-' || g FROM generate_series(1, 3000) g`,
	} {
		mustExec(t, app, q)
	}
	billing := r.src.AdminDB(t, "billing")
	mustExec(t, billing, `CREATE TABLE invoices (id serial PRIMARY KEY, amount int NOT NULL)`)
	mustExec(t, billing, `INSERT INTO invoices (amount) SELECT g FROM generate_series(1, 500) g`)
}

func (r *rig) appDSN() string {
	return fmt.Sprintf("postgres://postgres:%s@%s:%d/app?sslmode=disable", r.src.Password, r.src.Host, r.src.Port)
}

type output struct {
	stdout, stderr string
	code           int
}

func (o output) all() string { return o.stdout + o.stderr }

var allOutputs struct {
	sync.Mutex
	m map[*testing.T][]string
}

// run executes the CLI in-process. Everything printed is remembered so that the
// canary scan can look at it.
func (r *rig) run(args ...string) output {
	return r.runCtx(context.Background(), args...)
}

func (r *rig) runCtx(ctx context.Context, args ...string) output {
	r.t.Helper()
	var out, errb bytes.Buffer
	env := cli.Env{
		Stdin: strings.NewReader(r.stdin), Stdout: &out, Stderr: &errb,
		Getenv: func(k string) (string, bool) {
			switch k {
			case "LK_SRC_PW":
				return r.src.Password, true
			case "LK_TGT_PW":
				return r.tgt.Password, true
			case "PATH":
				return "/usr/local/bin:/usr/bin:/bin", true
			}
			return "", false
		},
		Deps: func(d service.Deps) service.Deps { d.Launcher = r.launcher; return d },
	}
	code := cli.Execute(ctx, env, append([]string{"-c", r.cfg}, args...))
	o := output{stdout: out.String(), stderr: errb.String(), code: code}
	allOutputs.Lock()
	if allOutputs.m == nil {
		allOutputs.m = map[*testing.T][]string{}
	}
	allOutputs.m[r.t] = append(allOutputs.m[r.t], strings.Join(args, " ")+"\n"+o.all())
	allOutputs.Unlock()
	return o
}

func (r *rig) outputs() []string {
	allOutputs.Lock()
	defer allOutputs.Unlock()
	return append([]string(nil), allOutputs.m[r.t]...)
}

var (
	planHashRe  = regexp.MustCompile(`Plan hash: ([0-9a-f]{64})`)
	migrationRe = regexp.MustCompile(`Migration: (m[0-9a-f]{8})`)
)

// planArgs are the flags every test passes to `migrate plan`.
func (r *rig) planArgs(extra ...string) []string {
	a := []string{"migrate", "plan", "--source", "src", "--target", "tgt", "--databases", "app,billing",
		"--source-peer-addr", "src:5432", "--source-peer-sslmode", "disable",
		"--copier", r.copier, "--allow-untested-pgcopydb"}
	return append(a, extra...)
}

// plan runs `migrate plan` and returns the plan hash and migration id.
func (r *rig) plan(extra ...string) (hash, id string) {
	r.t.Helper()
	o := r.run(r.planArgs(extra...)...)
	if o.code != 0 {
		r.t.Fatalf("migrate plan failed (%d):\n%s", o.code, o.all())
	}
	h, m := planHashRe.FindStringSubmatch(o.stdout), migrationRe.FindStringSubmatch(o.stdout)
	if h == nil || m == nil {
		r.t.Fatalf("no plan hash / migration id in:\n%s", o.stdout)
	}
	return h[1], m[1]
}

// apply runs apply-source-changes --apply with the plan hash.
func (r *rig) apply(hash string) output {
	r.t.Helper()
	return r.run("migrate", "apply-source-changes", "--plan-hash", hash, "--apply", "--allow-untested-pgcopydb")
}

func (r *rig) startArgs(id string, extra ...string) []string {
	a := []string{"migrate", "start", "--migration", id, "--allow-untested-pgcopydb",
		"--max-lag", "8MiB", "--caught-up-for", "3s", "--poll-interval", "1s"}
	return append(a, extra...)
}

func (r *rig) state(id string) string {
	r.t.Helper()
	o := r.run("migrate", "status", "--migration", id, "--json", "--allow-untested-pgcopydb")
	m := regexp.MustCompile(`"state": "([a-z_]+)"`).FindStringSubmatch(o.stdout)
	if m == nil {
		r.t.Fatalf("no state in status output (%d):\n%s", o.code, o.all())
	}
	return m[1]
}

// sourceFingerprint summarises every catalog fact a migration could change on
// the source: roles, publications, slots and the replica identity of every
// table, across the cluster's databases.
func (r *rig) sourceFingerprint() string {
	r.t.Helper()
	var parts []string
	q := func(c *pgx.Conn, sql string) {
		rows, err := c.Query(context.Background(), sql)
		if err != nil {
			r.t.Fatalf("%s: %v", sql, err)
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				r.t.Fatal(err)
			}
			parts = append(parts, s)
		}
	}
	admin := r.src.Admin(r.t)
	q(admin, `SELECT 'role:' || rolname FROM pg_roles ORDER BY 1`)
	q(admin, `SELECT 'slot:' || slot_name || ':' || plugin FROM pg_replication_slots ORDER BY 1`)
	for _, db := range []string{"app", "billing"} {
		c := r.src.AdminDB(r.t, db)
		q(c, `SELECT 'pub:' || pubname FROM pg_publication ORDER BY 1`)
		q(c, `SELECT 'identity:' || n.nspname || '.' || c.relname || ':' || c.relreplident::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind = 'r' AND n.nspname = 'public' ORDER BY 1`)
	}
	return strings.Join(parts, "\n")
}

// rowFingerprints is the row-level state of every table of app and billing.
func rowFingerprints(t testing.TB, p *testutil.NetPG) map[string]string {
	t.Helper()
	out := map[string]string{}
	app, billing := p.AdminDB(t, "app"), p.AdminDB(t, "billing")
	for _, tb := range []struct{ name, order string }{{"accounts", "id"}, {"ledger", "id"}, {"events", "payload"}} {
		out["app."+tb.name] = testutil.Fingerprint(t, app, tb.name, tb.order)
	}
	out["billing.invoices"] = testutil.Fingerprint(t, billing, "invoices", "id")
	return out
}

func assertSameRows(t testing.TB, src, tgt *testutil.NetPG) {
	t.Helper()
	s, g := rowFingerprints(t, src), rowFingerprints(t, tgt)
	for k, v := range s {
		if g[k] != v {
			t.Errorf("table %s differs: source %s, target %s", k, v, g[k])
		}
	}
}

// waitDrained waits until every Lockkeeper slot of the source has confirmed the
// source's current WAL position (call it after the writers stopped).
func waitDrained(t testing.TB, src *testutil.NetPG, within time.Duration) {
	t.Helper()
	admin := src.Admin(t)
	var target string
	if err := admin.QueryRow(context.Background(), `SELECT pg_current_wal_lsn()::text`).Scan(&target); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		var behind int
		if err := admin.QueryRow(context.Background(),
			`SELECT count(*) FROM pg_replication_slots WHERE slot_name LIKE 'lk\_%' AND (confirmed_flush_lsn IS NULL OR confirmed_flush_lsn < $1::pg_lsn)`, target).Scan(&behind); err != nil {
			t.Fatal(err)
		}
		if behind == 0 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("the subscriptions did not reach %s within %s", target, within)
}
