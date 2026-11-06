//go:build integration

package pg_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/dbconn"
	"github.com/wisnuvb/lockkeeper/internal/inventory"
	"github.com/wisnuvb/lockkeeper/internal/preflight"
	"github.com/wisnuvb/lockkeeper/internal/secret"
	"github.com/wisnuvb/lockkeeper/internal/service"
	"github.com/wisnuvb/lockkeeper/internal/testutil"
)

// entry is one configured connection in a test config.
type entry struct {
	name     string
	p        *testutil.PG
	user     string
	password string
}

func superuser(name string, p *testutil.PG) entry {
	return entry{name: name, p: p, user: p.User, password: p.Password}
}

func (e entry) envVar() string {
	return "LK_PW_" + strings.ToUpper(strings.ReplaceAll(e.name, "-", "_"))
}

// configYAML renders a Lockkeeper config for the entries. Passwords are env
// references, as in production.
func configYAML(extra string, entries ...entry) string {
	var b strings.Builder
	b.WriteString("version: 1\ndatabases:\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "  %s:\n    engine: postgres\n    host: %s\n    port: %d\n    database: postgres\n    user: %s\n    password: { env: %s }\n    tls: { mode: disable }\n",
			e.name, e.p.Host, e.p.Port, e.user, e.envVar())
	}
	b.WriteString(extra)
	return b.String()
}

func envOf(entries ...entry) map[string]string {
	m := map[string]string{}
	for _, e := range entries {
		m[e.envVar()] = e.password
	}
	return m
}

// writeConfig writes the config to a 0600 file and returns its path.
func writeConfig(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lockkeeper.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// sessionLog records what every Lockkeeper session looked like when it opened.
type sessionLog struct {
	mu       sync.Mutex
	sessions []sessionInfo
}

type sessionInfo struct {
	database            string
	defaultReadOnly     string
	temporaryTableError error
}

func (l *sessionLog) all() []sessionInfo {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]sessionInfo(nil), l.sessions...)
}

// deps wraps the real connection factory: every session is checked to be
// default_transaction_read_only and to refuse even a session-local temporary
// table (a write that would not need any privilege other than a session).
func (l *sessionLog) deps(d service.Deps) service.Deps {
	d.OpenPG = func(ctx context.Context, spec dbconn.PGSpec) (*pgx.Conn, error) {
		c, err := dbconn.OpenPG(ctx, spec)
		if err != nil {
			return nil, err
		}
		si := sessionInfo{database: spec.Database}
		_ = c.QueryRow(ctx, "SHOW default_transaction_read_only").Scan(&si.defaultReadOnly)
		_, si.temporaryTableError = c.Exec(ctx, "CREATE TEMP TABLE lk_must_fail (x int)")
		l.mu.Lock()
		l.sessions = append(l.sessions, si)
		l.mu.Unlock()
		return c, nil
	}
	return d
}

func newService(t *testing.T, yaml string, env map[string]string, deps func(service.Deps) service.Deps) *service.Service {
	t.Helper()
	cfg, _, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("config: %v\n%s", err, yaml)
	}
	d := service.Deps{Secrets: secret.Resolver{Getenv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }}}
	if deps != nil {
		d = deps(d)
	}
	svc, err := service.New(cfg, d)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func finding(t *testing.T, r *preflight.Report, id string) preflight.Finding {
	t.Helper()
	var ids []string
	for _, f := range r.Findings {
		if f.ID == id {
			return f
		}
		ids = append(ids, f.ID)
	}
	t.Fatalf("finding %q missing; have %v", id, ids)
	return preflight.Finding{}
}

// expect asserts severity and message/remediation fragments of one finding.
func expect(t *testing.T, r *preflight.Report, id string, sev preflight.Severity, msgFrags []string, remFrags ...string) {
	t.Helper()
	f := finding(t, r, id)
	if f.Severity != sev {
		t.Errorf("%s: severity %s, want %s\n  message: %s", id, f.Severity, sev, f.Message)
	}
	for _, frag := range msgFrags {
		if !strings.Contains(f.Message, frag) {
			t.Errorf("%s: message lacks %q:\n  %s", id, frag, f.Message)
		}
	}
	for _, frag := range remFrags {
		if !strings.Contains(f.Remediation, frag) {
			t.Errorf("%s: remediation lacks %q:\n  %s", id, frag, f.Remediation)
		}
	}
}

// openDDLProbe leaves a session with an open transaction that ran DDL, whose
// statement text contains the row-data canary: the pre-flight must count it and
// must never print the text.
func openDDLProbe(t *testing.T, p *testutil.PG) {
	t.Helper()
	conn := p.AdminDB(t, testutil.FixtureAppDB)
	ctx := context.Background()
	if _, err := conn.Exec(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "CREATE TABLE ddl_probe (note text DEFAULT '"+testutil.RowCanary+"')"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(context.Background(), "ROLLBACK") })
}

func mustExec(t *testing.T, c *pgx.Conn, sql string) {
	t.Helper()
	if _, err := c.Exec(context.Background(), sql); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// catalogSnapshot renders the state of a server that a pre-flight must not
// change: databases, roles and memberships, settings, slots, publications and
// subscriptions, and per database the relations, extensions, large objects and
// a digest of every table's rows. It is read through plain superuser sessions.
func catalogSnapshot(t *testing.T, p *testutil.PG) string {
	t.Helper()
	var b strings.Builder
	dump := func(c *pgx.Conn, title, sql string) {
		rows, err := c.Query(context.Background(), sql)
		if err != nil {
			t.Fatalf("snapshot %s: %v", title, err)
		}
		defer rows.Close()
		fmt.Fprintf(&b, "== %s\n", title)
		for rows.Next() {
			vals, err := rows.Values()
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintln(&b, vals...)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
	}
	admin := p.Admin(t)
	dump(admin, "databases", `SELECT datname, datdba::regrole::text, pg_encoding_to_char(encoding), datcollate, datistemplate, datallowconn FROM pg_database ORDER BY 1`)
	dump(admin, "roles", `SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolbypassrls, rolconnlimit, rolvaliduntil FROM pg_roles ORDER BY 1`)
	dump(admin, "memberships", `SELECT roleid::regrole::text, member::regrole::text, grantor::regrole::text FROM pg_auth_members ORDER BY 1, 2`)
	dump(admin, "role settings", `SELECT setdatabase, setrole, setconfig::text FROM pg_db_role_setting ORDER BY 1, 2`)
	dump(admin, "settings", `SELECT name, setting, source FROM pg_settings ORDER BY 1`)
	dump(admin, "slots", `SELECT slot_name, slot_type, plugin, database, active, temporary FROM pg_replication_slots ORDER BY 1`)

	var dbs []string
	rows, err := admin.Query(context.Background(), `SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		dbs = append(dbs, n)
	}
	rows.Close()

	for _, db := range dbs {
		c := p.AdminDB(t, db)
		dump(c, db+": relations", `SELECT n.nspname, c.relname, c.relkind, c.relpersistence, c.relreplident, c.relowner::regrole::text, c.relispartition
			FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%' ORDER BY 1, 2`)
		dump(c, db+": extensions", `SELECT extname, extversion FROM pg_extension ORDER BY 1`)
		dump(c, db+": publications", `SELECT pubname FROM pg_publication ORDER BY 1`)
		dump(c, db+": subscriptions", `SELECT count(subname) FROM pg_subscription`)
		dump(c, db+": large objects", `SELECT count(*) FROM pg_largeobject_metadata`)
		var tables [][2]string
		trows, err := c.Query(context.Background(), `SELECT n.nspname, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%' ORDER BY 1, 2`)
		if err != nil {
			t.Fatal(err)
		}
		for trows.Next() {
			var s, n string
			if err := trows.Scan(&s, &n); err != nil {
				t.Fatal(err)
			}
			tables = append(tables, [2]string{s, n})
		}
		trows.Close()
		for _, tb := range tables {
			dump(c, db+": rows of "+tb[0]+"."+tb[1], fmt.Sprintf(
				`SELECT count(*), md5(COALESCE(string_agg(to_jsonb(t)::text, '|' ORDER BY to_jsonb(t)::text), '')) FROM %s.%s t`,
				inventory.QuoteIdent(tb[0]), inventory.QuoteIdent(tb[1])))
		}
	}
	return b.String()
}

// firstDifference returns the first differing line of two snapshots.
func firstDifference(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(al) || i < len(bl); i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			return fmt.Sprintf("line %d:\n  before: %s\n  after:  %s", i+1, x, y)
		}
	}
	return ""
}
