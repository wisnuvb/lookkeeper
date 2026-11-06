package testutil

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Names and canaries used by the migration fixture (SeedMigrationSource and
// SeedMigrationTarget). Tests assert on these.
const (
	// FixtureAppDB exists on both servers: with data on the source and with an
	// unrelated pre-existing table on the target.
	FixtureAppDB = "app"
	// FixtureLatinDB is UTF8 on the source and LATIN1 on the target.
	FixtureLatinDB = "latin_db"
	// FixtureCollDB uses the C locale on the source and C.UTF-8 on the target.
	FixtureCollDB = "coll_db"
	// FixtureOwnerRole owns the source objects and does not exist on the target.
	FixtureOwnerRole = "app_owner"
	// FixtureSlot is an inactive logical slot on the source that retains WAL.
	FixtureSlot = "lk_old_slot"
	// RowCanary is stored as table data, in a large object and in the text of a
	// concurrently running DDL statement. It must never appear in any output.
	RowCanary = "CANARY_ROW_DATA_5b1f9c"
)

// AdminDB opens a superuser connection to another database of the same
// container, for arranging test state. It is closed at test end.
func (p *PG) AdminDB(t testing.TB, database string) *pgx.Conn {
	t.Helper()
	q := *p
	q.Database = database
	return q.Admin(t)
}

func mustExec(t testing.TB, c *pgx.Conn, sql string) {
	t.Helper()
	if _, err := c.Exec(context.Background(), sql); err != nil {
		t.Fatalf("fixture: %s: %v", sql, err)
	}
}

// SeedMigrationSource arranges a source server that exercises the pre-flight
// findings: a table without a primary key, an unlogged table, a partitioned
// table, a foreign table, a large object, an extension, objects owned by a
// role the target lacks, and an inactive logical slot with retained WAL. The
// server must run with wal_level=logical.
func SeedMigrationSource(t testing.TB, p *PG) {
	t.Helper()
	admin := p.AdminDB(t, "postgres")
	mustExec(t, admin, "CREATE ROLE "+FixtureOwnerRole+" LOGIN PASSWORD 'owner-pw-not-a-secret'")
	mustExec(t, admin, "CREATE DATABASE "+FixtureAppDB+" OWNER "+FixtureOwnerRole)
	mustExec(t, admin, "CREATE DATABASE "+FixtureLatinDB+" TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'")
	mustExec(t, admin, "CREATE DATABASE "+FixtureCollDB+" TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'")

	app := p.AdminDB(t, FixtureAppDB)
	for _, q := range []string{
		"CREATE EXTENSION pg_trgm",
		"CREATE TABLE accounts (id serial PRIMARY KEY, email text NOT NULL)",
		"INSERT INTO accounts (email) SELECT 'user' || g || '@" + RowCanary + ".example' FROM generate_series(1, 50) g",
		"CREATE TABLE events (ts timestamptz DEFAULT now(), payload text)",
		"INSERT INTO events (payload) SELECT '" + RowCanary + "' || repeat('x', 200) FROM generate_series(1, 3000)",
		"CREATE UNLOGGED TABLE scratch (id int, note text)",
		"CREATE TABLE measurements (id int, ts date, v int, PRIMARY KEY (id, ts)) PARTITION BY RANGE (ts)",
		"CREATE TABLE measurements_2025 PARTITION OF measurements FOR VALUES FROM ('2025-01-01') TO ('2026-01-01')",
		"CREATE TABLE measurements_2026 PARTITION OF measurements FOR VALUES FROM ('2026-01-01') TO ('2027-01-01')",
		"CREATE FOREIGN DATA WRAPPER lk_fdw",
		"CREATE SERVER lk_remote FOREIGN DATA WRAPPER lk_fdw",
		"CREATE FOREIGN TABLE remote_things (id int) SERVER lk_remote",
		"SELECT lo_from_bytea(0, '" + RowCanary + "'::bytea)",
		"ALTER TABLE accounts OWNER TO " + FixtureOwnerRole,
		"ALTER TABLE events OWNER TO " + FixtureOwnerRole,
		// The slot is created before the WAL below, so it retains it.
		"SELECT pg_create_logical_replication_slot('" + FixtureSlot + "', 'pgoutput')",
		"INSERT INTO events (payload) SELECT repeat('y', 300) FROM generate_series(1, 20000)",
	} {
		mustExec(t, app, q)
	}
	mustExec(t, p.AdminDB(t, FixtureLatinDB), "CREATE TABLE t (id int PRIMARY KEY)")
	mustExec(t, p.AdminDB(t, FixtureCollDB), "CREATE TABLE t (id int PRIMARY KEY)")
}

// SeedMigrationTarget arranges a target server for the same scenario: default
// settings, no app_owner role, a pre-existing user table in app, and databases
// whose encoding and locale differ from the source's. Extensions are not
// touched here; tests that need an unavailable extension edit the container's
// extension directory with PG.Exec.
func SeedMigrationTarget(t testing.TB, p *PG) {
	t.Helper()
	admin := p.AdminDB(t, "postgres")
	mustExec(t, admin, "CREATE DATABASE "+FixtureAppDB)
	mustExec(t, admin, "CREATE DATABASE "+FixtureLatinDB+" TEMPLATE template0 ENCODING 'LATIN1' LC_COLLATE 'C' LC_CTYPE 'C'")
	mustExec(t, admin, "CREATE DATABASE "+FixtureCollDB+" TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C.UTF-8' LC_CTYPE 'C.UTF-8'")
	mustExec(t, p.AdminDB(t, FixtureAppDB), "CREATE TABLE legacy_leftover (id int)")
}
