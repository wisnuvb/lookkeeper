//go:build integration

package inventory_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/wisnuvb/lockkeeper/internal/dbconn"
	"github.com/wisnuvb/lockkeeper/internal/inventory"
	"github.com/wisnuvb/lockkeeper/internal/secret"
	"github.com/wisnuvb/lockkeeper/internal/testutil"
)

// opener returns an Opener that records every session's read-only state.
func opener(t *testing.T, p *testutil.PG, opened *[]string) inventory.Opener {
	t.Helper()
	return func(ctx context.Context, database string) (inventory.Conn, error) {
		spec := p.Spec()
		spec.Database = database
		conn, err := dbconn.OpenPG(ctx, spec)
		if err != nil {
			return nil, err
		}
		var ro string
		if err := conn.QueryRow(ctx, "SHOW transaction_read_only").Scan(&ro); err != nil || ro != "on" {
			t.Errorf("session to %q is not read-only: %q %v", database, ro, err)
		}
		*opened = append(*opened, database)
		return conn, nil
	}
}

func collect(t *testing.T, p *testutil.PG, opts inventory.Options) (*inventory.Server, []string) {
	t.Helper()
	var opened []string
	open := opener(t, p, &opened)
	primary, err := open(context.Background(), p.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close(context.Background())
	srv, err := inventory.Collect(context.Background(), primary, open, opts)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	return srv, opened
}

func TestCollectSourceFixture(t *testing.T) {
	p := testutil.StartPG(t)
	testutil.SeedMigrationSource(t, p)

	srv, opened := collect(t, p, inventory.Options{Databases: []string{testutil.FixtureAppDB, "nope"}})

	if srv.Major < 12 || srv.Version == "" || srv.IsRDS {
		t.Errorf("version/RDS detection: %+v", srv)
	}
	if v, _ := srv.SettingString("wal_level"); v != "logical" {
		t.Errorf("wal_level = %q", v)
	}
	if !srv.Session.Superuser || !srv.Session.ReadOnly || srv.Session.User != "postgres" {
		t.Errorf("session: %+v", srv.Session)
	}
	if !srv.HasRole(testutil.FixtureOwnerRole) {
		t.Errorf("owner role missing from roles: %+v", srv.Roles)
	}
	for _, r := range srv.Roles {
		if strings.HasPrefix(r.Name, "pg_") {
			t.Errorf("system role %q must be omitted", r.Name)
		}
	}
	if len(srv.NotFound) != 1 || srv.NotFound[0] != "nope" {
		t.Errorf("NotFound = %v", srv.NotFound)
	}

	var slot *inventory.Slot
	for i := range srv.Slots {
		if srv.Slots[i].Name == testutil.FixtureSlot {
			slot = &srv.Slots[i]
		}
	}
	if slot == nil || slot.Active || slot.RetainedBytes < 1<<20 {
		t.Errorf("inactive slot with retained WAL expected: %+v", srv.Slots)
	}

	if len(srv.Databases) != 1 {
		t.Fatalf("only the selected database is inspected: %+v", srv.Databases)
	}
	d := srv.Databases[0]
	if d.Name != testutil.FixtureAppDB || d.Error != "" || len(d.Warnings) != 0 {
		t.Fatalf("app database: %+v", d)
	}
	if d.Owner != testutil.FixtureOwnerRole || d.Encoding != "UTF8" || d.SizeBytes <= 0 {
		t.Errorf("database facts: %+v", d)
	}
	if len(d.Extensions) < 3 || !hasExt(d, "hstore") || !hasExt(d, "pg_trgm") || !hasExt(d, "plpgsql") {
		t.Errorf("extensions: %+v", d.Extensions)
	}
	// accounts, events, scratch, measurements (partitioned): 4 tables, 2 partitions.
	if d.Tables != 4 || d.Partitions != 2 {
		t.Errorf("tables=%d partitions=%d", d.Tables, d.Partitions)
	}
	if d.Sequences < 1 || d.TableBytes <= 0 {
		t.Errorf("sequences=%d bytes=%d", d.Sequences, d.TableBytes)
	}

	// events has no primary key, default replica identity, and is the largest.
	if d.TablesWithoutPK.Total != 2 { // events and scratch
		t.Errorf("tables without PK: %+v", d.TablesWithoutPK)
	}
	if first := d.TablesWithoutPK.Items[0]; first.Name != "events" || first.ReplicaIdentity != "default" || first.TotalBytes <= 0 {
		t.Errorf("events must lead the no-PK list: %+v", d.TablesWithoutPK.Items)
	}
	if d.UnloggedTables.Total != 1 || d.UnloggedTables.Items[0].Name != "scratch" {
		t.Errorf("unlogged: %+v", d.UnloggedTables)
	}
	if d.PartitionedTables.Total != 1 || d.PartitionedTables.Items[0].Name != "measurements" || d.PartitionedTables.Items[0].Partitions != 2 {
		t.Errorf("partitioned: %+v", d.PartitionedTables)
	}
	if d.ForeignTables.Total != 1 || d.ForeignTables.Items[0].Name != "remote_things" {
		t.Errorf("foreign: %+v", d.ForeignTables)
	}
	if d.UnreadableTables.Total != 0 {
		t.Errorf("a superuser reads everything: %+v", d.UnreadableTables)
	}
	if d.LargeObjects != 1 || d.LargeObjectBytes <= 0 {
		t.Errorf("large objects: %d (%d bytes)", d.LargeObjects, d.LargeObjectBytes)
	}
	if len(d.LargestTables) == 0 || d.LargestTables[0].Name != "events" {
		t.Errorf("largest tables: %+v", d.LargestTables)
	}
	if !contains(d.Owners, testutil.FixtureOwnerRole) || !contains(d.Owners, "postgres") {
		t.Errorf("owners: %v", d.Owners)
	}

	// Other databases are listed by name only; postgres is the primary
	// connection, which must not be re-opened for app.
	if !contains(srv.OtherDatabases, testutil.FixtureLatinDB) {
		t.Errorf("other databases: %v", srv.OtherDatabases)
	}
	if len(opened) != 2 { // the primary plus one connection for app
		t.Errorf("one connection per inspected database expected, opened %v", opened)
	}

	// Neither JSON nor anything else may carry row data.
	b, _ := json.Marshal(srv)
	if strings.Contains(string(b), testutil.RowCanary) {
		t.Error("inventory output contains row data")
	}
}

func TestCollectDefaultSelectionAndCap(t *testing.T) {
	p := testutil.StartPG(t)
	testutil.SeedMigrationSource(t, p)

	srv, _ := collect(t, p, inventory.Options{})
	var names []string
	for _, d := range srv.Databases {
		names = append(names, d.Name)
		if d.Error != "" {
			t.Errorf("%s: %s", d.Name, d.Error)
		}
	}
	want := "app,coll_db,latin_db,postgres"
	if strings.Join(names, ",") != want {
		t.Errorf("databases = %v, want %s (templates are skipped)", names, want)
	}
	if srv.DefaultLocale.Encoding != "UTF8" {
		t.Errorf("template1 locale: %+v", srv.DefaultLocale)
	}

	var opened []string
	open := opener(t, p, &opened)
	primary, err := open(context.Background(), "postgres")
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close(context.Background())
	_, err = inventory.Collect(context.Background(), primary, open, inventory.Options{MaxDatabases: 2})
	if !errors.Is(err, inventory.ErrTooManyDatabases) || !strings.Contains(err.Error(), "--databases") {
		t.Errorf("the cap must be an explicit error, got %v", err)
	}
}

func TestCollectRecordsPerDatabaseFailureAndCapsLists(t *testing.T) {
	p := testutil.StartPG(t)
	testutil.SeedMigrationSource(t, p)
	admin := p.Admin(t)
	if _, err := admin.Exec(context.Background(), "CREATE ROLE lk_reader LOGIN PASSWORD 'r'"); err != nil {
		t.Fatal(err)
	}
	// lk_reader may not connect to latin_db and can only read the accounts table.
	for _, q := range []string{
		"REVOKE CONNECT ON DATABASE " + testutil.FixtureLatinDB + " FROM PUBLIC",
		"GRANT CONNECT ON DATABASE " + testutil.FixtureAppDB + " TO lk_reader",
	} {
		if _, err := admin.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
	app := p.AdminDB(t, testutil.FixtureAppDB)
	if _, err := app.Exec(context.Background(), "GRANT SELECT ON accounts TO lk_reader; GRANT USAGE ON SCHEMA public TO lk_reader"); err != nil {
		t.Fatal(err)
	}

	var opened []string
	spec := p.Spec()
	spec.User, spec.Database = "lk_reader", "app"
	spec.Password = secretOf("r")
	open := func(ctx context.Context, database string) (inventory.Conn, error) {
		s := spec
		s.Database = database
		c, err := dbconn.OpenPG(ctx, s)
		if err != nil {
			return nil, err
		}
		opened = append(opened, database)
		return c, nil
	}
	primary, err := open(context.Background(), "app")
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close(context.Background())

	srv, err := inventory.Collect(context.Background(), primary, open,
		inventory.Options{Databases: []string{"app", testutil.FixtureLatinDB}, ListCap: 1, TopTables: 1})
	if err != nil {
		t.Fatal(err)
	}
	latin, _ := srv.Database(testutil.FixtureLatinDB)
	if latin == nil || !strings.Contains(latin.Error, "CONNECT") || latin.Encoding != "UTF8" {
		t.Errorf("a database the role cannot enter is reported, not fatal: %+v", latin)
	}
	d, _ := srv.Database("app")
	if d == nil || d.Error != "" {
		t.Fatalf("app: %+v", d)
	}
	if srv.Session.Superuser || srv.Session.PgMonitor {
		t.Errorf("session privileges: %+v", srv.Session)
	}
	// Every table except accounts is unreadable: events, scratch, measurements, 2 partitions... capped to one item.
	if d.UnreadableTables.Total < 3 || len(d.UnreadableTables.Items) != 1 {
		t.Errorf("unreadable tables must be counted exactly and listed up to the cap: %+v", d.UnreadableTables)
	}
	if len(d.LargestTables) != 1 || len(d.TablesWithoutPK.Items) != 1 || d.TablesWithoutPK.Total != 2 {
		t.Errorf("caps: largest=%d nopk=%+v", len(d.LargestTables), d.TablesWithoutPK)
	}
	for _, o := range opened {
		if o == testutil.FixtureLatinDB {
			t.Error("must not even try to connect without the CONNECT privilege")
		}
	}
}

func hasExt(d inventory.Database, name string) bool {
	for _, e := range d.Extensions {
		if e.Name == name {
			return true
		}
	}
	return false
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

func secretOf(s string) secret.Value { return secret.New(s) }
