//go:build integration

package pg_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wisnuvb/lockkeeper/internal/cli"
	"github.com/wisnuvb/lockkeeper/internal/preflight"
	"github.com/wisnuvb/lockkeeper/internal/service"
	"github.com/wisnuvb/lockkeeper/internal/testutil"
)

var migrationDBs = service.DiscoveryOptions{Databases: []string{testutil.FixtureAppDB, testutil.FixtureLatinDB, testutil.FixtureCollDB}}

const lowSlotThresholds = `
alerts:
  rules:
    pg.slot.retained_wal_bytes:
      warning: 1MiB
      critical: 1GiB
`

// TestPreflightAgainstContainers runs the whole pre-flight against a real source
// (wal_level=logical with the usual problems) and a real target (defaults) and
// asserts the specific findings. The subtests share the two containers and run
// in order.
func TestPreflightAgainstContainers(t *testing.T) {
	src, tgt := testutil.StartPair(t, testutil.PairOptions{})
	testutil.SeedMigrationSource(t, src)
	testutil.SeedMigrationTarget(t, tgt)
	openDDLProbe(t, src)
	ctx := context.Background()

	s, g := superuser("src", src), superuser("tgt", tgt)
	svc := newService(t, configYAML(lowSlotThresholds, s, g), envOf(s, g), nil)

	rep, err := svc.PreflightPG(ctx, "src", "tgt", migrationDBs)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("findings on the source", func(t *testing.T) {
		if got := strings.Join(rep.Databases, ","); got != "app,coll_db,latin_db" {
			t.Errorf("databases = %s", got)
		}
		expect(t, rep, "connect.source", preflight.OK, []string{"connected to the source", "PostgreSQL"})
		expect(t, rep, "tls.source", preflight.Info, []string{"loopback"})
		expect(t, rep, "source.wal_level", preflight.OK, nil)
		expect(t, rep, "source.max_replication_slots", preflight.OK, []string{"needs 3"})
		expect(t, rep, "source.max_wal_senders", preflight.OK, nil)
		expect(t, rep, "source.replication_privilege", preflight.OK, []string{"superuser"})
		expect(t, rep, "source.read_privilege", preflight.OK, nil)
		// The container's defaults: a walsender timeout of 60 s and no WAL limit
		// (the latter only exists from PostgreSQL 13).
		expect(t, rep, "source.wal_sender_timeout", preflight.Warn, []string{"60000 ms"}, "wal_sender_timeout = 0")
		expect(t, rep, "source.max_slot_wal_keep_size", preflight.Warn, []string{"unlimited"}, "max_slot_wal_keep_size")

		expect(t, rep, "source.slot."+testutil.FixtureSlot, preflight.Warn,
			[]string{testutil.FixtureSlot, "INACTIVE", "above the 1.0 MiB warning threshold"}, "pg_drop_replication_slot('"+testutil.FixtureSlot+"')")
		expect(t, rep, "tables.no_pk.app", preflight.Warn, []string{"public.events", "1 table"},
			`ALTER TABLE "public"."events" REPLICA IDENTITY FULL`, "SOURCE")
		expect(t, rep, "tables.unlogged.app", preflight.Warn, []string{"public.scratch", "not written to WAL"}, "SET LOGGED")
		expect(t, rep, "objects.large_objects.app", preflight.Warn, []string{"1 large object"}, "cutover")
		expect(t, rep, "tables.partitioned.app", preflight.Info, []string{"public.measurements (2 partitions)"})
		expect(t, rep, "tables.foreign.app", preflight.Info, []string{"public.remote_things"})
		expect(t, rep, "tables.no_pk.latin_db", preflight.OK, nil)

		expect(t, rep, "source.ddl_activity", preflight.Info, []string{"1 session"})
	})

	t.Run("findings on the target and across both", func(t *testing.T) {
		expect(t, rep, "connect.target", preflight.OK, nil)
		expect(t, rep, "version.order", preflight.OK, nil) // both servers run the same image
		expect(t, rep, "target.subscription_privilege", preflight.OK, []string{"superuser"})
		expect(t, rep, "target.max_logical_replication_workers", preflight.OK, []string{"needs 3"})
		expect(t, rep, "target.logging", preflight.OK, nil)

		expect(t, rep, "target.empty.app", preflight.Blocker, []string{"legacy_leftover"}, "empty database", "never deletes")
		expect(t, rep, "target.empty.latin_db", preflight.OK, []string{"is empty"})

		expect(t, rep, "locale.app", preflight.OK, nil)
		expect(t, rep, "locale.latin_db", preflight.Blocker, []string{"encoding UTF8 vs LATIN1"}, "CREATE DATABASE", "template0")
		expect(t, rep, "locale.coll_db", preflight.Warn, []string{"C vs C.UTF-8"}, "CREATE DATABASE")

		expect(t, rep, "roles.owners", preflight.Warn, []string{testutil.FixtureOwnerRole}, `CREATE ROLE "app_owner"`)
		expect(t, rep, "extensions.available", preflight.OK, nil)

		expect(t, rep, "network.target_to_source", preflight.Warn,
			[]string{"cannot be verified read-only", "TARGET server can reach"}, "sslmode=verify-full", "From the TARGET host")
		expect(t, rep, "data.sizes", preflight.Info, []string{"1.5 x", "Free disk space cannot be read over SQL"}, "df -h")

		if rep.ExitCode() != 3 || rep.Summary.Blocker < 2 {
			t.Errorf("exit %d, summary %+v", rep.ExitCode(), rep.Summary)
		}
		for _, f := range rep.Findings {
			if f.Severity.Rank() >= preflight.Warn.Rank() && strings.TrimSpace(f.Remediation) == "" {
				t.Errorf("%s has no remediation", f.ID)
			}
		}
	})

	t.Run("a slot above the blocking threshold is a blocker", func(t *testing.T) {
		yaml := configYAML("alerts:\n  rules:\n    pg.slot.retained_wal_bytes:\n      warning: 1MiB\n      critical: 2MiB\n", s, g)
		r, err := newService(t, yaml, envOf(s, g), nil).PreflightPG(ctx, "src", "tgt", migrationDBs)
		if err != nil {
			t.Fatal(err)
		}
		expect(t, r, "source.slot."+testutil.FixtureSlot, preflight.Blocker, []string{"above the 2.0 MiB blocking threshold"})
	})

	t.Run("extensions that the target cannot provide", func(t *testing.T) {
		// Mimic a target that lacks pg_trgm and ships another hstore version by
		// editing the container's extension directory; the view reads it live.
		var dir string
		if err := tgt.Admin(t).QueryRow(ctx, `SELECT setting FROM pg_config WHERE name = 'SHAREDIR'`).Scan(&dir); err != nil {
			t.Fatal(err)
		}
		tgt.Exec(t, "rm", dir+"/extension/pg_trgm.control")
		tgt.Exec(t, "sed", "-i", "s/^default_version.*/default_version = '0.9'/", dir+"/extension/hstore.control")

		r, err := svc.PreflightPG(ctx, "src", "tgt", migrationDBs)
		if err != nil {
			t.Fatal(err)
		}
		expect(t, r, "extensions.pg_trgm", preflight.Blocker, []string{"not available on the target", "app"}, "package")
		expect(t, r, "extensions.hstore", preflight.Warn, []string{"0.9"}, "ALTER EXTENSION")
	})

	t.Run("least-privilege roles are told what they lack", func(t *testing.T) {
		mustExec(t, src.Admin(t), "CREATE ROLE lk_mon LOGIN PASSWORD 'mon-pw' ; GRANT pg_monitor TO lk_mon")
		mustExec(t, src.Admin(t), "CREATE ROLE lk_plain LOGIN PASSWORD 'plain-pw'")
		mustExec(t, tgt.Admin(t), "CREATE ROLE lk_t LOGIN PASSWORD 't-pw'")
		mon := entry{name: "src-mon", p: src, user: "lk_mon", password: "mon-pw"}
		plain := entry{name: "src-plain", p: src, user: "lk_plain", password: "plain-pw"}
		lt := entry{name: "tgt-plain", p: tgt, user: "lk_t", password: "t-pw"}
		all := []entry{s, g, mon, plain, lt}
		sv := newService(t, configYAML("", all...), envOf(all...), nil)

		r, err := sv.PreflightPG(ctx, "src-mon", "tgt-plain", migrationDBs)
		if err != nil {
			t.Fatal(err)
		}
		expect(t, r, "source.replication_privilege", preflight.Blocker, []string{"lk_mon"}, `ALTER ROLE "lk_mon" REPLICATION`)
		expect(t, r, "source.read_privilege", preflight.Blocker, []string{"cannot read", "app: public."}, "pg_read_all_data")
		expect(t, r, "target.subscription_privilege", preflight.Blocker, []string{"lk_t"}, "GRANT")
		// pg_monitor sees every session, so the DDL probe is counted exactly.
		expect(t, r, "source.ddl_activity", preflight.Info, []string{"1 session"})

		r, err = sv.PreflightPG(ctx, "src-plain", "tgt", migrationDBs)
		if err != nil {
			t.Fatal(err)
		}
		// Without pg_monitor the other sessions are invisible: say so.
		expect(t, r, "source.ddl_activity", preflight.Info, []string{"lower bound", "pg_monitor"})
	})

	t.Run("nothing changes on either server and every session is read-only", func(t *testing.T) {
		beforeSrc, beforeTgt := catalogSnapshot(t, src), catalogSnapshot(t, tgt)
		var sessions sessionLog
		sv := newService(t, configYAML(lowSlotThresholds, s, g), envOf(s, g), sessions.deps)

		if _, err := sv.PreflightPG(ctx, "src", "tgt", service.DiscoveryOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := sv.Inventory(ctx, "src", service.DiscoveryOptions{}); err != nil {
			t.Fatal(err)
		}

		if d := firstDifference(beforeSrc, catalogSnapshot(t, src)); d != "" {
			t.Errorf("the source changed:\n%s", d)
		}
		if d := firstDifference(beforeTgt, catalogSnapshot(t, tgt)); d != "" {
			t.Errorf("the target changed:\n%s", d)
		}

		all := sessions.all()
		if len(all) < 8 { // a primary and one per database, on both servers, plus the inventory
			t.Errorf("expected many sessions, saw %d", len(all))
		}
		for _, si := range all {
			if si.defaultReadOnly != "on" {
				t.Errorf("session to %q has default_transaction_read_only=%q", si.database, si.defaultReadOnly)
			}
			if si.temporaryTableError == nil || !strings.Contains(si.temporaryTableError.Error(), "read-only transaction") {
				t.Errorf("session to %q accepted a write: %v", si.database, si.temporaryTableError)
			}
		}
		// No session of ours is left behind.
		for name, p := range map[string]*testutil.PG{"source": src, "target": tgt} {
			var n int
			if err := p.Admin(t).QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE application_name = 'lockkeeper'`).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 0 {
				t.Errorf("%d Lockkeeper session(s) still open on the %s", n, name)
			}
		}
	})
}

// TestNoPasswordOrRowDataInAnyOutput runs the real CLI with debug logging
// against containers holding row data, a DDL statement containing that data and
// a role whose password is a canary, then scans everything it printed.
func TestNoPasswordOrRowDataInAnyOutput(t *testing.T) {
	src, tgt := testutil.StartPair(t, testutil.PairOptions{})
	testutil.SeedMigrationSource(t, src)
	testutil.SeedMigrationTarget(t, tgt)
	openDDLProbe(t, src)

	const canaryPW = "CANARY_PW_8e2a41c7d9"
	for _, p := range []*testutil.PG{src, tgt} {
		mustExec(t, p.Admin(t), "CREATE ROLE lk_can LOGIN SUPERUSER PASSWORD '"+canaryPW+"'")
	}
	s := entry{name: "src", p: src, user: "lk_can", password: canaryPW}
	g := entry{name: "tgt", p: tgt, user: "lk_can", password: canaryPW}
	cfgPath := writeConfig(t, configYAML("", s, g))
	env := envOf(s, g)

	var all bytes.Buffer
	run := func(args ...string) (string, int) {
		var out, errb bytes.Buffer
		code := cli.Execute(context.Background(), cli.Env{
			Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb,
			Getenv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		}, append([]string{"-c", cfgPath, "--log-level", "debug"}, args...))
		all.WriteString(out.String())
		all.WriteString(errb.String())
		return out.String(), code
	}

	out, code := run("preflight", "pg", "--source", "src", "--target", "tgt", "--databases", "app,latin_db,coll_db")
	if code != 3 || !strings.Contains(out, "BLOCKER") || !strings.Contains(out, "public.events") {
		t.Fatalf("text report: exit %d\n%s", code, out)
	}
	jsonOut, code := run("preflight", "pg", "--source", "src", "--target", "tgt", "--json")
	var rep preflight.Report
	if err := json.Unmarshal([]byte(jsonOut), &rep); err != nil || code != 3 {
		t.Fatalf("json report: exit %d, %v\n%s", code, err, jsonOut)
	}
	invOut, code := run("inventory", "--source", "src", "--json")
	if code != 0 || !strings.Contains(invOut, `"tables_without_pk"`) {
		t.Fatalf("inventory: exit %d\n%s", code, invOut)
	}
	if _, code := run("inventory", "--source", "src"); code != 0 {
		t.Fatalf("inventory text: exit %d", code)
	}
	// A failing connection must not echo the password either.
	bad := writeConfig(t, configYAML("", entry{name: "src", p: src, user: "lk_can", password: canaryPW}, entry{name: "tgt", p: tgt, user: "lk_can", password: canaryPW}))
	env[s.envVar()] = canaryPW + "-wrong"
	run2 := cli.Execute(context.Background(), cli.Env{
		Stdin: strings.NewReader(""), Stdout: &all, Stderr: &all,
		Getenv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
	}, []string{"-c", bad, "--log-level", "debug", "preflight", "pg", "--source", "src", "--target", "tgt"})
	if run2 != 3 {
		t.Errorf("a wrong password must be a blocker (exit 3), got %d", run2)
	}

	output := all.String()
	for what, canary := range map[string]string{
		"the password":                 canaryPW,
		"the wrong password":           canaryPW + "-wrong",
		"row data":                     testutil.RowCanary,
		"the container admin password": src.Password,
		"the target admin password":    tgt.Password,
	} {
		if strings.Contains(output, canary) {
			t.Errorf("%s leaked into the output", what)
		}
	}
	if !strings.Contains(output, "DEBUG") {
		t.Error("the scan is only meaningful with debug logs enabled")
	}
}

// TestRDSMimic imitates RDS only by role names and a setting name: a container
// whose wal_level is replica, which has an rds.logical_replication setting and
// the rds_superuser / rds_replication roles. It cannot reproduce RDS's managed
// behaviour (reboot-required parameters, parameter groups, the real roles).
func TestRDSMimic(t *testing.T) {
	src, tgt := testutil.StartPair(t, testutil.PairOptions{
		SourceArgs: []string{"wal_level=replica", "rds.logical_replication=off"},
	})
	ctx := context.Background()
	admin := src.Admin(t)
	for _, q := range []string{
		"CREATE ROLE rds_superuser", "CREATE ROLE rds_replication",
		"CREATE ROLE lk_rds LOGIN PASSWORD 'rds-pw'", "GRANT rds_superuser TO lk_rds",
	} {
		mustExec(t, admin, q)
	}
	s := entry{name: "src", p: src, user: "lk_rds", password: "rds-pw"}
	g := superuser("tgt", tgt)
	svc := newService(t, configYAML("", s, g), envOf(s, g), nil)

	rep, err := svc.PreflightPG(ctx, "src", "tgt", service.DiscoveryOptions{Databases: []string{"postgres"}})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep, "source.wal_level", preflight.Blocker, []string{`"replica"`},
		"Amazon RDS", "rds.logical_replication = 1", "STATIC", "reboot", "ApplyMethod=pending-reboot")
	expect(t, rep, "source.rds", preflight.Info, []string{"Amazon RDS", "a member of rds_superuser"}, "rds_replication")
	expect(t, rep, "source.replication_privilege", preflight.Blocker, nil, `GRANT rds_replication TO "lk_rds"`)

	mustExec(t, admin, "GRANT rds_replication TO lk_rds")
	rep, err = svc.PreflightPG(ctx, "src", "tgt", service.DiscoveryOptions{Databases: []string{"postgres"}})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep, "source.replication_privilege", preflight.OK, []string{"rds_replication"})
}
