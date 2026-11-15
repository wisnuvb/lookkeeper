//go:build integration

package pgnative_test

// Spike findings about the migration role (ADR 0004 item 7): what the target
// server stores and logs about the subscription password, and what privileges
// the role used by the target server needs on the source.

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/testutil"
)

// TestSpikeMigrationRoleNeedsOnlyReplication proves that the role named in the
// subscription's connection string needs LOGIN and REPLICATION and nothing
// else on the source: no SELECT on the tables, no superuser, no ownership.
func TestSpikeMigrationRoleNeedsOnlyReplication(t *testing.T) {
	e := newSpikeEnv(t)
	ctx := context.Background()
	srcApp := e.src.AdminDB(t, "app")
	mustExecT(t, e.src.Admin(t), `CREATE ROLE lk_mig LOGIN REPLICATION PASSWORD 'mig-pw-not-a-real-secret'`)
	mustExecT(t, srcApp, `CREATE PUBLICATION lk_spike FOR TABLE accounts, ledger, events`)

	h, err := createSlotWithSnapshot(ctx, e.replDSN(), spikeSlot)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	mustExecT(t, srcApp, `INSERT INTO events (payload) VALUES ('after-slot-before-copy')`)
	if out, err := e.runCopy(t, "pgdump", h.SnapshotID); err != nil {
		t.Fatalf("copy: %v\n%s", err, out)
	}
	h.Close()

	tgtApp := e.tgt.AdminDB(t, "app")
	mustExecT(t, tgtApp, `CREATE SUBSCRIPTION lk_spike_sub CONNECTION 'host=src port=5432 dbname=app user=lk_mig password=mig-pw-not-a-real-secret sslmode=disable' PUBLICATION lk_spike WITH (create_slot = false, slot_name = 'lk_spike', copy_data = false, enabled = false)`)
	mustExecT(t, tgtApp, `ALTER SUBSCRIPTION lk_spike_sub ENABLE`)
	mustExecT(t, srcApp, `INSERT INTO events (payload) VALUES ('streamed-after-enable')`)
	mustExecT(t, srcApp, `UPDATE accounts SET balance = balance + 1000 WHERE id = 7`)
	waitCaughtUp(t, srcApp, spikeSlot, 60*time.Second)
	assertIdentical(t, srcApp, tgtApp)
}

// TestSpikeSubscriptionPasswordVisibility documents where the source password
// lives once CREATE SUBSCRIPTION ran on the target, and shows which session
// settings keep it out of the server log.
func TestSpikeSubscriptionPasswordVisibility(t *testing.T) {
	tgt := testutil.StartPGWith(t, testutil.PGOptions{ServerArgs: []string{
		"log_statement=all",
		"log_min_duration_statement=0",
		"shared_preload_libraries=pg_stat_statements",
	}})
	ctx := context.Background()
	admin := tgt.Admin(t)
	mustExecT(t, admin, `CREATE EXTENSION pg_stat_statements`)
	mustExecT(t, admin, `CREATE ROLE plain_user LOGIN PASSWORD 'plain-user-pw'`)

	const unmitigated = "CANARY_UNMITIGATED_7c1e"
	const mitigated = "CANARY_MITIGATED_91ab"
	const mitigatedFail = "CANARY_MITIGATED_FAILING_5d02"

	create := func(name, pw string) string {
		return fmt.Sprintf(`CREATE SUBSCRIPTION %s CONNECTION 'host=src.invalid port=5432 dbname=app user=lk_mig password=%s' PUBLICATION p WITH (connect = false)`, name, pw)
	}

	// Without mitigation the statement text, password included, is logged.
	mustExecT(t, admin, create("s_unmitigated", unmitigated))

	// With the session settings the code applies (superuser only), it is not.
	conn := tgt.Admin(t)
	for _, q := range []string{
		`SET log_statement = 'none'`,
		`SET log_min_duration_statement = -1`,
		`SET log_min_error_statement = 'panic'`,
	} {
		mustExecT(t, conn, q)
	}
	mustExecT(t, conn, create("s_mitigated", mitigated))
	if _, err := conn.Exec(ctx, create("s_mitigated", mitigatedFail)); err == nil { // duplicate name: an error
		t.Fatal("expected the duplicate subscription to fail")
	}
	time.Sleep(500 * time.Millisecond)

	logs, err := exec.Command("docker", "logs", tgt.ContainerID()).CombinedOutput()
	if err != nil {
		t.Fatalf("docker logs: %v", err)
	}
	text := string(logs)
	if !strings.Contains(text, unmitigated) {
		t.Errorf("positive control failed: log_statement=all should have logged the unmitigated statement")
	}
	if strings.Contains(text, mitigated) {
		t.Errorf("the mitigated CREATE SUBSCRIPTION leaked its password into the server log")
	}
	if strings.Contains(text, mitigatedFail) {
		t.Errorf("the failing CREATE SUBSCRIPTION leaked its password into the server log (log_min_error_statement)")
	}

	// pg_stat_statements: utility statements are stored with their text.
	var leaked int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_stat_statements WHERE query LIKE '%' || $1 || '%'`, mitigated).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	t.Logf("pg_stat_statements entries containing the mitigated password: %d", leaked)
	if leaked == 0 {
		t.Log("pg_stat_statements did not retain the CREATE SUBSCRIPTION text")
	} else {
		t.Log("RESIDUAL RISK: pg_stat_statements keeps the CREATE SUBSCRIPTION text (visible to superusers and pg_read_all_stats); the pre-flight/plan must warn when the extension is loaded on the target")
	}

	// The catalog: only superusers can read the connection string.
	var conninfo string
	if err := admin.QueryRow(ctx, `SELECT subconninfo FROM pg_subscription WHERE subname = 's_mitigated'`).Scan(&conninfo); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conninfo, mitigated) {
		t.Errorf("a superuser should see the password in pg_subscription.subconninfo, got %q", conninfo)
	}
	plain := testutil.PG{Host: tgt.Host, Port: tgt.Port, User: "plain_user", Password: "plain-user-pw", Database: "postgres"}
	pc := plain.Admin(t)
	if _, err := pc.Exec(ctx, `SELECT subconninfo FROM pg_subscription`); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("a normal role must not be able to read subconninfo, got err=%v", err)
	}
	// ...and a normal role does see the rest of the row, never the password.
	var names int
	if err := pc.QueryRow(ctx, `SELECT count(*) FROM pg_subscription`).Scan(&names); err != nil {
		t.Errorf("a normal role can read the non-secret columns: %v", err)
	}
}
