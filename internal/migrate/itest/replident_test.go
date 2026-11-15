//go:build integration

package itest

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestReplicaIdentityFullForATableWithoutPrimaryKey checks the whole story for a
// table that cannot identify its rows: the plan lists the confirmed ALTER TABLE,
// nothing changes before it is applied, and afterwards updates and deletes on that
// table replicate (they would be refused by the source without it).
func TestReplicaIdentityFullForATableWithoutPrimaryKey(t *testing.T) {
	r := newRig(t, copierKinds()[0], rigOptions{})
	hash, id := r.plan()

	dry := r.run("migrate", "apply-source-changes", "--plan-hash", hash)
	if !strings.Contains(dry.stdout, `ALTER TABLE "public"."events" REPLICA IDENTITY FULL`) {
		t.Fatalf("the plan must list the REPLICA IDENTITY change with its exact SQL:\n%s", dry.stdout)
	}
	if strings.Contains(dry.stdout, `ALTER TABLE "public"."accounts"`) || strings.Contains(dry.stdout, `ALTER TABLE "public"."invoices"`) {
		t.Fatalf("tables with a primary key must be left alone:\n%s", dry.stdout)
	}
	app := r.src.AdminDB(t, "app")
	if n := count(t, r, "app", `SELECT count(*) FROM pg_class WHERE relname = 'events' AND relreplident = 'f'`); n != 0 {
		t.Fatal("nothing may change before the plan is applied")
	}

	if o := r.apply(hash); o.code != 0 {
		t.Fatalf("apply: %s", o.all())
	}
	if o := r.run(r.startArgs(id)...); o.code != 0 {
		t.Fatalf("start: %s", o.all())
	}
	// Updates and deletes on the table without a primary key, after catch-up.
	mustExec(t, app, `UPDATE events SET n = n + 5 WHERE payload IN ('seed-1', 'seed-2', 'seed-3')`)
	mustExec(t, app, `DELETE FROM events WHERE payload IN ('seed-10', 'seed-11')`)
	mustExec(t, app, `INSERT INTO events (payload, n) VALUES ('seed-1', 99)`) // a duplicate payload: no key to tell them apart
	mustExec(t, app, `UPDATE events SET n = 7 WHERE payload = 'seed-1' AND n = 99`)
	waitDrained(t, r.src, time.Minute)
	assertSameRows(t, r.src, r.tgt)

	tgt := r.tgt.AdminDB(t, "app")
	var n, rows int
	if err := tgt.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE payload = 'seed-10' OR payload = 'seed-11'), count(*) FILTER (WHERE payload = 'seed-1') FROM events`).Scan(&n, &rows); err != nil {
		t.Fatal(err)
	}
	if n != 0 || rows != 2 {
		t.Fatalf("the target must reflect the deletes and the duplicate row: deleted rows left=%d, seed-1 rows=%d", n, rows)
	}
}
