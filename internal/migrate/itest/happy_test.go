//go:build integration

package itest

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestHappyPathToCaughtUpUnderConcurrentWrites runs the whole Phase 3 flow with
// the real CLI: plan, dry run, refusals, apply, start under continuous writes
// (insert, update, delete, rollback, including on a table without a primary
// key), caught up, then row-level equality of every table.
func TestHappyPathToCaughtUpUnderConcurrentWrites(t *testing.T) {
	for _, kind := range copierKinds() {
		t.Run(kind, func(t *testing.T) {
			r := newRig(t, kind, rigOptions{})
			before := r.sourceFingerprint()

			// plan: changes nothing on either server.
			hash, id := r.plan()
			if after := r.sourceFingerprint(); after != before {
				t.Fatalf("`migrate plan` changed the source:\nbefore:\n%s\nafter:\n%s", before, after)
			}
			if again, id2 := r.plan(); again != hash || id2 != id {
				t.Fatalf("planning the same thing twice must give the same plan: %s/%s vs %s/%s", hash, id, again, id2)
			}
			if got := r.state(id); got != "preflight_ok" {
				t.Fatalf("state after plan = %s", got)
			}

			// dry run is the default and changes nothing.
			o := r.run("migrate", "apply-source-changes", "--plan-hash", hash)
			if o.code != 0 || !strings.Contains(o.stdout, "DRY RUN") || !strings.Contains(o.stdout, "CREATE PUBLICATION") ||
				!strings.Contains(o.stdout, "REPLICA IDENTITY FULL") || !strings.Contains(o.stdout, "PASSWORD ***") {
				t.Fatalf("dry run (%d):\n%s", o.code, o.all())
			}
			if after := r.sourceFingerprint(); after != before {
				t.Fatal("the dry run changed the source")
			}

			// refusals: no confirmation, wrong hash.
			r.stdin = ""
			if o := r.run("migrate", "apply-source-changes", "--migration", id, "--apply"); o.code == 0 {
				t.Fatalf("--apply without --plan-hash and without typing must be refused:\n%s", o.all())
			}
			wrong := strings.Repeat("0", 64)
			if o := r.run("migrate", "apply-source-changes", "--plan-hash", wrong, "--apply"); o.code == 0 {
				t.Fatalf("a plan hash that matches no plan must be refused:\n%s", o.all())
			}
			if after := r.sourceFingerprint(); after != before {
				t.Fatal("a refused apply changed the source")
			}

			// apply with the exact hash.
			if o := r.apply(hash); o.code != 0 {
				t.Fatalf("apply failed (%d):\n%s", o.code, o.all())
			}
			if got := r.state(id); got != "source_changes_approved" {
				t.Fatalf("state after apply = %s", got)
			}
			app := r.src.AdminDB(t, "app")
			var ident, pubs, roles int
			_ = app.QueryRow(context.Background(), `SELECT count(*) FROM pg_class WHERE relname = 'events' AND relreplident = 'f'`).Scan(&ident)
			_ = app.QueryRow(context.Background(), `SELECT count(*) FROM pg_publication WHERE pubname LIKE 'lk\_%'`).Scan(&pubs)
			_ = r.src.Admin(t).QueryRow(context.Background(), `SELECT count(*) FROM pg_roles WHERE rolname LIKE 'lk\_%' AND rolreplication`).Scan(&roles)
			if ident != 1 || pubs != 1 || roles != 1 {
				t.Fatalf("expected REPLICA IDENTITY FULL on events, one publication and one replication role: %d %d %d", ident, pubs, roles)
			}
			if o := r.apply(hash); o.code == 0 {
				t.Fatalf("applying twice must be refused (already applied):\n%s", o.all())
			}

			// start under concurrent writes.
			w := startWriters(t, r)
			time.Sleep(500 * time.Millisecond)
			o = r.run(r.startArgs(id)...)
			if o.code != 0 {
				t.Fatalf("start failed (%d):\n%s", o.code, o.all())
			}
			if got := r.state(id); got != "caught_up" {
				t.Fatalf("state after start = %s\n%s", got, o.all())
			}
			time.Sleep(time.Second) // more writes after caught_up
			w.Stop()
			t.Logf("writers committed %d transactions", w.Committed())
			if w.Committed() < 300 {
				t.Errorf("only %d transactions: the test did not exercise concurrency", w.Committed())
			}
			waitDrained(t, r.src, 90*time.Second)
			assertSameRows(t, r.src, r.tgt)

			// The target does not keep the source's publication.
			var tpubs int
			_ = r.tgt.AdminDB(t, "app").QueryRow(context.Background(), `SELECT count(*) FROM pg_publication`).Scan(&tpubs)
			if tpubs != 0 {
				t.Errorf("the target holds %d publication(s) copied from the source", tpubs)
			}

			// status shows the state, retained WAL and the guardrail, read-only.
			fp := r.sourceFingerprint()
			st := r.run("migrate", "status", "--migration", id, "--allow-untested-pgcopydb")
			if st.code != 0 || !strings.Contains(st.stdout, "caught_up") || !strings.Contains(st.stdout, "RETAINED WAL") || !strings.Contains(st.stdout, "GUARDRAIL") {
				t.Fatalf("status (%d):\n%s", st.code, st.all())
			}
			if r.sourceFingerprint() != fp {
				t.Fatal("status changed the source")
			}
			if o := r.run(r.startArgs(id)...); o.code != 0 {
				t.Fatalf("start on a caught-up migration is a no-op, got %d:\n%s", o.code, o.all())
			}
		})
	}
}
