//go:build integration

package itest

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const rowCanary = "CANARY_DATA_ROW_c0ffee42"

// TestRowDataNeverReachesPersistedErrors makes the copy fail on a constraint
// violation whose message quotes a row containing a canary value (the tools print
// "DETAIL: Failing row contains (...)" and "CONTEXT: COPY t, line 1: ..."), and
// asserts that the canary appears in no row of audit_events, steps, migrations,
// actions or checkpoints, nowhere in the state files, and not on the terminal.
// The tool's raw log does hold it (positive control); cleanup deletes that log.
func TestRowDataNeverReachesPersistedErrors(t *testing.T) {
	for _, kind := range []string{"pgcopydb", "pgdump"} {
		t.Run(kind, func(t *testing.T) {
			r := newRig(t, kind, rigOptions{})
			mustExec(t, r.src.AdminDB(t, "app"), `CREATE TABLE secrets (id int PRIMARY KEY, note text)`)
			mustExec(t, r.src.AdminDB(t, "app"), `INSERT INTO secrets VALUES (1, '`+rowCanary+`')`)
			hash, id := r.plan()

			// A trap on the target: every table named secrets gets a CHECK that the row violates.
			tgt := r.tgt.AdminDB(t, "app")
			mustExec(t, tgt, `CREATE FUNCTION lk_trap() RETURNS event_trigger LANGUAGE plpgsql AS $$
				DECLARE r record;
				BEGIN
				  FOR r IN SELECT * FROM pg_event_trigger_ddl_commands() WHERE command_tag = 'CREATE TABLE' LOOP
				    IF r.object_identity = 'public.secrets' THEN
				      EXECUTE format('ALTER TABLE %s ADD CONSTRAINT lk_trap CHECK (note NOT LIKE ''CANARY%%'')', r.object_identity);
				    END IF;
				  END LOOP;
				END $$`)
			mustExec(t, tgt, `CREATE EVENT TRIGGER lk_trap ON ddl_command_end WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION lk_trap()`)

			if o := r.apply(hash); o.code != 0 {
				t.Fatalf("apply: %s", o.all())
			}
			o := r.run(r.startArgs(id, "--no-wait")...)
			if o.code == 0 {
				t.Fatalf("the copy was expected to fail:\n%s", o.all())
			}
			if !strings.Contains(o.all(), "output is in") {
				t.Fatalf("the error must point at the log:\n%s", o.all())
			}
			if strings.Contains(o.all(), rowCanary) {
				t.Fatalf("row data reached the terminal:\n%s", o.all())
			}
			for _, out := range r.outputs() {
				if strings.Contains(out, rowCanary) {
					t.Fatal("row data reached a command's output")
				}
			}

			root := filepath.Dir(r.stateDB)
			logs, _ := filepath.Glob(filepath.Join(root, "migrations", id, "logs", "*.log"))
			found := false
			for _, l := range logs {
				if b, _ := os.ReadFile(l); strings.Contains(string(b), rowCanary) {
					found = true
				}
			}
			if !found {
				t.Fatal("positive control failed: the tool's raw log should hold the failing row, otherwise this test proves nothing")
			}

			// Every persisted table, row by row.
			db, err := sql.Open("sqlite", "file:"+r.stateDB+"?mode=ro")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			for table, q := range map[string]string{
				"audit_events": `SELECT coalesce(group_concat(kind || '|' || actor || '|' || action_id || '|' || detail, char(10)), '') FROM audit_events`,
				"steps":        `SELECT coalesce(group_concat(name || '|' || detail || '|' || error, char(10)), '') FROM steps`,
				"migrations":   `SELECT coalesce(group_concat(failed_step || '|' || failed_reason || '|' || plan_json || '|' || input_json, char(10)), '') FROM migrations`,
				"actions":      `SELECT coalesce(group_concat(sql_text || '|' || error, char(10)), '') FROM actions`,
				"checkpoints":  `SELECT coalesce(group_concat(key || '|' || value, char(10)), '') FROM checkpoints`,
			} {
				var text string
				if err := db.QueryRow(q).Scan(&text); err != nil {
					t.Fatalf("%s: %v", table, err)
				}
				if strings.Contains(text, rowCanary) {
					t.Errorf("row data found in the %s table", table)
				}
				if table == "steps" && !strings.Contains(text, "failed") && !strings.Contains(text, "exit status") {
					t.Errorf("the failed step should be recorded (without the data): %q", text)
				}
			}
			entries, _ := filepath.Glob(filepath.Join(root, "lockkeeper.db*"))
			for _, f := range entries {
				if b, _ := os.ReadFile(f); strings.Contains(string(b), rowCanary) {
					t.Errorf("row data found in %s", filepath.Base(f))
				}
			}

			// abort + cleanup remove the raw logs and work directories.
			dry := r.run("migrate", "abort", "--migration", id, "--allow-untested-pgcopydb")
			ah := hashInOutput.FindStringSubmatch(dry.stdout)
			if ah == nil {
				t.Fatalf("abort dry run: %s", dry.all())
			}
			if o := r.run("migrate", "abort", "--migration", id, "--apply", "--plan-hash", ah[1], "--allow-untested-pgcopydb"); o.code != 0 {
				t.Fatalf("abort: %s", o.all())
			}
			cdry := r.run("migrate", "cleanup", "--migration", id, "--allow-untested-pgcopydb")
			ch := hashInOutput.FindStringSubmatch(cdry.stdout)
			if ch == nil || !strings.Contains(cdry.stdout, "can contain table rows") {
				t.Fatalf("the cleanup plan must say that the tool logs can hold rows:\n%s", cdry.all())
			}
			if o := r.run("migrate", "cleanup", "--migration", id, "--apply", "--plan-hash", ch[1], "--allow-untested-pgcopydb"); o.code != 0 {
				t.Fatalf("cleanup: %s", o.all())
			}
			for _, d := range []string{"logs", "work"} {
				if _, err := os.Stat(filepath.Join(root, "migrations", id, d)); !os.IsNotExist(err) {
					t.Errorf("cleanup must delete the tools' %s directory", d)
				}
			}
		})
	}
}
