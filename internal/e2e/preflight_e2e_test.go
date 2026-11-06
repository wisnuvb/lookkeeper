//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/inventory"
	"github.com/wisnuvb/lockkeeper/internal/preflight"
	"github.com/wisnuvb/lockkeeper/internal/testutil"
)

const preflightPassword = "CANARY-pf-password-3d8f12"

// TestPreflightBinaryAgainstRealPostgres runs the real binary's inventory and
// pre-flight commands against a source and a target container and checks, from
// the outside, exit codes, output shape and that neither the password nor row
// data shows up in the output or in the process list.
func TestPreflightBinaryAgainstRealPostgres(t *testing.T) {
	bin := buildBinary(t)
	src, tgt := testutil.StartPair(t, testutil.PairOptions{})
	testutil.SeedMigrationSource(t, src)
	testutil.SeedMigrationTarget(t, tgt)
	ctx := context.Background()

	for _, p := range []*testutil.PG{src, tgt} {
		if _, err := p.Admin(t).Exec(ctx, "CREATE ROLE lk_pf LOGIN SUPERUSER PASSWORD '"+preflightPassword+"'"); err != nil {
			t.Fatal(err)
		}
	}
	// A DDL statement in an open transaction whose text holds the row-data canary.
	probe := src.AdminDB(t, testutil.FixtureAppDB)
	if _, err := probe.Exec(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, "CREATE TABLE ddl_probe (note text DEFAULT '"+testutil.RowCanary+"')"); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "lockkeeper.yaml")
	cfg := fmt.Sprintf(`
version: 1
databases:
  old:
    engine: postgres
    host: %s
    port: %d
    database: postgres
    user: lk_pf
    password: { env: LK_PF_PASSWORD }
    tls: { mode: disable }
  new:
    engine: postgres
    host: %s
    port: %d
    database: postgres
    user: lk_pf
    password: { env: LK_PF_PASSWORD }
    tls: { mode: disable }
store:
  path: %s
`, src.Host, src.Port, tgt.Host, tgt.Port, filepath.Join(dir, "state.db"))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "LK_PF_PASSWORD="+preflightPassword, "PGPASSWORD=ambient-must-be-ignored")

	var all strings.Builder
	var psSnapshots []byte
	runCLI := func(args ...string) (stdout string, code int) {
		cmd := exec.Command(bin, append([]string{"-c", cfgPath, "--log-level", "debug"}, args...)...)
		cmd.Env = env
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		// Look at the process list while it runs.
		var err error
		finished := false
		for i := 0; i < 3 && !finished; i++ {
			if ps, perr := exec.Command("ps", "-axo", "args").Output(); perr == nil {
				psSnapshots = append(psSnapshots, ps...)
			}
			select {
			case err = <-done:
				finished = true
			case <-time.After(150 * time.Millisecond):
			}
		}
		if !finished {
			err = <-done
		}
		code = 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("run %v: %v", args, err)
		}
		all.WriteString(out.String() + errb.String())
		return out.String(), code
	}

	out, code := runCLI("preflight", "pg", "--source", "old", "--target", "new", "--databases", "app,latin_db,coll_db")
	if code != 3 {
		t.Fatalf("preflight text: want exit 3 (blockers), got %d\n%s", code, out)
	}
	for _, want := range []string{"BLOCKER (", "WARN (", "[target.empty.app]", "[locale.latin_db]", "[source.slot.lk_old_slot]", "[network.target_to_source]", "Read-only", "NOT READY"} {
		if !strings.Contains(out, want) {
			t.Errorf("text report lacks %q", want)
		}
	}

	jsonOut, code := runCLI("preflight", "pg", "--source", "old", "--target", "new", "--json", "--databases", "app")
	var rep preflight.Report
	if err := json.Unmarshal([]byte(jsonOut), &rep); err != nil {
		t.Fatalf("--json: %v\n%s", err, jsonOut)
	}
	if code != 3 || rep.SchemaVersion != 1 || rep.Source != "old" || rep.Target != "new" || len(rep.Databases) != 1 {
		t.Errorf("json report: exit %d, %+v", code, rep.Summary)
	}

	invOut, code := runCLI("inventory", "--source", "old", "--json", "--databases", "app")
	var inv struct {
		Source string `json:"source"`
		inventory.Server
	}
	if err := json.Unmarshal([]byte(invOut), &inv); err != nil || code != 0 {
		t.Fatalf("inventory --json: exit %d, %v\n%s", code, err, invOut)
	}
	if inv.Source != "old" || len(inv.Databases) != 1 || inv.Databases[0].TablesWithoutPK.Total != 2 || inv.Databases[0].LargeObjects != 1 {
		t.Errorf("inventory content: %+v", inv.Databases)
	}

	if out, code := runCLI("preflight", "pg", "--source", "old", "--target", "old"); code != 1 {
		t.Errorf("--source equal to --target must exit 1, got %d\n%s", code, out)
	}
	if _, code := runCLI("inventory", "--source", "old", "--databases", "no_such_db"); code != 1 {
		t.Errorf("an unknown database must exit 1, got %d", code)
	}

	scan := all.String() + string(psSnapshots)
	for what, canary := range map[string]string{
		"the password":         preflightPassword,
		"row data":             testutil.RowCanary,
		"the source admin pw":  src.Password,
		"the target admin pw":  tgt.Password,
		"the ambient password": "ambient-must-be-ignored",
	} {
		if strings.Contains(scan, canary) {
			t.Errorf("%s leaked into output, logs or the process list", what)
		}
	}
	if len(psSnapshots) == 0 {
		t.Error("the process list was never sampled")
	}
}
