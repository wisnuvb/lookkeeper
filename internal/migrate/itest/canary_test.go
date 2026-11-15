//go:build integration

package itest

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/wisnuvb/lockkeeper/internal/testutil"
)

// TestNoSecretLeaksAnywhere runs a full migration (plan, apply, start, abort,
// cleanup) with statement logging switched on at BOTH servers, and then looks for
// the three passwords (the source's, the target's and the generated migration
// role's) everywhere Lockkeeper, its tools or the servers could have written
// them: the process list while tools run, stdout and stderr of every command, the
// plan JSON, the state database (and its WAL), the audit log, the tool log and
// work directories, the passfile directories, and both servers' logs.
//
// The migration password is in two allowed places only: the 0600 file in the 0700
// migration directory, and (necessarily) the target's pg_subscription catalog
// while the migration exists. The test documents what is visible there.
func TestNoSecretLeaksAnywhere(t *testing.T) {
	r := newRig(t, copierKinds()[0], rigOptions{
		sourceArgs: []string{"log_statement=all", "log_min_duration_statement=0"},
		targetArgs: []string{"log_statement=all", "log_min_duration_statement=0"},
	})

	// Sample the process list for the whole run.
	var mu sync.Mutex
	var psHits []string
	stopPS := make(chan struct{})
	psDone := make(chan struct{})
	secrets := func() []string { return []string{r.src.Password, r.tgt.Password} }
	go func() {
		defer close(psDone)
		for {
			select {
			case <-stopPS:
				return
			case <-time.After(60 * time.Millisecond):
			}
			out, err := exec.Command("ps", "-axww", "-o", "args=").Output()
			if err != nil {
				continue
			}
			for _, s := range append(secrets(), migrationPassword(r)) {
				if s != "" && strings.Contains(string(out), s) {
					mu.Lock()
					psHits = append(psHits, "a password is visible in the process list")
					mu.Unlock()
				}
			}
		}
	}()

	planOut := r.run(append(r.planArgs(), "--json")...)
	if planOut.code != 0 {
		t.Fatalf("plan --json: %s", planOut.all())
	}
	hash, id := r.plan()
	if o := r.apply(hash); o.code != 0 {
		t.Fatalf("apply: %s", o.all())
	}
	w := startWriters(t, r)
	if o := r.run(r.startArgs(id)...); o.code != 0 {
		t.Fatalf("start: %s", o.all())
	}
	w.Stop()
	waitDrained(t, r.src, 90*time.Second)
	assertSameRows(t, r.src, r.tgt)

	migPW := migrationPassword(r)
	if migPW == "" {
		t.Fatal("the generated migration password file was not found")
	}
	passFile := filepath.Join(filepath.Dir(r.stateDB), "migrations", id, "migration-role.secret")
	if fi, err := os.Stat(passFile); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the password file must be 0600: %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Dir(passFile)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the migration directory must be 0700: %v %v", fi, err)
	}
	if migPW == r.src.Password || migPW == r.tgt.Password {
		t.Fatal("the migration role must have its own password, never the source's or the target's")
	}

	// What is visible in the target's catalog while the migration exists.
	tgtApp := r.tgt.AdminDB(t, "app")
	var conninfo string
	if err := tgtApp.QueryRow(context.Background(), `SELECT subconninfo FROM pg_subscription`).Scan(&conninfo); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conninfo, "password="+migPW) || !strings.Contains(conninfo, "user='lk_"+id+"'") {
		t.Errorf("the subscription must use the per-migration role and its password: %q", conninfo)
	}
	if strings.Contains(conninfo, r.src.Password) || strings.Contains(conninfo, r.tgt.Password) {
		t.Error("the subscription connection string must never carry the source's or the target's own password")
	}
	mustExec(t, r.tgt.Admin(t), `CREATE ROLE plain_viewer LOGIN PASSWORD 'plain-viewer-pw'`)
	pv := testutilConn(t, r, "plain_viewer", "plain-viewer-pw")
	if _, err := pv.Exec(context.Background(), `SELECT subconninfo FROM pg_subscription`); err == nil {
		t.Error("a normal role must not be able to read pg_subscription.subconninfo")
	}

	// The source only ever got the SCRAM verifier of the migration password.
	var verifier string
	if err := r.src.Admin(t).QueryRow(context.Background(), `SELECT rolpassword FROM pg_authid WHERE rolname = $1`, "lk_"+id).Scan(&verifier); err != nil || !strings.HasPrefix(verifier, "SCRAM-SHA-256$") {
		t.Errorf("the role must hold a SCRAM verifier: %q %v", verifier, err)
	}

	// abort and cleanup, so those outputs are scanned too.
	dry := r.run("migrate", "abort", "--migration", id)
	ah := hashInOutput.FindStringSubmatch(dry.stdout)
	if ah == nil {
		t.Fatalf("abort dry run: %s", dry.all())
	}
	if o := r.run("migrate", "abort", "--migration", id, "--apply", "--plan-hash", ah[1]); o.code != 0 {
		t.Fatalf("abort: %s", o.all())
	}
	cdry := r.run("migrate", "cleanup", "--migration", id)
	ch := hashInOutput.FindStringSubmatch(cdry.stdout)
	if ch == nil {
		t.Fatalf("cleanup dry run: %s", cdry.all())
	}
	if o := r.run("migrate", "cleanup", "--migration", id, "--apply", "--plan-hash", ch[1]); o.code != 0 {
		t.Fatalf("cleanup: %s", o.all())
	}
	close(stopPS)
	<-psDone
	mu.Lock()
	if len(psHits) > 0 {
		t.Errorf("secrets were visible in `ps`: %d samples", len(psHits))
	}
	mu.Unlock()

	// After cleanup the migration password opens nothing: the role is gone.
	if c, err := pgx.Connect(context.Background(), "postgres://lk_"+id+":"+migPW+"@"+r.src.Host+":"+strconv.Itoa(r.src.Port)+"/postgres?sslmode=disable"); err == nil {
		_ = c.Close(context.Background())
		t.Error("the migration role must be gone after cleanup")
	}
	if _, err := os.Stat(passFile); !os.IsNotExist(err) {
		t.Error("cleanup must delete the generated password file")
	}

	// Everything Lockkeeper wrote.
	all := append(secrets(), migPW)
	scan := func(what, text string) {
		for i, s := range all {
			if strings.Contains(text, s) {
				t.Errorf("%s contains password #%d (%s)", what, i, []string{"source", "target", "migration"}[i])
			}
		}
	}
	for _, o := range r.outputs() {
		scan("CLI output", o)
	}
	scan("plan JSON", planOut.all())
	root := filepath.Dir(r.stateDB)
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		scan("file "+strings.TrimPrefix(p, root), string(b))
		return nil
	})
	if entries, _ := filepath.Glob(filepath.Join(root, "run", "run-*")); len(entries) > 0 {
		t.Errorf("per-run directories (with passfiles) were left behind: %v", entries)
	}
	// Both servers' logs, with statement logging on.
	for name, p := range map[string]*testutil.NetPG{"source": r.src, "target": r.tgt} {
		logs, err := exec.Command("docker", "logs", p.ContainerID()).CombinedOutput()
		if err != nil {
			t.Fatalf("docker logs: %v", err)
		}
		if !strings.Contains(string(logs), "CREATE") {
			t.Errorf("%s: statement logging was not on, the log scan proves nothing", name)
		}
		scan(name+" server log", string(logs))
	}
}

func migrationPassword(r *rig) string {
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(r.stateDB), "migrations", "m*", "migration-role.secret"))
	for _, m := range matches {
		if b, err := os.ReadFile(m); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

func testutilConn(t *testing.T, r *rig, user, pw string) *pgx.Conn {
	t.Helper()
	testutil.RequireLoopback(t, r.tgt.Host)
	c, err := pgx.Connect(context.Background(), "postgres://"+user+":"+pw+"@"+r.tgt.Host+":"+strconv.Itoa(r.tgt.Port)+"/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}
