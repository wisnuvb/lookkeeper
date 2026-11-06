//go:build unix

package runner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/redact"
	"github.com/wisnuvb/lockkeeper/internal/secret"
)

const canary = "CANARY_PW_6f2d91c4"

func newRunner(t *testing.T) *Runner {
	t.Helper()
	root := t.TempDir()
	return &Runner{
		BaseDir: filepath.Join(root, "run"), LogDir: filepath.Join(root, "logs"),
		Redactor: redact.New(), Grace: 600 * time.Millisecond,
	}
}

func script(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tool.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func endpoints() []Endpoint {
	return []Endpoint{
		{Host: "src.example", Port: 5432, Database: "app", User: "lk", Password: secret.New(canary), TLSMode: "verify-full", CAFile: "/etc/ca.pem"},
		{Host: "tgt.example", Port: 5432, Database: "app", User: "admin", Password: secret.New(canary + "_tgt")},
	}
}

func TestURIHasNoPassword(t *testing.T) {
	e := endpoints()[0]
	u := e.URI()
	if strings.Contains(u, canary) || !strings.HasPrefix(u, "postgres://lk@src.example:5432/app?") || !strings.Contains(u, "sslmode=verify-full") || !strings.Contains(u, "sslrootcert=%2Fetc%2Fca.pem") {
		t.Fatalf("uri: %s", u)
	}
	if got := (Endpoint{Host: "h", User: "u", Database: "d"}).URI(); got != "postgres://u@h:5432/d" {
		t.Fatalf("default port: %s", got)
	}
}

func TestEmptyEnvPassfileModesAndNoSecretOnArgvOrLog(t *testing.T) {
	t.Setenv("LK_AMBIENT_CANARY", "ambient-value")
	t.Setenv("PGPASSWORD", canary)
	r := newRunner(t)
	run, err := r.Begin("probe", endpoints())
	if err != nil {
		t.Fatal(err)
	}
	// The tool reports its environment, its own argv as the OS shows it, the mode
	// of the passfile and of its directory, and prints a URI with a password and
	// the bare password, as a misbehaving tool might.
	tool := script(t, `
env | sort
echo "ARGV: $(ps -o args= -p $$)"
echo "PASSMODE: $(stat -f %Lp "$PGPASSFILE" 2>/dev/null || stat -c %a "$PGPASSFILE")"
echo "DIRMODE: $(stat -f %Lp "$(dirname "$PGPASSFILE")" 2>/dev/null || stat -c %a "$(dirname "$PGPASSFILE")")"
echo "leak: postgres://lk:`+canary+`@src.example/app and `+canary+`"
`)
	args := []string{"clone", "--source", run.Endpoint(0).URI(), "--target", run.Endpoint(1).URI()}
	res, err := run.Capture(context.Background(), tool, args, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := res.Output

	// Environment: exactly the allowed variables.
	for _, line := range strings.Split(out, "\n") {
		if k, _, ok := strings.Cut(line, "="); ok && strings.ToUpper(k) == k && !strings.Contains(line, " ") {
			switch k {
			case "PATH", "LANG", "LC_ALL", "HOME", "PGPASSFILE", "PWD", "SHLVL", "_", "OLDPWD":
			default:
				t.Errorf("unexpected variable in the child environment: %s", k)
			}
		}
	}
	if strings.Contains(out, "ambient-value") || strings.Contains(out, "PGPASSWORD") {
		t.Fatal("the ambient environment leaked into the child")
	}
	if !strings.Contains(out, "PASSMODE: 600") || !strings.Contains(out, "DIRMODE: 700") {
		t.Fatalf("passfile must be 0600 in a 0700 directory:\n%s", out)
	}
	if strings.Contains(out, canary) {
		t.Fatalf("the canary password reached the redacted output:\n%s", out)
	}
	logBytes, _ := os.ReadFile(res.LogPath)
	if strings.Contains(string(logBytes), canary) {
		t.Fatal("the canary password is in the log file")
	}
	if fi, err := os.Stat(res.LogPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("log file must be 0600: %v %v", fi, err)
	}
	if fi, _ := os.Stat(r.LogDir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("log dir must be 0700: %v", fi.Mode())
	}

	// The passfile holds the secret (it is the one allowed place) and is gone after Close.
	pf, _ := os.ReadFile(run.PassFile)
	if !strings.Contains(string(pf), "src.example:5432:*:lk:"+canary) {
		t.Fatalf("passfile content: %q", pf)
	}
	if err := run.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(run.Dir); !os.IsNotExist(err) {
		t.Fatal("the run directory (and passfile) must be deleted")
	}
}

func TestSecretNeverOnArgvWhileRunning(t *testing.T) {
	r := newRunner(t)
	run, err := r.Begin("probe", endpoints())
	if err != nil {
		t.Fatal(err)
	}
	defer run.Close()
	tool := script(t, `sleep 20`)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := run.Exec(ctx, tool, []string{"clone", "--source", run.Endpoint(0).URI(), "--target", run.Endpoint(1).URI()}, nil)
		done <- err
	}()
	time.Sleep(400 * time.Millisecond)
	ps, err := exec.Command("ps", "-axww", "-o", "args=").Output()
	if err != nil {
		t.Skipf("ps unavailable: %v", err)
	}
	if strings.Contains(string(ps), canary) {
		t.Fatal("the password is visible in the process list")
	}
	if !strings.Contains(string(ps), "src.example:5432/app") {
		t.Fatal("test bug: the tool is not running with its URIs")
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("a cancelled run must report that it was stopped")
	}
}

func TestSIGTERMThenSIGKILLAfterGraceKillsTheWholeGroup(t *testing.T) {
	r := newRunner(t)
	run, _ := r.Begin("stubborn", endpoints())
	defer run.Close()
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	// The tool ignores SIGTERM and starts a child that also ignores it.
	tool := script(t, `
trap '' TERM
sh -c 'trap "" TERM; echo $$ > `+pidFile+`; while :; do sleep 1; done' &
while :; do sleep 1; done
`)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var start time.Time
	go func() { _, err := run.Exec(ctx, tool, nil, nil); done <- err }()
	// Wait until the grandchild is really up (slow machines, parallel tests).
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(pidFile); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	start = time.Now() // the grace period is measured from the cancellation
	cancel()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "stopped") {
			t.Fatalf("want a 'stopped' error, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SIGKILL after the grace period did not stop the stubborn tool")
	}
	if d := time.Since(start); d < r.Grace {
		t.Fatalf("the tool was killed after %s: SIGTERM must get the grace period (%s) first", d, r.Grace)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("child pid file: %v", err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	time.Sleep(300 * time.Millisecond)
	if processAlive(pid) {
		t.Fatalf("grandchild %d survived: the signal must go to the whole process group", pid)
	}
}

func TestPolitelyExitingToolIsNotKilled(t *testing.T) {
	r := newRunner(t)
	run, _ := r.Begin("polite", endpoints())
	defer run.Close()
	marker := filepath.Join(t.TempDir(), "term-seen")
	ready := filepath.Join(t.TempDir(), "ready")
	tool := script(t, `trap 'echo seen > `+marker+`; exit 0' TERM
touch `+ready+`
while :; do sleep 0.1; done`)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := run.Exec(ctx, tool, nil, nil); done <- err }()
	for i := 0; i < 200; i++ { // the trap is installed once the tool says it is ready
		if _, err := os.Stat(ready); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("SIGTERM must reach the tool so it can shut down cleanly")
	}
}

const dataCanary = "CANARY_DATA_ROW_77aa"

// A failing tool's error is persisted (audit log, steps, failed_reason): it must
// carry the tool, the exit code and the log path only. pg_restore and pgcopydb
// quote rows of the table in DETAIL and CONTEXT lines.
func TestFailureErrorNeverCarriesToolOutput(t *testing.T) {
	r := newRunner(t)
	run, _ := r.Begin("failing", endpoints())
	defer run.Close()
	tool := script(t, `echo "connecting with password=`+canary+`" >&2
echo "pg_restore: error: COPY failed for table \"secrets\": ERROR:  new row violates check constraint \"trap\"" >&2
echo "DETAIL:  Failing row contains (1, `+dataCanary+`)." >&2
echo "CONTEXT:  COPY secrets, line 1: \"1	`+dataCanary+`\"" >&2
echo "fatal: boom" >&2
exit 3`)
	res, err := run.Exec(context.Background(), tool, nil, nil)
	if err == nil || res.ExitCode != 3 {
		t.Fatalf("want exit 3 error, got %v (%d)", err, res.ExitCode)
	}
	for _, bad := range []string{canary, dataCanary, "boom", "DETAIL", "Failing row", "check constraint"} {
		if strings.Contains(err.Error(), bad) {
			t.Fatalf("the error value must not contain tool output (%q): %v", bad, err)
		}
	}
	if !strings.Contains(err.Error(), "exit status 3") || !strings.Contains(err.Error(), res.LogPath) || !strings.Contains(err.Error(), "tool.sh") {
		t.Fatalf("the error must name the tool, the exit code and the log: %v", err)
	}

	// The terminal-only tail drops the lines that can hold data and the password.
	var te *ToolError
	if !errors.As(err, &te) {
		t.Fatalf("want a *ToolError, got %T", err)
	}
	tail := te.Tail()
	if !strings.Contains(tail, "boom") || !strings.Contains(tail, "check constraint") {
		t.Fatalf("the tail should still help the operator: %q", tail)
	}
	for _, bad := range []string{canary, dataCanary, "DETAIL", "CONTEXT", "Failing row"} {
		if strings.Contains(tail, bad) {
			t.Fatalf("the tail must not contain %q: %q", bad, tail)
		}
	}
	// The log file keeps everything the tool said except the secrets.
	raw, _ := os.ReadFile(res.LogPath)
	if !strings.Contains(string(raw), dataCanary) || strings.Contains(string(raw), canary) {
		t.Fatalf("the log has the raw output with secrets redacted: %s", raw)
	}
}

func TestBeginRefusesOpenDirectoriesAndSweepsStaleRuns(t *testing.T) {
	r := newRunner(t)
	if err := os.MkdirAll(r.BaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(r.BaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Begin("x", nil); err == nil || !strings.Contains(err.Error(), "chmod 700") {
		t.Fatalf("a group-readable run directory must be refused: %v", err)
	}
	_ = os.Chmod(r.BaseDir, 0o700)

	// A run directory left by a SIGKILLed process (pid that no longer exists).
	dead := exec.Command("true")
	_ = dead.Run()
	stale := filepath.Join(r.BaseDir, "run-stale")
	_ = os.Mkdir(stale, 0o700)
	_ = os.WriteFile(filepath.Join(stale, "owner.pid"), []byte(strconv.Itoa(dead.Process.Pid)), 0o600)
	_ = os.WriteFile(filepath.Join(stale, "pgpass"), []byte("secret"), 0o600)
	live := filepath.Join(r.BaseDir, "run-live")
	_ = os.Mkdir(live, 0o700)
	_ = os.WriteFile(filepath.Join(live, "owner.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600)

	run, err := r.Begin("x", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer run.Close()
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("the stale run directory must be removed (it may hold a passfile)")
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatal("a directory of a live process must be left alone")
	}
}
