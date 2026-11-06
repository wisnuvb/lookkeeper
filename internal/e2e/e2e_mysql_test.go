//go:build integration

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/testutil"
)

const (
	mysqlMonitorPassword = "CANARY-mysql-password-5d2b71"
	mysqlAmbientPassword = "ambient-mysql-must-be-ignored"
)

// TestMonitorBinaryAgainstRealMySQL runs the real binary against a real MySQL
// container with a least-privilege account (over TLS) and checks behaviour and
// secret hygiene from the outside.
func TestMonitorBinaryAgainstRealMySQL(t *testing.T) {
	bin := buildBinary(t)
	m := testutil.StartMySQL(t)
	admin := m.Admin(t)
	m.MustExec(t, admin,
		"CREATE USER 'lk_mon'@'%' IDENTIFIED BY '"+mysqlMonitorPassword+"' REQUIRE SSL",
		"GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'lk_mon'@'%'",
	)

	slack := newSlack(t)
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state", "lockkeeper.db")
	cfgPath := filepath.Join(dir, "lockkeeper.yaml")
	cfg := fmt.Sprintf(`
version: 1
databases:
  e2e-my:
    engine: mysql
    host: %[1]s
    port: %[2]d
    user: lk_mon
    password: { env: LK_E2E_MY_PASSWORD }
    tls: { mode: require }
  e2e-root:
    engine: mysql
    host: %[1]s
    port: %[2]d
    user: root
    password: { env: LK_E2E_ROOT_PASSWORD }
    tls: { mode: disable }
monitor:
  interval: 5s
  query_timeout: 2s
  targets: [e2e-my]
alerts:
  channels:
    slack:
      webhook_url: { env: LK_E2E_SLACK }
  rules:
    my.connections.used_ratio:
      warning: 0.001
      for_warning: 0s
store:
  path: %[3]s
`, m.Host, m.Port, statePath)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(),
		"LK_E2E_MY_PASSWORD="+mysqlMonitorPassword,
		"LK_E2E_ROOT_PASSWORD="+m.RootPassword,
		"LK_E2E_SLACK="+slack.URL+"/services/T0/B0/"+slackSecret,
		"MYSQL_PWD="+mysqlAmbientPassword,
	)
	secrets := []string{mysqlMonitorPassword, m.RootPassword, slackSecret, mysqlAmbientPassword}

	runCLI := func(args ...string) (string, string, int) {
		cmd := exec.Command(bin, append([]string{"-c", cfgPath}, args...)...)
		cmd.Env = env
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("run %v: %v", args, err)
		}
		return out.String(), errb.String(), code
	}
	var allOutput strings.Builder
	collect := func(parts ...string) {
		for _, s := range parts {
			allOutput.WriteString(s)
		}
	}

	so, se, code := runCLI("config", "validate")
	collect(so, se)
	if code != 0 || !strings.Contains(so, "Configuration OK") {
		t.Fatalf("config validate: code=%d\n%s\n%s", code, so, se)
	}

	// check: the lowered threshold makes the connection usage a warning (exit 2).
	// The least-privilege account must not trigger any role warning.
	so, se, code = runCLI("check", "-t", "e2e-my")
	collect(so, se)
	if code != 2 || !strings.Contains(so, "connection usage") || !strings.Contains(so, "[warning]") {
		t.Fatalf("check: want exit 2 with a connection finding, got code=%d\n%s\n%s", code, so, se)
	}
	if strings.Contains(so, "role:") || strings.Contains(so, "error:") {
		t.Errorf("the least-privilege account must produce no role warning or error:\n%s", so)
	}

	// check with the root account: it works, and the audit calls the account out.
	so, se, _ = runCLI("check", "-t", "e2e-root")
	collect(so, se)
	if !strings.Contains(so, "role: account root@") || !strings.Contains(so, "ALL PRIVILEGES") || !strings.Contains(so, "REQUIRE SSL") {
		t.Errorf("an over-privileged account must be flagged with the recommended grants:\n%s\n%s", so, se)
	}

	// slots list does not apply to MySQL and says so.
	so, se, code = runCLI("slots", "list", "-t", "e2e-my")
	collect(so, se)
	if code == 0 || !strings.Contains(se, "do not apply to mysql") {
		t.Errorf("slots list on a mysql target must fail clearly: code=%d\n%s\n%s", code, so, se)
	}

	// Run the daemon.
	var daemonOut, daemonErr bytes.Buffer
	daemon := exec.Command(bin, "-c", cfgPath, "--log-level", "debug", "monitor", "run")
	daemon.Env = env
	daemon.Stdout, daemon.Stderr = &daemonOut, &daemonErr
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- daemon.Wait() }()
	t.Cleanup(func() { _ = daemon.Process.Kill() })

	msg := slack.waitFor(t, "connection usage", 30*time.Second)
	if !strings.Contains(msg, "WARNING") {
		t.Errorf("unexpected alert text: %q", msg)
	}

	// The daemon's server session really is read-only and tagged.
	var ro string
	err := admin.QueryRowContext(context.Background(), `
		SELECT vt.VARIABLE_VALUE
		FROM performance_schema.variables_by_thread vt
		JOIN performance_schema.threads th ON th.THREAD_ID = vt.THREAD_ID
		JOIN performance_schema.session_connect_attrs a ON a.PROCESSLIST_ID = th.PROCESSLIST_ID
		WHERE a.ATTR_NAME = 'program_name' AND a.ATTR_VALUE = 'lockkeeper'
		  AND vt.VARIABLE_NAME = 'transaction_read_only' LIMIT 1`).Scan(&ro)
	if err != nil || ro != "ON" {
		t.Errorf("the daemon's MySQL session must be read-only: value=%q err=%v", ro, err)
	}

	ps, err := exec.Command("ps", "-axo", "args").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if bytes.Contains(ps, []byte(s)) {
			t.Errorf("a secret appears in the process list (ps): %q", s)
		}
	}

	before := len(slack.messages())
	time.Sleep(7 * time.Second)
	if after := len(slack.messages()); after != before {
		t.Errorf("an active alert must not be re-notified every tick: %d -> %d", before, after)
	}

	if err := daemon.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("daemon did not exit cleanly: %v\nstderr:\n%s", err, daemonErr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("daemon did not stop within 30s\nstderr:\n%s", daemonErr.String())
	}
	collect(daemonOut.String(), daemonErr.String())
	if !strings.Contains(daemonErr.String(), "monitor stopped") {
		t.Errorf("expected a clean shutdown log line:\n%s", daemonErr.String())
	}

	// The least-privilege account gives no audit warning at start-up either.
	if strings.Contains(daemonErr.String(), "role privilege warning") {
		t.Errorf("unexpected role warning in the daemon log:\n%s", daemonErr.String())
	}

	// A restart must not repeat the notification.
	before = len(slack.messages())
	restart := exec.Command(bin, "-c", cfgPath, "monitor", "run")
	restart.Env = env
	var rErr bytes.Buffer
	restart.Stderr = &rErr
	if err := restart.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(8 * time.Second)
	_ = restart.Process.Signal(syscall.SIGTERM)
	_ = restart.Wait()
	collect(rErr.String())
	if after := len(slack.messages()); after != before {
		t.Errorf("a restart must not re-notify: %d -> %d", before, after)
	}

	// Canary scan: no secret in any output nor in the state database, and no
	// statement text of other sessions anywhere (threat T10).
	scan := func(name string, data []byte) {
		for _, s := range secrets {
			if bytes.Contains(data, []byte(s)) {
				t.Errorf("secret %q leaked into %s", s, name)
			}
		}
	}
	scan("command output and logs", []byte(allOutput.String()))
	entries, _ := filepath.Glob(statePath + "*")
	if len(entries) == 0 {
		t.Fatal("expected a state database")
	}
	for _, f := range entries {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		scan(filepath.Base(f), b)
		for _, kw := range []string{"SELECT ", "INNODB_TRX"} {
			if bytes.Contains(b, []byte(kw)) {
				t.Errorf("statement text %q found in %s", kw, filepath.Base(f))
			}
		}
	}
	fi, _ := os.Stat(statePath)
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("state database must be 0600, got %v", fi.Mode().Perm())
	}
}
