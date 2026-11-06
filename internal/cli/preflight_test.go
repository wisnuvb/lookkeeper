package cli

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/wisnuvb/lockkeeper/internal/dbconn"
	"github.com/wisnuvb/lockkeeper/internal/preflight"
	"github.com/wisnuvb/lockkeeper/internal/service"
)

const twoServersYAML = `
version: 1
databases:
  src:
    engine: postgres
    host: 127.0.0.1
    port: 15432
    user: mon
    password: { env: DB_PW }
    tls: { mode: disable }
  tgt:
    engine: postgres
    host: 127.0.0.1
    port: 15433
    user: mon
    password: { env: DB_PW }
    tls: { mode: disable }
`

func unreachable(d service.Deps) service.Deps {
	d.OpenPG = func(context.Context, dbconn.PGSpec) (*pgx.Conn, error) { return nil, errors.New("refused") }
	return d
}

func TestPreflightRefusesSourceEqualToTarget(t *testing.T) {
	path := writeConfig(t, twoServersYAML)
	r := run(t, map[string]string{"DB_PW": "pw"}, unreachable, "-c", path, "preflight", "pg", "--source", "src", "--target", "src")
	if r.code != 1 || !strings.Contains(r.err, "must be different") {
		t.Errorf("--source equal to --target must be an operational error: %+v", r)
	}
}

func TestPreflightArgumentErrors(t *testing.T) {
	path := writeConfig(t, twoServersYAML)
	env := map[string]string{"DB_PW": "pw"}
	if r := run(t, env, unreachable, "-c", path, "preflight", "pg", "--source", "src"); r.code != 1 || !strings.Contains(r.err, "target") {
		t.Errorf("a missing --target must fail: %+v", r)
	}
	if r := run(t, env, unreachable, "-c", path, "preflight", "pg", "--source", "src", "--target", "ghost"); r.code != 1 || !strings.Contains(r.err, `unknown database "ghost"`) {
		t.Errorf("an unknown name must fail: %+v", r)
	}
	if r := run(t, env, unreachable, "-c", path, "inventory"); r.code != 1 || !strings.Contains(r.err, "--source is required") {
		t.Errorf("inventory with two configured servers needs --source: %+v", r)
	}
}

func TestPreflightExitCodeAndOutputWhenServersAreDown(t *testing.T) {
	path := writeConfig(t, twoServersYAML)
	env := map[string]string{"DB_PW": "pw"}

	r := run(t, env, unreachable, "-c", path, "preflight", "pg", "--source", "src", "--target", "tgt")
	if r.code != 3 {
		t.Fatalf("a blocker must exit 3: %+v", r)
	}
	for _, want := range []string{"BLOCKER (2)", "[connect.source]", "[connect.target]", "Read-only", "NOT READY"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("text output lacks %q:\n%s", want, r.stdout)
		}
	}

	r = run(t, env, unreachable, "-c", path, "preflight", "pg", "--source", "src", "--target", "tgt", "--json")
	var rep preflight.Report
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("--json must print one JSON object: %v\n%s", err, r.stdout)
	}
	if r.code != 3 || rep.Summary.Highest != preflight.Blocker || rep.Source != "src" || rep.Target != "tgt" || rep.SchemaVersion != 1 {
		t.Errorf("code %d, report %+v", r.code, rep.Summary)
	}
}

func TestHelpStatesThatTheCommandsAreReadOnly(t *testing.T) {
	for _, args := range [][]string{{"preflight", "pg", "--help"}, {"inventory", "--help"}} {
		r := run(t, nil, nil, args...)
		if r.code != 0 || !strings.Contains(strings.ToLower(r.stdout), "read-only") && !strings.Contains(strings.ToLower(r.stdout), "only reads") {
			t.Errorf("%v help must say the command is read-only:\n%s", args, r.stdout)
		}
		if !strings.Contains(r.stdout, "--databases") {
			t.Errorf("%v help must document --databases", args)
		}
	}
}

func TestTerminalControlCharactersInNamesAreNeutralised(t *testing.T) {
	rep := preflight.NewReport("postgres", "s\x1b[31m", "t", []string{"db\x07x"}, []preflight.Finding{
		{ID: "x", Area: "a", Severity: preflight.Warn, Message: "table evil\x1b]0;pwned\x07name\nsecond line", Remediation: "do it"},
	})
	var b strings.Builder
	pfPrintReport(&b, rep)
	if strings.ContainsAny(b.String(), "\x1b\x07") {
		t.Errorf("control characters reached the terminal output: %q", b.String())
	}
}

func TestWrapKeepsWordsAndWidth(t *testing.T) {
	lines := pfWrap("one two three four five six seven", 12)
	for _, l := range lines {
		if len(l) > 12 {
			t.Errorf("line %q exceeds the width", l)
		}
	}
	if strings.Join(lines, " ") != "one two three four five six seven" {
		t.Errorf("words lost: %v", lines)
	}
}
