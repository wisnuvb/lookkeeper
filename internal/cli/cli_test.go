package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/collector"
	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/model"
	"github.com/wisnuvb/lockkeeper/internal/service"
)

type result struct {
	code        int
	stdout, err string
}

func run(t *testing.T, env map[string]string, deps func(service.Deps) service.Deps, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	e := Env{
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb,
		Getenv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		Deps:   deps,
	}
	code := Execute(context.Background(), e, args)
	return result{code: code, stdout: out.String(), err: errb.String()}
}

func TestInitWritesRestrictedParsableConfigAndNeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lockkeeper.yaml")
	r := run(t, nil, nil, "init", "--path", path)
	if r.code != 0 {
		t.Fatalf("init failed: %+v", r)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("config must be 0600: %v %v", fi.Mode(), err)
		}
	}
	if _, warnings, err := config.Load(path); err != nil {
		t.Fatalf("the example config must be valid: %v (warnings %v)", err, warnings)
	}
	if strings.Contains(ExampleConfig, "password: ") && !strings.Contains(ExampleConfig, "{ env:") {
		t.Error("the example must use secret references")
	}

	if err := os.WriteFile(path, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	r = run(t, nil, nil, "init", "--path", path)
	if r.code != 1 || !strings.Contains(r.err, "refusing to overwrite") {
		t.Errorf("init must refuse to overwrite: %+v", r)
	}
	if b, _ := os.ReadFile(path); string(b) != "keep me" {
		t.Error("existing config was modified")
	}
}

func writeConfig(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lockkeeper.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const minimalYAML = `
version: 1
databases:
  db:
    engine: postgres
    host: 127.0.0.1
    user: mon
    password: { env: DB_PW }
    tls: { mode: disable }
`

func TestConfigValidate(t *testing.T) {
	path := writeConfig(t, minimalYAML)

	r := run(t, map[string]string{"DB_PW": "x-secret-pw"}, nil, "-c", path, "config", "validate")
	if r.code != 0 || !strings.Contains(r.stdout, "Configuration OK") {
		t.Fatalf("valid config rejected: %+v", r)
	}
	if strings.Contains(r.stdout+r.err, "x-secret-pw") {
		t.Error("validate must never print secret values")
	}

	r = run(t, nil, nil, "-c", path, "config", "validate")
	if r.code != 1 || !strings.Contains(r.err, "DB_PW") {
		t.Errorf("a missing env secret must fail validation and name the variable: %+v", r)
	}

	bad := writeConfig(t, strings.Replace(minimalYAML, "{ env: DB_PW }", "hunter2", 1))
	r = run(t, nil, nil, "-c", bad, "config", "validate")
	if r.code != 1 || !strings.Contains(r.err, "inline secrets are not allowed") || strings.Contains(r.err, "hunter2") {
		t.Errorf("inline secret must be rejected without echoing it: %+v", r)
	}

	r = run(t, nil, nil, "-c", filepath.Join(t.TempDir(), "missing.yaml"), "config", "validate")
	if r.code != 1 || !strings.Contains(r.err, "lockkeeper init") {
		t.Errorf("missing config should suggest init: %+v", r)
	}
}

type scripted struct {
	samples  []model.Sample
	complete bool
}

func (s scripted) Target() string { return "db" }
func (s scripted) Close() error   { return nil }
func (s scripted) Collect(context.Context) ([]model.Sample, bool, error) {
	return s.samples, s.complete, nil
}

func withCollector(c collector.Collector) func(service.Deps) service.Deps {
	return func(d service.Deps) service.Deps {
		d.NewCollector = func(string) collector.Collector { return c }
		return d
	}
}

func sm(metric string, v float64) model.Sample {
	return model.Sample{Target: "db", Metric: metric, Value: v, At: time.Now()}
}

func TestCheckExitCodesAndOutput(t *testing.T) {
	path := writeConfig(t, minimalYAML)
	env := map[string]string{"DB_PW": "pw"}
	cases := []struct {
		name     string
		samples  []model.Sample
		wantCode int
		wantText string
	}{
		{"healthy", []model.Sample{sm(rules.MetricPGUp, 1), sm(rules.MetricPGConnectionsRatio, 0.1)}, 0, "db: ok"},
		{"warning", []model.Sample{sm(rules.MetricPGUp, 1), sm(rules.MetricPGConnectionsRatio, 0.85)}, 2, "[warning]"},
		{"critical", []model.Sample{sm(rules.MetricPGUp, 1), sm(rules.MetricPGSlotRetainedWAL, 30<<30)}, 3, "[critical]"},
		{"down", []model.Sample{sm(rules.MetricPGUp, 0)}, 3, "UNREACHABLE"},
	}
	for _, c := range cases {
		r := run(t, env, withCollector(scripted{samples: c.samples, complete: true}), "-c", path, "check")
		if r.code != c.wantCode || !strings.Contains(r.stdout, c.wantText) {
			t.Errorf("%s: code=%d (want %d), stdout=%q", c.name, r.code, c.wantCode, r.stdout)
		}
	}

	r := run(t, env, withCollector(scripted{samples: []model.Sample{sm(rules.MetricPGUp, 1), sm(rules.MetricPGConnectionsRatio, 0.99)}, complete: true}),
		"-c", path, "check", "--json", "--samples")
	var parsed service.CheckResult
	if err := json.Unmarshal([]byte(r.stdout), &parsed); err != nil {
		t.Fatalf("--json output must be valid JSON: %v\n%s", err, r.stdout)
	}
	if r.code != 3 || parsed.Severity != model.SeverityCritical || len(parsed.Targets) != 1 || len(parsed.Targets[0].Samples) != 2 {
		t.Errorf("unexpected JSON result (code %d): %+v", r.code, parsed)
	}

	r = run(t, env, withCollector(scripted{}), "-c", path, "check", "--target", "nope")
	if r.code != 1 || !strings.Contains(r.err, `unknown database "nope"`) {
		t.Errorf("unknown target must be an operational error: %+v", r)
	}
}

func TestLogFlagsAreValidated(t *testing.T) {
	path := writeConfig(t, minimalYAML)
	r := run(t, map[string]string{"DB_PW": "pw"}, withCollector(scripted{}), "-c", path, "--log-level", "loud", "check")
	if r.code != 1 || !strings.Contains(r.err, "invalid --log-level") {
		t.Errorf("bad log level must fail: %+v", r)
	}
	r = run(t, map[string]string{"DB_PW": "pw"}, withCollector(scripted{}), "-c", path, "--log-format", "xml", "check")
	if r.code != 1 || !strings.Contains(r.err, "invalid --log-format") {
		t.Errorf("bad log format must fail: %+v", r)
	}
}

func TestVersionAndConfigEnvVar(t *testing.T) {
	if r := run(t, nil, nil, "version"); r.code != 0 || !strings.HasPrefix(r.stdout, "lockkeeper ") {
		t.Errorf("version: %+v", r)
	}
	path := writeConfig(t, minimalYAML)
	r := run(t, map[string]string{"LOCKKEEPER_CONFIG": path, "DB_PW": "pw"}, nil, "config", "validate")
	if r.code != 0 {
		t.Errorf("LOCKKEEPER_CONFIG must be honoured: %+v", r)
	}
}
