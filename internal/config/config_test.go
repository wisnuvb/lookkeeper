package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const validYAML = `
version: 1
databases:
  rds-main:
    engine: postgres
    host: example-db.abc123.eu-west-1.rds.amazonaws.com
    user: lockkeeper_monitor
    password: { env: LK_RDS_MAIN_PASSWORD }
    tls: { mode: verify-full, ca_file: /etc/lockkeeper/ca.pem }
    read_only: true
    disk_total_gb: 500
    cloudwatch: { region: eu-west-1, db_instance_id: example-db }
monitor:
  interval: 30s
  retention: 14d
alerts:
  channels:
    telegram:
      bot_token: { env: LK_TELEGRAM_TOKEN }
      chat_id: "123456789"
    slack:
      webhook_url: { env: LK_SLACK_WEBHOOK }
  routes:
    - match: { severity: [critical] }
      to: [telegram, slack]
  rules:
    pg.slot.retained_wal_bytes:
      warning: 5GiB
      critical: 20GiB
      for_warning: 2m
`

func TestParseValidAppliesDefaults(t *testing.T) {
	cfg, warnings, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	db := cfg.Databases["rds-main"]
	if db.Port != 5432 || db.Database != "postgres" || db.TLS.Mode != TLSVerifyFull {
		t.Errorf("defaults not applied: %+v", db)
	}
	if got := cfg.Monitor.Retention.D(); got != 14*24*time.Hour {
		t.Errorf("retention = %v", got)
	}
	if got := cfg.Monitor.QueryTimeout.D(); got != 10*time.Second {
		t.Errorf("query timeout default = %v", got)
	}
	if len(cfg.Monitor.Targets) != 1 || cfg.Monitor.Targets[0] != "rds-main" {
		t.Errorf("targets default = %v", cfg.Monitor.Targets)
	}
	ov := cfg.Alerts.Rules["pg.slot.retained_wal_bytes"]
	if ov.Warning.F() != 5*(1<<30) || ov.Critical.F() != 20*(1<<30) {
		t.Errorf("size thresholds: %v %v", ov.Warning, ov.Critical)
	}
	if ov.ForWarning.D() != 2*time.Minute {
		t.Errorf("for_warning = %v", ov.ForWarning.D())
	}
}

func TestParseRejects(t *testing.T) {
	base := func(mut func(string) string) string { return mut(validYAML) }
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"inline password", base(func(s string) string {
			return strings.Replace(s, "{ env: LK_RDS_MAIN_PASSWORD }", "hunter2", 1)
		}), "inline secrets are not allowed"},
		{"unknown key", base(func(s string) string { return s + "\nbogus: 1\n" }), "bogus"},
		{"wrong version", base(func(s string) string { return strings.Replace(s, "version: 1", "version: 2", 1) }), "version: must be 1"},
		{"mysql not yet", base(func(s string) string { return strings.Replace(s, "engine: postgres", "engine: mysql", 1) }), "mysql is not supported yet"},
		{"weak tls remote", base(func(s string) string { return strings.Replace(s, "mode: verify-full", "mode: require", 1) }), "does not authenticate the server"},
		{"read_only false", base(func(s string) string { return strings.Replace(s, "read_only: true", "read_only: false", 1) }), "always read-only"},
		{"unknown target", base(func(s string) string {
			return strings.Replace(s, "interval: 30s", "interval: 30s\n  targets: [nope]", 1)
		}), "unknown database"},
		{"route to unknown channel", base(func(s string) string { return strings.Replace(s, "to: [telegram, slack]", "to: [pagerduty]", 1) }), "not configured"},
		{"bad severity", base(func(s string) string { return strings.Replace(s, "severity: [critical]", "severity: [fatal]", 1) }), "warning or critical"},
		{"short interval", base(func(s string) string { return strings.Replace(s, "interval: 30s", "interval: 1s", 1) }), "at least 5s"},
		{"bad duration", base(func(s string) string { return strings.Replace(s, "interval: 30s", "interval: soon", 1) }), "invalid duration"},
		{"bad size", base(func(s string) string { return strings.Replace(s, "warning: 5GiB", "warning: lots", 1) }), "invalid size"},
		{"cloudwatch incomplete", base(func(s string) string {
			return strings.Replace(s, "cloudwatch: { region: eu-west-1, db_instance_id: example-db }", "cloudwatch: { region: eu-west-1 }", 1)
		}), "db_instance_id are required"},
	}
	for _, c := range cases {
		_, _, err := Parse([]byte(c.yaml))
		if err == nil {
			t.Errorf("%s: expected an error", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not contain %q", c.name, err, c.want)
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: error leaks the inline value", c.name)
		}
	}
}

func TestParseReportsAllProblemsAtOnce(t *testing.T) {
	_, _, err := Parse([]byte("version: 3\ndatabases:\n  Bad_Name:\n    engine: oracle\n"))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"version: must be 1", "name must match", "engine", "host: required", "user: required", "password: required"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in:\n%v", want, err)
		}
	}
}

func TestInsecureTLSOptInWarnsAndLoopbackIsExempt(t *testing.T) {
	yamlText := strings.Replace(validYAML, "mode: verify-full", "mode: require, allow_insecure: true", 1)
	_, warnings, err := Parse([]byte(yamlText))
	if err != nil {
		t.Fatalf("opt-in should be accepted: %v", err)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "man-in-the-middle") {
		t.Errorf("expected a MITM warning, got %v", warnings)
	}

	local := strings.NewReplacer(
		"host: example-db.abc123.eu-west-1.rds.amazonaws.com", "host: 127.0.0.1",
		"mode: verify-full", "mode: disable",
	).Replace(validYAML)
	if _, _, err := Parse([]byte(local)); err != nil {
		t.Errorf("loopback with tls disabled must be accepted: %v", err)
	}
}

func TestIsLocalHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost": true, "LOCALHOST": true, "127.0.0.1": true, "::1": true, "[::1]": true,
		"/var/run/postgresql": true,
		"10.0.0.5":            false, "db.example.com": false, "": false, "127.0.0.1.nip.io": false,
	} {
		if got := IsLocalHost(host); got != want {
			t.Errorf("IsLocalHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestParseDurationAndSize(t *testing.T) {
	durs := map[string]time.Duration{
		"30s": 30 * time.Second, "5m": 5 * time.Minute, "14d": 14 * 24 * time.Hour,
		"2w": 14 * 24 * time.Hour, "1d12h": 36 * time.Hour, "1w2d": 9 * 24 * time.Hour,
	}
	for in, want := range durs {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "d", "abc", "5x", "1d2x"} {
		if _, err := ParseDuration(in); err == nil {
			t.Errorf("ParseDuration(%q) should fail", in)
		}
	}
	sizes := map[string]float64{
		"100": 100, "1KiB": 1024, "5GiB": 5 << 30, "5G": 5 << 30, "2MB": 2e6, "1.5GiB": 1.5 * (1 << 30), "7b": 7,
	}
	for in, want := range sizes {
		got, err := ParseSize(in)
		if err != nil || got != want {
			t.Errorf("ParseSize(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "GiB", "5 parsecs", "-1"} {
		if _, err := ParseSize(in); err == nil {
			t.Errorf("ParseSize(%q) should fail", in)
		}
	}
}

func TestLoadRefusesWritableConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	path := filepath.Join(t.TempDir(), "lockkeeper.yaml")
	if err := os.WriteFile(path, []byte(validYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err != nil {
		t.Fatalf("0600 config should load: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil || !strings.Contains(err.Error(), "must not be writable") {
		t.Fatalf("group/world-writable config must be refused, got %v", err)
	}
}

func TestEmptyConfig(t *testing.T) {
	if _, _, err := Parse(nil); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("got %v", err)
	}
}
