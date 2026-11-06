package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// TLS modes.
const (
	TLSVerifyFull = "verify-full"
	TLSVerifyCA   = "verify-ca"
	TLSRequire    = "require"
	TLSDisable    = "disable"
)

// EnginePostgres is the only engine supported by the collectors so far.
const EnginePostgres = "postgres"

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// Parse decodes and validates configuration from YAML. Unknown keys are errors.
// The returned warnings are non-fatal findings (for example weak TLS opt-ins).
func Parse(data []byte) (*Config, []string, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil, errors.New("config is empty")
		}
		return nil, nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	warnings, err := cfg.Validate()
	if err != nil {
		return nil, warnings, err
	}
	return &cfg, warnings, nil
}

// Load reads, parses and validates the config file at path. The file itself must
// not be writable by group or others, since it controls what Lockkeeper connects to.
func Load(path string) (*Config, []string, error) {
	if err := checkNotWritableByOthers(path); err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

func checkNotWritableByOthers(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat config: %w", pathOnly(err))
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("config file %s has mode %#o; it must not be writable by group or others (chmod 600)", path, fi.Mode().Perm())
	}
	return nil
}

func pathOnly(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("%s: %w", pe.Path, pe.Err)
	}
	return err
}

func (c *Config) applyDefaults() {
	for name, db := range c.Databases {
		if db.Port == 0 {
			db.Port = 5432
		}
		if db.Database == "" {
			db.Database = "postgres"
		}
		if db.TLS.Mode == "" {
			db.TLS.Mode = TLSVerifyFull
		}
		c.Databases[name] = db
	}
	if c.Monitor.Interval == 0 {
		c.Monitor.Interval = Duration(30 * time.Second)
	}
	if c.Monitor.QueryTimeout == 0 {
		c.Monitor.QueryTimeout = Duration(10 * time.Second)
	}
	if c.Monitor.Retention == 0 {
		c.Monitor.Retention = Duration(14 * 24 * time.Hour)
	}
	if len(c.Monitor.Targets) == 0 {
		for name := range c.Databases {
			c.Monitor.Targets = append(c.Monitor.Targets, name)
		}
		sort.Strings(c.Monitor.Targets)
	}
	if c.Monitor.Heartbeat != nil && c.Monitor.Heartbeat.Interval == 0 {
		c.Monitor.Heartbeat.Interval = Duration(time.Minute)
	}
	if c.Monitor.Metrics != nil && c.Monitor.Metrics.Listen == "" {
		c.Monitor.Metrics.Listen = DefaultMetricsListen
	}
	if c.Alerts.RepeatInterval == 0 {
		c.Alerts.RepeatInterval = Duration(4 * time.Hour)
	}
	if c.Alerts.Cooldown == 0 {
		c.Alerts.Cooldown = Duration(5 * time.Minute)
	}
	if c.Store.Path == "" {
		c.Store.Path = "~/.local/state/lockkeeper/lockkeeper.db"
	}
}

// ChannelNames returns the configured channel names in a stable order.
func (c *Config) ChannelNames() []string {
	var out []string
	if c.Alerts.Channels.Telegram != nil {
		out = append(out, "telegram")
	}
	if c.Alerts.Channels.Slack != nil {
		out = append(out, "slack")
	}
	return out
}

// Validate checks the configuration. It returns every problem at once, plus
// non-fatal warnings.
func (c *Config) Validate() (warnings []string, err error) {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if c.Version != 1 {
		add("version: must be 1 (got %d)", c.Version)
	}
	if len(c.Databases) == 0 {
		add("databases: at least one database is required")
	}

	names := make([]string, 0, len(c.Databases))
	for n := range c.Databases {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		db := c.Databases[name]
		p := "databases." + name
		if !nameRe.MatchString(name) {
			add("%s: name must match %s", p, nameRe)
		}
		switch db.Engine {
		case EnginePostgres:
		case "mysql":
			add("%s.engine: mysql is not supported yet (the MySQL collector is planned for Phase 1 slice 2)", p)
		default:
			add("%s.engine: must be %q (got %q)", p, EnginePostgres, db.Engine)
		}
		if db.Host == "" {
			add("%s.host: required", p)
		}
		if db.Port < 1 || db.Port > 65535 {
			add("%s.port: must be 1-65535 (got %d)", p, db.Port)
		}
		if db.User == "" {
			add("%s.user: required", p)
		}
		if db.Password.IsZero() {
			add("%s.password: required; use { env: NAME }, { file: PATH } or { prompt: true }", p)
		}
		if db.ReadOnly != nil && !*db.ReadOnly {
			add("%s.read_only: monitoring sessions are always read-only; false is not allowed", p)
		}
		if db.DiskTotalGB < 0 {
			add("%s.disk_total_gb: must not be negative", p)
		}
		if cw := db.CloudWatch; cw != nil && (cw.Region == "" || cw.DBInstanceID == "") {
			add("%s.cloudwatch: region and db_instance_id are required", p)
		}
		switch db.TLS.Mode {
		case TLSVerifyFull, TLSVerifyCA:
		case TLSRequire, TLSDisable:
			if !IsLocalHost(db.Host) {
				if !db.TLS.AllowInsecure {
					add("%s.tls.mode: %q does not authenticate the server and is refused for remote host %q; use %s with ca_file, or set allow_insecure: true to accept the risk",
						p, db.TLS.Mode, db.Host, TLSVerifyFull)
				} else {
					warnings = append(warnings, fmt.Sprintf("%s: TLS mode %q with allow_insecure is vulnerable to man-in-the-middle attacks", p, db.TLS.Mode))
				}
			}
		default:
			add("%s.tls.mode: must be one of verify-full, verify-ca, require, disable (got %q)", p, db.TLS.Mode)
		}
		if db.TLS.Mode == TLSVerifyCA && db.TLS.CAFile == "" {
			add("%s.tls.ca_file: required for verify-ca", p)
		}
	}

	if c.Monitor.Interval.D() < 5*time.Second {
		add("monitor.interval: must be at least 5s")
	}
	if c.Monitor.QueryTimeout.D() < time.Second {
		add("monitor.query_timeout: must be at least 1s")
	}
	if c.Monitor.QueryTimeout.D() >= c.Monitor.Interval.D() {
		add("monitor.query_timeout: must be shorter than monitor.interval")
	}
	if c.Monitor.Retention.D() < time.Hour {
		add("monitor.retention: must be at least 1h")
	}
	for _, t := range c.Monitor.Targets {
		if _, ok := c.Databases[t]; !ok {
			add("monitor.targets: unknown database %q", t)
		}
	}
	if hb := c.Monitor.Heartbeat; hb != nil {
		if err := hb.URL.Validate(); err != nil {
			add("monitor.heartbeat.url: %v", err)
		}
		if hb.Interval.D() < 10*time.Second {
			add("monitor.heartbeat.interval: must be at least 10s")
		}
	}

	if m := c.Monitor.Metrics; m != nil {
		if w, err := CheckMetricsListen(m.Listen, m.AllowNonLoopback); err != nil {
			add("monitor.metrics.listen: %v", err)
		} else if w != "" {
			warnings = append(warnings, "monitor.metrics: "+w)
		}
	}

	channels := map[string]bool{}
	if t := c.Alerts.Channels.Telegram; t != nil {
		channels["telegram"] = true
		if err := t.BotToken.Validate(); err != nil {
			add("alerts.channels.telegram.bot_token: %v", err)
		}
		if strings.TrimSpace(t.ChatID) == "" {
			add("alerts.channels.telegram.chat_id: required")
		}
	}
	if s := c.Alerts.Channels.Slack; s != nil {
		channels["slack"] = true
		if err := s.WebhookURL.Validate(); err != nil {
			add("alerts.channels.slack.webhook_url: %v", err)
		}
	}
	for i, r := range c.Alerts.Routes {
		if len(r.To) == 0 {
			add("alerts.routes[%d].to: at least one channel is required", i)
		}
		for _, ch := range r.To {
			if !channels[ch] {
				add("alerts.routes[%d].to: channel %q is not configured", i, ch)
			}
		}
		for _, sev := range r.Match.Severity {
			if sev != "warning" && sev != "critical" {
				add("alerts.routes[%d].match.severity: must be warning or critical (got %q)", i, sev)
			}
		}
	}
	if len(channels) == 0 {
		warnings = append(warnings, "alerts: no notification channel is configured; alerts will only be logged")
	}
	if c.Alerts.RepeatInterval.D() < time.Minute {
		add("alerts.repeat_interval: must be at least 1m")
	}

	return warnings, errors.Join(errs...)
}

// IsLocalHost reports whether host is a loopback address, "localhost", or a
// unix-socket directory (starts with "/"). Such connections are exempt from the
// TLS requirement.
func IsLocalHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.HasPrefix(host, "/") {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
