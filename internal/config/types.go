// Package config loads and validates Lockkeeper's YAML configuration.
//
// Parsing is strict: unknown keys are errors, inline plaintext secrets are
// errors, and weak TLS settings must be opted into explicitly.
package config

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/wisnuvb/lockkeeper/internal/secret"
)

// Config is the root of the configuration file.
type Config struct {
	Version   int                 `yaml:"version"`
	Databases map[string]Database `yaml:"databases"`
	Monitor   Monitor             `yaml:"monitor"`
	Alerts    Alerts              `yaml:"alerts"`
	Store     Store               `yaml:"store"`
}

// Database is one monitored database server. A connection has no "source" or
// "target" role: that is chosen per operation.
type Database struct {
	Engine   string     `yaml:"engine"`
	Host     string     `yaml:"host"`
	Port     int        `yaml:"port"`
	Database string     `yaml:"database"`
	User     string     `yaml:"user"`
	Password secret.Ref `yaml:"password"`
	TLS      TLS        `yaml:"tls"`
	// ReadOnly is accepted for readability; monitoring sessions are always
	// read-only and false is rejected.
	ReadOnly *bool `yaml:"read_only"`
	// DiskTotalGB lets absolute WAL thresholds be judged against disk size when
	// no CloudWatch reader is configured.
	DiskTotalGB float64     `yaml:"disk_total_gb"`
	CloudWatch  *CloudWatch `yaml:"cloudwatch"`
}

// TLS describes transport security for a database connection.
type TLS struct {
	// Mode is verify-full (default), verify-ca, require or disable.
	Mode   string `yaml:"mode"`
	CAFile string `yaml:"ca_file"`
	// AllowInsecure must be true for require/disable on non-loopback hosts.
	AllowInsecure bool `yaml:"allow_insecure"`
}

// CloudWatch configures the optional RDS metrics reader. AWS credentials come
// from the standard AWS credential chain and are never stored by Lockkeeper.
type CloudWatch struct {
	Region       string `yaml:"region"`
	DBInstanceID string `yaml:"db_instance_id"`
}

// Monitor configures collection.
type Monitor struct {
	Interval     Duration   `yaml:"interval"`
	QueryTimeout Duration   `yaml:"query_timeout"`
	Retention    Duration   `yaml:"retention"`
	Targets      []string   `yaml:"targets"`
	Heartbeat    *Heartbeat `yaml:"heartbeat"`
}

// Heartbeat is an optional dead-man ping: Lockkeeper GETs the URL on every
// interval, so an external service can alert when Lockkeeper itself stops.
type Heartbeat struct {
	URL      secret.Ref `yaml:"url"`
	Interval Duration   `yaml:"interval"`
}

// Alerts configures notification channels, routing and rule overrides.
type Alerts struct {
	Channels Channels                `yaml:"channels"`
	Routes   []Route                 `yaml:"routes"`
	Rules    map[string]RuleOverride `yaml:"rules"`
	// RepeatInterval re-sends a still-active alert. Default 4h.
	RepeatInterval Duration `yaml:"repeat_interval"`
	// Cooldown suppresses a new notification for an alert that just resolved,
	// to damp flapping. Default 5m.
	Cooldown Duration `yaml:"cooldown"`
}

// Channels lists the configured notifiers.
type Channels struct {
	Telegram *Telegram `yaml:"telegram"`
	Slack    *Slack    `yaml:"slack"`
	Email    *Email    `yaml:"email"`
}

// Telegram posts through a bot.
type Telegram struct {
	BotToken secret.Ref `yaml:"bot_token"`
	ChatID   string     `yaml:"chat_id"`
}

// Slack posts through an incoming webhook.
type Slack struct {
	WebhookURL secret.Ref `yaml:"webhook_url"`
}

// Email sends alerts through an SMTP server. Port defaults to 587 (465 for
// tls: tls) and TLS to starttls.
type Email struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	// TLS is starttls (default), tls (implicit TLS) or none.
	TLS      string     `yaml:"tls"`
	Username string     `yaml:"username"`
	Password secret.Ref `yaml:"password"`
	From     string     `yaml:"from"`
	To       []string   `yaml:"to"`
	// CAFile is an optional PEM bundle used instead of the system roots to
	// verify the server certificate.
	CAFile string `yaml:"ca_file"`
	// AllowInsecure must be true for tls: none towards a non-loopback host.
	AllowInsecure bool `yaml:"allow_insecure"`
}

// Route sends matching events to channels.
type Route struct {
	Match RouteMatch `yaml:"match"`
	To    []string   `yaml:"to"`
}

// RouteMatch selects events; empty means all.
type RouteMatch struct {
	Severity []string `yaml:"severity"`
}

// RuleOverride replaces default thresholds for a rule. Nil fields keep defaults.
type RuleOverride struct {
	Warning     *Threshold `yaml:"warning"`
	Critical    *Threshold `yaml:"critical"`
	ForWarning  *Duration  `yaml:"for_warning"`
	ForCritical *Duration  `yaml:"for_critical"`
}

// Store configures local state.
type Store struct {
	Path string `yaml:"path"`
}

// Duration is a time.Duration that also understands days ("14d") and weeks ("2w").
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

var dayWeek = regexp.MustCompile(`^(?:(\d+)w)?(?:(\d+)d)?(.*)$`)

// ParseDuration parses Go durations extended with w and d units.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	m := dayWeek.FindStringSubmatch(s)
	var total time.Duration
	if m[1] != "" {
		w, _ := strconv.Atoi(m[1])
		total += time.Duration(w) * 7 * 24 * time.Hour
	}
	if m[2] != "" {
		d, _ := strconv.Atoi(m[2])
		total += time.Duration(d) * 24 * time.Hour
	}
	if rest := m[3]; rest != "" {
		r, err := time.ParseDuration(rest)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		total += r
	} else if m[1] == "" && m[2] == "" {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return total, nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: duration must be a string such as 30s, 5m, 14d", n.Line)
	}
	v, err := ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

// Threshold is a numeric rule threshold that also accepts byte sizes ("5GiB").
type Threshold float64

// F returns the value as a float64.
func (t Threshold) F() float64 { return float64(t) }

var sizeRe = regexp.MustCompile(`(?i)^\s*([0-9]+(?:\.[0-9]+)?)\s*(b|[kmgt]i?b?)?\s*$`)

// ParseSize parses a byte size. KB/MB/GB are decimal; KiB/MiB/GiB are binary.
// A bare "K", "M", "G", "T" is treated as binary.
func ParseSize(s string) (float64, error) {
	m := sizeRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	f, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	mult, ok := sizeUnits[strings.ToLower(m[2])]
	if !ok {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return f * mult, nil
}

// sizeUnits maps a lower-cased unit to its multiplier. KB/MB/GB/TB are decimal,
// KiB/MiB/GiB/TiB binary; a bare K/M/G/T is binary.
var sizeUnits = map[string]float64{
	"": 1, "b": 1,
	"k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40,
	"ki": 1 << 10, "mi": 1 << 20, "gi": 1 << 30, "ti": 1 << 40,
	"kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30, "tib": 1 << 40,
	"kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12,
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (t *Threshold) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: threshold must be a number or a size such as 5GiB", n.Line)
	}
	if f, err := strconv.ParseFloat(n.Value, 64); err == nil {
		*t = Threshold(f)
		return nil
	}
	f, err := ParseSize(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*t = Threshold(f)
	return nil
}
