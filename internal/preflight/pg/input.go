// Package pg implements the PostgreSQL migration pre-flight checks (SPEC 8.1)
// and the consequences of ADR 0002 (native logical replication for CDC).
//
// The package is strictly read-only. It decides on data that was already read
// (inventory.Server and Facts); the only SQL it contains is in GatherFacts, and
// that is read-only too. What cannot be verified without writing (for example
// whether the target can reach the source) is reported as a finding with the
// command the operator can run by hand; nothing is created to find out.
package pg

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/inventory"
)

// Endpoint identifies a configured connection. It never holds a password.
type Endpoint struct {
	Host     string
	Port     int
	Database string
	User     string
	// TLSMode is the configured mode (verify-full, verify-ca, require, disable).
	TLSMode string
}

// Local reports whether the host is loopback or a unix socket, which is exempt
// from the TLS requirement (ADR 0004).
func (e Endpoint) Local() bool { return config.IsLocalHost(e.Host) }

// Address returns host:port.
func (e Endpoint) Address() string {
	port := e.Port
	if port == 0 {
		port = 5432
	}
	return net.JoinHostPort(e.Host, strconv.Itoa(port))
}

// PsqlCommand returns a psql invocation that checks reachability and TLS from
// the machine it is run on. It contains no password: psql prompts for it.
func (e Endpoint) PsqlCommand() string {
	db := e.Database
	if db == "" {
		db = "postgres"
	}
	u := url.URL{
		Scheme:   "postgresql",
		User:     url.User(e.User),
		Host:     e.Address(),
		Path:     "/" + db,
		RawQuery: "sslmode=verify-full",
	}
	return "psql " + shellQuote(u.String()) + ` -c "SELECT 1"`
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// Side is everything the checks know about one server.
type Side struct {
	// Name is the configured connection name.
	Name     string
	Endpoint Endpoint
	// ConnectError is why Lockkeeper could not connect (already redacted); empty
	// when it did. Server is nil in that case.
	ConnectError   string
	ConnectLatency time.Duration
	Server         *inventory.Server
	Facts          Facts
}

// Reachable reports whether the inventory was collected.
func (s Side) Reachable() bool { return s.Server != nil }

// Thresholds are the retained-WAL limits for existing replication slots. They
// default to the monitor rules (WARN above 5 GiB, BLOCKER above 20 GiB), and the
// service passes the effective values including config overrides.
type Thresholds struct {
	SlotWarnBytes    int64
	SlotBlockerBytes int64
}

// DefaultThresholds matches the default pg.slot.retained_wal_bytes rule.
var DefaultThresholds = Thresholds{SlotWarnBytes: 5 << 30, SlotBlockerBytes: 20 << 30}

// Input is what Run decides on. The source and target are roles for this run
// only; a configured connection has no fixed role.
type Input struct {
	Source, Target Side
	Thresholds     Thresholds
}

// databases returns the names of the databases inspected on the source.
func (in Input) databases() []string {
	if in.Source.Server == nil {
		return nil
	}
	out := make([]string, 0, len(in.Source.Server.Databases))
	for _, d := range in.Source.Server.Databases {
		out = append(out, d.Name)
	}
	return out
}
