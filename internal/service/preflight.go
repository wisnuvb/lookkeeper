package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/dbconn"
	"github.com/wisnuvb/lockkeeper/internal/inventory"
	"github.com/wisnuvb/lockkeeper/internal/model"
	"github.com/wisnuvb/lockkeeper/internal/preflight"
	pfpg "github.com/wisnuvb/lockkeeper/internal/preflight/pg"
)

// inventoryStatementTimeout is the per-statement budget of inventory sessions.
// It is longer than the monitor's query timeout because catalog queries on
// servers with many tables are heavier than the monitor's counters.
const inventoryStatementTimeout = 30 * time.Second

// DiscoveryOptions selects what inventory and pre-flight look at.
type DiscoveryOptions struct {
	// Databases restricts the run to these databases (default: all
	// non-template databases except rdsadmin, up to MaxDatabases).
	Databases []string
	// MaxDatabases caps how many databases are inspected (default 50). Going
	// over it is an error, never a silent truncation.
	MaxDatabases int
}

func (o DiscoveryOptions) inventory(databases []string) inventory.Options {
	return inventory.Options{Databases: databases, MaxDatabases: o.MaxDatabases}
}

// requirePostgresEngine refuses connections of another engine for Postgres-only
// operations.
func (s *Service) requirePostgresEngine(name string) error {
	if e := s.cfg.Databases[name].Engine; e != "" && e != config.EnginePostgres {
		return fmt.Errorf("%q is a %s database; this command supports PostgreSQL only", name, e)
	}
	return nil
}

// openInventoryDB opens a read-only session to a configured database. database
// overrides only the database name of the configured connection (empty keeps
// it); host, port, role, password and TLS policy are unchanged. Errors are
// redacted.
func (s *Service) openInventoryDB(ctx context.Context, name, database string) (*pgx.Conn, error) {
	db, ok := s.cfg.Databases[name]
	if !ok {
		return nil, fmt.Errorf("unknown database %q", name)
	}
	pw, err := s.resolveSecret(ctx, db.Password, "password for "+name)
	if err != nil {
		return nil, err
	}
	timeout := s.cfg.Monitor.QueryTimeout.D()
	if timeout < inventoryStatementTimeout {
		timeout = inventoryStatementTimeout
	}
	spec := dbconn.SpecFromConfig(db, pw, timeout)
	if database != "" {
		spec.Database = database
	}
	conn, err := s.deps.OpenPG(ctx, spec)
	if err != nil {
		return nil, s.redactErr(err)
	}
	return conn, nil
}

func (s *Service) inventoryOpener(name string) inventory.Opener {
	return func(ctx context.Context, database string) (inventory.Conn, error) {
		return s.openInventoryDB(ctx, name, database)
	}
}

func (s *Service) pfEndpoint(name string) pfpg.Endpoint {
	db := s.cfg.Databases[name]
	return pfpg.Endpoint{Host: db.Host, Port: db.Port, Database: db.Database, User: db.User, TLSMode: db.TLS.Mode}
}

func pfCloseConn(c *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = c.Close(ctx)
}

// Inventory discovers one server: version, settings, roles, slots and the
// selected databases. It is strictly read-only; every session is forced
// read-only and only catalog views and functions are queried.
func (s *Service) Inventory(ctx context.Context, source string, opts DiscoveryOptions) (*inventory.Server, error) {
	if err := s.validateTargets([]string{source}); err != nil {
		return nil, err
	}
	if err := s.requirePostgresEngine(source); err != nil {
		return nil, err
	}
	conn, err := s.openInventoryDB(ctx, source, "")
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", source, err)
	}
	defer pfCloseConn(conn)
	srv, err := inventory.Collect(ctx, conn, s.inventoryOpener(source), opts.inventory(opts.Databases))
	if err != nil {
		return nil, s.redactErr(err)
	}
	if len(srv.NotFound) > 0 {
		return nil, fmt.Errorf("database(s) not found on %s: %s", source, strings.Join(srv.NotFound, ", "))
	}
	return srv, nil
}

// preflightSide connects to one server, reads facts and the inventory, and returns what
// the checks need. A failure to connect or inspect is recorded on the Side (so
// the report can show it) and is not an error, except for an explicit cap
// violation, which the operator must resolve.
func (s *Service) preflightSide(ctx context.Context, name string, databases []string, opts DiscoveryOptions) (pfpg.Side, error) {
	sd := pfpg.Side{Name: name, Endpoint: s.pfEndpoint(name)}
	start := time.Now()
	conn, err := s.openInventoryDB(ctx, name, "")
	if err != nil {
		sd.ConnectError = pfOneLine(err.Error())
		return sd, nil
	}
	defer pfCloseConn(conn)
	sd.ConnectLatency = time.Since(start)

	sd.Facts = pfpg.GatherFacts(ctx, conn)
	srv, err := inventory.Collect(ctx, conn, s.inventoryOpener(name), opts.inventory(databases))
	if err != nil {
		if errors.Is(err, inventory.ErrTooManyDatabases) {
			return sd, fmt.Errorf("%s: %w", name, err)
		}
		sd.ConnectError = "connected, but the inventory failed: " + pfOneLine(s.redactErr(err).Error())
		return sd, nil
	}
	sd.Server = srv
	return sd, nil
}

// PreflightPG runs the PostgreSQL migration pre-flight between two configured
// connections. source and target are roles for this run only. It is strictly
// read-only on both servers.
func (s *Service) PreflightPG(ctx context.Context, source, target string, opts DiscoveryOptions) (*preflight.Report, error) {
	if err := s.validateTargets([]string{source, target}); err != nil {
		return nil, err
	}
	if source == target {
		return nil, fmt.Errorf("--source and --target must be different connections (both are %q)", source)
	}
	for _, n := range []string{source, target} {
		if err := s.requirePostgresEngine(n); err != nil {
			return nil, err
		}
	}
	if a, b := s.cfg.Databases[source], s.cfg.Databases[target]; pfSameServer(a, b) {
		return nil, fmt.Errorf("%q and %q point at the same server (%s); a migration needs two different servers", source, target, pfHostPort(a))
	}

	src, err := s.preflightSide(ctx, source, opts.Databases, opts)
	if err != nil {
		return nil, err
	}
	if src.Server != nil && len(src.Server.NotFound) > 0 {
		return nil, fmt.Errorf("database(s) not found on the source %s: %s", source, strings.Join(src.Server.NotFound, ", "))
	}
	// The target is inspected for the same databases the source contributes.
	tgtDBs := opts.Databases
	if src.Server != nil {
		tgtDBs = nil
		for _, d := range src.Server.Databases {
			tgtDBs = append(tgtDBs, d.Name)
		}
		if len(tgtDBs) == 0 {
			return nil, fmt.Errorf("the source %s has no database to migrate (rdsadmin and templates are never migrated)", source)
		}
	}
	tgt, err := s.preflightSide(ctx, target, tgtDBs, opts)
	if err != nil {
		return nil, err
	}
	return pfpg.Run(pfpg.Input{Source: src, Target: tgt, Thresholds: s.slotThresholds()}), nil
}

// slotThresholds takes the retained-WAL limits from the effective monitor rule,
// so the pre-flight and the monitor agree even when the config overrides them.
func (s *Service) slotThresholds() pfpg.Thresholds {
	th := pfpg.DefaultThresholds
	for _, r := range s.rules {
		if r.Metric != rules.MetricPGSlotRetainedWAL {
			continue
		}
		for _, l := range r.Levels {
			switch l.Severity {
			case model.SeverityWarning:
				th.SlotWarnBytes = int64(l.Threshold)
			case model.SeverityCritical:
				th.SlotBlockerBytes = int64(l.Threshold)
			}
		}
	}
	return th
}

func pfHostPort(d config.Database) string {
	port := d.Port
	if port == 0 {
		port = 5432
	}
	return net.JoinHostPort(strings.ToLower(d.Host), fmt.Sprint(port))
}

// pfSameServer reports whether two configured connections address the same
// host and port. Comparing names is not enough: an alias of the same server
// under another name would otherwise pass as a "different" target.
func pfSameServer(a, b config.Database) bool { return pfHostPort(a) == pfHostPort(b) }

// pfOneLine collapses whitespace so an error fits on one line of a report.
func pfOneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
