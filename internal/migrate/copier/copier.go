// Package copier implements migrate.Copier: the bulk copy of one database
// inside a snapshot that another connection exported (ADR 0002).
//
// Two implementations exist behind the same interface, both proven by the
// Phase 3 spike (docs/PHASE3-NOTES.md):
//
//   - pgcopydb: `pgcopydb clone --snapshot ID` (parallel table copy, indexes
//     after data). The default.
//   - pgdump: `pg_dump --snapshot=ID -Fd -j N` followed by `pg_restore -j N`.
//
// Neither is ever started with options that restart or reuse earlier state
// (`--restart`, `--resume`, `--drop-if-exists`), neither follows changes
// (`--follow`: CDC is native logical replication), and neither is given a
// password on argv.
package copier

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/wisnuvb/lockkeeper/internal/migrate"
	"github.com/wisnuvb/lockkeeper/internal/migrate/runner"
)

// Kinds.
const (
	KindPgcopydb = "pgcopydb"
	KindPgdump   = "pgdump"
)

// Config selects and configures a Copier.
type Config struct {
	Kind   string
	Runner *runner.Runner
	// Pgcopydb, PgDump and PgRestore are tool names or paths (default: the bare
	// name, searched in the runner's PATH).
	Pgcopydb, PgDump, PgRestore string
	// PinnedVersion is the pgcopydb version Lockkeeper was tested with. Any other
	// version, or one that cannot be determined, is refused unless AllowUntested.
	PinnedVersion string
	AllowUntested bool
}

// New returns the Copier for cfg.
func New(cfg Config) (migrate.Copier, error) {
	if cfg.Runner == nil {
		return nil, fmt.Errorf("copier: a runner is required")
	}
	if cfg.Pgcopydb == "" {
		cfg.Pgcopydb = "pgcopydb"
	}
	if cfg.PgDump == "" {
		cfg.PgDump = "pg_dump"
	}
	if cfg.PgRestore == "" {
		cfg.PgRestore = "pg_restore"
	}
	switch cfg.Kind {
	case KindPgcopydb, "":
		return &pgcopydb{cfg: cfg}, nil
	case KindPgdump:
		return &pgdump{cfg: cfg}, nil
	default:
		return nil, fmt.Errorf("unknown copier %q (use %s or %s)", cfg.Kind, KindPgcopydb, KindPgdump)
	}
}

// endpoints converts migrate endpoints for the runner.
func endpoints(in migrate.CopyInput) []runner.Endpoint {
	conv := func(e migrate.Endpoint) runner.Endpoint {
		return runner.Endpoint{Host: e.Host, Port: e.Port, Database: e.Database, User: e.User, Password: e.Password, TLSMode: e.TLSMode, CAFile: e.CAFile}
	}
	return []runner.Endpoint{conv(in.Source), conv(in.Target)}
}

// ensureWorkDir creates the private work directory.
func ensureWorkDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("a work directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create work directory: %w", err)
	}
	return os.Chmod(dir, 0o700)
}

var clientMajor = regexp.MustCompile(`(?m)^(?:pg_dump|pg_restore) \(PostgreSQL\) (\d+)`)

// checkClientTool runs `<tool> --version` and requires its major version to be
// at least the source's: a pg_dump older than the server refuses to dump it.
func checkClientTool(ctx context.Context, r *runner.Runner, tool string, sourceMajor int) error {
	run, err := r.Begin("version-"+tool, nil)
	if err != nil {
		return err
	}
	defer run.Close()
	res, err := run.Capture(ctx, tool, []string{"--version"}, nil)
	if err != nil {
		return fmt.Errorf("%s is not usable: %w", tool, err)
	}
	m := clientMajor.FindStringSubmatch(res.Output)
	if m == nil {
		return fmt.Errorf("cannot determine the version of %s from %q", tool, firstLine(res.Output))
	}
	major, _ := strconv.Atoi(m[1])
	if sourceMajor > 0 && major < sourceMajor {
		return fmt.Errorf("%s is PostgreSQL %d but the source server is %d: it would refuse with \"server version mismatch\"; install the PostgreSQL %d (or newer) client tools and put them first on the tool PATH", tool, major, sourceMajor, sourceMajor)
	}
	return nil
}

func firstLine(s string) string {
	for i, c := range s {
		if c == '\n' {
			return s[:i]
		}
	}
	return s
}
