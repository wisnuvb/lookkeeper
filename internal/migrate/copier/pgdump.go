package copier

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/wisnuvb/lockkeeper/internal/migrate"
	"github.com/wisnuvb/lockkeeper/internal/migrate/runner"
)

type pgdump struct{ cfg Config }

func (p *pgdump) Name() string { return KindPgdump }

func (p *pgdump) Check(ctx context.Context, sourceMajor int) error {
	if err := checkClientTool(ctx, p.cfg.Runner, p.cfg.PgDump, sourceMajor); err != nil {
		return err
	}
	return checkClientTool(ctx, p.cfg.Runner, p.cfg.PgRestore, sourceMajor)
}

func (p *pgdump) dumpArgs(in migrate.CopyInput, srcURI, dumpDir string) []string {
	a := []string{"--snapshot=" + in.SnapshotID, "-Fd", "-j", jobs(in.TableJobs), "--no-password", "--no-publications", "-f", dumpDir}
	if in.NoOwner {
		a = append(a, "--no-owner")
	}
	return append(a, srcURI)
}

func (p *pgdump) restoreArgs(in migrate.CopyInput, tgtURI, dumpDir string) []string {
	a := []string{"-j", jobs(in.IndexJobs), "--exit-on-error", "--no-password", "-d", tgtURI}
	if in.NoOwner {
		a = append(a, "--no-owner")
	}
	return append(a, dumpDir)
}

func jobs(n int) string {
	if n <= 0 {
		n = 4
	}
	return strconv.Itoa(n)
}

func (p *pgdump) Describe(in migrate.CopyInput) []string {
	dump := filepath.Join(in.WorkDir, "dump")
	return []string{
		p.cfg.PgDump + " " + strings.Join(p.dumpArgs(in, endpointURI(in.Source), dump), " "),
		p.cfg.PgRestore + " " + strings.Join(p.restoreArgs(in, endpointURI(in.Target), dump), " "),
	}
}

func (p *pgdump) Copy(ctx context.Context, in migrate.CopyInput) error {
	if in.SnapshotID == "" {
		return fmt.Errorf("pg_dump: no snapshot id: refusing to copy without a consistent snapshot")
	}
	if err := ensureWorkDir(in.WorkDir); err != nil {
		return err
	}
	dumpDir := filepath.Join(in.WorkDir, "dump")
	// The directory-format dump holds table data: it is removed whatever happens.
	defer os.RemoveAll(dumpDir)
	run, err := p.cfg.Runner.Begin("pgdump", endpoints(in), in.WorkDir)
	if err != nil {
		return err
	}
	defer run.Close()
	if _, err := run.Exec(ctx, p.cfg.PgDump, p.dumpArgs(in, run.Endpoint(0).URI(), dumpDir), map[string]string{"TMPDIR": in.WorkDir}); err != nil {
		return fmt.Errorf("dump inside the snapshot: %w", err)
	}
	if _, err := run.Exec(ctx, p.cfg.PgRestore, p.restoreArgs(in, run.Endpoint(1).URI(), dumpDir), map[string]string{"TMPDIR": in.WorkDir}); err != nil {
		return fmt.Errorf("restore into the target: %w", err)
	}
	return nil
}

// endpointURI is the passwordless URI of a migrate endpoint (for Describe).
func endpointURI(e migrate.Endpoint) string {
	return runner.Endpoint{Host: e.Host, Port: e.Port, Database: e.Database, User: e.User, TLSMode: e.TLSMode, CAFile: e.CAFile}.URI()
}
