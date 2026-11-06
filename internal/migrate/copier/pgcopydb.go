package copier

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/wisnuvb/lockkeeper/internal/migrate"
)

type pgcopydb struct{ cfg Config }

func (p *pgcopydb) Name() string { return KindPgcopydb }

// The official image prints "pgcopydb version " with nothing after it (observed
// with v0.18 in the Phase 3 spike), so an empty version is a real case.
//
// stdout and stderr arrive interleaved, so the line may be glued to a log line
// ("pgcopydb version 2026-11-06 ... INFO"): only a token that looks like a
// release number counts as the version.
var pgcopydbVersion = regexp.MustCompile(`pgcopydb version(?: ([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b)?`)

// forbiddenFlags must never reach pgcopydb (ADR 0002, SPEC 9). A test asserts
// that no code path builds them.
var forbiddenFlags = []string{"--restart", "--resume", "--follow", "--drop-if-exists", "--replicate-ddl", "--create-slot", "--slot-name", "--not-consistent"}

func (p *pgcopydb) Check(ctx context.Context, sourceMajor int) error {
	r := p.cfg.Runner
	run, err := r.Begin("version-pgcopydb", nil)
	if err != nil {
		return err
	}
	res, err := run.Capture(ctx, p.cfg.Pgcopydb, []string{"--version"}, nil)
	run.Close()
	if err != nil {
		return fmt.Errorf("pgcopydb is not usable: %w", err)
	}
	all := pgcopydbVersion.FindAllStringSubmatch(res.Output, -1)
	if len(all) == 0 {
		return fmt.Errorf("cannot determine the pgcopydb version from %q", firstLine(res.Output))
	}
	got := ""
	for _, m := range all { // the log line "Running pgcopydb version  from" has none
		if m[1] != "" {
			got = m[1]
			break
		}
	}
	if p.cfg.PinnedVersion != "" && got != p.cfg.PinnedVersion && !p.cfg.AllowUntested {
		if got == "" {
			return fmt.Errorf("this pgcopydb build does not report its version (the official container image does not); Lockkeeper is pinned to %s: use a package build that reports it, or pass --allow-untested-pgcopydb if you pinned the image by digest", p.cfg.PinnedVersion)
		}
		return fmt.Errorf("pgcopydb %s is not the pinned version %s; pass --allow-untested-pgcopydb to use it anyway", got, p.cfg.PinnedVersion)
	}
	return checkClientTool(ctx, r, "pg_dump", sourceMajor)
}

func (p *pgcopydb) args(in migrate.CopyInput, srcURI, tgtURI string) []string {
	jobs := func(n int) string {
		if n <= 0 {
			n = 4
		}
		return strconv.Itoa(n)
	}
	a := []string{"clone",
		"--source", srcURI, "--target", tgtURI,
		"--dir", in.WorkDir,
		"--snapshot", in.SnapshotID,
		"--table-jobs", jobs(in.TableJobs), "--index-jobs", jobs(in.IndexJobs),
	}
	if in.NoOwner {
		a = append(a, "--no-owner")
	}
	return a
}

func (p *pgcopydb) Describe(in migrate.CopyInput) []string {
	src, tgt := endpointURI(in.Source), endpointURI(in.Target)
	return []string{p.cfg.Pgcopydb + " " + strings.Join(p.args(in, src, tgt), " ")}
}

func (p *pgcopydb) Copy(ctx context.Context, in migrate.CopyInput) error {
	if in.SnapshotID == "" {
		return fmt.Errorf("pgcopydb: no snapshot id: refusing to copy without a consistent snapshot")
	}
	if err := ensureWorkDir(in.WorkDir); err != nil {
		return err
	}
	if es, err := os.ReadDir(in.WorkDir); err != nil || len(es) > 0 {
		return fmt.Errorf("pgcopydb: work directory %s is not empty: every attempt needs a fresh one (never --restart)", in.WorkDir)
	}
	run, err := p.cfg.Runner.Begin("pgcopydb", endpoints(in), in.WorkDir)
	if err != nil {
		return err
	}
	defer run.Close()
	args := p.args(in, run.Endpoint(0).URI(), run.Endpoint(1).URI())
	for _, a := range args {
		for _, f := range forbiddenFlags {
			if a == f {
				return fmt.Errorf("internal error: forbidden pgcopydb flag %s", f)
			}
		}
	}
	// pgcopydb keeps its state in --dir and writes under $HOME; both are private.
	_, err = run.Exec(ctx, p.cfg.Pgcopydb, args, map[string]string{"TMPDIR": in.WorkDir})
	return err
}
