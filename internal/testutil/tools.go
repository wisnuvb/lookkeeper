package testutil

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	// PgcopydbBaseImage is the official pgcopydb image, pinned by digest (the
	// multi-architecture index digest of dimitri/pgcopydb:v0.18, verified
	// 2026-11-06). Its pg_dump is 16, which refuses a PostgreSQL 17 source, so
	// tests derive PgcopydbImage from it.
	PgcopydbBaseImage = "dimitri/pgcopydb:v0.18@sha256:8d93b05602689a34cb66b0f2dc090c175646a6b2ce2c7d9804001703ae6218f8"
	// PgcopydbImage is PgcopydbBaseImage plus the PostgreSQL 17 client tools,
	// with their directory first on PATH. pgcopydb runs the pg_dump and
	// pg_restore it finds there, which makes sources up to 17 (and targets 17)
	// work. It is built locally by EnsurePgcopydbImage.
	PgcopydbImage = "lockkeeper-test/pgcopydb:0.18-pg17client"
	// PGToolsImage provides pg_dump, pg_restore and psql 17.
	PGToolsImage = "postgres:17-alpine"
)

const pgcopydbDockerfile = `FROM ` + PgcopydbBaseImage + `
USER root
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends postgresql-client-17 && rm -rf /var/lib/apt/lists/*
USER docker
ENV PATH=/usr/lib/postgresql/17/bin:/usr/local/bin:/usr/bin:/bin
`

// EnsurePgcopydbImage builds PgcopydbImage if it is not present yet. Building
// needs network access to the Debian/PGDG mirrors once; later runs reuse it.
func EnsurePgcopydbImage(t testing.TB) {
	t.Helper()
	requireDocker(t)
	if exec.Command("docker", "image", "inspect", PgcopydbImage).Run() == nil {
		return
	}
	cmd := exec.Command("docker", "build", "-q", "-t", PgcopydbImage, "-")
	cmd.Stdin = strings.NewReader(pgcopydbDockerfile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", PgcopydbImage, err, out)
	}
}

// ToolRun describes one command-line tool run in a throwaway container.
type ToolRun struct {
	Image string
	// Entrypoint is the executable inside the image (pg_dump, pgcopydb, ...).
	Entrypoint string
	Args       []string
	// Dir is a host directory mounted at the same path inside the container and
	// used as the working directory. It must be private to the test.
	Dir string
	// Env is the complete environment of the tool (nothing is inherited).
	Env     map[string]string
	Timeout time.Duration
}

// RunTool runs the tool on the network and returns its combined output. The
// container is removed afterwards. The container runs as the calling user so
// files it writes into Dir are owned by the test.
func (n *Net) RunTool(t testing.TB, r ToolRun) (string, error) {
	t.Helper()
	requireDocker(t)
	if r.Timeout == 0 {
		r.Timeout = 5 * time.Minute
	}
	name := "lk-tool-" + randomHex(t, 4)
	args := []string{"run", "--rm", "--name", name, "--label", LabelKey + "=" + LabelValue, "--network", n.Name}
	if u, err := user.Current(); err == nil && u.Uid != "" {
		args = append(args, "--user", u.Uid+":"+u.Gid)
	}
	if r.Dir != "" {
		args = append(args, "-v", r.Dir+":"+r.Dir, "-w", r.Dir)
	}
	keys := make([]string, 0, len(r.Env))
	for k := range r.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "-e", k+"="+r.Env[k])
	}
	args = append(args, "--entrypoint", r.Entrypoint, r.Image)
	args = append(args, r.Args...)

	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	if ctx.Err() != nil {
		_ = exec.Command("docker", "rm", "-f", name).Run()
	}
	return buf.String(), err
}

// WritePassfile writes a libpq password file with 0600 into dir and returns its
// path. Each entry is host, port, database, user, password.
func WritePassfile(t testing.TB, dir string, entries ...[5]string) string {
	t.Helper()
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "%s:%s:%s:%s:%s\n", e[0], e[1], e[2], e[3], strings.NewReplacer(`\`, `\\`, `:`, `\:`).Replace(e[4]))
	}
	path := dir + "/pgpass"
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
