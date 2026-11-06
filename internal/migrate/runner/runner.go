// Package runner runs external tools (pgcopydb, pg_dump, pg_restore) the way
// ADR 0004 requires:
//
//   - the child starts from an empty environment (PATH, a locale and PGPASSFILE,
//     nothing inherited), so ambient PG* variables and secrets cannot leak in;
//   - passwords are never on argv: endpoints are passed as passwordless URIs and
//     the secrets live in a 0600 PGPASSFILE inside a 0700 per-run directory that
//     is removed when the run ends;
//   - the child gets its own process group; on cancellation the group receives
//     SIGTERM and, after a grace period, SIGKILL;
//   - everything the child prints goes through the redaction writer into a log
//     file (0600, in a 0700 directory) and never to our own stdout or stderr.
//
// A Launcher builds the actual command, so tests can run the same tools inside
// throwaway containers (the host does not have matching PostgreSQL client tools)
// without changing anything else.
package runner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/redact"
	"github.com/wisnuvb/lockkeeper/internal/secret"
)

// Endpoint is a database a tool connects to.
type Endpoint struct {
	Host     string
	Port     int
	Database string
	User     string
	Password secret.Value
	TLSMode  string
	CAFile   string
}

// URI returns the connection URI without any password.
func (e Endpoint) URI() string {
	port := e.Port
	if port == 0 {
		port = 5432
	}
	u := url.URL{Scheme: "postgres", User: url.User(e.User), Host: net.JoinHostPort(e.Host, strconv.Itoa(port)), Path: "/" + e.Database}
	q := url.Values{}
	if e.TLSMode != "" {
		q.Set("sslmode", e.TLSMode)
	}
	if e.CAFile != "" {
		q.Set("sslrootcert", e.CAFile)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Invocation is one prepared process start.
type Invocation struct {
	Tool string
	Args []string
	// Env is the complete environment as KEY=VALUE.
	Env []string
	// Dir is the working directory and the per-run directory.
	Dir string
	// Dirs are further host directories the tool reads or writes (its work
	// directory). A containerised Launcher mounts them.
	Dirs []string
}

// Launcher builds commands. Local runs the tool on this machine.
type Launcher interface {
	// Command returns the command for inv. Runner sets the process group and
	// output streams.
	Command(inv Invocation) *exec.Cmd
	// MapEndpoint translates an endpoint as Lockkeeper reaches it into the one
	// the tool process must use (identity for Local).
	MapEndpoint(Endpoint) (Endpoint, error)
	// Resolve turns a tool name into what Command needs, searching path (the
	// PATH the child will get), and fails if the tool is not there.
	Resolve(name, path string) (string, error)
	// Cleanup is called after the process ended, to remove anything the
	// Launcher created besides the process (a container).
	Cleanup(inv Invocation)
}

// Local runs tools directly on this machine.
type Local struct{}

// Resolve implements Launcher: a name without a slash is searched in path.
func (Local) Resolve(name, path string) (string, error) {
	if strings.Contains(name, "/") {
		if fi, err := os.Stat(name); err != nil || fi.IsDir() {
			return "", fmt.Errorf("tool %s not found", name)
		}
		return name, nil
	}
	for _, dir := range filepath.SplitList(path) {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found in PATH %q", name, path)
}

// Command implements Launcher.
func (Local) Command(inv Invocation) *exec.Cmd {
	cmd := exec.Command(inv.Tool, inv.Args...) //nolint:gosec // the tool path is configured, not user-supplied text
	cmd.Dir = inv.Dir
	cmd.Env = inv.Env
	return cmd
}

// MapEndpoint implements Launcher.
func (Local) MapEndpoint(e Endpoint) (Endpoint, error) { return e, nil }

// Cleanup implements Launcher.
func (Local) Cleanup(Invocation) {}

// Runner starts runs.
type Runner struct {
	// BaseDir holds the per-run directories (created 0700).
	BaseDir string
	// LogDir receives one log file per process (created 0700).
	LogDir   string
	Launcher Launcher
	Redactor *redact.Redactor
	// Grace is how long a process group gets after SIGTERM before SIGKILL.
	Grace time.Duration
	// Path is the PATH the child gets. Empty means a minimal system PATH.
	Path string
}

const defaultPath = "/usr/local/bin:/usr/bin:/bin"

func (r *Runner) launcher() Launcher {
	if r.Launcher == nil {
		return Local{}
	}
	return r.Launcher
}

func (r *Runner) grace() time.Duration {
	if r.Grace <= 0 {
		return 10 * time.Second
	}
	return r.Grace
}

func (r *Runner) redactor() *redact.Redactor {
	if r.Redactor == nil {
		return redact.New()
	}
	return r.Redactor
}

// ensureDir creates dir with mode 0700 and refuses an existing one that group or
// others can access.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s has mode %#o; it must not be accessible by group or others (chmod 700)", dir, fi.Mode().Perm())
	}
	return nil
}

// Run is one set of tool invocations sharing a private directory and passfile.
type Run struct {
	// Dir is the private per-run directory (0700); the passfile is in it.
	Dir      string
	PassFile string

	r    *Runner
	name string
	eps  []Endpoint
	dirs []string
	seq  atomic.Int32
}

// Begin creates the per-run directory and the passfile for the endpoints. Their
// passwords are registered with the redactor. Close removes everything.
func (r *Runner) Begin(name string, eps []Endpoint, dirs ...string) (*Run, error) {
	if r.BaseDir == "" || r.LogDir == "" {
		return nil, errors.New("runner: BaseDir and LogDir are required")
	}
	if err := ensureDir(r.BaseDir); err != nil {
		return nil, err
	}
	if err := ensureDir(r.LogDir); err != nil {
		return nil, err
	}
	SweepStale(r.BaseDir)
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	dir := filepath.Join(r.BaseDir, "run-"+strconv.Itoa(os.Getpid())+"-"+hex.EncodeToString(b[:]))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create run directory: %w", err)
	}
	run := &Run{Dir: dir, r: r, name: name, dirs: dirs}
	fail := func(err error) (*Run, error) { _ = os.RemoveAll(dir); return nil, err }

	var pass bytes.Buffer
	for _, e := range eps {
		m, err := r.launcher().MapEndpoint(e)
		if err != nil {
			return fail(err)
		}
		run.eps = append(run.eps, m)
		r.redactor().Add(e.Password.Reveal())
		if !e.Password.IsSet() {
			continue
		}
		port := m.Port
		if port == 0 {
			port = 5432
		}
		fmt.Fprintf(&pass, "%s:%d:*:%s:%s\n", passEsc(m.Host), port, passEsc(m.User), passEsc(e.Password.Reveal()))
	}
	run.PassFile = filepath.Join(dir, "pgpass")
	if err := os.WriteFile(run.PassFile, pass.Bytes(), 0o600); err != nil {
		return fail(fmt.Errorf("write passfile: %w", err))
	}
	if err := os.WriteFile(filepath.Join(dir, "owner.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		return fail(err)
	}
	return run, nil
}

func passEsc(s string) string { return strings.NewReplacer(`\`, `\\`, `:`, `\:`).Replace(s) }

// Endpoint returns endpoint i as the tool must address it.
func (run *Run) Endpoint(i int) Endpoint { return run.eps[i] }

// Close removes the run directory including the passfile.
func (run *Run) Close() error { return os.RemoveAll(run.Dir) }

// Result describes a finished process.
type Result struct {
	ExitCode int
	LogPath  string
	Duration time.Duration
	// Output is the redacted output when the run was Capture'd; otherwise empty.
	Output string
}

// Exec runs tool with args and waits. extraEnv holds non-secret variables. The
// returned error includes the exit status and the tail of the redacted log.
func (run *Run) Exec(ctx context.Context, tool string, args []string, extraEnv map[string]string) (Result, error) {
	return run.exec(ctx, tool, args, extraEnv, false)
}

// Capture is Exec that also returns the redacted output (for version checks).
func (run *Run) Capture(ctx context.Context, tool string, args []string, extraEnv map[string]string) (Result, error) {
	return run.exec(ctx, tool, args, extraEnv, true)
}

func (run *Run) exec(ctx context.Context, tool string, args []string, extraEnv map[string]string, capture bool) (Result, error) {
	r := run.r
	n := run.seq.Add(1)
	logPath := filepath.Join(r.LogDir, fmt.Sprintf("%s-%s-%d.log", run.name, filepath.Base(run.Dir), n))
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return Result{}, fmt.Errorf("open log file: %w", err)
	}
	defer lf.Close()
	w := r.redactor().Writer(lf)

	path := r.Path
	if path == "" {
		path = defaultPath
	}
	env := []string{"PATH=" + path, "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=" + run.Dir, "PGPASSFILE=" + run.PassFile}
	keys := make([]string, 0, len(extraEnv))
	for k := range extraEnv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		env = append(env, k+"="+extraEnv[k])
	}

	resolved, err := r.launcher().Resolve(tool, path)
	if err != nil {
		_ = w.Close()
		return Result{LogPath: logPath}, err
	}
	inv := Invocation{Tool: resolved, Args: args, Env: env, Dir: run.Dir, Dirs: run.dirs}
	cmd := r.launcher().Command(inv)
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = w, w
	setProcessGroup(cmd)
	cmd.WaitDelay = r.grace() // do not hang on a grandchild that keeps the output pipe open

	start := time.Now()
	if err := cmd.Start(); err != nil {
		_ = w.Close()
		r.launcher().Cleanup(inv)
		return Result{LogPath: logPath}, fmt.Errorf("start %s: %w", filepath.Base(tool), r.redactor().Error(err))
	}
	done := make(chan struct{})
	killed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			terminateGroup(cmd.Process.Pid, r.grace(), done)
			close(killed)
		case <-done:
			close(killed)
		}
	}()
	waitErr := cmd.Wait()
	close(done)
	<-killed
	_ = w.Close()
	r.launcher().Cleanup(inv)

	res := Result{LogPath: logPath, Duration: time.Since(start)}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if capture {
		if b, err := os.ReadFile(logPath); err == nil {
			res.Output = string(b)
		}
	}
	if ctx.Err() != nil {
		return res, fmt.Errorf("%s was stopped: %w", filepath.Base(tool), ctx.Err())
	}
	if waitErr != nil {
		return res, fmt.Errorf("%s failed (exit status %d, log %s): %s", filepath.Base(tool), res.ExitCode, logPath, tailOf(logPath, 12))
	}
	return res, nil
}

// tailOf returns the last n lines of a (already redacted) log file on one line.
func tailOf(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "(no log)"
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(strings.Fields(strings.Join(lines, " | ")), " ")
}

// SweepStale removes run directories whose owning process is gone: a process
// killed with SIGKILL cannot clean up after itself, so the next run does.
func SweepStale(base string) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "run-") {
			continue
		}
		dir := filepath.Join(base, e.Name())
		b, err := os.ReadFile(filepath.Join(dir, "owner.pid"))
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || pid <= 0 || processAlive(pid) {
			continue
		}
		_ = os.RemoveAll(dir)
	}
}
