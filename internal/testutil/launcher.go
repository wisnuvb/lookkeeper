package testutil

import (
	"crypto/sha1" //nolint:gosec // only to name a container deterministically
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/wisnuvb/lockkeeper/internal/migrate/runner"
)

// DockerLauncher runs the bulk-copy tools (pgcopydb, pg_dump, pg_restore) inside
// throwaway containers on a test network, through the same runner that runs
// them as local processes in production. The host has no matching PostgreSQL 17
// client tools, and a containerised tool reaches the test servers by network
// alias.
//
// It refuses every endpoint that is not one of the registered test containers,
// so a misconfigured test cannot make a tool talk to a real server.
type DockerLauncher struct {
	t     testing.TB
	net   *Net
	mu    sync.Mutex
	alias map[string]string // "127.0.0.1:<published port>" -> network alias
}

// NewDockerLauncher registers the containers a tool may reach.
func NewDockerLauncher(t testing.TB, n *Net, pgs ...*NetPG) *DockerLauncher {
	t.Helper()
	EnsurePgcopydbImage(t)
	l := &DockerLauncher{t: t, net: n, alias: map[string]string{}}
	for _, p := range pgs {
		RequireLoopback(t, p.Host)
		l.alias[net.JoinHostPort(p.Host, strconv.Itoa(p.Port))] = p.Alias
	}
	return l
}

func containerName(inv runner.Invocation) string {
	h := sha1.Sum([]byte(inv.Dir + "\x00" + inv.Tool + "\x00" + strings.Join(inv.Args, "\x00"))) //nolint:gosec
	return "lk-tool-" + hex.EncodeToString(h[:])[:12]
}

// Resolve implements runner.Launcher: the tool name is the entrypoint inside the image.
func (l *DockerLauncher) Resolve(name, _ string) (string, error) { return filepath.Base(name), nil }

// MapEndpoint implements runner.Launcher.
func (l *DockerLauncher) MapEndpoint(e runner.Endpoint) (runner.Endpoint, error) {
	port := e.Port
	if port == 0 {
		port = 5432
	}
	l.mu.Lock()
	alias, ok := l.alias[net.JoinHostPort(e.Host, strconv.Itoa(port))]
	l.mu.Unlock()
	if !ok {
		return e, fmt.Errorf("test launcher: refusing to let a tool connect to %s:%d, which is not a container started by this test", e.Host, port)
	}
	e.Host, e.Port = alias, 5432
	return e, nil
}

// Command implements runner.Launcher.
func (l *DockerLauncher) Command(inv runner.Invocation) *exec.Cmd {
	entry := filepath.Base(inv.Tool)
	image := PGToolsImage
	if entry == "pgcopydb" {
		image = PgcopydbImage
	}
	args := []string{"run", "--rm", "--name", containerName(inv), "--label", LabelKey + "=" + LabelValue, "--network", l.net.Name}
	if u, err := user.Current(); err == nil && u.Uid != "" {
		args = append(args, "--user", u.Uid+":"+u.Gid)
	}
	seen := map[string]bool{}
	for _, d := range append([]string{inv.Dir}, inv.Dirs...) {
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		args = append(args, "-v", d+":"+d)
	}
	args = append(args, "-w", inv.Dir)
	for _, kv := range inv.Env {
		if strings.HasPrefix(kv, "PATH=") {
			continue // the image's own PATH is the right one inside the container
		}
		args = append(args, "-e", kv)
	}
	args = append(args, "--entrypoint", entry, image)
	args = append(args, inv.Args...)
	cmd := exec.Command("docker", args...)
	cmd.Env = os.Environ() // the docker client needs HOME/DOCKER_HOST; the tool only gets the -e flags
	return cmd
}

// Cleanup implements runner.Launcher: SIGKILL of the docker client does not stop
// the container, so remove it.
func (l *DockerLauncher) Cleanup(inv runner.Invocation) {
	_ = exec.Command("docker", "rm", "-f", containerName(inv)).Run()
}

// KillToolContainers kills every running tool container of this launcher's
// network, simulating a bulk-copy tool that crashed. It returns how many it killed.
func (l *DockerLauncher) KillToolContainers() int {
	out, err := exec.Command("docker", "ps", "-q", "--filter", "name=lk-tool-", "--filter", "network="+l.net.Name).Output()
	if err != nil {
		return 0
	}
	ids := strings.Fields(string(out))
	for _, id := range ids {
		_ = exec.Command("docker", "kill", id).Run()
	}
	return len(ids)
}
