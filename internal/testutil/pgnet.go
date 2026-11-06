package testutil

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// LabelKey marks every container and network a test starts, so leftovers are
// easy to find: docker ps -a --filter label=lockkeeper-test=1.
const (
	LabelKey   = "lockkeeper-test"
	LabelValue = "1"
)

// Net is a private Docker network created by a test. Containers on it reach each
// other by network alias, which is how a target server (and a bulk-copy tool
// running in its own container) reaches the source without ever leaving the
// machine. Lockkeeper itself still talks to the published loopback ports.
type Net struct {
	Name string
}

// StartNet creates a throwaway private Docker network, removed at test end.
func StartNet(t testing.TB) *Net {
	t.Helper()
	requireDocker(t)
	name := "lk-test-" + randomHex(t, 6)
	out, err := exec.Command("docker", "network", "create", "--label", LabelKey+"="+LabelValue, name).CombinedOutput()
	if err != nil {
		t.Fatalf("docker network create: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		// Containers are removed by their own cleanups (registered later, so they
		// run first); the network can only be removed once they are gone.
		_ = exec.Command("docker", "network", "rm", name).Run()
	})
	return &Net{Name: name}
}

// NetPG is a throwaway Postgres container that is also reachable by alias on a
// private network.
type NetPG struct {
	*PG
	Net   *Net
	Alias string
}

// PeerHost is the host name other containers on the network use.
func (p *NetPG) PeerHost() string { return p.Alias }

// PeerPort is always 5432: the in-container port.
func (p *NetPG) PeerPort() int { return 5432 }

// StartPGNet is StartPGWith plus attachment to a private network under alias.
// The published port is still loopback-only and is still checked.
func StartPGNet(t testing.TB, n *Net, alias string, o PGOptions) *NetPG {
	t.Helper()
	requireDocker(t)

	image := o.Image
	if image == "" {
		image = os.Getenv("LK_TEST_PG_IMAGE")
	}
	if image == "" {
		image = DefaultPGImage
	}
	pw := randomHex(t, 12)

	args := []string{"run", "-d", "--rm", "-p", "127.0.0.1::5432",
		"--label", LabelKey + "=" + LabelValue,
		"--network", n.Name, "--network-alias", alias,
		"-e", "POSTGRES_PASSWORD=" + pw}
	for _, e := range o.Env {
		args = append(args, "-e", e)
	}
	args = append(args, image, "postgres")
	for _, a := range o.ServerArgs {
		args = append(args, "-c", a)
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run failed: %v\n%s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })

	portOut, err := exec.Command("docker", "port", id, "5432/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	first := strings.Fields(strings.Split(strings.TrimSpace(string(portOut)), "\n")[0])
	host, portStr, err := net.SplitHostPort(first[len(first)-1])
	if err != nil {
		t.Fatalf("parse docker port %q: %v", first[len(first)-1], err)
	}
	if host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	RequireLoopback(t, host)
	port, _ := strconv.Atoi(portStr)

	p := &PG{Host: host, Port: port, User: "postgres", Password: pw, Database: "postgres", id: id}
	p.waitReady(t)
	return &NetPG{PG: p, Net: n, Alias: alias}
}

// StartPairNet starts a migration-shaped pair (see StartPair) on a private
// network under the aliases "src" and "tgt".
func StartPairNet(t testing.TB, n *Net, o PairOptions) (source, target *NetPG) {
	t.Helper()
	if o.SourceImage == "" {
		o.SourceImage = os.Getenv("LK_TEST_PG_SOURCE_IMAGE")
	}
	if o.TargetImage == "" {
		o.TargetImage = os.Getenv("LK_TEST_PG_TARGET_IMAGE")
	}
	src := append([]string{"wal_level=logical", "max_replication_slots=20", "max_wal_senders=20"}, o.SourceArgs...)
	source = StartPGNet(t, n, "src", PGOptions{Image: o.SourceImage, ServerArgs: src})
	tgtArgs := append([]string{"max_logical_replication_workers=8", "max_worker_processes=16"}, o.TargetArgs...)
	target = StartPGNet(t, n, "tgt", PGOptions{Image: o.TargetImage, ServerArgs: tgtArgs})
	return source, target
}

// ContainerID returns the Docker container id (for docker exec/kill in tests).
func (p *PG) ContainerID() string { return p.id }
