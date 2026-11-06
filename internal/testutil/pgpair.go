package testutil

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// PGOptions configures StartPGWith.
type PGOptions struct {
	// Image is the Docker image. Default: LK_TEST_PG_IMAGE, then DefaultPGImage.
	Image string
	// ServerArgs are passed to postgres as -c name=value. Unlike StartPG, nothing
	// is added: the server runs with the image defaults (wal_level=replica).
	ServerArgs []string
	// Env holds extra container environment variables (KEY=VALUE).
	Env []string
}

// StartPGWith starts a throwaway Postgres container with exactly the given
// options and waits until it accepts connections. Like StartPG it publishes the
// port on loopback only, refuses any other host, and skips the test when Docker
// is unavailable (unless LK_TEST_REQUIRE_DOCKER=1).
func StartPGWith(t testing.TB, o PGOptions) *PG {
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

	args := []string{"run", "-d", "--rm", "-p", "127.0.0.1::5432", "-e", "POSTGRES_PASSWORD=" + pw}
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
	return p
}

// PairOptions configures StartPair.
type PairOptions struct {
	// SourceImage and TargetImage default to LK_TEST_PG_SOURCE_IMAGE and
	// LK_TEST_PG_TARGET_IMAGE, then to LK_TEST_PG_IMAGE, then to DefaultPGImage.
	SourceImage, TargetImage string
	// SourceArgs and TargetArgs are extra postgres -c settings.
	SourceArgs, TargetArgs []string
}

// StartPair starts a migration-shaped pair of containers on loopback: a source
// with wal_level=logical (ready to be replicated from) and a target with the
// image defaults (wal_level=replica), each with its own random superuser
// password. Both are removed at test end.
func StartPair(t testing.TB, o PairOptions) (source, target *PG) {
	t.Helper()
	if o.SourceImage == "" {
		o.SourceImage = os.Getenv("LK_TEST_PG_SOURCE_IMAGE")
	}
	if o.TargetImage == "" {
		o.TargetImage = os.Getenv("LK_TEST_PG_TARGET_IMAGE")
	}
	src := append([]string{"wal_level=logical", "max_replication_slots=10", "max_wal_senders=10"}, o.SourceArgs...)
	source = StartPGWith(t, PGOptions{Image: o.SourceImage, ServerArgs: src})
	target = StartPGWith(t, PGOptions{Image: o.TargetImage, ServerArgs: o.TargetArgs})
	return source, target
}
