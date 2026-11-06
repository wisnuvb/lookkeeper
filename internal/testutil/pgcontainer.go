// Package testutil provides helpers for integration tests. Tests may only ever
// talk to throwaway containers started by the test itself on loopback; they
// must never be pointed at a real database.
package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/wisnuvb/lockkeeper/internal/dbconn"
	"github.com/wisnuvb/lockkeeper/internal/secret"
)

// DefaultPGImage is used unless LK_TEST_PG_IMAGE is set.
const DefaultPGImage = "postgres:17-alpine"

// RequireLoopback fails the test if host is not a loopback address. Every
// integration helper calls it so a misconfiguration cannot reach production.
func RequireLoopback(t testing.TB, host string) {
	t.Helper()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		t.Fatalf("refusing to connect to non-loopback host %q from a test", host)
	}
}

// PG is a running throwaway Postgres container.
type PG struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	id       string
}

// StartPG starts a Postgres container with logical replication enabled and waits
// until it accepts connections. The test is skipped when Docker is unavailable,
// unless LK_TEST_REQUIRE_DOCKER=1.
func StartPG(t testing.TB, extraServerArgs ...string) *PG {
	t.Helper()
	requireDocker(t)

	image := os.Getenv("LK_TEST_PG_IMAGE")
	if image == "" {
		image = DefaultPGImage
	}
	pw := randomHex(t, 12)

	args := []string{
		"run", "-d", "--rm",
		"-p", "127.0.0.1::5432",
		"-e", "POSTGRES_PASSWORD=" + pw,
		image, "postgres",
		"-c", "wal_level=logical",
		"-c", "max_replication_slots=10",
		"-c", "max_wal_senders=10",
	}
	for _, a := range extraServerArgs {
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
	// Output may list IPv4 and IPv6 lines; take the first.
	first := strings.Fields(strings.Split(strings.TrimSpace(string(portOut)), "\n")[0])
	hostPort := first[len(first)-1]
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatalf("parse docker port %q: %v", hostPort, err)
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

func requireDocker(t testing.TB) {
	t.Helper()
	if err := exec.Command("docker", "info").Run(); err != nil {
		if os.Getenv("LK_TEST_REQUIRE_DOCKER") == "1" {
			t.Fatalf("docker is required but unavailable: %v", err)
		}
		t.Skip("docker is not available; skipping integration test")
	}
}

func randomHex(t testing.TB, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func (p *PG) waitReady(t testing.TB) {
	t.Helper()
	deadline := time.Now().Add(120 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err := pgx.Connect(ctx, p.adminDSN())
		if err == nil {
			err = conn.Ping(ctx)
			_ = conn.Close(ctx)
		}
		cancel()
		if err == nil {
			return
		}
		last = err
		time.Sleep(500 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", "--tail", "30", p.id).CombinedOutput()
	t.Fatalf("postgres container did not become ready: %v\n%s", last, logs)
}

func (p *PG) adminDSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", p.User, p.Password, p.Host, p.Port, p.Database)
}

// Admin opens a plain superuser connection (read-write, no Lockkeeper policy),
// for arranging test state. It is closed automatically at test end.
func (p *PG) Admin(t testing.TB) *pgx.Conn {
	t.Helper()
	RequireLoopback(t, p.Host)
	conn, err := pgx.Connect(context.Background(), p.adminDSN())
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// Spec returns a Lockkeeper connection spec (read-only session, TLS disabled
// because the host is loopback).
func (p *PG) Spec() dbconn.PGSpec {
	return dbconn.PGSpec{
		Host: p.Host, Port: p.Port, Database: p.Database, User: p.User,
		Password: secret.New(p.Password), TLSMode: "disable",
		StatementTimeout: 10 * time.Second,
	}
}

// Stop stops the container (simulating an outage).
func (p *PG) Stop(t testing.TB) {
	t.Helper()
	if out, err := exec.Command("docker", "stop", "-t", "1", p.id).CombinedOutput(); err != nil {
		t.Fatalf("docker stop: %v\n%s", err, out)
	}
}

// Exec runs a command inside the container and returns its combined output.
func (p *PG) Exec(t testing.TB, cmd ...string) string {
	t.Helper()
	out, err := exec.Command("docker", append([]string{"exec", p.id}, cmd...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec %v: %v\n%s", cmd, err, out)
	}
	return string(out)
}
