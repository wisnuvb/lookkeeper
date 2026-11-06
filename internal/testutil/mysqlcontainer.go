package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/wisnuvb/lockkeeper/internal/dbconn"
	"github.com/wisnuvb/lockkeeper/internal/secret"
)

// DefaultMySQLImage is used unless LK_TEST_MYSQL_IMAGE is set.
const DefaultMySQLImage = "mysql:8.4"

var mysqlServerID atomic.Int32

// MySQL is a running throwaway MySQL container.
type MySQL struct {
	Host         string
	Port         int
	RootPassword string
	// Alias is the container's name on the private Docker network, when it has one.
	Alias string
	id    string
}

// MySQLOptions tunes StartMySQLWith.
type MySQLOptions struct {
	// Network, when set, attaches the container to this (test-created) Docker
	// network under Alias, so that a second container can reach it.
	Network string
	Alias   string
	// NoBinlog starts the server without binary logging (and without GTIDs, which
	// need it for replication).
	NoBinlog bool
	// Env are extra container environment variables, for example "TZ=Asia/Jakarta".
	Env []string
	// Args are extra mysqld arguments, for example "--long_query_time=1".
	Args []string
}

// MySQLImage returns the image under test (LK_TEST_MYSQL_IMAGE or the default).
func MySQLImage() string {
	if v := os.Getenv("LK_TEST_MYSQL_IMAGE"); v != "" {
		return v
	}
	return DefaultMySQLImage
}

// StartMySQL starts a MySQL container with binary logging and GTIDs enabled and
// waits until it accepts connections. The test is skipped when Docker is
// unavailable, unless LK_TEST_REQUIRE_DOCKER=1.
func StartMySQL(t testing.TB, extraServerArgs ...string) *MySQL {
	t.Helper()
	return StartMySQLWith(t, MySQLOptions{Args: extraServerArgs})
}

// StartMySQLWith is StartMySQL with options.
func StartMySQLWith(t testing.TB, opts MySQLOptions) *MySQL {
	t.Helper()
	requireDocker(t)
	pw := randomHex(t, 12)

	args := []string{
		"run", "-d", "--rm",
		"-p", "127.0.0.1::3306",
		"-e", "MYSQL_ROOT_PASSWORD=" + pw,
	}
	for _, e := range opts.Env {
		args = append(args, "-e", e)
	}
	if opts.Network != "" {
		args = append(args, "--network", opts.Network, "--network-alias", opts.Alias)
	}
	args = append(args, MySQLImage(),
		"--server-id="+strconv.Itoa(int(mysqlServerID.Add(1))+100),
		"--innodb-buffer-pool-size=64M",
	)
	if opts.NoBinlog {
		args = append(args, "--skip-log-bin")
	} else {
		args = append(args, "--log-bin=mysql-bin", "--gtid-mode=ON", "--enforce-gtid-consistency=ON")
	}
	args = append(args, opts.Args...)
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run failed: %v\n%s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })

	portOut, err := exec.Command("docker", "port", id, "3306/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	first := strings.Fields(strings.Split(strings.TrimSpace(string(portOut)), "\n")[0])
	host, portStr, err := net.SplitHostPort(first[len(first)-1])
	if err != nil {
		t.Fatalf("parse docker port %q: %v", first, err)
	}
	if host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	RequireLoopback(t, host)
	port, _ := strconv.Atoi(portStr)

	m := &MySQL{Host: host, Port: port, RootPassword: pw, Alias: opts.Alias, id: id}
	m.waitReady(t)
	return m
}

// NewDockerNetwork creates a private bridge network for a multi-container test
// and removes it at the end. Containers on it talk to each other only; the
// published ports stay bound to loopback.
func NewDockerNetwork(t testing.TB) string {
	t.Helper()
	requireDocker(t)
	name := "lk-test-" + randomHex(t, 6)
	if out, err := exec.Command("docker", "network", "create", name).CombinedOutput(); err != nil {
		t.Fatalf("docker network create: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", name).Run() })
	return name
}

// StartMySQLPair starts a source and a replica on a private network. The replica
// is NOT configured; call ConfigureReplica to attach it.
func StartMySQLPair(t testing.TB) (source, replica *MySQL) {
	t.Helper()
	netName := NewDockerNetwork(t)
	source = StartMySQLWith(t, MySQLOptions{Network: netName, Alias: "lk-source"})
	replica = StartMySQLWith(t, MySQLOptions{Network: netName, Alias: "lk-replica"})
	return source, replica
}

func (m *MySQL) adminConfig() *mysql.Config {
	cfg := mysql.NewConfig()
	cfg.User = "root"
	cfg.Passwd = m.RootPassword
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(m.Host, strconv.Itoa(m.Port))
	cfg.Timeout = 3 * time.Second
	cfg.ReadTimeout = 30 * time.Second
	cfg.MultiStatements = false
	cfg.Logger = &mysql.NopLogger{} // the entrypoint restarts the server during init; its resets are noise
	return cfg
}

func (m *MySQL) openAdmin() (*sql.DB, error) {
	c, err := mysql.NewConnector(m.adminConfig())
	if err != nil {
		return nil, err
	}
	return sql.OpenDB(c), nil
}

func (m *MySQL) waitReady(t testing.TB) {
	t.Helper()
	deadline := time.Now().Add(180 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		db, err := m.openAdmin()
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			err = db.PingContext(ctx)
			cancel()
			_ = db.Close()
		}
		if err == nil {
			return
		}
		last = err
		time.Sleep(time.Second)
	}
	logs, _ := exec.Command("docker", "logs", "--tail", "30", m.id).CombinedOutput()
	t.Fatalf("mysql container did not become ready: %v\n%s", last, logs)
}

// Admin opens a plain root pool (read-write, no Lockkeeper policy) for arranging
// test state. It is closed automatically at test end.
func (m *MySQL) Admin(t testing.TB) *sql.DB {
	t.Helper()
	RequireLoopback(t, m.Host)
	db, err := m.openAdmin()
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// Session returns a dedicated root connection (one server session), for tests
// that need to hold a transaction or a lock open. It is closed at test end.
func (m *MySQL) Session(t testing.TB) *sql.Conn {
	t.Helper()
	conn, err := m.Admin(t).Conn(context.Background())
	if err != nil {
		t.Fatalf("admin session: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// MustExec runs statements as root and fails the test on error.
func (m *MySQL) MustExec(t testing.TB, db *sql.DB, statements ...string) {
	t.Helper()
	for _, s := range statements {
		if _, err := db.ExecContext(context.Background(), s); err != nil {
			t.Fatalf("%s: %v", redactStatement(s), err)
		}
	}
}

// redactStatement keeps test failure output free of passwords in
// CREATE USER / CHANGE REPLICATION statements.
func redactStatement(s string) string {
	if i := strings.Index(strings.ToUpper(s), "IDENTIFIED BY"); i >= 0 {
		return s[:i] + "IDENTIFIED BY ***"
	}
	if i := strings.Index(strings.ToUpper(s), "SOURCE_PASSWORD"); i >= 0 {
		return s[:i] + "SOURCE_PASSWORD=***"
	}
	return s
}

// Spec returns a Lockkeeper connection spec for the root account (read-only
// session, TLS disabled because the host is loopback).
func (m *MySQL) Spec() dbconn.MySQLSpec { return m.SpecFor("root", m.RootPassword) }

// SpecFor returns a spec for another account.
func (m *MySQL) SpecFor(user, password string) dbconn.MySQLSpec {
	return dbconn.MySQLSpec{
		Host: m.Host, Port: m.Port, User: user,
		Password: secret.New(password), TLSMode: "disable",
		QueryTimeout: 10 * time.Second,
	}
}

// Stop stops the container (simulating an outage).
func (m *MySQL) Stop(t testing.TB) {
	t.Helper()
	if out, err := exec.Command("docker", "stop", "-t", "1", m.id).CombinedOutput(); err != nil {
		t.Fatalf("docker stop: %v\n%s", err, out)
	}
}

// Exec runs a command inside the container and returns its combined output.
func (m *MySQL) Exec(t testing.TB, cmd ...string) string {
	t.Helper()
	out, err := exec.Command("docker", append([]string{"exec", m.id}, cmd...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec %v: %v\n%s", cmd, err, out)
	}
	return string(out)
}

// CACertFile copies the server's auto-generated CA certificate out of the
// container into a temporary file and returns its path.
func (m *MySQL) CACertFile(t testing.TB) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mysql-ca.pem")
	if out, err := exec.Command("docker", "cp", m.id+":/var/lib/mysql/ca.pem", path).CombinedOutput(); err != nil {
		t.Fatalf("docker cp ca.pem: %v\n%s", err, out)
	}
	return path
}

// ConfigureReplica attaches replica to source with GTID auto-positioning over
// the private Docker network and starts replication. It creates a replication
// account on the source (a throwaway container) and waits until both replica
// threads run. Statements use the version-appropriate syntax of MySQL 8.0.23+
// and 8.4 (CHANGE REPLICATION SOURCE TO / START REPLICA).
func ConfigureReplica(t testing.TB, source, replica *MySQL) {
	t.Helper()
	if source.Alias == "" {
		t.Fatal("the source container needs a network alias")
	}
	replPW := randomHex(t, 8)
	sdb := source.Admin(t)
	source.MustExec(t, sdb,
		"CREATE USER 'repl'@'%' IDENTIFIED BY '"+replPW+"'",
		"GRANT REPLICATION SLAVE ON *.* TO 'repl'@'%'",
	)
	rdb := replica.Admin(t)
	replica.MustExec(t, rdb,
		fmt.Sprintf("CHANGE REPLICATION SOURCE TO SOURCE_HOST='%s', SOURCE_PORT=3306, SOURCE_USER='repl', SOURCE_PASSWORD='%s', SOURCE_AUTO_POSITION=1, GET_SOURCE_PUBLIC_KEY=1", source.Alias, replPW),
		"START REPLICA",
	)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		var io, sqlr string
		row := rdb.QueryRow("SELECT SERVICE_STATE FROM performance_schema.replication_connection_status")
		_ = row.Scan(&io)
		row = rdb.QueryRow("SELECT SERVICE_STATE FROM performance_schema.replication_applier_status")
		_ = row.Scan(&sqlr)
		if io == "ON" && sqlr == "ON" {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("replication threads did not start")
}
