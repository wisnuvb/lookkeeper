package dbconn

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/secret"
)

func mysqlSpec(mut func(*MySQLSpec)) MySQLSpec {
	s := MySQLSpec{
		Host: "127.0.0.1", Port: 3306, User: "mon", Database: "app",
		Password: secret.New("pw-xyz-123"), TLSMode: "disable",
		QueryTimeout: 7 * time.Second,
	}
	if mut != nil {
		mut(&s)
	}
	return s
}

func TestMySQLConfigSecurityDefaults(t *testing.T) {
	cfg, err := MySQLConfig(mysqlSpec(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Passwd != "pw-xyz-123" {
		t.Error("password must be set on the config field")
	}
	if strings.Contains(cfg.Addr, "pw-xyz-123") || strings.Contains(cfg.User, "pw-xyz-123") || strings.Contains(cfg.DBName, "pw-xyz-123") {
		t.Error("the password must appear nowhere but cfg.Passwd")
	}
	if cfg.Net != "tcp" || cfg.Addr != "127.0.0.1:3306" {
		t.Errorf("address = %s %s", cfg.Net, cfg.Addr)
	}

	// The settings below are the policy; each is pinned so a driver default
	// change or a careless edit cannot weaken it unnoticed.
	if cfg.MultiStatements {
		t.Error("multi-statements must be off")
	}
	if cfg.AllowAllFiles {
		t.Error("LOAD DATA LOCAL INFILE must never be served")
	}
	if cfg.AllowCleartextPasswords {
		t.Error("the cleartext password plugin must be refused")
	}
	if cfg.AllowOldPasswords {
		t.Error("old (pre-4.1) passwords must be refused")
	}
	if cfg.InterpolateParams {
		t.Error("client-side parameter interpolation must be off")
	}
	if cfg.AllowFallbackToPlaintext {
		t.Error("there must be no silent fall back to plaintext")
	}
	if cfg.TLSConfig != "" {
		t.Errorf("no registered TLS name may be used, got %q", cfg.TLSConfig)
	}
	if cfg.RejectReadOnly || cfg.ClientFoundRows {
		t.Error("unexpected behaviour flags set")
	}

	if cfg.Params["transaction_read_only"] != "1" {
		t.Errorf("sessions must be read-only, params = %v", cfg.Params)
	}
	if cfg.Params["max_execution_time"] != "7000" || cfg.Params["lock_wait_timeout"] != "7" {
		t.Errorf("timeouts not applied: %v", cfg.Params)
	}
	if len(cfg.Params) != 3 {
		t.Errorf("unexpected extra session variables: %v", cfg.Params)
	}

	if cfg.Timeout <= 0 || cfg.ReadTimeout <= cfg.Timeout-time.Second || cfg.WriteTimeout <= 0 {
		t.Errorf("connect/read/write timeouts must be bounded: %v %v %v", cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout)
	}
	if cfg.ReadTimeout < 7*time.Second {
		t.Errorf("the read timeout must not undercut the query timeout: %v", cfg.ReadTimeout)
	}
	if cfg.ConnectionAttributes != "program_name:lockkeeper" {
		t.Errorf("connection attributes = %q", cfg.ConnectionAttributes)
	}
}

func TestMySQLConfigDefaults(t *testing.T) {
	cfg, err := MySQLConfig(MySQLSpec{Host: "127.0.0.1", User: "mon", TLSMode: "disable"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != "127.0.0.1:3306" || cfg.DBName != "" {
		t.Errorf("defaults: addr=%q db=%q", cfg.Addr, cfg.DBName)
	}
	if cfg.Params["max_execution_time"] != "10000" {
		t.Errorf("default statement timeout = %v", cfg.Params)
	}
	if _, err := MySQLConfig(MySQLSpec{User: "mon"}); err == nil {
		t.Error("host is required")
	}
	if _, err := MySQLConfig(MySQLSpec{Host: "h"}); err == nil {
		t.Error("user is required")
	}
}

func TestMySQLConfigAwkwardPasswordAndNames(t *testing.T) {
	// Characters that would break or be echoed by a DSN string.
	pw := `p@ss/w:o)r(d?&=%#"' `
	cfg, err := MySQLConfig(mysqlSpec(func(s *MySQLSpec) {
		s.Password = secret.New(pw)
		s.User = "we ird@user:name"
		s.Database = "db/with space"
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Passwd != pw || cfg.User != "we ird@user:name" || cfg.DBName != "db/with space" {
		t.Errorf("round trip failed: user=%q db=%q", cfg.User, cfg.DBName)
	}
}

func TestMySQLConfigIgnoresAmbientEnvironment(t *testing.T) {
	t.Setenv("MYSQL_PWD", "ambient-password")
	t.Setenv("MYSQL_HOST", "evil.example.com")
	t.Setenv("MYSQL_TCP_PORT", "1")
	cfg, err := MySQLConfig(mysqlSpec(func(s *MySQLSpec) { s.TLSMode = "verify-full"; s.Host = "db.example.com" }))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Passwd != "pw-xyz-123" || cfg.Addr != "db.example.com:3306" {
		t.Errorf("ambient MYSQL_* variables leaked into the config: %q %q", cfg.Passwd, cfg.Addr)
	}
	if cfg.TLS == nil || cfg.TLS.InsecureSkipVerify {
		t.Error("TLS must stay verified")
	}
}

func TestMySQLConfigTLSUsesSharedPolicy(t *testing.T) {
	// Default (empty mode) is verify-full, as for Postgres.
	cfg, err := MySQLConfig(mysqlSpec(func(s *MySQLSpec) { s.Host = "db.example.com"; s.TLSMode = "" }))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLS == nil || cfg.TLS.InsecureSkipVerify || cfg.TLS.ServerName != "db.example.com" || cfg.TLS.MinVersion < tls.VersionTLS12 {
		t.Errorf("default must be verify-full with TLS>=1.2: %+v", cfg.TLS)
	}

	// Weak modes are refused for remote hosts without the explicit opt-in...
	for _, mode := range []string{"require", "disable"} {
		if _, err := MySQLConfig(mysqlSpec(func(s *MySQLSpec) { s.Host = "db.example.com"; s.TLSMode = mode })); err == nil {
			t.Errorf("%s must be refused for a remote host", mode)
		}
	}
	// ...and allowed with it.
	cfg, err = MySQLConfig(mysqlSpec(func(s *MySQLSpec) { s.Host = "db.example.com"; s.TLSMode = "require"; s.AllowInsecure = true }))
	if err != nil || cfg.TLS == nil || !cfg.TLS.InsecureSkipVerify {
		t.Errorf("explicit opt-in must work: %v %+v", err, cfg)
	}

	// Loopback may disable TLS; then the driver gets no TLS config at all.
	cfg, err = MySQLConfig(mysqlSpec(nil))
	if err != nil || cfg.TLS != nil {
		t.Errorf("disable on loopback: err=%v tls=%v", err, cfg.TLS)
	}

	if _, err := MySQLConfig(mysqlSpec(func(s *MySQLSpec) { s.TLSMode = "bogus" })); err == nil {
		t.Error("unknown TLS mode must fail")
	}
	if _, err := MySQLConfig(mysqlSpec(func(s *MySQLSpec) {
		s.Host = "db.example.com"
		s.TLSMode = "verify-full"
		s.CAFile = "/nonexistent/ca.pem"
	})); err == nil {
		t.Error("a missing CA file must fail")
	}
}

func TestMySQLConfigUnixSocket(t *testing.T) {
	cfg, err := MySQLConfig(mysqlSpec(func(s *MySQLSpec) { s.Host = "/var/run/mysqld/mysqld.sock"; s.TLSMode = "verify-full" }))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Net != "unix" || cfg.Addr != "/var/run/mysqld/mysqld.sock" {
		t.Errorf("socket address: %s %s", cfg.Net, cfg.Addr)
	}
	if cfg.TLS != nil {
		t.Error("TLS is not used on a local socket")
	}
}

func TestMySQLSpecFromConfig(t *testing.T) {
	db := config.Database{
		Engine: "mysql", Host: "h", Port: 3307, Database: "d", User: "u",
		TLS: config.TLS{Mode: "verify-ca", CAFile: "/ca.pem", AllowInsecure: true},
	}
	s := MySQLSpecFromConfig(db, secret.New("pw"), 9*time.Second)
	if s.Host != "h" || s.Port != 3307 || s.Database != "d" || s.User != "u" || s.TLSMode != "verify-ca" ||
		s.CAFile != "/ca.pem" || !s.AllowInsecure || s.QueryTimeout != 9*time.Second || s.Password.Reveal() != "pw" {
		t.Errorf("mapping wrong: %+v", s)
	}
}

func TestMySQLErrorsDoNotContainPassword(t *testing.T) {
	// A refused connection (nothing listens on port 1) must not echo the password.
	_, err := OpenMySQL(t.Context(), mysqlSpec(func(s *MySQLSpec) { s.Port = 1; s.ConnectTimeout = time.Second }))
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if strings.Contains(err.Error(), "pw-xyz-123") {
		t.Errorf("error leaks the password: %v", err)
	}
}
