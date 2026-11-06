package dbconn

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/secret"
)

// MySQLSpec describes one MySQL connection.
type MySQLSpec struct {
	Host string
	Port int
	// Database is optional; empty selects no default schema.
	Database string
	User     string
	Password secret.Value

	TLSMode       string
	CAFile        string
	AllowInsecure bool

	// ConnectTimeout bounds dialing (the handshake is bounded by the I/O timeouts).
	ConnectTimeout time.Duration
	// QueryTimeout is applied server-side (max_execution_time) and, with a margin,
	// as the client's I/O timeout. Default 10s.
	QueryTimeout time.Duration
	// ProgramName is shown in performance_schema.session_connect_attrs.
	ProgramName string
}

// MySQLSpecFromConfig maps a validated config entry plus its resolved password.
func MySQLSpecFromConfig(db config.Database, pw secret.Value, queryTimeout time.Duration) MySQLSpec {
	return MySQLSpec{
		Host:           db.Host,
		Port:           db.Port,
		Database:       db.Database,
		User:           db.User,
		Password:       pw,
		TLSMode:        db.TLS.Mode,
		CAFile:         db.TLS.CAFile,
		AllowInsecure:  db.TLS.AllowInsecure,
		ConnectTimeout: 10 * time.Second,
		QueryTimeout:   queryTimeout,
		ProgramName:    "lockkeeper",
	}
}

// nopLogger drops the driver's own log lines. The driver would otherwise write
// to the process's standard error, bypassing Lockkeeper's redacting log sink.
type nopLogger struct{}

func (nopLogger) Print(...any) {}

// MySQLConfig builds the driver configuration for spec. It is separate from
// OpenMySQL so the security-relevant settings can be unit-tested without a server.
//
// The configuration is built field by field, never by formatting a DSN string,
// so a password containing "@", "/" or ")" cannot corrupt (or be echoed by) a
// connection string. TLS uses the same policy function as Postgres and is passed
// to the driver as a *tls.Config, so no process-global registration (and no name
// collision or cleanup) is involved.
func MySQLConfig(spec MySQLSpec) (*mysql.Config, error) {
	if spec.Host == "" || spec.User == "" {
		return nil, errors.New("host and user are required")
	}
	if spec.Port == 0 {
		spec.Port = 3306
	}
	if spec.ConnectTimeout == 0 {
		spec.ConnectTimeout = 10 * time.Second
	}
	if spec.QueryTimeout == 0 {
		spec.QueryTimeout = 10 * time.Second
	}
	if spec.ProgramName == "" {
		spec.ProgramName = "lockkeeper"
	}

	tlsCfg, err := TLSConfig(spec.TLSMode, spec.Host, spec.CAFile, spec.AllowInsecure)
	if err != nil {
		return nil, err
	}

	cfg := mysql.NewConfig()
	cfg.User = spec.User
	cfg.Passwd = spec.Password.Reveal()
	cfg.DBName = spec.Database
	if len(spec.Host) > 0 && spec.Host[0] == '/' { // unix socket path
		cfg.Net = "unix"
		cfg.Addr = spec.Host
		// MySQL does not use TLS on a local socket, and a certificate cannot be
		// verified against a socket path.
		tlsCfg = nil
	} else {
		cfg.Net = "tcp"
		cfg.Addr = net.JoinHostPort(spec.Host, strconv.Itoa(spec.Port))
	}
	cfg.TLS = tlsCfg
	cfg.TLSConfig = "" // never a registered name: cfg.TLS is the single source of truth
	cfg.AllowFallbackToPlaintext = false

	cfg.Timeout = spec.ConnectTimeout
	cfg.ReadTimeout = spec.QueryTimeout + 5*time.Second
	cfg.WriteTimeout = cfg.ReadTimeout
	cfg.Logger = nopLogger{}
	cfg.ConnectionAttributes = "program_name:" + spec.ProgramName

	// Explicit even where the driver default is already safe, so a future change
	// of a default cannot silently weaken the policy (the unit tests pin these).
	cfg.MultiStatements = false
	cfg.InterpolateParams = false
	cfg.AllowAllFiles = false // LOAD DATA LOCAL INFILE is never served
	cfg.AllowCleartextPasswords = false
	cfg.AllowOldPasswords = false
	cfg.AllowNativePasswords = true // challenge-response; needed by many existing accounts
	cfg.ClientFoundRows = false
	cfg.RejectReadOnly = false

	// Session variables, applied by the driver with one SET after every connect.
	// All values are numeric literals built here, never user input.
	qms := spec.QueryTimeout.Milliseconds()
	if qms < 1 {
		qms = 1
	}
	lockSecs := int64((spec.QueryTimeout + time.Second - 1) / time.Second)
	if lockSecs < 1 {
		lockSecs = 1
	}
	cfg.Params = map[string]string{
		// Defence in depth only: a role with the privilege can still run
		// SET GLOBAL, GRANT, ... The real boundary is a least-privilege account
		// (see mysql.Collector.Audit).
		"transaction_read_only": "1",
		"max_execution_time":    strconv.FormatInt(qms, 10), // SELECT statements only
		"lock_wait_timeout":     strconv.FormatInt(lockSecs, 10),
	}
	return cfg, nil
}

// OpenMySQL connects using spec and returns a pool limited to one connection, so
// the session variables set at connect time apply to every statement. Callers
// that want to pick up a rotated password close the pool and open a new one.
func OpenMySQL(ctx context.Context, spec MySQLSpec) (*sql.DB, error) {
	cfg, err := MySQLConfig(spec)
	if err != nil {
		return nil, err
	}
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, fmt.Errorf("build connection: %w", err)
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect to %s: %w", cfg.Addr, err)
	}
	return db, nil
}
