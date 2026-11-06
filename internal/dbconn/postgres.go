// Package dbconn builds database connections with Lockkeeper's safety policy:
// TLS verified by default, no silent fall back to plaintext, read-only sessions,
// bounded timeouts, and no influence from ambient PG* environment variables.
package dbconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/secret"
)

// PGSpec describes one Postgres connection.
type PGSpec struct {
	Host     string
	Port     int
	Database string
	User     string
	Password secret.Value

	TLSMode       string
	CAFile        string
	AllowInsecure bool

	// ConnectTimeout bounds dialing and the TLS/auth handshake.
	ConnectTimeout time.Duration
	// StatementTimeout is applied server-side to every statement of the session.
	StatementTimeout time.Duration
	// ApplicationName is shown in pg_stat_activity.
	ApplicationName string
}

// SpecFromConfig maps a validated config entry plus its resolved password.
func SpecFromConfig(db config.Database, pw secret.Value, queryTimeout time.Duration) PGSpec {
	return PGSpec{
		Host:             db.Host,
		Port:             db.Port,
		Database:         db.Database,
		User:             db.User,
		Password:         pw,
		TLSMode:          db.TLS.Mode,
		CAFile:           db.TLS.CAFile,
		AllowInsecure:    db.TLS.AllowInsecure,
		ConnectTimeout:   10 * time.Second,
		StatementTimeout: queryTimeout,
		ApplicationName:  "lockkeeper",
	}
}

// ConnConfig builds the pgx configuration for spec. It is separate from Open so
// the security-relevant settings can be unit-tested without a server.
func ConnConfig(spec PGSpec) (*pgx.ConnConfig, error) {
	if spec.Host == "" || spec.User == "" {
		return nil, errors.New("host and user are required")
	}
	if spec.Port == 0 {
		spec.Port = 5432
	}
	if spec.Database == "" {
		spec.Database = "postgres"
	}
	if spec.ConnectTimeout == 0 {
		spec.ConnectTimeout = 10 * time.Second
	}
	if spec.ApplicationName == "" {
		spec.ApplicationName = "lockkeeper"
	}

	tlsCfg, err := TLSConfig(spec.TLSMode, spec.Host, spec.CAFile, spec.AllowInsecure)
	if err != nil {
		return nil, err
	}

	// Build a URL so that special characters in names are escaped correctly. The
	// password is deliberately not part of it; it is set on the config below.
	u := url.URL{
		Scheme: "postgres",
		User:   url.User(spec.User),
		Host:   net.JoinHostPort(spec.Host, strconv.Itoa(spec.Port)),
		Path:   "/" + spec.Database,
	}
	if len(spec.Host) > 0 && spec.Host[0] == '/' { // unix socket directory
		q := url.Values{}
		q.Set("host", spec.Host)
		u = url.URL{Scheme: "postgres", User: url.User(spec.User), Path: "/" + spec.Database, RawQuery: q.Encode()}
	}
	cfg, err := pgx.ParseConfig(u.String())
	if err != nil {
		// pgx errors can echo the input; the URL has no password, so this is safe.
		return nil, fmt.Errorf("build connection config: %w", err)
	}

	cfg.Password = spec.Password.Reveal()
	cfg.TLSConfig = tlsCfg
	cfg.Fallbacks = nil // never retry in plaintext
	cfg.ConnectTimeout = spec.ConnectTimeout
	cfg.DefaultQueryExecMode = pgx.QueryExecModeExec // no prepared statements: friendly to poolers

	// Ambient PGOPTIONS etc. must not change session behaviour.
	for k := range cfg.RuntimeParams {
		delete(cfg.RuntimeParams, k)
	}
	cfg.RuntimeParams["application_name"] = spec.ApplicationName
	cfg.RuntimeParams["default_transaction_read_only"] = "on"
	cfg.RuntimeParams["idle_in_transaction_session_timeout"] = "60000"
	if spec.StatementTimeout > 0 {
		ms := strconv.FormatInt(spec.StatementTimeout.Milliseconds(), 10)
		cfg.RuntimeParams["statement_timeout"] = ms
		cfg.RuntimeParams["lock_timeout"] = ms
	}
	return cfg, nil
}

// OpenPG connects using spec.
func OpenPG(ctx context.Context, spec PGSpec) (*pgx.Conn, error) {
	cfg, err := ConnConfig(spec)
	if err != nil {
		return nil, err
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to %s:%d: %w", spec.Host, spec.Port, err)
	}
	return conn, nil
}

// TLSConfig returns the TLS configuration for a mode, or nil for "disable".
//
//   - verify-full: certificate chain and host name verified (default, required for remote hosts)
//   - verify-ca:   chain verified, host name not checked
//   - require:     encrypted, server NOT authenticated (vulnerable to MITM)
//   - disable:     plaintext
//
// require and disable are refused for non-loopback hosts unless allowInsecure.
func TLSConfig(mode, host, caFile string, allowInsecure bool) (*tls.Config, error) {
	if mode == "" {
		mode = config.TLSVerifyFull
	}
	local := config.IsLocalHost(host)
	if (mode == config.TLSRequire || mode == config.TLSDisable) && !local && !allowInsecure {
		return nil, fmt.Errorf("tls mode %q is refused for remote host %q without allow_insecure", mode, host)
	}

	switch mode {
	case config.TLSDisable:
		return nil, nil
	case config.TLSRequire:
		return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, nil //nolint:gosec // explicit, warned opt-in
	case config.TLSVerifyFull, config.TLSVerifyCA:
		pool, err := rootPool(caFile)
		if err != nil {
			return nil, err
		}
		if mode == config.TLSVerifyFull {
			return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: host}, nil
		}
		// verify-ca: verify the chain ourselves, skip only the host name check.
		return &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // chain is verified in VerifyPeerCertificate
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				return verifyChainOnly(raw, pool)
			},
		}, nil
	default:
		return nil, fmt.Errorf("unknown tls mode %q", mode)
	}
}

func rootPool(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system CA pool: %w", err)
		}
		return pool, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read tls ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("tls ca_file %s contains no valid PEM certificates", caFile)
	}
	return pool, nil
}

func verifyChainOnly(raw [][]byte, roots *x509.CertPool) error {
	if len(raw) == 0 {
		return errors.New("server presented no certificate")
	}
	certs := make([]*x509.Certificate, 0, len(raw))
	for _, r := range raw {
		c, err := x509.ParseCertificate(r)
		if err != nil {
			return fmt.Errorf("parse server certificate: %w", err)
		}
		certs = append(certs, c)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter})
	return err
}
