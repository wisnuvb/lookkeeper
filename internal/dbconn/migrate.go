package dbconn

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// OpenPGWrite connects for an action that changes the database. It is the only
// opener whose sessions are read-write: everything else in Lockkeeper forces
// default_transaction_read_only=on. It keeps the TLS policy, the timeouts and
// the isolation from ambient PG* variables, and names the session so the
// operator can recognise it in pg_stat_activity. lockTimeout bounds how long a
// change may wait for a lock held by the application (zero keeps the
// statement timeout).
func OpenPGWrite(ctx context.Context, spec PGSpec, lockTimeout time.Duration) (*pgx.Conn, error) {
	cfg, err := ConnConfig(spec)
	if err != nil {
		return nil, err
	}
	cfg.RuntimeParams["default_transaction_read_only"] = "off"
	cfg.RuntimeParams["application_name"] = "lockkeeper-migrate"
	if lockTimeout > 0 {
		cfg.RuntimeParams["lock_timeout"] = strconv.FormatInt(lockTimeout.Milliseconds(), 10)
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to %s:%d: %w", spec.Host, spec.Port, err)
	}
	return conn, nil
}

// OpenReplication opens a replication-protocol connection (replication=database)
// to the database of spec. It can run replication commands such as
// CREATE_REPLICATION_SLOT but no ordinary SQL with parameters. TLS policy and
// timeouts are the same as for every other connection.
func OpenReplication(ctx context.Context, spec PGSpec) (*pgconn.PgConn, error) {
	cfg, err := ConnConfig(spec)
	if err != nil {
		return nil, err
	}
	// A walsender session does not accept the session parameters that ConnConfig
	// sets for ordinary sessions (idle_in_transaction_session_timeout would also
	// kill the idle snapshot holder), so start from the connection settings only.
	pc := cfg.Config
	pc.RuntimeParams = map[string]string{
		"replication":      "database",
		"application_name": "lockkeeper-snapshot",
	}
	conn, err := pgconn.ConnectConfig(ctx, &pc)
	if err != nil {
		return nil, fmt.Errorf("connect (replication) to %s:%d: %w", spec.Host, spec.Port, err)
	}
	return conn, nil
}
