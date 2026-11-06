package pg

import (
	"context"

	"github.com/wisnuvb/lockkeeper/internal/inventory"
)

// SSLInfo describes the TLS state of the connection Lockkeeper itself used.
type SSLInfo struct {
	Enabled bool   `json:"enabled"`
	Version string `json:"version,omitempty"`
	Cipher  string `json:"cipher,omitempty"`
}

// Facts are live observations that are not part of the inventory. A nil pointer
// or map means the fact could not be read (usually a missing privilege); the
// checks then say that it could not be verified instead of guessing.
type Facts struct {
	// SSL is the TLS state of the connection used for the pre-flight.
	SSL *SSLInfo
	// AvailableExtensions maps extension name to default version, from
	// pg_available_extensions: what CREATE EXTENSION could install here.
	AvailableExtensions map[string]string
	// DDLSessions counts other sessions that are running or holding a
	// transaction open with a DDL statement; HiddenSessions counts sessions of
	// other users that this role cannot see into (it lacks pg_read_all_stats),
	// so DDLSessions is then only a lower bound.
	// Only counts are read: the statement text never leaves the server.
	DDLSessions    *int
	HiddenSessions int
	// WALSenders is the number of walsender processes running now.
	WALSenders *int
	// LogicalWorkers is the number of logical replication workers running now.
	LogicalWorkers *int
}

// GatherFacts reads Facts with read-only queries. A query that fails leaves its
// fact unset; it never fails the pre-flight.
func GatherFacts(ctx context.Context, db inventory.DB) Facts {
	var f Facts

	var ssl SSLInfo
	if err := db.QueryRow(ctx,
		`SELECT ssl, COALESCE(version, ''), COALESCE(cipher, '') FROM pg_stat_ssl WHERE pid = pg_backend_pid()`).
		Scan(&ssl.Enabled, &ssl.Version, &ssl.Cipher); err == nil {
		f.SSL = &ssl
	}

	if rows, err := db.Query(ctx, `SELECT name::text, COALESCE(default_version, '') FROM pg_available_extensions`); err == nil {
		avail := map[string]string{}
		for rows.Next() {
			var name, ver string
			if err := rows.Scan(&name, &ver); err != nil {
				avail = nil
				break
			}
			avail[name] = ver
		}
		if rows.Err() != nil {
			avail = nil
		}
		rows.Close()
		f.AvailableExtensions = avail
	}

	// backend_type is NULL for sessions of other users that this role cannot
	// see into, so those are matched by having a database.
	// The statement text is matched on the server and only counts come back
	// (threat T10). Sessions of other users show '<insufficient privilege>'
	// unless the role has pg_read_all_stats (pg_monitor), which we report.
	var ddl, hidden int
	if err := db.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE query ~* '^\s*(create|alter|drop|truncate|reindex|cluster|comment|grant|revoke)\M'),
		       count(*) FILTER (WHERE query = '<insufficient privilege>')
		FROM pg_stat_activity
		WHERE pid <> pg_backend_pid() AND datname IS NOT NULL
		  AND (backend_type IS NULL OR backend_type = 'client backend')
		  AND (state IN ('active', 'idle in transaction') OR query = '<insufficient privilege>')`).Scan(&ddl, &hidden); err == nil {
		f.DDLSessions, f.HiddenSessions = &ddl, hidden
	}

	var senders int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM pg_stat_replication`).Scan(&senders); err == nil {
		f.WALSenders = &senders
	}

	var workers int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM pg_stat_subscription WHERE pid IS NOT NULL`).Scan(&workers); err == nil {
		f.LogicalWorkers = &workers
	}
	return f
}
