package pgnative

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/wisnuvb/lockkeeper/internal/migrate"
)

// SlotHolder owns the replication-protocol connection that created a slot and
// exported a snapshot. The snapshot lives exactly as long as this connection:
// keep it open and idle for the whole copy, then Close it (the slot stays).
type SlotHolder struct {
	conn            *pgconn.PgConn
	Slot            string
	ConsistentPoint migrate.LSN
	SnapshotID      string
}

// CreateSlot runs CREATE_REPLICATION_SLOT on conn (a replication=database
// connection) and returns the holder. PostgreSQL 14 only knows the legacy
// EXPORT_SNAPSHOT option; 15 and later also take the parenthesised form
// (docs/PHASE3-NOTES.md 1.1 a).
//
// Creating a logical slot waits until every transaction that was running when
// the command started has finished: a long transaction on the source delays it.
// ctx bounds that wait; on expiry the connection is closed, which abandons the
// creation (no slot is left behind).
func CreateSlot(ctx context.Context, conn *pgconn.PgConn, slot string) (*SlotHolder, error) {
	cmd := "CREATE_REPLICATION_SLOT " + quoteIdent(slot) + " LOGICAL pgoutput (SNAPSHOT 'export')"
	if serverMajor(conn.ParameterStatus("server_version")) < 15 {
		cmd = "CREATE_REPLICATION_SLOT " + quoteIdent(slot) + " LOGICAL pgoutput EXPORT_SNAPSHOT"
	}
	results, err := conn.Exec(ctx, cmd).ReadAll()
	if err != nil {
		_ = conn.Close(context.WithoutCancel(ctx))
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("creating the replication slot did not finish in time: it waits for every transaction that was open when it started (check pg_stat_activity on the source for long-running transactions): %w", err)
		}
		return nil, fmt.Errorf("create replication slot %s: %w", slot, err)
	}
	if len(results) != 1 || len(results[0].Rows) != 1 || len(results[0].Rows[0]) < 3 {
		_ = conn.Close(context.WithoutCancel(ctx))
		return nil, fmt.Errorf("create replication slot %s: unexpected result", slot)
	}
	row := results[0].Rows[0]
	lsn, err := migrate.ParseLSN(string(row[1]))
	if err != nil {
		_ = conn.Close(context.WithoutCancel(ctx))
		return nil, err
	}
	if len(row[2]) == 0 {
		_ = conn.Close(context.WithoutCancel(ctx))
		return nil, errors.New("the server returned no snapshot name")
	}
	return &SlotHolder{conn: conn, Slot: slot, ConsistentPoint: lsn, SnapshotID: string(row[2])}, nil
}

// Alive reports whether the holder connection is still usable (it is idle, so a
// closed or broken connection means the snapshot is gone).
func (h *SlotHolder) Alive() bool { return h != nil && h.conn != nil && !h.conn.IsClosed() }

// Close releases the snapshot. The slot stays on the server.
func (h *SlotHolder) Close() {
	if h == nil || h.conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = h.conn.Close(ctx)
}

func serverMajor(v string) int {
	n := 0
	for _, r := range v {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// SlotState is the source's view of a replication slot.
type SlotState struct {
	Exists         bool
	Active         bool
	Plugin         string
	Database       string
	WALStatus      string
	RestartLSN     migrate.LSN
	ConfirmedFlush migrate.LSN
	CurrentLSN     migrate.LSN
	RetainedBytes  int64
	LagBytes       int64
}

// ReadSlot reads slot state for a slot name, or for the newest slot whose name
// starts with prefix when name is empty. It is read-only.
func ReadSlot(ctx context.Context, db DB, name string) (SlotState, error) {
	var s SlotState
	var restart, flush, current string
	err := db.QueryRow(ctx, `
		SELECT active, COALESCE(plugin::text, ''), COALESCE(database::text, ''), COALESCE(wal_status, ''),
		       COALESCE(restart_lsn::text, '0/0'), COALESCE(confirmed_flush_lsn::text, '0/0'), pg_current_wal_lsn()::text,
		       COALESCE(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn), 0)::bigint,
		       COALESCE(pg_wal_lsn_diff(pg_current_wal_lsn(), confirmed_flush_lsn), 0)::bigint
		FROM pg_replication_slots WHERE slot_name = $1`, name).
		Scan(&s.Active, &s.Plugin, &s.Database, &s.WALStatus, &restart, &flush, &current, &s.RetainedBytes, &s.LagBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		return SlotState{}, nil
	}
	if err != nil {
		return SlotState{}, fmt.Errorf("read slot %s: %w", name, err)
	}
	s.Exists = true
	s.RestartLSN, _ = migrate.ParseLSN(restart)
	s.ConfirmedFlush, _ = migrate.ParseLSN(flush)
	s.CurrentLSN, _ = migrate.ParseLSN(current)
	return s, nil
}

// SlotsWithPrefix lists the names of the slots whose name starts with prefix.
func SlotsWithPrefix(ctx context.Context, db DB, prefix string) ([]string, error) {
	rows, err := db.Query(ctx, `SELECT slot_name::text FROM pg_replication_slots WHERE starts_with(slot_name::text, $1) ORDER BY slot_name`, prefix)
	if err != nil {
		return nil, fmt.Errorf("list slots: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// SubState is the target's view of a subscription.
type SubState struct {
	Exists     bool
	Enabled    bool
	SlotName   string
	WorkerPID  int
	Received   migrate.LSN
	LatestEnd  migrate.LSN
	RemoteLSN  migrate.LSN
	ApplyError int64 // -1 when this server version cannot say
}

// ReadSub reads the subscription named name of the connected database.
func ReadSub(ctx context.Context, db DB, name string) (SubState, error) {
	var s SubState
	var recv, latest, remote string
	var oid int64
	err := db.QueryRow(ctx, `
		SELECT s.oid::bigint, s.subenabled, COALESCE(s.subslotname::text, ''),
		       COALESCE((SELECT min(pid) FROM pg_stat_subscription st WHERE st.subid = s.oid AND st.relid IS NULL), 0),
		       COALESCE((SELECT max(received_lsn)::text FROM pg_stat_subscription st WHERE st.subid = s.oid AND st.relid IS NULL), '0/0'),
		       COALESCE((SELECT max(latest_end_lsn)::text FROM pg_stat_subscription st WHERE st.subid = s.oid AND st.relid IS NULL), '0/0'),
		       COALESCE((SELECT remote_lsn::text FROM pg_replication_origin_status o WHERE o.external_id = 'pg_' || s.oid), '0/0')
		FROM pg_subscription s
		WHERE s.subname = $1 AND s.subdbid = (SELECT oid FROM pg_database WHERE datname = current_database())`, name).
		Scan(&oid, &s.Enabled, &s.SlotName, &s.WorkerPID, &recv, &latest, &remote)
	if errors.Is(err, pgx.ErrNoRows) {
		return SubState{}, nil
	}
	if err != nil {
		return SubState{}, fmt.Errorf("read subscription %s: %w", name, err)
	}
	s.Exists = true
	s.Received, _ = migrate.ParseLSN(recv)
	s.LatestEnd, _ = migrate.ParseLSN(latest)
	s.RemoteLSN, _ = migrate.ParseLSN(remote)
	s.ApplyError = -1
	var n int64
	if err := db.QueryRow(ctx, `SELECT apply_error_count + sync_error_count FROM pg_stat_subscription_stats WHERE subid = $1::oid`, strconv.FormatInt(oid, 10)).Scan(&n); err == nil {
		s.ApplyError = n
	}
	return s, nil
}

// UserTables counts the tables a migration would copy that already exist in the
// connected database (extension members are ignored: an extension the
// operator installed on purpose brings its own tables).
func UserTables(ctx context.Context, db DB) (int, error) {
	var n int
	err := db.QueryRow(ctx, `
		SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p', 'f') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_toast'
		  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count tables: %w", err)
	}
	return n, nil
}

// CreateStatementFor returns the CREATE DATABASE statement that recreates an
// existing database empty with its encoding, locale, provider and owner. It is
// used by the recovery plan before the database is dropped.
func CreateStatementFor(ctx context.Context, db DB, name string) (string, error) {
	var enc, collate, ctype, owner, provider string
	var icu *string
	err := db.QueryRow(ctx, `
		SELECT pg_encoding_to_char(d.encoding), d.datcollate::text, d.datctype::text, pg_get_userbyid(d.datdba)::text,
		       COALESCE(to_jsonb(d)->>'datlocprovider', 'c'),
		       COALESCE(to_jsonb(d)->>'datlocale', to_jsonb(d)->>'daticulocale')
		FROM pg_database d WHERE d.datname = $1`, name).Scan(&enc, &collate, &ctype, &owner, &provider, &icu)
	if err != nil {
		return "", fmt.Errorf("read properties of database %s: %w", name, err)
	}
	var b strings.Builder
	b.WriteString("CREATE DATABASE " + quoteIdent(name) + " WITH TEMPLATE template0 ENCODING " + quoteLit(enc))
	if provider == "i" && icu != nil {
		b.WriteString(" LOCALE_PROVIDER icu ICU_LOCALE " + quoteLit(*icu))
	}
	b.WriteString(" LC_COLLATE " + quoteLit(collate) + " LC_CTYPE " + quoteLit(ctype) + " OWNER " + quoteIdent(owner))
	return b.String(), nil
}

func quoteLit(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
