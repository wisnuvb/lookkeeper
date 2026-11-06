package inventory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/wisnuvb/lockkeeper/internal/collector/pg"
)

// DB is the read-only subset of a pgx connection that the inventory uses.
type DB interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Conn is a DB that can be closed.
type Conn interface {
	DB
	Close(ctx context.Context) error
}

// Opener opens a read-only connection to the named database on the same server
// and with the same credentials as the primary connection. Only the database
// name differs.
type Opener func(ctx context.Context, database string) (Conn, error)

// Default limits.
const (
	DefaultMaxDatabases       = 50
	DefaultTopTables          = 10
	DefaultListCap            = 200
	DefaultPerDatabaseTimeout = 2 * time.Minute
)

// Options tunes Collect.
type Options struct {
	// Databases selects databases by name. Empty means every connectable,
	// non-template database except rdsadmin.
	Databases []string
	// MaxDatabases caps how many databases are inspected; selecting more is an
	// error rather than a silent truncation. Default DefaultMaxDatabases.
	MaxDatabases int
	// TopTables is how many of the largest tables are listed per database.
	TopTables int
	// ListCap caps each per-database table list (the totals stay exact).
	ListCap int
	// Log, if set, receives debug lines about progress (database names only).
	Log *slog.Logger
	// PerDatabaseTimeout bounds the inspection of one database, including
	// connecting to it. Default DefaultPerDatabaseTimeout.
	PerDatabaseTimeout time.Duration
}

func (o *Options) defaults() {
	if o.MaxDatabases <= 0 {
		o.MaxDatabases = DefaultMaxDatabases
	}
	if o.TopTables <= 0 {
		o.TopTables = DefaultTopTables
	}
	if o.ListCap <= 0 {
		o.ListCap = DefaultListCap
	}
	if o.PerDatabaseTimeout <= 0 {
		o.PerDatabaseTimeout = DefaultPerDatabaseTimeout
	}
}

// ErrTooManyDatabases is returned when more databases are selected than
// Options.MaxDatabases allows.
var ErrTooManyDatabases = errors.New("too many databases selected")

// migrationSettings are the settings read from pg_settings. The list is a
// constant so that no caller-controlled text ever reaches the query.
var migrationSettings = []string{
	"wal_level", "max_replication_slots", "max_wal_senders", "wal_sender_timeout",
	"max_slot_wal_keep_size", "max_logical_replication_workers", "max_worker_processes",
	"max_sync_workers_per_subscription", "max_connections", "log_statement",
	"log_min_duration_statement", "log_min_error_statement", "rds.logical_replication",
	"server_encoding", "shared_preload_libraries",
}

// Collect inventories the server behind primary and the selected databases. It
// is read-only. primary is used for server-level facts and for the database it
// is connected to; every other database is reached through open, one at a time,
// and closed before the next one is opened. Closing primary is the caller's job.
//
// A failure to inspect one database is recorded on that database (Error) and
// does not abort the run; a failure of the server-level queries does.
func Collect(ctx context.Context, primary DB, open Opener, opts Options) (*Server, error) {
	opts.defaults()
	s := &Server{SchemaVersion: SchemaVersion, Settings: map[string]Setting{}}

	if err := serverBasics(ctx, primary, s); err != nil {
		return nil, err
	}
	if err := serverSettings(ctx, primary, s); err != nil {
		return nil, err
	}
	if err := serverRoles(ctx, primary, s); err != nil {
		return nil, err
	}
	if _, ok := s.Settings["rds.logical_replication"]; ok || s.HasRole("rds_superuser") {
		s.IsRDS = true
	}
	slots, err := pg.ListSlots(ctx, primary)
	if err != nil {
		return nil, err
	}
	for _, sl := range slots {
		s.Slots = append(s.Slots, Slot{
			Name: sl.Name, Type: sl.Type, Plugin: sl.Plugin, Database: sl.Database,
			Active: sl.Active, RetainedBytes: int64(sl.RetainedBytes),
		})
	}

	all, err := listDatabases(ctx, primary, s)
	if err != nil {
		return nil, err
	}
	selected, err := selectDatabases(s, all, opts)
	if err != nil {
		return nil, err
	}

	for _, d := range selected {
		s.Databases = append(s.Databases, inspect(ctx, primary, open, s.Session.Database, d, opts))
	}
	return s, nil
}

func serverBasics(ctx context.Context, db DB, s *Server) error {
	var ro string
	err := db.QueryRow(ctx, `
		SELECT current_setting('server_version'), current_setting('server_version_num')::int,
		       current_database()::text, current_setting('transaction_read_only'), pg_is_in_recovery(),
		       r.rolname::text, r.rolsuper, r.rolreplication, r.rolcreaterole, r.rolcreatedb,
		       COALESCE((SELECT pg_has_role(current_user, 'rds_superuser', 'usage') FROM pg_roles WHERE rolname = 'rds_superuser'), false),
		       COALESCE((SELECT pg_has_role(current_user, 'rds_replication', 'usage') FROM pg_roles WHERE rolname = 'rds_replication'), false),
		       COALESCE((SELECT pg_has_role(current_user, 'pg_create_subscription', 'usage') FROM pg_roles WHERE rolname = 'pg_create_subscription'), false),
		       COALESCE((SELECT pg_has_role(current_user, 'pg_read_all_data', 'usage') FROM pg_roles WHERE rolname = 'pg_read_all_data'), false),
		       COALESCE((SELECT pg_has_role(current_user, 'pg_monitor', 'usage') FROM pg_roles WHERE rolname = 'pg_monitor'), false)
		FROM pg_roles r WHERE r.rolname = current_user`).
		Scan(&s.Version, &s.VersionNum, &s.Session.Database, &ro, &s.InRecovery,
			&s.Session.User, &s.Session.Superuser, &s.Session.Replication, &s.Session.CreateRole, &s.Session.CreateDB,
			&s.Session.RDSSuperuser, &s.Session.RDSReplication, &s.Session.PgCreateSubscription,
			&s.Session.PgReadAllData, &s.Session.PgMonitor)
	if err != nil {
		return fmt.Errorf("read server version and session role: %w", err)
	}
	s.Major = s.VersionNum / 10000
	s.Session.ReadOnly = ro == "on"
	return nil
}

func serverSettings(ctx context.Context, db DB, s *Server) error {
	quoted := make([]string, len(migrationSettings))
	for i, n := range migrationSettings {
		quoted[i] = QuoteLiteral(n)
	}
	rows, err := db.Query(ctx, `
		SELECT name, setting, COALESCE(unit, ''), pending_restart
		FROM pg_settings WHERE name IN (`+strings.Join(quoted, ",")+`)`)
	if err != nil {
		return fmt.Errorf("read settings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var st Setting
		if err := rows.Scan(&name, &st.Value, &st.Unit, &st.PendingRestart); err != nil {
			return fmt.Errorf("scan setting: %w", err)
		}
		s.Settings[name] = st
	}
	return rows.Err()
}

func serverRoles(ctx context.Context, db DB, s *Server) error {
	// pg_roles never exposes password hashes (unlike pg_authid).
	rows, err := db.Query(ctx, `
		SELECT r.rolname::text, r.rolsuper, r.rolcanlogin, r.rolcreaterole, r.rolcreatedb,
		       r.rolreplication, r.rolbypassrls, r.rolconnlimit,
		       COALESCE((SELECT array_agg(g.rolname::text ORDER BY g.rolname)
		                 FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
		                 WHERE m.member = r.oid), '{}'::text[]),
		       count(*) OVER ()
		FROM pg_roles r WHERE r.rolname !~ '^pg_'
		ORDER BY r.rolname LIMIT $1`, RolesCap)
	if err != nil {
		return fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.Name, &r.Superuser, &r.CanLogin, &r.CreateRole, &r.CreateDB,
			&r.Replication, &r.BypassRLS, &r.ConnLimit, &r.MemberOf, &s.RolesTotal); err != nil {
			return fmt.Errorf("scan role: %w", err)
		}
		s.Roles = append(s.Roles, r)
	}
	return rows.Err()
}

type dbRow struct {
	Database
	allowConn  bool
	isTemplate bool
	canConnect bool
}

func listDatabases(ctx context.Context, db DB, s *Server) ([]dbRow, error) {
	// to_jsonb(d) keeps one query valid across versions: datlocprovider appeared
	// in PostgreSQL 15 and the ICU locale column was renamed in 17.
	rows, err := db.Query(ctx, `
		SELECT d.datname::text, pg_get_userbyid(d.datdba)::text, pg_encoding_to_char(d.encoding)::text,
		       d.datcollate::text, d.datctype::text,
		       COALESCE(to_jsonb(d)->>'datlocprovider', 'c'),
		       COALESCE(to_jsonb(d)->>'datlocale', to_jsonb(d)->>'daticulocale', ''),
		       d.datallowconn, d.datistemplate, has_database_privilege(d.oid, 'CONNECT'),
		       CASE WHEN has_database_privilege(d.oid, 'CONNECT') THEN pg_database_size(d.oid) ELSE -1 END
		FROM pg_database d ORDER BY d.datname`)
	if err != nil {
		return nil, fmt.Errorf("list databases: %w", err)
	}
	defer rows.Close()
	var out []dbRow
	for rows.Next() {
		var d dbRow
		if err := rows.Scan(&d.Name, &d.Owner, &d.Encoding, &d.Collate, &d.Ctype, &d.Provider, &d.ICULocale,
			&d.allowConn, &d.isTemplate, &d.canConnect, &d.SizeBytes); err != nil {
			return nil, fmt.Errorf("scan database: %w", err)
		}
		if d.Name == "template1" {
			s.DefaultLocale = d.Locale
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// selectDatabases applies --databases, skips what is never inspected and
// enforces the cap. It records what it left out on s.
func selectDatabases(s *Server, all []dbRow, opts Options) ([]dbRow, error) {
	byName := make(map[string]dbRow, len(all))
	for _, d := range all {
		byName[d.Name] = d
	}
	var selected []dbRow
	if len(opts.Databases) > 0 {
		seen := map[string]bool{}
		for _, name := range opts.Databases {
			if seen[name] {
				continue
			}
			seen[name] = true
			d, ok := byName[name]
			switch {
			case !ok:
				s.NotFound = append(s.NotFound, name)
			case d.isTemplate || name == "rdsadmin":
				s.SkippedDatabases = append(s.SkippedDatabases, name)
			default:
				selected = append(selected, d)
			}
		}
		for _, d := range all {
			if !d.isTemplate && d.Name != "rdsadmin" && !seen[d.Name] {
				s.OtherDatabases = append(s.OtherDatabases, d.Name)
			}
		}
	} else {
		for _, d := range all {
			switch {
			case d.isTemplate:
			case d.Name == "rdsadmin" || !d.allowConn:
				s.SkippedDatabases = append(s.SkippedDatabases, d.Name)
			default:
				selected = append(selected, d)
			}
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Name < selected[j].Name })
	sort.Strings(s.NotFound)
	if len(selected) > opts.MaxDatabases {
		return nil, fmt.Errorf("%w: %d databases match but at most %d are inspected; choose with --databases a,b or raise --max-databases",
			ErrTooManyDatabases, len(selected), opts.MaxDatabases)
	}
	return selected, nil
}

// inspect gathers the detail of one database. It never returns an error: a
// failure is recorded on the database so the others can still be reported.
func inspect(ctx context.Context, primary DB, open Opener, primaryDB string, d dbRow, opts Options) Database {
	if opts.Log != nil {
		opts.Log.Debug("inventory: inspecting database", "database", d.Name, "own_connection", d.Name != primaryDB)
	}
	out := d.Database
	out.Extensions = []Extension{}
	out.LargestTables = []Table{}
	out.Owners = []string{}
	empty := TableList{Items: []Table{}}
	out.TablesWithoutPK, out.UnloggedTables, out.PartitionedTables, out.ForeignTables, out.UnreadableTables = empty, empty, empty, empty, empty

	if !d.canConnect {
		out.Error = "the connected role has no CONNECT privilege on this database"
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, opts.PerDatabaseTimeout)
	defer cancel()

	var db DB = primary
	if d.Name != primaryDB {
		c, err := open(ctx, d.Name)
		if err != nil {
			out.Error = "connect: " + err.Error()
			return out
		}
		defer func() {
			cctx, ccancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer ccancel()
			_ = c.Close(cctx)
		}()
		db = c
	}
	detail(ctx, db, &out, opts)
	return out
}

// userRel selects ordinary relations that belong to the user: not in system
// schemas and not owned by an extension. Aliases c (pg_class) and n
// (pg_namespace) are used by every query that embeds it.
const userRel = `
	FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
	WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
	  AND NOT EXISTS (SELECT 1 FROM pg_depend d
	                  WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')`

func detail(ctx context.Context, db DB, out *Database, opts Options) {
	warn := func(part string, err error) {
		out.Warnings = append(out.Warnings, part+": "+err.Error())
	}

	if err := db.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE c.relkind IN ('r','p') AND NOT c.relispartition),
		       count(*) FILTER (WHERE c.relkind IN ('r','p') AND c.relispartition),
		       count(*) FILTER (WHERE c.relkind = 'S'),
		       count(*) FILTER (WHERE c.relkind IN ('v','m')),
		       COALESCE(sum(pg_total_relation_size(c.oid)) FILTER (WHERE c.relkind IN ('r','m')), 0)::bigint
		`+userRel).
		Scan(&out.Tables, &out.Partitions, &out.Sequences, &out.Views, &out.TableBytes); err != nil {
		warn("count relations", err)
	}

	if err := db.QueryRow(ctx, `
		SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
		  AND NOT EXISTS (SELECT 1 FROM pg_depend d
		                  WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')`).
		Scan(&out.Functions); err != nil {
		warn("count functions", err)
	}

	if err := db.QueryRow(ctx, `
		SELECT count(*) FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE a.attgenerated <> '' AND NOT a.attisdropped AND c.relkind IN ('r','p')
		  AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'`).
		Scan(&out.GeneratedColumns); err != nil {
		warn("count generated columns", err)
	}

	exts, err := queryExtensions(ctx, db)
	if err != nil {
		warn("list extensions", err)
	} else {
		out.Extensions = exts
	}

	if err := db.QueryRow(ctx, `SELECT count(*), pg_total_relation_size('pg_largeobject'::regclass) FROM pg_largeobject_metadata`).
		Scan(&out.LargeObjects, &out.LargeObjectBytes); err != nil {
		warn("count large objects", err)
	}

	owners, err := queryOwners(ctx, db)
	if err != nil {
		warn("list object owners", err)
	} else {
		out.Owners = owners
	}

	sizeCols := `pg_total_relation_size(c.oid), GREATEST(c.reltuples, 0)::bigint`
	lists := []struct {
		part  string
		dst   *TableList
		query string
	}{
		{"tables without a primary key", &out.TablesWithoutPK, `
			SELECT n.nspname::text, c.relname::text, ` + sizeCols + `,
			       CASE c.relreplident WHEN 'd' THEN 'default' WHEN 'n' THEN 'nothing' WHEN 'f' THEN 'full' ELSE 'index' END, 0,
			       count(*) OVER ()
			` + userRel + ` AND c.relkind = 'r'
			  AND NOT EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conrelid = c.oid AND k.contype = 'p')
			ORDER BY 3 DESC, 1, 2 LIMIT $1`},
		{"unlogged tables", &out.UnloggedTables, `
			SELECT n.nspname::text, c.relname::text, ` + sizeCols + `, '', 0, count(*) OVER ()
			` + userRel + ` AND c.relkind = 'r' AND c.relpersistence = 'u'
			ORDER BY 3 DESC, 1, 2 LIMIT $1`},
		{"partitioned tables", &out.PartitionedTables, `
			SELECT n.nspname::text, c.relname::text, 0::bigint, 0::bigint, '',
			       (SELECT count(*) FROM pg_inherits i WHERE i.inhparent = c.oid)::int, count(*) OVER ()
			` + userRel + ` AND c.relkind = 'p'
			ORDER BY 1, 2 LIMIT $1`},
		{"foreign tables", &out.ForeignTables, `
			SELECT n.nspname::text, c.relname::text, 0::bigint, 0::bigint, '', 0, count(*) OVER ()
			` + userRel + ` AND c.relkind = 'f'
			ORDER BY 1, 2 LIMIT $1`},
		{"tables the role cannot read", &out.UnreadableTables, `
			SELECT n.nspname::text, c.relname::text, 0::bigint, 0::bigint, '', 0, count(*) OVER ()
			` + userRel + ` AND c.relkind IN ('r','p')
			  AND (NOT has_table_privilege(c.oid, 'SELECT') OR NOT has_schema_privilege(n.oid, 'USAGE'))
			ORDER BY 1, 2 LIMIT $1`},
	}
	for _, l := range lists {
		items, total, err := queryTables(ctx, db, l.query, opts.ListCap)
		if err != nil {
			warn(l.part, err)
			continue
		}
		l.dst.Items, l.dst.Total = items, total
	}

	largest, _, err := queryTables(ctx, db, `
		SELECT n.nspname::text, c.relname::text, `+sizeCols+`, '', 0, count(*) OVER ()
		`+userRel+` AND c.relkind = 'r'
		ORDER BY 3 DESC, 1, 2 LIMIT $1`, opts.TopTables)
	if err != nil {
		warn("largest tables", err)
	} else {
		out.LargestTables = largest
	}
}

// queryTables runs a query returning (schema, name, bytes, rows, replica
// identity, partitions, total) and one LIMIT parameter.
func queryTables(ctx context.Context, db DB, sql string, limit int) (items []Table, total int, err error) {
	rows, err := db.Query(ctx, sql, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items = []Table{}
	for rows.Next() {
		var t Table
		if err := rows.Scan(&t.Schema, &t.Name, &t.TotalBytes, &t.EstimatedRows, &t.ReplicaIdentity, &t.Partitions, &total); err != nil {
			return nil, 0, err
		}
		items = append(items, t)
	}
	return items, total, rows.Err()
}

func queryExtensions(ctx context.Context, db DB) ([]Extension, error) {
	rows, err := db.Query(ctx, `
		SELECT e.extname::text, e.extversion, n.nspname::text
		FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace ORDER BY e.extname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Extension{}
	for rows.Next() {
		var e Extension
		if err := rows.Scan(&e.Name, &e.Version, &e.Schema); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func queryOwners(ctx context.Context, db DB) ([]string, error) {
	rows, err := db.Query(ctx, `
		SELECT DISTINCT o FROM (
		  SELECT pg_get_userbyid(c.relowner)::text AS o `+userRel+` AND c.relkind IN ('r','p','v','m','S','f')
		  UNION
		  SELECT pg_get_userbyid(n.nspowner)::text FROM pg_namespace n
		   WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
		  UNION
		  SELECT pg_get_userbyid(p.proowner)::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		   WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
		     AND NOT EXISTS (SELECT 1 FROM pg_depend d
		                     WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
		  UNION
		  SELECT pg_get_userbyid(t.typowner)::text FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
		   WHERE t.typtype IN ('e','d') AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
		     AND NOT EXISTS (SELECT 1 FROM pg_depend d
		                     WHERE d.classid = 'pg_type'::regclass AND d.objid = t.oid AND d.deptype = 'e')
		) s WHERE o !~ '^pg_' ORDER BY o`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var o string
		if err := rows.Scan(&o); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
