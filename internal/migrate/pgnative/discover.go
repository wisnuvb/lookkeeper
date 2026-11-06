package pgnative

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// DB is the read-only query surface of a connection (*pgx.Conn implements it).
type DB interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Table names one table.
type Table struct {
	Schema string
	Name   string
}

// String is the quoted, schema-qualified name used in SQL.
func (t Table) String() string { return quoteIdent(t.Schema) + "." + quoteIdent(t.Name) }

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// DBFacts is what the plan needs to know about one source database.
type DBFacts struct {
	Database string
	// Publish are the tables that go into the publication: permanent ordinary
	// tables and the leaf partitions of partitioned tables (a partitioned parent
	// holds no rows itself), excluding members of extensions.
	Publish []Table
	// NeedFull are published tables whose replica identity cannot identify rows
	// (no primary key, identity default or NOTHING). They need REPLICA IDENTITY
	// FULL for updates and deletes to replicate.
	NeedFull []Table
	// NotOwned are published tables the connected role may not ALTER (it is
	// neither owner nor member of the owner role, nor superuser).
	NotOwned []Table
	// Counts of what is not published, for notices.
	Unlogged, Foreign, PartitionedParents, ExtensionTables int
	Sequences                                              int
	LargeObjects                                           int64
	// CanCreate is whether the role may create objects (a publication) in the database.
	CanCreate bool
	// Superuser is true when the connected role is a superuser.
	Superuser bool
}

// DiscoverDatabase reads DBFacts through db, a session to that database. Strictly read-only.
func DiscoverDatabase(ctx context.Context, db DB, database string) (DBFacts, error) {
	f := DBFacts{Database: database}
	rows, err := db.Query(ctx, `
		SELECT n.nspname::text, c.relname::text, c.relkind::text, c.relpersistence::text, c.relreplident::text,
		       EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.oid AND i.indisprimary AND i.indisvalid),
		       EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.oid AND i.indisreplident AND i.indisvalid),
		       (SELECT rolsuper OR pg_has_role(current_user, c.relowner, 'USAGE') FROM pg_roles WHERE rolname = current_user),
		       EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p', 'f') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND n.nspname !~ '^pg_toast' AND n.nspname !~ '^pg_temp'
		ORDER BY n.nspname, c.relname`)
	if err != nil {
		return f, fmt.Errorf("list tables of %s: %w", database, err)
	}
	defer rows.Close()
	for rows.Next() {
		var schema, name, kind, persist, ident string
		var hasPK, hasRI, owns, ext bool
		if err := rows.Scan(&schema, &name, &kind, &persist, &ident, &hasPK, &hasRI, &owns, &ext); err != nil {
			return f, err
		}
		t := Table{Schema: schema, Name: name}
		switch {
		case ext:
			f.ExtensionTables++
		case kind == "f":
			f.Foreign++
		case kind == "p":
			f.PartitionedParents++
		case persist == "u":
			f.Unlogged++
		case persist == "t":
			// temporary tables of other sessions: never part of a migration
		default: // 'r', permanent
			f.Publish = append(f.Publish, t)
			if !owns {
				f.NotOwned = append(f.NotOwned, t)
			}
			// 'f' FULL and 'i' (a valid identity index) identify rows; 'd' default
			// needs a primary key; 'n' NOTHING never does.
			identifies := ident == "f" || (ident == "i" && hasRI) || (ident == "d" && hasPK)
			if !identifies {
				f.NeedFull = append(f.NeedFull, t)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return f, err
	}
	rows.Close()
	if err := db.QueryRow(ctx, `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind = 'S' AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_toast'`).Scan(&f.Sequences); err != nil {
		return f, fmt.Errorf("count sequences: %w", err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM pg_largeobject_metadata`).Scan(&f.LargeObjects); err != nil {
		f.LargeObjects = -1 // not readable: unknown
	}
	if err := db.QueryRow(ctx, `SELECT has_database_privilege(current_database(), 'CREATE'),
		(SELECT rolsuper FROM pg_roles WHERE rolname = current_user)`).Scan(&f.CanCreate, &f.Superuser); err != nil {
		return f, fmt.Errorf("read privileges: %w", err)
	}
	return f, nil
}

// SourceFacts describes the source server and the role Lockkeeper connects as.
type SourceFacts struct {
	User                       string
	VersionNum, Major          int
	Version                    string
	Superuser, CreateRole      bool
	Replication                bool
	RDSSuperuser, RDSReplicate bool
	WALLevel                   string
	MaxSlots, MaxSenders       int
	SlotsUsed, SendersUsed     int
	InRecovery                 bool
}

// DiscoverSource reads SourceFacts. Read-only.
func DiscoverSource(ctx context.Context, db DB) (SourceFacts, error) {
	var f SourceFacts
	err := db.QueryRow(ctx, `
		SELECT r.rolname::text, current_setting('server_version'), current_setting('server_version_num')::int,
		       r.rolsuper, r.rolcreaterole, r.rolreplication,
		       COALESCE((SELECT pg_has_role(r.oid, x.oid, 'MEMBER') FROM pg_roles x WHERE x.rolname = 'rds_superuser'), false),
		       COALESCE((SELECT pg_has_role(r.oid, x.oid, 'MEMBER') FROM pg_roles x WHERE x.rolname = 'rds_replication'), false),
		       current_setting('wal_level'), current_setting('max_replication_slots')::int, current_setting('max_wal_senders')::int,
		       (SELECT count(*) FROM pg_replication_slots), (SELECT count(*) FROM pg_stat_replication), pg_is_in_recovery()
		FROM pg_roles r WHERE r.rolname = current_user`).
		Scan(&f.User, &f.Version, &f.VersionNum, &f.Superuser, &f.CreateRole, &f.Replication, &f.RDSSuperuser, &f.RDSReplicate,
			&f.WALLevel, &f.MaxSlots, &f.MaxSenders, &f.SlotsUsed, &f.SendersUsed, &f.InRecovery)
	if err != nil {
		return f, fmt.Errorf("read source facts: %w", err)
	}
	f.Major = f.VersionNum / 10000
	return f, nil
}

// TargetFacts describes the target server and the role Lockkeeper connects as.
type TargetFacts struct {
	User              string
	VersionNum, Major int
	Version           string
	Superuser         bool
	// CreateSubscription is true for a superuser, or (PostgreSQL 16+) a member of
	// pg_create_subscription that may create objects in the database.
	CreateSubscription bool
	CanCreate          bool
	UserTables         int
	// StatementStats is true when pg_stat_statements is loaded: it would keep the
	// text of CREATE SUBSCRIPTION, password included (see PHASE3-NOTES 1.2).
	StatementStats bool
	MaxWorkers     int
}

// DiscoverTarget reads TargetFacts from a session to the target database. Read-only.
func DiscoverTarget(ctx context.Context, db DB) (TargetFacts, error) {
	var f TargetFacts
	err := db.QueryRow(ctx, `
		SELECT r.rolname::text, current_setting('server_version'), current_setting('server_version_num')::int, r.rolsuper,
		       has_database_privilege(current_database(), 'CREATE'),
		       (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		         WHERE c.relkind IN ('r', 'p', 'f') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_toast'),
		       current_setting('shared_preload_libraries') ~ 'pg_stat_statements',
		       current_setting('max_logical_replication_workers')::int
		FROM pg_roles r WHERE r.rolname = current_user`).
		Scan(&f.User, &f.Version, &f.VersionNum, &f.Superuser, &f.CanCreate, &f.UserTables, &f.StatementStats, &f.MaxWorkers)
	if err != nil {
		return f, fmt.Errorf("read target facts: %w", err)
	}
	f.Major = f.VersionNum / 10000
	f.CreateSubscription = f.Superuser
	if !f.Superuser && f.Major >= 16 {
		var member bool
		if err := db.QueryRow(ctx, `SELECT COALESCE((SELECT pg_has_role(current_user, 'pg_create_subscription', 'MEMBER')), false)`).Scan(&member); err == nil {
			f.CreateSubscription = member && f.CanCreate
		}
	}
	return f, nil
}

// CheckSource returns every reason the source cannot be migrated by this role,
// each with what to do. An empty result means the role has what it needs. It
// runs before any change is made.
func CheckSource(f SourceFacts, dbs []DBFacts) []string {
	var p []string
	if f.InRecovery {
		p = append(p, "the source is a standby (in recovery): a migration needs the primary")
	}
	if f.WALLevel != "logical" {
		p = append(p, fmt.Sprintf("source wal_level is %q, not logical: set wal_level=logical (on RDS: rds.logical_replication=1 in the parameter group, then reboot)", f.WALLevel))
	}
	if !(f.Superuser || f.Replication || f.RDSReplicate) {
		p = append(p, fmt.Sprintf("source role %q cannot create a replication slot: it needs the REPLICATION attribute (on RDS: GRANT rds_replication TO %s)", f.User, quoteIdent(f.User)))
	}
	if !(f.Superuser || f.CreateRole || f.RDSSuperuser) {
		p = append(p, fmt.Sprintf("source role %q cannot create the per-migration role: it needs CREATEROLE (on RDS: rds_superuser)", f.User))
	}
	if free := f.MaxSlots - f.SlotsUsed; free < len(dbs) {
		p = append(p, fmt.Sprintf("source has %d free replication slot(s) (max_replication_slots=%d, %d in use) but %d database(s) need one each: raise max_replication_slots", free, f.MaxSlots, f.SlotsUsed, len(dbs)))
	}
	if free := f.MaxSenders - f.SendersUsed; free < len(dbs)+1 {
		p = append(p, fmt.Sprintf("source has %d free WAL sender(s) (max_wal_senders=%d, %d in use) but needs %d (one per database plus one for the snapshot connection): raise max_wal_senders", free, f.MaxSenders, f.SendersUsed, len(dbs)+1))
	}
	for _, d := range dbs {
		if !d.CanCreate && !d.Superuser {
			p = append(p, fmt.Sprintf("source role %q has no CREATE privilege on database %s, so it cannot create the publication: GRANT CREATE ON DATABASE %s TO %s", f.User, quoteIdent(d.Database), quoteIdent(d.Database), quoteIdent(f.User)))
		}
		if len(d.NotOwned) > 0 {
			p = append(p, fmt.Sprintf("source role %q does not own %s in database %s, so it can neither publish them nor set REPLICA IDENTITY: connect as their owner or a superuser", f.User, tableList(d.NotOwned, 5), d.Database))
		}
		if len(d.Publish) == 0 {
			p = append(p, fmt.Sprintf("database %s has no ordinary table to replicate", d.Database))
		}
	}
	return p
}

// CheckTarget returns every reason the target cannot receive the migration.
func CheckTarget(f TargetFacts, src SourceFacts, databases []string) []string {
	var p []string
	if !f.CreateSubscription {
		if f.Major >= 16 {
			p = append(p, fmt.Sprintf("target role %q cannot create subscriptions: use a superuser, or GRANT pg_create_subscription TO %s and CREATE on the database", f.User, quoteIdent(f.User)))
		} else {
			p = append(p, fmt.Sprintf("target role %q cannot create subscriptions: PostgreSQL %d requires a superuser", f.User, f.Major))
		}
	}
	if f.Major < src.Major {
		p = append(p, fmt.Sprintf("target PostgreSQL %d is older than the source %d: logical replication needs target >= source", f.Major, src.Major))
	}
	if f.MaxWorkers < len(databases) {
		p = append(p, fmt.Sprintf("target max_logical_replication_workers=%d is below the %d databases being migrated", f.MaxWorkers, len(databases)))
	}
	return p
}

func tableList(ts []Table, max int) string {
	names := make([]string, 0, len(ts))
	for _, t := range ts {
		names = append(names, t.String())
	}
	sort.Strings(names)
	if len(names) > max {
		return strings.Join(names[:max], ", ") + fmt.Sprintf(" and %d more", len(names)-max)
	}
	return strings.Join(names, ", ")
}
