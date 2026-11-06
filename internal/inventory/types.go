// Package inventory discovers what a PostgreSQL server contains, strictly
// read-only: version, the settings that matter for a migration, roles (names and
// attributes only, never passwords or hashes), replication slots, and for every
// selected database its size, locale, extensions and the tables that need
// attention before logical replication (no primary key, unlogged, partitioned,
// foreign, large objects).
//
// What it never does: create objects, change settings, terminate sessions, or
// read table contents. It never returns SQL text of other sessions or any data
// value; the only strings it reports are names of schema objects, roles,
// settings and extensions (threat T10).
//
// JSON: every type here is part of the machine-readable output of
// `lockkeeper inventory --json` and of the inputs of the preflight report, so
// the field names are a stable interface (see SchemaVersion). Sizes are bytes.
package inventory

import "fmt"

// SchemaVersion is the version of the JSON layout of Server. Bump it when a
// field is removed or changes meaning (adding fields does not need a bump).
const SchemaVersion = 1

// RolesCap is the most roles listed in Server.Roles.
const RolesCap = 2000

// Server is the inventory of one PostgreSQL server.
type Server struct {
	SchemaVersion int `json:"schema_version"`
	// Version is server_version (for example "17.2"); VersionNum is
	// server_version_num (170002); Major is the major version (17).
	Version    string `json:"version"`
	VersionNum int    `json:"version_num"`
	Major      int    `json:"major"`
	// InRecovery is true on a standby (pg_is_in_recovery()). A standby cannot be
	// written to, and before PostgreSQL 16 it cannot host logical slots.
	InRecovery bool `json:"in_recovery"`
	// IsRDS is true when the server looks like Amazon RDS/Aurora: the
	// rds.logical_replication setting or the rds_superuser role exists. This is
	// a heuristic, not a guarantee.
	IsRDS bool `json:"is_rds"`
	// Session describes the role Lockkeeper connected as.
	Session Session `json:"session"`
	// Settings holds the migration-relevant settings that exist on this server,
	// by name. Settings that do not exist on this version are absent.
	Settings map[string]Setting `json:"settings"`
	// Roles lists non-system roles (pg_* roles are omitted), capped at RolesCap
	// entries; RolesTotal is the real count.
	Roles      []Role `json:"roles"`
	RolesTotal int    `json:"roles_total"`
	// DefaultLocale is the encoding and locale of template1, which is what a
	// newly created database inherits unless told otherwise.
	DefaultLocale Locale `json:"default_locale"`
	// Slots are all replication slots of the server (cluster-wide).
	Slots []Slot `json:"slots"`
	// Databases holds the detailed inventory of the selected databases.
	Databases []Database `json:"databases"`
	// OtherDatabases are connectable non-template databases that were not
	// selected (names only), so the operator sees what was left out.
	OtherDatabases []string `json:"other_databases,omitempty"`
	// SkippedDatabases are databases that are never inspected (rdsadmin,
	// databases that refuse connections).
	SkippedDatabases []string `json:"skipped_databases,omitempty"`
	// NotFound lists requested databases that do not exist on this server.
	NotFound []string `json:"not_found,omitempty"`
	// Warnings are partial failures (a query that failed or timed out). They
	// carry the failing part's name and the server's error text, never data.
	Warnings []string `json:"warnings,omitempty"`
}

// Session describes the connected role and session.
type Session struct {
	User        string `json:"user"`
	Database    string `json:"database"`
	Superuser   bool   `json:"superuser"`
	Replication bool   `json:"replication"`
	CreateRole  bool   `json:"create_role"`
	CreateDB    bool   `json:"create_db"`
	// The following are true when the role has the privileges of the named
	// role (membership with INHERIT), which is what matters for what the role
	// can do without SET ROLE. They are false when the role does not exist.
	RDSSuperuser         bool `json:"rds_superuser"`
	RDSReplication       bool `json:"rds_replication"`
	PgCreateSubscription bool `json:"pg_create_subscription"`
	PgReadAllData        bool `json:"pg_read_all_data"`
	PgMonitor            bool `json:"pg_monitor"`
	// ReadOnly is true when the session refuses writes (transaction_read_only).
	ReadOnly bool `json:"read_only"`
}

// Setting is one row of pg_settings.
type Setting struct {
	Value string `json:"value"`
	// Unit is the unit of Value as in pg_settings ("ms", "MB", "8kB", or empty).
	Unit string `json:"unit,omitempty"`
	// PendingRestart is true when the configured value differs from the value
	// the running server uses and a restart would change it.
	PendingRestart bool `json:"pending_restart,omitempty"`
}

// Role is a database role. Passwords and hashes are never read.
type Role struct {
	Name        string   `json:"name"`
	Superuser   bool     `json:"superuser"`
	CanLogin    bool     `json:"can_login"`
	CreateRole  bool     `json:"create_role"`
	CreateDB    bool     `json:"create_db"`
	Replication bool     `json:"replication"`
	BypassRLS   bool     `json:"bypass_rls"`
	ConnLimit   int      `json:"conn_limit"`
	MemberOf    []string `json:"member_of,omitempty"`
}

// Locale is a database's encoding and collation settings.
type Locale struct {
	Encoding string `json:"encoding"`
	Collate  string `json:"collate"`
	Ctype    string `json:"ctype"`
	// Provider is the locale provider: "c" (libc), "i" (ICU) or "b" (builtin);
	// "c" on servers older than PostgreSQL 15.
	Provider string `json:"provider"`
	// ICULocale is the ICU or builtin locale name, empty for libc.
	ICULocale string `json:"icu_locale,omitempty"`
}

// Slot is a replication slot.
type Slot struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Plugin        string `json:"plugin,omitempty"`
	Database      string `json:"database,omitempty"`
	Active        bool   `json:"active"`
	RetainedBytes int64  `json:"retained_bytes"`
}

// Extension is an installed extension.
type Extension struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Schema  string `json:"schema"`
}

// Table identifies a table. Fields other than Schema and Name are set only
// where they make sense for the list the table appears in.
type Table struct {
	Schema        string `json:"schema"`
	Name          string `json:"name"`
	TotalBytes    int64  `json:"total_bytes,omitempty"`
	EstimatedRows int64  `json:"estimated_rows,omitempty"`
	// ReplicaIdentity is default, nothing, full or index (tables without a
	// primary key only).
	ReplicaIdentity string `json:"replica_identity,omitempty"`
	// Partitions is the number of direct partitions (partitioned tables only).
	Partitions int `json:"partitions,omitempty"`
}

// QualifiedName returns schema.name, quoted, for display and for the SQL given
// to the operator in remediation text.
func (t Table) QualifiedName() string {
	return fmt.Sprintf("%s.%s", QuoteIdent(t.Schema), QuoteIdent(t.Name))
}

// TableList is a possibly truncated list of tables with the real total.
type TableList struct {
	// Total is the number of matching tables; Items holds at most the
	// configured cap, largest first.
	Total int     `json:"total"`
	Items []Table `json:"items"`
}

// Database is the inventory of one database. When Error is set, only the
// server-level fields (name, owner, size, locale) are filled in.
type Database struct {
	Name      string `json:"name"`
	Owner     string `json:"owner"`
	SizeBytes int64  `json:"size_bytes"` // -1 when the role cannot read it
	Locale
	// Error says why the database could not be inspected in detail.
	Error string `json:"error,omitempty"`

	Extensions []Extension `json:"extensions"`
	// Tables counts ordinary and partitioned tables that are not partitions;
	// Partitions counts partitions. Extension-owned objects are never counted.
	Tables     int `json:"tables"`
	Partitions int `json:"partitions"`
	Sequences  int `json:"sequences"`
	Views      int `json:"views"`
	Functions  int `json:"functions"`
	// TableBytes is the total size (heap, indexes, TOAST) of all tables.
	TableBytes int64 `json:"table_bytes"`
	// GeneratedColumns counts stored generated columns.
	GeneratedColumns int `json:"generated_columns"`

	LargestTables     []Table   `json:"largest_tables"`
	TablesWithoutPK   TableList `json:"tables_without_pk"`
	UnloggedTables    TableList `json:"unlogged_tables"`
	PartitionedTables TableList `json:"partitioned_tables"`
	ForeignTables     TableList `json:"foreign_tables"`
	// UnreadableTables are tables the connected role cannot SELECT from (or
	// whose schema it cannot use).
	UnreadableTables TableList `json:"unreadable_tables"`

	LargeObjects int64 `json:"large_objects"`
	// LargeObjectBytes is the on-disk size of pg_largeobject (data and index).
	LargeObjectBytes int64 `json:"large_object_bytes"`
	// Owners are the non-system roles that own objects here (tables, views,
	// sequences, schemas, functions, enum and domain types).
	Owners []string `json:"owners"`
	// Warnings are queries that failed for this database.
	Warnings []string `json:"warnings,omitempty"`
}

// QuoteIdent quotes an identifier for SQL shown to the operator. It is used for
// display only; Lockkeeper itself never builds executed SQL from names.
func QuoteIdent(s string) string {
	out := make([]byte, 0, len(s)+2)
	out = append(out, '"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			out = append(out, '"')
		}
		out = append(out, s[i])
	}
	return string(append(out, '"'))
}

// QuoteLiteral quotes a string literal for SQL shown to the operator.
func QuoteLiteral(s string) string {
	out := make([]byte, 0, len(s)+2)
	out = append(out, '\'')
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'')
		}
		out = append(out, s[i])
	}
	return string(append(out, '\''))
}

// Database returns the named database, if it was inspected.
func (s *Server) Database(name string) (*Database, bool) {
	for i := range s.Databases {
		if s.Databases[i].Name == name {
			return &s.Databases[i], true
		}
	}
	return nil, false
}

// SettingInt returns a numeric setting. ok is false if the setting does not
// exist on this server or is not an integer.
func (s *Server) SettingInt(name string) (v int64, ok bool) {
	st, found := s.Settings[name]
	if !found {
		return 0, false
	}
	if _, err := fmt.Sscanf(st.Value, "%d", &v); err != nil {
		return 0, false
	}
	return v, true
}

// SettingString returns a setting's value, or "" and false if absent.
func (s *Server) SettingString(name string) (string, bool) {
	st, ok := s.Settings[name]
	return st.Value, ok
}

// HasRole reports whether a role of that name is listed (non-system roles).
func (s *Server) HasRole(name string) bool {
	for _, r := range s.Roles {
		if r.Name == name {
			return true
		}
	}
	return false
}
