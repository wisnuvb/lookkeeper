package pgnative

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/wisnuvb/lockkeeper/internal/action"
	"github.com/wisnuvb/lockkeeper/internal/migrate"
)

// Side identifies one server in a plan.
type Side struct {
	Name string
	Host string
	Port int
	User string
	// Database is the database of the configured connection; cluster-wide
	// actions (create a role, drop a database) run through it.
	Database string
	// TLSMode is the configured sslmode (shown in the copy command line).
	TLSMode string
	// CAFile is the CA bundle the tools use to verify this server (shown in the
	// copy command line, so it is part of the plan hash).
	CAFile  string
	Version string
	Major   int
}

// adminDB is the database used for cluster-wide statements.
func (s Side) adminDB() string {
	if s.Database == "" {
		return "postgres"
	}
	return s.Database
}

// otherDB returns a database to connect to that is not `avoid` (a database
// cannot be dropped from a session connected to it).
func (s Side) otherDB(avoid string) string {
	if d := s.adminDB(); d != avoid {
		return d
	}
	if avoid != "postgres" {
		return "postgres"
	}
	return "template1"
}

// Peer is how the target server reaches the source (the subscription's
// connection) and how a bulk-copy tool reaches both. It defaults to the
// configured host and port but can differ, for example when Lockkeeper reaches
// the source through a tunnel the target cannot use.
type Peer struct {
	Host        string
	Port        int
	SSLMode     string
	SSLRootCert string // path on the TARGET server
}

// PlanInput is everything BuildPlan needs. It is plain data so the plan can be
// built and tested without any database.
type PlanInput struct {
	LockkeeperVersion string
	Source, Target    Side
	SourceFacts       SourceFacts
	TargetFacts       TargetFacts
	SourceIsRDS       bool
	Peer              Peer
	// DBs is the databases in plan order (sorted by name); a database's index in
	// the migration is its position + 1.
	DBs    []DBFacts
	Copier migrate.Copier `json:"-"`
	// CopierKind names the Copier so a stored input can be rebuilt.
	CopierKind string
	TableJobs  int
	IndexJobs  int
	NoOwner    bool
	Password   PasswordFile `json:"-"`
	ExtraNotes []string
}

// DeriveID names a migration from what it is about, so planning the same thing
// twice gives the same id (and the same hash), and a different plan never reuses
// the names of another one.
func DeriveID(in PlanInput) string {
	type dbDoc struct {
		Name    string
		Tables  []string
		NeedFul []string
	}
	doc := struct {
		Src, Tgt                   string
		Peer                       Peer
		DBs                        []dbDoc
		Copier                     string
		TableJobs, IndexJobs       int
		NoOwner                    bool
		SourceMajor, TargetVersion int
	}{
		Src:  fmt.Sprintf("%s|%s:%d", in.Source.Name, strings.ToLower(in.Source.Host), in.Source.Port),
		Tgt:  fmt.Sprintf("%s|%s:%d", in.Target.Name, strings.ToLower(in.Target.Host), in.Target.Port),
		Peer: in.Peer, Copier: in.Copier.Name(), TableJobs: in.TableJobs, IndexJobs: in.IndexJobs, NoOwner: in.NoOwner,
		SourceMajor: in.Source.Major, TargetVersion: in.Target.Major,
	}
	for _, d := range in.DBs {
		dd := dbDoc{Name: d.Database}
		for _, t := range d.Publish {
			dd.Tables = append(dd.Tables, t.String())
		}
		for _, t := range d.NeedFull {
			dd.NeedFul = append(dd.NeedFul, t.String())
		}
		doc.DBs = append(doc.DBs, dd)
	}
	b, _ := json.Marshal(doc)
	sum := sha256.Sum256(b)
	return "m" + hex.EncodeToString(sum[:])[:8]
}

// Action ids. They are the contract between the plan and the engine.
func IDCreateRole() string               { return "source.create-role" }
func IDReplicaIdentity(db, k int) string { return fmt.Sprintf("source.replica-identity.%d.%d", db, k) }
func IDCreatePublication(db int) string  { return fmt.Sprintf("source.create-publication.%d", db) }
func IDSlotSnapshot(db int) string       { return fmt.Sprintf("start.slot-snapshot.%d", db) }
func IDCopy(db int) string               { return fmt.Sprintf("start.copy.%d", db) }
func IDDropCopiedPublication(db int) string {
	return fmt.Sprintf("start.drop-copied-publication.%d", db)
}
func IDCreateSubscription(db int) string  { return fmt.Sprintf("start.create-subscription.%d", db) }
func IDEnableSubscription(db int) string  { return fmt.Sprintf("start.enable-subscription.%d", db) }
func IDAbortSubscription(db int) string   { return fmt.Sprintf("abort.disable-subscription.%d", db) }
func IDCleanupSubscription(db int) string { return fmt.Sprintf("cleanup.drop-subscription.%d", db) }
func IDCleanupSlot(db int, slot string) string {
	return fmt.Sprintf("cleanup.drop-slot.%d.%s", db, slot)
}
func IDCleanupPublication(db int) string { return fmt.Sprintf("cleanup.drop-publication.%d", db) }
func IDCleanupRole() string              { return "cleanup.drop-role" }
func IDRecoverSubscription(db int) string {
	return fmt.Sprintf("recover.drop-subscription.%d", db)
}
func IDRecoverSlot(db int, slot string) string {
	return fmt.Sprintf("recover.drop-slot.%d.%s", db, slot)
}
func IDRecoverReset(db int) string { return fmt.Sprintf("recover.reset-target.%d", db) }

func lit(s string) string { return action.QuoteLiteral(s) }

func (in PlanInput) srcEP(db string) action.Endpoint {
	return action.Endpoint{Role: "source", Name: in.Source.Name, Host: in.Source.Host, Port: in.Source.Port, Database: db, User: in.Source.User}
}

func (in PlanInput) tgtEP(db string) action.Endpoint {
	return action.Endpoint{Role: "target", Name: in.Target.Name, Host: in.Target.Host, Port: in.Target.Port, Database: db, User: in.Target.User}
}

func identity(s Side) action.Identity {
	return action.Identity{Name: s.Name, Host: s.Host, Port: s.Port, User: s.User, ServerVersion: s.Version}
}

// commentOnMarker reads the comment of a role or publication to prove that
// Lockkeeper created it.
const (
	roleMarkerSQL = `SELECT shobj_description(oid, 'pg_authid') FROM pg_roles WHERE rolname = $1`
	pubMarkerSQL  = `SELECT obj_description(oid, 'pg_publication') FROM pg_publication WHERE pubname = $1`
)

// existsWithMarker reports whether an object exists; an object that exists
// without our marker is an error (a name collision must never be adopted or
// dropped).
func existsWithMarker(ctx context.Context, c action.Conn, existsSQL, markerSQL, name, marker string) (bool, error) {
	var exists bool
	if err := c.QueryRow(ctx, existsSQL, name).Scan(&exists); err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	var comment *string
	if err := c.QueryRow(ctx, markerSQL, name).Scan(&comment); err != nil {
		return false, err
	}
	if comment == nil || *comment != marker {
		return false, fmt.Errorf("%s already exists but was not created by this migration (comment %q, want %q): refusing to touch it", name, deref(comment), marker)
	}
	return true, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func roleExists(ctx context.Context, c action.Conn, name, marker string) (bool, error) {
	return existsWithMarker(ctx, c, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, roleMarkerSQL, name, marker)
}

func pubExists(ctx context.Context, c action.Conn, name, marker string) (bool, error) {
	return existsWithMarker(ctx, c, `SELECT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = $1)`, pubMarkerSQL, name, marker)
}

func subState(ctx context.Context, c action.Conn, name string) (exists, enabled, hasSlot bool, err error) {
	var en *bool
	var slot *string
	e := c.QueryRow(ctx, `SELECT subenabled, subslotname::text FROM pg_subscription WHERE subname = $1 AND subdbid = (SELECT oid FROM pg_database WHERE datname = current_database())`, name).Scan(&en, &slot)
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return false, false, false, nil
		}
		return false, false, false, e
	}
	return true, en != nil && *en, slot != nil, nil
}

// BuildPlan builds the migration plan: what apply-source-changes does, then what
// start does under the same approval. Everything is deterministic in the input.
func BuildPlan(in PlanInput) (*action.Plan, error) {
	if len(in.DBs) == 0 {
		return nil, fmt.Errorf("no database to migrate")
	}
	id := DeriveID(in)
	names := migrate.Names{MigrationID: id}
	p := &action.Plan{
		Kind: action.KindMigrate, LockkeeperVer: in.LockkeeperVersion, MigrationID: id,
		Source: identity(in.Source), Target: identity(in.Target),
		Settings: map[string]string{
			"copier": in.Copier.Name(), "table_jobs": strconv.Itoa(in.TableJobs), "index_jobs": strconv.Itoa(in.IndexJobs),
			"no_owner": strconv.FormatBool(in.NoOwner),
			"peer":     fmt.Sprintf("%s:%d", in.Peer.Host, in.Peer.Port), "peer_sslmode": in.Peer.SSLMode, "peer_sslrootcert": in.Peer.SSLRootCert,
			"role": names.Role(),
		},
	}
	for i, d := range in.DBs {
		p.Databases = append(p.Databases, d.Database)
		p.Settings[fmt.Sprintf("db.%d", i+1)] = d.Database
		p.Settings[fmt.Sprintf("publication.%d", i+1)] = names.Publication(i + 1)
		p.Settings[fmt.Sprintf("slot.%d", i+1)] = names.Slot(i+1, 1)
	}
	p.Notices = planNotices(in, names)

	// --- source changes ---
	p.Actions = append(p.Actions, createRoleAction(in, names))
	for i, d := range in.DBs {
		for k, t := range d.NeedFull {
			p.Actions = append(p.Actions, replicaIdentityAction(in, i+1, k+1, d.Database, t))
		}
		p.Actions = append(p.Actions, createPublicationAction(in, names, i+1, d))
	}
	// --- start ---
	for i, d := range in.DBs {
		p.Actions = append(p.Actions, startActions(in, names, i+1, d.Database, 1)...)
	}
	return p, p.Validate()
}

func planNotices(in PlanInput, names migrate.Names) []string {
	n := []string{
		"This plan changes the SOURCE (a role, publications, replica identity, replication slots) and the TARGET (the copied data and subscriptions). Nothing on the source is deleted or truncated.",
		"While a slot exists the source keeps all WAL it has not yet streamed. A stalled or abandoned migration can fill the source's disk: watch `lockkeeper migrate status`; see docs/runbooks/wal-slot-full.md.",
		"Logical replication carries data only: freeze schema changes until cutover. Sequences and large objects are not replicated.",
		fmt.Sprintf("The source's pg_hba.conf must let the new role %s connect from the target server (%s:%d); Lockkeeper cannot check this.", names.Role(), in.Peer.Host, in.Peer.Port),
	}
	for _, d := range in.DBs {
		if len(d.NeedFull) > 0 {
			n = append(n, fmt.Sprintf("database %s: %d table(s) without a usable replica identity get REPLICA IDENTITY FULL (a brief ACCESS EXCLUSIVE lock each; every update/delete then logs the whole old row): %s", d.Database, len(d.NeedFull), tableList(d.NeedFull, 5)))
		}
		if d.Unlogged > 0 || d.Foreign > 0 {
			n = append(n, fmt.Sprintf("database %s: %d unlogged and %d foreign table(s) are not replicated (unlogged data is copied once, changes are not streamed)", d.Database, d.Unlogged, d.Foreign))
		}
		if d.LargeObjects != 0 {
			n = append(n, fmt.Sprintf("database %s: large objects (%d) are not replicated by logical replication", d.Database, d.LargeObjects))
		}
	}
	if in.TargetFacts.StatementStats {
		n = append(n, "pg_stat_statements is loaded on the target: it keeps the text of CREATE SUBSCRIPTION, including the migration role's password, readable by superusers and pg_read_all_stats. The password belongs to a per-migration role that cleanup drops.")
	}
	if !in.TargetFacts.Superuser {
		n = append(n, "the target role is not a superuser, so the subscription statement cannot be kept out of the target's server log (SET log_statement needs superuser): make sure log_statement is 'none' and log_min_error_statement is above 'error' on the target.")
	}
	if in.SourceIsRDS {
		n = append(n, "RDS detected: the role is granted rds_replication instead of the REPLICATION attribute. These RDS-specific statements come from documentation and have NOT been run against RDS.")
	}
	return append(n, in.ExtraNotes...)
}

func createRoleAction(in PlanInput, names migrate.Names) action.Action {
	role := names.Role()
	attrs := "LOGIN REPLICATION"
	var after []action.Template
	if in.SourceIsRDS {
		attrs = "LOGIN"
		after = append(after, action.Template("GRANT rds_replication TO "+quoteIdent(role)))
	}
	after = append(after, action.Template("COMMENT ON ROLE "+quoteIdent(role)+" IS "+lit(names.Marker())))
	return &action.Statement{
		Key: IDCreateRole(), At: action.PhaseSource, Where: in.srcEP(in.Source.adminDB()), Changes: true,
		Summary: "create the per-migration role the target uses to read the source (a random password; only its SCRAM verifier is sent here)",
		Main:    action.Template("CREATE ROLE " + quoteIdent(role) + " WITH " + attrs + " NOSUPERUSER NOCREATEDB NOCREATEROLE CONNECTION LIMIT " + strconv.Itoa(2*len(in.DBs)+2) + " PASSWORD {{verifier}}"),
		After:   after,
		Secrets: roleSecrets(in.Password),
		Satisfied: func(ctx context.Context, c action.Conn) (bool, error) {
			return roleExists(ctx, c, role, names.Marker())
		},
	}
}

func replicaIdentityAction(in PlanInput, db, k int, dbName string, t Table) action.Action {
	return &action.Statement{
		Key: IDReplicaIdentity(db, k), At: action.PhaseSource, Where: in.srcEP(dbName), Changes: true,
		Summary: fmt.Sprintf("table %s cannot identify rows for UPDATE/DELETE: set REPLICA IDENTITY FULL", t),
		Session: []action.Template{"SET lock_timeout = '10s'"},
		Main:    action.Template("ALTER TABLE " + t.String() + " REPLICA IDENTITY FULL"),
		Satisfied: func(ctx context.Context, c action.Conn) (bool, error) {
			var ident *string
			if err := c.QueryRow(ctx, `SELECT relreplident::text FROM pg_class WHERE oid = to_regclass($1)`, t.String()).Scan(&ident); err != nil {
				return false, err
			}
			return ident != nil && *ident == "f", nil
		},
	}
}

func createPublicationAction(in PlanInput, names migrate.Names, db int, d DBFacts) action.Action {
	pub := names.Publication(db)
	tables := make([]string, 0, len(d.Publish))
	for _, t := range d.Publish {
		tables = append(tables, t.String())
	}
	return &action.Statement{
		Key: IDCreatePublication(db), At: action.PhaseSource, Where: in.srcEP(d.Database), Changes: true,
		Summary: fmt.Sprintf("publish %d table(s) of %s (published before the slot exists, so no change can be missed)", len(tables), d.Database),
		Main:    action.Template("CREATE PUBLICATION " + quoteIdent(pub) + " FOR TABLE " + strings.Join(tables, ", ")),
		After:   []action.Template{action.Template("COMMENT ON PUBLICATION " + quoteIdent(pub) + " IS " + lit(names.Marker()))},
		Satisfied: func(ctx context.Context, c action.Conn) (bool, error) {
			return pubExists(ctx, c, pub, names.Marker())
		},
	}
}

// conninfoTemplate is the subscription's connection string with the password as
// a placeholder, already escaped to sit inside an SQL string literal.
func conninfoTemplate(in PlanInput, role, dbName string) string {
	q := func(s string) string { return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'" }
	parts := []string{
		"host=" + q(in.Peer.Host), "port=" + strconv.Itoa(in.Peer.Port), "dbname=" + q(dbName), "user=" + q(role),
		"password={{password}}", "sslmode=" + q(in.Peer.SSLMode),
	}
	if in.Peer.SSLRootCert != "" {
		parts = append(parts, "sslrootcert="+q(in.Peer.SSLRootCert))
	}
	return strings.ReplaceAll(strings.Join(parts, " "), "'", "''")
}

func startActions(in PlanInput, names migrate.Names, db int, dbName string, attempt int) []action.Action {
	slot, pub, sub, role := names.Slot(db, attempt), names.Publication(db), names.Subscription(db), names.Role()
	var sessions []action.Template
	if in.TargetFacts.Superuser {
		sessions = []action.Template{"SET log_statement = 'none'", "SET log_min_duration_statement = -1", "SET log_min_error_statement = 'panic'"}
	}
	src := migrate.CopyInput{
		Source:     migrate.Endpoint{Host: in.Source.Host, Port: in.Source.Port, Database: dbName, User: in.Source.User, TLSMode: in.Source.TLSMode, CAFile: in.Source.CAFile},
		Target:     migrate.Endpoint{Host: in.Target.Host, Port: in.Target.Port, Database: dbName, User: in.Target.User, TLSMode: in.Target.TLSMode, CAFile: in.Target.CAFile},
		SnapshotID: "<snapshot id from the slot>", WorkDir: "<private work directory>", TableJobs: in.TableJobs, IndexJobs: in.IndexJobs, NoOwner: in.NoOwner,
	}
	return []action.Action{
		&action.Step{
			Key: IDSlotSnapshot(db), At: action.PhaseStart, Where: in.srcEP(dbName), Changes: true,
			Summary: fmt.Sprintf("create replication slot %s and export a snapshot; the connection stays open and idle during the copy (PostgreSQL 14 uses the legacy EXPORT_SNAPSHOT form)", slot),
			Display: "CREATE_REPLICATION_SLOT " + quoteIdent(slot) + " LOGICAL pgoutput (SNAPSHOT 'export');",
		},
		&action.Step{
			Key: IDCopy(db), At: action.PhaseStart, Where: in.tgtEP(dbName), Changes: true,
			Summary: fmt.Sprintf("copy database %s into the target inside that snapshot with %s (never --restart, never --follow)", dbName, in.Copier.Name()),
			Display: strings.Join(in.Copier.Describe(src), "\n"),
		},
		&action.Statement{
			Key: IDDropCopiedPublication(db), At: action.PhaseStart, Where: in.tgtEP(dbName), Changes: true,
			Summary: "remove the copy of the source publication that the schema copy brought along (the target must not keep it)",
			Main:    action.Template("DROP PUBLICATION IF EXISTS " + quoteIdent(pub)),
		},
		&action.Statement{
			Key: IDCreateSubscription(db), At: action.PhaseStart, Where: in.tgtEP(dbName), Changes: true,
			Summary: "create the subscription disabled, attached to the existing slot, without a second copy",
			Session: sessions,
			Main: action.Template("CREATE SUBSCRIPTION " + quoteIdent(sub) + " CONNECTION '" + conninfoTemplate(in, role, dbName) + "' PUBLICATION " + quoteIdent(pub) +
				" WITH (create_slot = false, slot_name = " + lit(slot) + ", copy_data = false, enabled = false)"),
			Secrets: subscriptionSecrets(in.Password),
			Satisfied: func(ctx context.Context, c action.Conn) (bool, error) {
				exists, _, _, err := subState(ctx, c, sub)
				return exists, err
			},
		},
		&action.Statement{
			Key: IDEnableSubscription(db), At: action.PhaseStart, Where: in.tgtEP(dbName), Changes: true,
			Summary: "enable the subscription: streaming starts at the slot's consistent point, which is exactly the copy's snapshot",
			Main:    action.Template("ALTER SUBSCRIPTION " + quoteIdent(sub) + " ENABLE"),
			Satisfied: func(ctx context.Context, c action.Conn) (bool, error) {
				_, enabled, _, err := subState(ctx, c, sub)
				return enabled, err
			},
		},
	}
}

// BuildAbortPlan stops consumption: it disables every subscription. The source's
// slots and publications stay exactly as they are.
func BuildAbortPlan(in PlanInput, migrationID string, withSubscriptions bool) (*action.Plan, error) {
	names := migrate.Names{MigrationID: migrationID}
	p := &action.Plan{
		Kind: action.KindAbort, LockkeeperVer: in.LockkeeperVersion, MigrationID: migrationID,
		Source: identity(in.Source), Target: identity(in.Target), Settings: map[string]string{},
		Notices: []string{
			"Abort stops the target from consuming changes. It does NOT drop the replication slots or publications on the source: the source keeps retaining WAL for every slot until you run `lockkeeper migrate cleanup` (a separate, confirmed step) or drop the slots yourself.",
			"A migration that was aborted cannot be resumed.",
		},
	}
	for i, d := range in.DBs {
		p.Databases = append(p.Databases, d.Database)
		if !withSubscriptions {
			continue // no subscription can exist yet: nothing on the target to stop
		}
		sub := names.Subscription(i + 1)
		p.Actions = append(p.Actions, &action.Statement{
			Key: IDAbortSubscription(i + 1), At: action.PhaseAbort, Where: in.tgtEP(d.Database), Changes: true,
			Summary: "disable the subscription so the target stops consuming (it stays defined; the slot stays on the source)",
			Main:    action.Template("ALTER SUBSCRIPTION " + quoteIdent(sub) + " DISABLE"),
			Satisfied: func(ctx context.Context, c action.Conn) (bool, error) {
				exists, enabled, _, err := subState(ctx, c, sub)
				return !exists || !enabled, err
			},
		})
	}
	return p, p.Validate()
}

// CleanupInput adds what only the live source knows to a PlanInput: the slots
// that carry this migration's name prefix.
type CleanupInput struct {
	PlanInput
	MigrationID string
	// Slots lists, per database index, the slot names found on the source with
	// this migration's prefix.
	Slots map[int][]string
}

// BuildCleanupPlan removes exactly what Lockkeeper created: subscriptions on the
// target, then slots, publications and the role on the source, each only if it
// carries this migration's name and marker.
func BuildCleanupPlan(in CleanupInput) (*action.Plan, error) {
	names := migrate.Names{MigrationID: in.MigrationID}
	p := &action.Plan{
		Kind: action.KindCleanup, LockkeeperVer: in.LockkeeperVersion, MigrationID: in.MigrationID,
		Source: identity(in.Source), Target: identity(in.Target), Settings: map[string]string{},
		Notices: []string{
			"Cleanup drops this migration's replication slots, publications and role on the SOURCE and its subscriptions on the TARGET. It never deletes or modifies any user data.",
			"After cleanup the migration cannot be resumed and the replication state is gone for good. Only continue if you have decided to abandon or have finished with this migration.",
			"REPLICA IDENTITY FULL, which the migration set on tables without a usable key, is left in place: it is a property of your tables, not something Lockkeeper created. Revert it yourself with ALTER TABLE ... REPLICA IDENTITY DEFAULT if you want.",
		},
	}
	for i, d := range in.DBs {
		p.Databases = append(p.Databases, d.Database)
		db := i + 1
		sub := names.Subscription(db)
		p.Actions = append(p.Actions, dropSubscriptionAction(in.PlanInput, IDCleanupSubscription(db), action.PhaseCleanup, db, d.Database, sub))
	}
	for i, d := range in.DBs {
		db := i + 1
		for _, slot := range in.Slots[db] {
			p.Actions = append(p.Actions, dropSlotAction(in.PlanInput, IDCleanupSlot(db, slot), action.PhaseCleanup, d.Database, slot))
		}
		pub := names.Publication(db)
		p.Actions = append(p.Actions, &action.Statement{
			Key: IDCleanupPublication(db), At: action.PhaseCleanup, Where: in.srcEP(d.Database), Changes: true,
			Summary: "drop the publication this migration created (only if it carries this migration's marker)",
			Main:    action.Template("DROP PUBLICATION " + quoteIdent(pub)),
			Satisfied: func(ctx context.Context, c action.Conn) (bool, error) {
				ok, err := pubExists(ctx, c, pub, names.Marker())
				return !ok, err
			},
		})
	}
	role := names.Role()
	p.Actions = append(p.Actions, &action.Statement{
		Key: IDCleanupRole(), At: action.PhaseCleanup, Where: in.srcEP(in.Source.adminDB()), Changes: true,
		Summary: "drop the per-migration role (only if it carries this migration's marker)",
		Main:    action.Template("DROP ROLE " + quoteIdent(role)),
		Satisfied: func(ctx context.Context, c action.Conn) (bool, error) {
			ok, err := roleExists(ctx, c, role, names.Marker())
			return !ok, err
		},
	})
	return p, p.Validate()
}

func dropSubscriptionAction(in PlanInput, key string, ph action.Phase, db int, dbName, sub string) action.Action {
	return &action.Statement{
		Key: key, At: ph, Where: in.tgtEP(dbName), Changes: true,
		Summary: "disable and drop the subscription WITHOUT dropping the remote slot (detached first; the slot is dropped by its own action)",
		Main:    action.Template("ALTER SUBSCRIPTION " + quoteIdent(sub) + " DISABLE"),
		After: []action.Template{
			action.Template("ALTER SUBSCRIPTION " + quoteIdent(sub) + " SET (slot_name = NONE)"),
			action.Template("DROP SUBSCRIPTION " + quoteIdent(sub)),
		},
		Satisfied: func(ctx context.Context, c action.Conn) (bool, error) {
			exists, _, _, err := subState(ctx, c, sub)
			return !exists, err
		},
	}
}

func dropSlotAction(in PlanInput, key string, ph action.Phase, dbName, slot string) action.Action {
	return &action.Statement{
		Key: key, At: ph, Where: in.srcEP(dbName), Changes: true,
		Summary: fmt.Sprintf("drop replication slot %s (a pgoutput slot of this database, only while no consumer is attached); the source then stops retaining its WAL", slot),
		Main:    action.Template("SELECT pg_drop_replication_slot(" + lit(slot) + ")"),
		Satisfied: func(ctx context.Context, c action.Conn) (bool, error) {
			var active bool
			var plugin, database *string
			err := c.QueryRow(ctx, `SELECT active, plugin::text, database::text FROM pg_replication_slots WHERE slot_name = $1`, slot).Scan(&active, &plugin, &database)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return true, nil
				}
				return false, err
			}
			if plugin == nil || *plugin != "pgoutput" || database == nil || *database != dbName {
				return false, fmt.Errorf("slot %s is not a pgoutput slot of database %s: refusing to drop it", slot, dbName)
			}
			if active {
				return false, fmt.Errorf("slot %s is active: a consumer is still attached; disable or drop the subscription first", slot)
			}
			return false, nil
		},
	}
}

// RecoverInput is a PlanInput plus the interrupted databases.
type RecoverInput struct {
	PlanInput
	MigrationID string
	// Databases maps database index to the interrupted attempt number; the
	// recovery runs attempt+1.
	Attempts map[int]int
	// OldSlots are the slots of the interrupted attempts that still exist.
	OldSlots map[int][]string
	// TargetCreate maps database index to the CREATE DATABASE statement that
	// recreates the (empty) target database with its original properties.
	TargetCreate map[int]string
}

// BuildRecoverPlan is the plan for restarting the copy of interrupted databases:
// drop the old subscription and slot, reset the target database, then run the
// start steps again under a new slot. A slot is never reused for a new copy
// (docs/PHASE3-NOTES.md 1.1 d3).
func BuildRecoverPlan(in RecoverInput) (*action.Plan, error) {
	names := migrate.Names{MigrationID: in.MigrationID}
	p := &action.Plan{
		Kind: action.KindRecover, LockkeeperVer: in.LockkeeperVersion, MigrationID: in.MigrationID,
		Source: identity(in.Source), Target: identity(in.Target), Settings: map[string]string{
			"copier": in.Copier.Name(), "peer": fmt.Sprintf("%s:%d", in.Peer.Host, in.Peer.Port),
		},
		Notices: []string{
			"The previous copy was interrupted. Its snapshot is gone and a slot cannot be reused for a new copy (the new snapshot is later than the slot's start, which would replay changes the copy already holds).",
			"This plan DROPS and recreates the target database(s) listed, which must hold nothing but the partial copy (they were empty when the migration was planned), drops the old slot on the source, and copies again under a new slot.",
		},
	}
	idx := make([]int, 0, len(in.Attempts))
	for db := range in.Attempts {
		idx = append(idx, db)
	}
	sort.Ints(idx)
	for _, db := range idx {
		d := in.DBs[db-1]
		p.Databases = append(p.Databases, d.Database)
		p.Settings[fmt.Sprintf("db.%d", db)] = d.Database
		p.Settings[fmt.Sprintf("attempt.%d", db)] = strconv.Itoa(in.Attempts[db] + 1)
		p.Settings[fmt.Sprintf("slot.%d", db)] = names.Slot(db, in.Attempts[db]+1)
	}
	for _, db := range idx {
		d := in.DBs[db-1]
		sub := names.Subscription(db)
		p.Actions = append(p.Actions, dropSubscriptionAction(in.PlanInput, IDRecoverSubscription(db), action.PhaseRecover, db, d.Database, sub))
		for _, slot := range in.OldSlots[db] {
			p.Actions = append(p.Actions, dropSlotAction(in.PlanInput, IDRecoverSlot(db, slot), action.PhaseRecover, d.Database, slot))
		}
		create := in.TargetCreate[db]
		p.Actions = append(p.Actions, &action.Statement{
			Key: IDRecoverReset(db), At: action.PhaseRecover, Where: in.tgtEP(in.Target.otherDB(d.Database)), Changes: true,
			Summary: fmt.Sprintf("reset target database %s: drop it and create it again empty with its original properties", d.Database),
			Main:    action.Template("DROP DATABASE IF EXISTS " + quoteIdent(d.Database) + " WITH (FORCE)"),
			After:   []action.Template{action.Template(create)},
		})
	}
	for _, db := range idx {
		p.Actions = append(p.Actions, startActions(in.PlanInput, names, db, in.DBs[db-1].Database, in.Attempts[db]+1)...)
	}
	return p, p.Validate()
}
