package pg

import (
	"fmt"
	"sort"
	"strings"

	"github.com/wisnuvb/lockkeeper/internal/inventory"
	"github.com/wisnuvb/lockkeeper/internal/preflight"
)

const rdsParamGroupHint = "RDS: change the parameter in the DB parameter group attached to the instance (for example `aws rds modify-db-parameter-group --db-parameter-group-name <your-group> --parameters ParameterName=%s,ParameterValue=%s,ApplyMethod=pending-reboot`), then reboot the instance. A reboot interrupts connections; plan it."

// checkWALLevel requires wal_level = logical on the source. On RDS the level is
// driven by the static parameter rds.logical_replication, which needs a reboot.
func checkWALLevel(in Input) []preflight.Finding {
	s := in.Source.Server
	if s == nil {
		return nil
	}
	st, ok := s.Settings["wal_level"]
	if ok && st.Value == "logical" && !st.PendingRestart {
		return []preflight.Finding{finding("source.wal_level", areaSourceParams, preflight.OK, "wal_level is logical", "")}
	}
	if ok && st.Value == "logical" {
		return []preflight.Finding{finding("source.wal_level", areaSourceParams, preflight.Warn,
			"wal_level is logical now, but the configuration has a pending change that takes effect at the next restart and may lower it",
			"Check the configured value (`SELECT name, setting, pending_restart FROM pg_settings WHERE name = 'wal_level';`) and make sure it stays logical before any restart.")}
	}
	cur := st.Value
	if !ok {
		cur = "unknown"
	}
	msg := fmt.Sprintf("wal_level is %q; logical replication needs \"logical\"", cur)
	if st.PendingRestart {
		msg += " (a restart is already pending; it may already carry the change, verify with SHOW wal_level afterwards)"
	}
	_, rdsParam := s.Settings["rds.logical_replication"]
	var rem string
	if s.IsRDS || rdsParam {
		rem = "This looks like Amazon RDS: set rds.logical_replication = 1 in the DB parameter group (it is a STATIC parameter, so it only applies after a reboot). " +
			fmt.Sprintf(rdsParamGroupHint, "rds.logical_replication", "1") +
			" Changing the parameter group needs AWS permissions (rds:ModifyDBParameterGroup), not a database role."
	} else {
		rem = "Run `ALTER SYSTEM SET wal_level = 'logical';` as a superuser (or edit postgresql.conf) and restart PostgreSQL; the setting needs a restart. Plan the restart: it interrupts connections."
	}
	return []preflight.Finding{finding("source.wal_level", areaSourceParams, preflight.Blocker, msg, rem)}
}

// checkRDSNote is the INFO row of SPEC 8.1: on RDS the privileges involved are
// split between AWS (parameter group) and database roles.
func checkRDSNote(in Input) []preflight.Finding {
	s := in.Source.Server
	if s == nil || !s.IsRDS {
		return nil
	}
	return []preflight.Finding{finding("source.rds", areaSourcePrivs, preflight.Info,
		fmt.Sprintf("the source looks like Amazon RDS (detected from the rds.logical_replication setting or the rds_superuser role); the connected role %q is %sa member of rds_superuser", s.Session.User, notWord(s.Session.RDSSuperuser)),
		"On RDS, enabling logical replication is done in the parameter group (rds.logical_replication = 1, reboot) and needs AWS permissions; managing slots from SQL needs the rds_replication role. RDS-specific behaviour is based on documentation and has not been verified against a live RDS instance by this tool.")}
}

func notWord(is bool) string {
	if is {
		return ""
	}
	return "not "
}

// checkSlotHeadroom needs one logical slot per migrated database: a
// subscription belongs to one database and uses its own slot.
func checkSlotHeadroom(in Input) []preflight.Finding {
	s := in.Source.Server
	if s == nil {
		return nil
	}
	limit, ok := s.SettingInt("max_replication_slots")
	if !ok {
		return nil
	}
	need := int64(len(in.databases()))
	if need == 0 {
		need = 1
	}
	used := int64(len(s.Slots))
	free, enough := capacity(limit, used, need)
	msg := fmt.Sprintf("max_replication_slots is %d, %d in use, %d free; the migration needs %d (one logical slot per migrated database)", limit, used, free, need)
	if enough {
		return []preflight.Finding{finding("source.max_replication_slots", areaSourceParams, preflight.OK, msg, "")}
	}
	return []preflight.Finding{finding("source.max_replication_slots", areaSourceParams, preflight.Blocker, msg,
		fmt.Sprintf("Raise max_replication_slots to at least %d (it needs a restart). Self-hosted: `ALTER SYSTEM SET max_replication_slots = %d;` then restart. ", used+need, used+need+2)+
			fmt.Sprintf(rdsParamGroupHint, "max_replication_slots", fmt.Sprint(used+need+2))+
			" Alternatively drop a slot nobody uses (see the slot findings); Lockkeeper never does that for you.")}
}

// checkSenderHeadroom needs one walsender per subscription plus one transient
// walsender for the replication connection that exports the snapshot (ADR 0002).
func checkSenderHeadroom(in Input) []preflight.Finding {
	s := in.Source.Server
	if s == nil {
		return nil
	}
	limit, ok := s.SettingInt("max_wal_senders")
	if !ok {
		return nil
	}
	n := int64(len(in.databases()))
	if n == 0 {
		n = 1
	}
	var used int64
	note := ""
	if in.Source.Facts.WALSenders != nil {
		used = int64(*in.Source.Facts.WALSenders)
	} else {
		for _, sl := range s.Slots {
			if sl.Active {
				used++
			}
		}
		note = " (running walsenders could not be read; active slots were counted instead)"
	}
	free, _ := capacity(limit, used, n)
	msg := fmt.Sprintf("max_wal_senders is %d, %d in use, %d free; the migration needs %d (one per subscription) plus one transient sender while a snapshot is exported%s", limit, used, free, n, note)
	rem := fmt.Sprintf("Raise max_wal_senders to at least %d (it needs a restart). Self-hosted: `ALTER SYSTEM SET max_wal_senders = %d;` then restart. ", used+n+1, used+n+3) +
		fmt.Sprintf(rdsParamGroupHint, "max_wal_senders", fmt.Sprint(used+n+3))
	switch {
	case limit-used < n:
		return []preflight.Finding{finding("source.max_wal_senders", areaSourceParams, preflight.Blocker, msg, rem)}
	case limit-used < n+1:
		return []preflight.Finding{finding("source.max_wal_senders", areaSourceParams, preflight.Warn, msg, rem)}
	}
	return []preflight.Finding{finding("source.max_wal_senders", areaSourceParams, preflight.OK, msg, "")}
}

// checkWALSenderTimeout follows the pgcopydb guidance in SPEC 8.1: a walsender
// timeout above zero can drop a replication connection during a long copy.
func checkWALSenderTimeout(in Input) []preflight.Finding {
	s := in.Source.Server
	if s == nil {
		return nil
	}
	v, ok := s.SettingInt("wal_sender_timeout")
	if !ok {
		return nil
	}
	if v == 0 {
		return []preflight.Finding{finding("source.wal_sender_timeout", areaSourceParams, preflight.OK,
			"wal_sender_timeout is 0 (disabled) for the role Lockkeeper connected as", "")}
	}
	return []preflight.Finding{finding("source.wal_sender_timeout", areaSourceParams, preflight.Warn,
		fmt.Sprintf("wal_sender_timeout is %d ms for the role Lockkeeper connected as; a replication connection that stops answering for that long is dropped, which can end a long initial copy (pgcopydb advises 0 for the migration user). Whether an idle snapshot-holding connection is affected has not been verified", v),
		"Set it for the migration role only: `ALTER ROLE <migration_role> SET wal_sender_timeout = 0;` (a per-role setting; it applies to that role's next sessions). On RDS you can set it in the parameter group instead. "+sourceChangeNote)}
}

// checkSlotWALKeep warns when an abandoned slot could fill the source's disk.
func checkSlotWALKeep(in Input) []preflight.Finding {
	s := in.Source.Server
	if s == nil {
		return nil
	}
	v, ok := s.SettingInt("max_slot_wal_keep_size")
	if !ok {
		return []preflight.Finding{finding("source.max_slot_wal_keep_size", areaSourceParams, preflight.Info,
			fmt.Sprintf("PostgreSQL %d has no max_slot_wal_keep_size (added in 13): nothing limits how much WAL a slot retains", s.Major),
			"Watch retained WAL while migrating: run `lockkeeper monitor run` against the source with the slot rules enabled.")}
	}
	if v >= 0 {
		return []preflight.Finding{finding("source.max_slot_wal_keep_size", areaSourceParams, preflight.OK,
			fmt.Sprintf("max_slot_wal_keep_size is %d MB: a slot that falls further behind is invalidated instead of filling the disk", v), "")}
	}
	return []preflight.Finding{finding("source.max_slot_wal_keep_size", areaSourceParams, preflight.Warn,
		"max_slot_wal_keep_size is unlimited (-1): a replication slot that is not read keeps WAL forever and can fill the source's disk, which stops the database",
		"Set a limit that is larger than the WAL produced during the copy but smaller than the free disk, for example `ALTER SYSTEM SET max_slot_wal_keep_size = '50GB'; SELECT pg_reload_conf();` (reload is enough). A slot that exceeds it is invalidated and the migration must restart, which is the lesser evil. "+
			"On RDS set it in the parameter group. Independently of that, Lockkeeper's monitor alerts on retained WAL (5 GiB warning, 20 GiB critical by default). "+sourceChangeNote)}
}

// checkSourcePrivileges checks that the connected role could start the
// migration: create a slot over a replication connection and read every table.
func checkSourcePrivileges(in Input) []preflight.Finding {
	s := in.Source.Server
	if s == nil {
		return nil
	}
	var out []preflight.Finding
	role := s.Session.User
	switch {
	case s.Session.Superuser || s.Session.Replication || s.Session.RDSReplication:
		how := "the REPLICATION attribute"
		switch {
		case s.Session.Superuser:
			how = "superuser rights"
		case s.Session.RDSReplication:
			how = "membership of rds_replication"
		}
		out = append(out, finding("source.replication_privilege", areaSourcePrivs, preflight.OK,
			fmt.Sprintf("role %q can create replication slots (%s)", role, how), ""))
	default:
		rem := fmt.Sprintf("Give the migration role the privilege: `ALTER ROLE %s REPLICATION;`", inventory.QuoteIdent(role))
		if s.IsRDS {
			rem = fmt.Sprintf("On RDS: `GRANT rds_replication TO %s;` (run as a member of rds_superuser).", inventory.QuoteIdent(role))
		}
		out = append(out, finding("source.replication_privilege", areaSourcePrivs, preflight.Blocker,
			fmt.Sprintf("role %q cannot create replication slots: it lacks REPLICATION and, on RDS, membership of rds_replication. The migration needs a role that can (this may be a different role than the one used for this pre-flight)", role),
			rem+" Prefer a dedicated, time-limited migration role. "+sourceChangeNote))
	}

	var unreadable []string
	total := 0
	for _, d := range s.Databases {
		for _, t := range d.UnreadableTables.Items {
			unreadable = append(unreadable, d.Name+": "+t.Schema+"."+t.Name)
		}
		total += d.UnreadableTables.Total
	}
	switch {
	case total > 0:
		rest := ""
		if total > len(unreadable) {
			rest = fmt.Sprintf(" (%d listed)", len(unreadable))
		}
		out = append(out, finding("source.read_privilege", areaSourcePrivs, preflight.Blocker,
			fmt.Sprintf("role %q cannot read %s: %s%s; their data cannot be copied or replicated", role, plural(total, "table"), nameList(unreadable, maxNamesPerMessage), rest),
			"Grant read access to the migration role, for example `GRANT pg_read_all_data TO <migration_role>;` (PostgreSQL 14+), or `GRANT USAGE ON SCHEMA <schema> TO <migration_role>; GRANT SELECT ON ALL TABLES IN SCHEMA <schema> TO <migration_role>;` per schema. "+sourceChangeNote))
	case s.Session.Superuser || s.Session.PgReadAllData:
		out = append(out, finding("source.read_privilege", areaSourcePrivs, preflight.OK,
			fmt.Sprintf("role %q can read every table in the inspected databases", role), ""))
	default:
		out = append(out, finding("source.read_privilege", areaSourcePrivs, preflight.Info,
			fmt.Sprintf("role %q can read every existing table, but through individual grants; tables created later are not readable unless default privileges cover them", role),
			"Prefer `GRANT pg_read_all_data TO <migration_role>;` (PostgreSQL 14+) for the migration role so no table is missed."))
	}
	return out
}

// checkSlots judges existing replication slots on the source: they hold WAL and
// they use up max_replication_slots.
func checkSlots(in Input) []preflight.Finding {
	s := in.Source.Server
	if s == nil {
		return nil
	}
	if len(s.Slots) == 0 {
		return []preflight.Finding{finding("source.slots", areaSlots, preflight.OK, "no replication slots exist on the source", "")}
	}
	th := in.Thresholds
	if th.SlotWarnBytes == 0 && th.SlotBlockerBytes == 0 {
		th = DefaultThresholds
	}
	slots := append([]inventory.Slot(nil), s.Slots...)
	sort.SliceStable(slots, func(i, j int) bool { return slots[i].RetainedBytes > slots[j].RetainedBytes })
	var out []preflight.Finding
	for _, sl := range slots {
		id := "source.slot." + sl.Name
		state := "active"
		if !sl.Active {
			state = "INACTIVE"
		}
		desc := fmt.Sprintf("replication slot %q (%s, %s, database %s) retains %s of WAL", sl.Name, sl.Type, state, dashIfEmpty(sl.Database), bytesStr(sl.RetainedBytes))
		drop := fmt.Sprintf("If nothing uses this slot any more, drop it yourself after checking with its owner: `SELECT pg_drop_replication_slot(%s);`. Lockkeeper's pre-flight never drops slots.", inventory.QuoteLiteral(sl.Name))
		switch {
		case sl.RetainedBytes > th.SlotBlockerBytes:
			out = append(out, finding(id, areaSlots, preflight.Blocker,
				desc+fmt.Sprintf(", above the %s blocking threshold; it keeps growing while it is not consumed and threatens the disk of the source", bytesStr(th.SlotBlockerBytes)),
				"Resolve this before migrating, since adding a migration on top raises the risk of a full disk. "+drop))
		case sl.RetainedBytes > th.SlotWarnBytes:
			out = append(out, finding(id, areaSlots, preflight.Warn,
				desc+fmt.Sprintf(", above the %s warning threshold", bytesStr(th.SlotWarnBytes)),
				"Find out who consumes this slot and why it lags. "+drop))
		case !sl.Active:
			out = append(out, finding(id, areaSlots, preflight.Warn,
				desc+"; an inactive slot keeps retaining WAL until it is dropped or consumed",
				"Find out whether the slot is still needed. "+drop))
		default:
			out = append(out, finding(id, areaSlots, preflight.Info, desc+"; it counts against max_replication_slots", ""))
		}
	}
	return out
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// checkSourceTables reports per database the tables that logical replication
// handles differently.
func checkSourceTables(in Input) []preflight.Finding {
	s := in.Source.Server
	if s == nil {
		return nil
	}
	var out []preflight.Finding
	for _, d := range s.Databases {
		if d.Error != "" {
			continue
		}
		out = append(out, noPKFindings(d)...)
		out = append(out, unloggedFindings(d)...)
		out = append(out, largeObjectFindings(d)...)
		out = append(out, otherTableFindings(d)...)
	}
	return out
}

func noPKFindings(d inventory.Database) []preflight.Finding {
	id := "tables.no_pk." + d.Name
	var need []inventory.Table
	covered := 0
	for _, t := range d.TablesWithoutPK.Items {
		if t.ReplicaIdentity == "full" || t.ReplicaIdentity == "index" {
			covered++
			continue
		}
		need = append(need, t)
	}
	// The inventory caps its list: tables beyond the cap are assumed to need
	// action, which is the safe reading.
	unlisted := d.TablesWithoutPK.Total - len(d.TablesWithoutPK.Items)
	needTotal := len(need) + unlisted
	if needTotal == 0 {
		msg := fmt.Sprintf("database %s: every table has a primary key", d.Name)
		if covered > 0 {
			msg = fmt.Sprintf("database %s: %s without a primary key already have a usable REPLICA IDENTITY (full or index)", d.Name, plural(covered, "table"))
		}
		return []preflight.Finding{finding(id, areaTables, preflight.OK, msg, "")}
	}
	var stmts []string
	for i, t := range need {
		if i == 3 {
			break
		}
		stmts = append(stmts, fmt.Sprintf("ALTER TABLE %s REPLICA IDENTITY FULL;", t.QualifiedName()))
	}
	return []preflight.Finding{finding(id, areaTables, preflight.Warn,
		fmt.Sprintf("database %s: %s without a primary key and without a replica identity; UPDATE and DELETE on them fail once they are published and would not replicate: %s",
			d.Name, plural(needTotal, "table"), tableList(need, needTotal)),
		"Either add a primary key, or set REPLICA IDENTITY FULL (works without a key but logs whole old rows, so write volume and WAL grow), or USING INDEX on a unique, non-null index. For example (connected to "+d.Name+"): "+strings.Join(stmts, " ")+
			" REPLICA IDENTITY FULL is a SOURCE change that takes a table lock; the migration will require explicit confirmation before applying it. "+sourceChangeNote)}
}

func unloggedFindings(d inventory.Database) []preflight.Finding {
	id := "tables.unlogged." + d.Name
	if d.UnloggedTables.Total == 0 {
		return []preflight.Finding{finding(id, areaTables, preflight.OK, fmt.Sprintf("database %s: no unlogged tables", d.Name), "")}
	}
	var stmts []string
	for i, t := range d.UnloggedTables.Items {
		if i == 3 {
			break
		}
		stmts = append(stmts, fmt.Sprintf("ALTER TABLE %s SET LOGGED;", t.QualifiedName()))
	}
	return []preflight.Finding{finding(id, areaTables, preflight.Warn,
		fmt.Sprintf("database %s: %s unlogged; unlogged tables are not written to WAL, so logical replication never carries their rows: %s",
			d.Name, pluralIs(d.UnloggedTables.Total, "table"), tableList(d.UnloggedTables.Items, d.UnloggedTables.Total)),
		"If the data must reach the target, make the tables logged (connected to "+d.Name+"): "+strings.Join(stmts, " ")+
			" SET LOGGED rewrites the table under an exclusive lock and writes it to WAL. If the data is disposable, nothing is needed: the tables will exist on the target but start empty. "+sourceChangeNote)}
}

func largeObjectFindings(d inventory.Database) []preflight.Finding {
	id := "objects.large_objects." + d.Name
	if d.LargeObjects == 0 {
		return []preflight.Finding{finding(id, areaTables, preflight.OK, fmt.Sprintf("database %s: no large objects", d.Name), "")}
	}
	return []preflight.Finding{finding(id, areaTables, preflight.Warn,
		fmt.Sprintf("database %s: %d large object(s) (pg_largeobject occupies %s); logical replication does not replicate large objects", d.Name, d.LargeObjects, bytesStr(d.LargeObjectBytes)),
		"Plan a separate copy of the large objects after writes are frozen at cutover (for example `pg_dump --blobs` of the large objects only, or move the data into a bytea column or object storage first). Lockkeeper does not copy large objects yet. Verify afterwards: `SELECT count(*) FROM pg_largeobject_metadata;` must match on both servers.")}
}

func otherTableFindings(d inventory.Database) []preflight.Finding {
	var out []preflight.Finding
	if d.PartitionedTables.Total > 0 {
		out = append(out, finding("tables.partitioned."+d.Name, areaTables, preflight.Info,
			fmt.Sprintf("database %s: %s partitioned: %s; the target must have the same partition layout, or the publication must publish via the partition root",
				d.Name, pluralIs(d.PartitionedTables.Total, "table"), partitionedList(d.PartitionedTables)), ""))
	}
	if d.ForeignTables.Total > 0 {
		out = append(out, finding("tables.foreign."+d.Name, areaTables, preflight.Info,
			fmt.Sprintf("database %s: %s foreign: %s; their rows live elsewhere and are not replicated, only the definitions move. The target must be able to reach the foreign servers",
				d.Name, pluralIs(d.ForeignTables.Total, "table"), tableList(d.ForeignTables.Items, d.ForeignTables.Total)), ""))
	}
	if d.GeneratedColumns > 0 {
		out = append(out, finding("tables.generated."+d.Name, areaTables, preflight.Info,
			fmt.Sprintf("database %s: %d stored generated column(s); before PostgreSQL 18 logical replication does not send them and the target computes them itself, so the schema copied to the target must define the same expressions", d.Name, d.GeneratedColumns), ""))
	}
	return out
}

func partitionedList(l inventory.TableList) string {
	parts := make([]string, 0, len(l.Items))
	for i, t := range l.Items {
		if i == maxNamesPerMessage {
			break
		}
		parts = append(parts, fmt.Sprintf("%s.%s (%d partitions)", t.Schema, t.Name, t.Partitions))
	}
	s := strings.Join(parts, ", ")
	if rest := l.Total - len(parts); rest > 0 {
		s += fmt.Sprintf(" and %d more", rest)
	}
	return s
}

// checkSchemaFreeze reports DDL activity on the source as a count only.
func checkSchemaFreeze(in Input) []preflight.Finding {
	if in.Source.Server == nil {
		return nil
	}
	f := in.Source.Facts
	if f.DDLSessions == nil {
		return []preflight.Finding{finding("source.ddl_activity", areaSchemaFreeze, preflight.Info,
			"could not read pg_stat_activity, so DDL activity on the source is unknown",
			"Make sure no schema changes run during the migration (logical replication does not carry DDL): pause migrations and deploys that alter the schema.")}
	}
	msg := fmt.Sprintf("%s on the source currently running or holding a transaction open with a DDL statement", plural(*f.DDLSessions, "session"))
	if *f.DDLSessions == 0 {
		msg = "no session on the source is currently running DDL"
	}
	if f.HiddenSessions > 0 {
		msg += fmt.Sprintf(" (%d other session(s) are not visible to this role, so this is a lower bound; grant pg_monitor for the full picture)", f.HiddenSessions)
	}
	return []preflight.Finding{finding("source.ddl_activity", areaSchemaFreeze, preflight.Info,
		msg+". Logical replication carries no DDL: from the start of the copy until cutover, schema changes (migrations, deploys, ALTER TABLE) must be frozen", "")}
}
