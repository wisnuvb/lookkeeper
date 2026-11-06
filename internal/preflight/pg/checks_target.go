package pg

import (
	"fmt"
	"sort"
	"strings"

	"github.com/wisnuvb/lockkeeper/internal/inventory"
	"github.com/wisnuvb/lockkeeper/internal/preflight"
)

// checkTargetSubscribe requires a role that may CREATE SUBSCRIPTION.
func checkTargetSubscribe(in Input) []preflight.Finding {
	t := in.Target.Server
	if t == nil {
		return nil
	}
	role := t.Session.User
	if t.Session.Superuser || t.Session.PgCreateSubscription {
		how := "superuser rights"
		if !t.Session.Superuser {
			how = "membership of pg_create_subscription"
		}
		return []preflight.Finding{finding("target.subscription_privilege", areaTargetPrivs, preflight.OK,
			fmt.Sprintf("role %q can create subscriptions on the target (%s)", role, how), "")}
	}
	rem := fmt.Sprintf("Before PostgreSQL 16 only a superuser can create subscriptions: use a superuser for the migration (self-hosted: `ALTER ROLE %s SUPERUSER;`, then revoke it after cleanup).", inventory.QuoteIdent(role))
	if t.Major >= 16 {
		rem = fmt.Sprintf("Run on the target as a superuser: `GRANT pg_create_subscription TO %s;` and, for each migrated database, `GRANT CREATE ON DATABASE <db> TO %s;`.", inventory.QuoteIdent(role), inventory.QuoteIdent(role))
	}
	return []preflight.Finding{finding("target.subscription_privilege", areaTargetPrivs, preflight.Blocker,
		fmt.Sprintf("role %q cannot create subscriptions on the target (neither superuser nor member of pg_create_subscription, which exists from PostgreSQL 16). The migration needs a role that can; it may differ from the role used for this pre-flight", role),
		rem+" This changes the TARGET server and is your decision; Lockkeeper's pre-flight never does it.")}
}

// checkTargetWorkers checks logical replication worker headroom on the target.
// Every migrated database gets its own subscription and so its own apply worker.
func checkTargetWorkers(in Input) []preflight.Finding {
	t := in.Target.Server
	if t == nil {
		return nil
	}
	need := int64(len(in.databases()))
	if need == 0 {
		need = 1
	}
	var out []preflight.Finding

	lw, lwOK := t.SettingInt("max_logical_replication_workers")
	mwp, mwpOK := t.SettingInt("max_worker_processes")
	sync, syncOK := t.SettingInt("max_sync_workers_per_subscription")

	if lwOK {
		var used int64
		note := ""
		if in.Target.Facts.LogicalWorkers != nil {
			used = int64(*in.Target.Facts.LogicalWorkers)
		} else {
			note = " (running workers could not be read; assumed none)"
		}
		free, enough := capacity(lw, used, need)
		msg := fmt.Sprintf("max_logical_replication_workers is %d, %d running, %d free; the migration needs %d (one apply worker per migrated database)%s", lw, used, free, need, note)
		if enough {
			out = append(out, finding("target.max_logical_replication_workers", areaTargetParams, preflight.OK, msg, ""))
		} else {
			out = append(out, finding("target.max_logical_replication_workers", areaTargetParams, preflight.Blocker, msg,
				fmt.Sprintf("Raise max_logical_replication_workers to at least %d and max_worker_processes accordingly (both need a restart): `ALTER SYSTEM SET max_logical_replication_workers = %d;` then restart.", used+need, used+need+2)))
		}
	}
	if mwpOK && lwOK {
		if mwp < lw+1 {
			out = append(out, finding("target.max_worker_processes", areaTargetParams, preflight.Warn,
				fmt.Sprintf("max_worker_processes is %d, but the logical replication workers (up to %d) and the launcher draw from the same pool, as do parallel query workers", mwp, lw),
				fmt.Sprintf("Raise max_worker_processes to at least %d (needs a restart): `ALTER SYSTEM SET max_worker_processes = %d;` then restart.", lw+1+8, lw+1+8)))
		} else {
			out = append(out, finding("target.max_worker_processes", areaTargetParams, preflight.OK,
				fmt.Sprintf("max_worker_processes is %d, enough for %d logical replication workers plus the launcher", mwp, lw), ""))
		}
	}
	if syncOK {
		if sync < 1 {
			out = append(out, finding("target.max_sync_workers_per_subscription", areaTargetParams, preflight.Warn,
				"max_sync_workers_per_subscription is 0, so a subscription cannot copy tables itself. This only matters for the fallback path of ADR 0002 (copy_data = true); the pgcopydb path copies outside the subscription",
				"Set it to 2 or more if you may use the in-subscription copy for small databases: `ALTER SYSTEM SET max_sync_workers_per_subscription = 2;` (reload is enough)."))
		} else {
			out = append(out, finding("target.max_sync_workers_per_subscription", areaTargetParams, preflight.Info,
				fmt.Sprintf("max_sync_workers_per_subscription is %d (used only if a subscription copies tables itself, the fallback of ADR 0002)", sync), ""))
		}
	}

	// Connections: after cutover the applications connect to the target.
	if in.Source.Server != nil {
		sc, sOK := in.Source.Server.SettingInt("max_connections")
		tc, tOK := t.SettingInt("max_connections")
		if sOK && tOK {
			if tc < sc {
				out = append(out, finding("target.max_connections", areaTargetParams, preflight.Warn,
					fmt.Sprintf("max_connections is %d on the target but %d on the source; after cutover the applications' connection pools may not fit", tc, sc),
					fmt.Sprintf("Raise max_connections on the target to at least %d (needs a restart), or put a connection pooler in front, or lower the pool sizes.", sc)))
			} else {
				out = append(out, finding("target.max_connections", areaTargetParams, preflight.OK,
					fmt.Sprintf("max_connections is %d on the target (source: %d)", tc, sc), ""))
			}
		}
	}
	return out
}

// checkTargetLogging warns when the target would write the subscription's
// connection string, which contains the source password, to its logs
// (ADR 0004 item 7).
func checkTargetLogging(in Input) []preflight.Finding {
	t := in.Target.Server
	if t == nil {
		return nil
	}
	ls, lsOK := t.SettingString("log_statement")
	lmd, lmdOK := t.SettingInt("log_min_duration_statement")
	var problems []string
	if lsOK && ls != "none" {
		problems = append(problems, fmt.Sprintf("log_statement is %q", ls))
	}
	if lmdOK && lmd >= 0 {
		problems = append(problems, fmt.Sprintf("log_min_duration_statement is %d ms", lmd))
	}
	if len(problems) == 0 {
		return []preflight.Finding{finding("target.logging", areaTargetLogging, preflight.OK,
			"log_statement is none and log_min_duration_statement is off: CREATE SUBSCRIPTION will not be logged by these settings. A statement that fails is still logged with its text at log_min_error_statement (default error); a per-database or per-role setting can also differ from what this session sees", "")}
	}
	return []preflight.Finding{finding("target.logging", areaTargetLogging, preflight.Warn,
		fmt.Sprintf("%s on the target: the CREATE SUBSCRIPTION statement, whose connection string contains the source password, can be written to the target's server log", strings.Join(problems, " and ")),
		"Before creating the subscription, as superuser: `SET log_statement = 'none';` in the session that runs it, and use a dedicated migration role with a password generated for this migration that you drop at cleanup (never an application or admin password). Or switch statement logging off for the migration window: `ALTER SYSTEM SET log_statement = 'none'; ALTER SYSTEM SET log_min_duration_statement = -1; SELECT pg_reload_conf();`. Acknowledge this finding before starting the migration (ADR 0004).")}
}

// checkTargetEmpty requires the databases to migrate to be empty on the target.
func checkTargetEmpty(in Input) []preflight.Finding {
	t := in.Target.Server
	if t == nil || in.Source.Server == nil {
		return nil
	}
	var out []preflight.Finding
	for _, sd := range in.Source.Server.Databases {
		id := "target.empty." + sd.Name
		td, ok := t.Database(sd.Name)
		switch {
		case !ok:
			out = append(out, finding(id, areaTargetState, preflight.OK,
				fmt.Sprintf("database %s does not exist on the target; it will be created for the migration", sd.Name), ""))
		case td.Error != "":
			out = append(out, finding(id, areaTargetState, preflight.Warn,
				fmt.Sprintf("database %s exists on the target but could not be inspected (%s), so it is unknown whether it is empty", sd.Name, td.Error),
				"Grant the target role CONNECT on the database, or inspect it by hand: `\\dt *.*` in psql."))
		case td.Tables > 0 || td.Partitions > 0 || td.ForeignTables.Total > 0:
			names := make([]string, 0, len(td.LargestTables))
			for _, lt := range td.LargestTables {
				names = append(names, lt.Schema+"."+lt.Name)
			}
			out = append(out, finding(id, areaTargetState, preflight.Blocker,
				fmt.Sprintf("database %s on the target already holds %s (%s); the migration copies into an empty database and would collide with or silently mix into existing data",
					sd.Name, plural(td.Tables+td.ForeignTables.Total, "user table"), nameList(names, maxNamesPerMessage)),
				"Use an empty database: create a fresh one on the target (`CREATE DATABASE "+inventory.QuoteIdent(sd.Name+"_new")+" TEMPLATE template0 ENCODING '"+sd.Encoding+"';` and point the migration at it), or, only if the existing tables are disposable, drop and recreate the database yourself. Lockkeeper never deletes anything for you."))
		case td.Views > 0 || td.Functions > 0 || td.Sequences > 0:
			out = append(out, finding(id, areaTargetState, preflight.Warn,
				fmt.Sprintf("database %s on the target has no tables but already contains %d view(s), %d function(s) and %d sequence(s)", sd.Name, td.Views, td.Functions, td.Sequences),
				"Remove them or use a fresh database; leftovers can make the schema copy fail with 'already exists' errors."))
		default:
			out = append(out, finding(id, areaTargetState, preflight.OK,
				fmt.Sprintf("database %s exists on the target and is empty", sd.Name), ""))
		}
	}
	return out
}

// checkSizes gives the size of what will be copied and the disk rule of thumb.
// Free disk space is not visible over SQL, so this can only be an estimate.
func checkSizes(in Input) []preflight.Finding {
	src := in.Source.Server
	if src == nil {
		return nil
	}
	var total int64
	var parts []string
	unknown := false
	for _, d := range src.Databases {
		if d.SizeBytes < 0 {
			unknown = true
			continue
		}
		total += d.SizeBytes
		parts = append(parts, fmt.Sprintf("%s %s", d.Name, bytesStr(d.SizeBytes)))
	}
	var largest []string
	for _, d := range src.Databases {
		for i, lt := range d.LargestTables {
			if i == 3 {
				break
			}
			largest = append(largest, fmt.Sprintf("%s: %s.%s (%s)", d.Name, lt.Schema, lt.Name, bytesStr(lt.TotalBytes)))
		}
	}
	need := total + total/2
	msg := fmt.Sprintf("the %s to migrate total %s (%s); the rule of thumb is a target with at least 1.5 x that free, about %s, on top of what it already stores",
		plural(len(src.Databases), "database"), bytesStr(total), strings.Join(parts, ", "), bytesStr(need))
	if unknown {
		msg += "; some sizes were not readable and are not counted"
	}
	if len(largest) > 0 {
		msg += ". Largest tables: " + nameList(largest, 6)
	}
	msg += ". Free disk space cannot be read over SQL, so Lockkeeper cannot check it, and the copy time is not estimated (no throughput is measured, because that would mean reading table data)"
	return []preflight.Finding{finding("data.sizes", areaData, preflight.Info, msg,
		"On the target host check the free space of the data directory volume, for example `df -h <data_directory>` (`SHOW data_directory;` as superuser). Indexes are rebuilt on the target, and the WAL volume may be a separate disk.")}
}

// checkSourceInspection and checkTargetInspection surface partial failures of
// the inventory, so a gap in the evidence is never silently read as "all good".
func checkInspection(role string, s Side) []preflight.Finding {
	if s.Server == nil {
		return nil
	}
	var out []preflight.Finding
	var msgs []string
	for _, d := range s.Server.Databases {
		if d.Error != "" {
			msgs = append(msgs, fmt.Sprintf("%s: %s", d.Name, d.Error))
		}
		for _, w := range d.Warnings {
			msgs = append(msgs, fmt.Sprintf("%s: %s", d.Name, w))
		}
	}
	msgs = append(msgs, s.Server.Warnings...)
	if len(msgs) == 0 {
		return nil
	}
	sort.Strings(msgs)
	out = append(out, finding("inspection."+role, areaInspection, preflight.Warn,
		fmt.Sprintf("the %s could not be inspected completely, so the checks below may be missing findings: %s", role, nameList(msgs, maxNamesPerMessage)),
		"Make sure the Lockkeeper role can CONNECT to every database and read the system catalogs (granting pg_monitor helps), and that query_timeout in the config is long enough for large catalogs; then re-run the pre-flight."))
	return out
}
