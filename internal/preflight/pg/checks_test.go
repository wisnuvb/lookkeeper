package pg

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/inventory"
	"github.com/wisnuvb/lockkeeper/internal/preflight"
)

const gib = int64(1 << 30)

func ptr(i int) *int { return &i }

func settings(kv ...string) map[string]inventory.Setting {
	m := map[string]inventory.Setting{}
	for i := 0; i < len(kv); i += 2 {
		m[kv[i]] = inventory.Setting{Value: kv[i+1]}
	}
	return m
}

var utf8 = inventory.Locale{Encoding: "UTF8", Collate: "en_US.UTF-8", Ctype: "en_US.UTF-8", Provider: "c"}

// healthy returns an input for which every check passes (OK or INFO), except
// the target-to-source reachability, which is always a WARN.
func healthy() Input {
	app := inventory.Database{
		Name: "app", Owner: "app_owner", SizeBytes: 10 * gib, Locale: utf8,
		Extensions: []inventory.Extension{{Name: "plpgsql", Version: "1.0", Schema: "pg_catalog"}},
		Owners:     []string{"app_owner"},
	}
	src := &inventory.Server{
		Version: "14.10", VersionNum: 140010, Major: 14,
		Session: inventory.Session{User: "lk_mig", Replication: true, PgReadAllData: true, ReadOnly: true},
		Settings: settings("wal_level", "logical", "max_replication_slots", "10", "max_wal_senders", "10",
			"wal_sender_timeout", "0", "max_slot_wal_keep_size", "2048", "max_connections", "100", "shared_preload_libraries", ""),
		Roles:     []inventory.Role{{Name: "app_owner"}, {Name: "lk_mig"}},
		Databases: []inventory.Database{app},
	}
	tgtApp := inventory.Database{Name: "app", Owner: "postgres", SizeBytes: 8 << 20, Locale: utf8,
		Extensions: []inventory.Extension{{Name: "plpgsql", Version: "1.0", Schema: "pg_catalog"}}}
	tgt := &inventory.Server{
		Version: "17.2", VersionNum: 170002, Major: 17, DefaultLocale: utf8,
		Session: inventory.Session{User: "postgres", Superuser: true, ReadOnly: true},
		Settings: settings("max_logical_replication_workers", "4", "max_worker_processes", "8",
			"max_sync_workers_per_subscription", "2", "max_connections", "100", "log_statement", "none",
			"log_min_duration_statement", "-1", "shared_preload_libraries", ""),
		Roles:     []inventory.Role{{Name: "app_owner"}, {Name: "postgres"}},
		Databases: []inventory.Database{tgtApp},
	}
	ssl := &SSLInfo{Enabled: true, Version: "TLSv1.3"}
	return Input{
		Source: Side{Name: "rds-main", Endpoint: Endpoint{Host: "db.example.com", Port: 5432, Database: "postgres", User: "lk_mig", TLSMode: "verify-full"},
			ConnectLatency: 40 * time.Millisecond, Server: src,
			Facts: Facts{SSL: ssl, DDLSessions: ptr(0), WALSenders: ptr(0)}},
		Target: Side{Name: "ovh-new", Endpoint: Endpoint{Host: "10.0.0.5", Port: 5432, Database: "postgres", User: "postgres", TLSMode: "verify-full"},
			ConnectLatency: 5 * time.Millisecond, Server: tgt,
			Facts: Facts{SSL: ssl, AvailableExtensions: map[string]string{"plpgsql": "1.0"}, LogicalWorkers: ptr(0)}},
		Thresholds: Thresholds{SlotWarnBytes: 5 * gib, SlotBlockerBytes: 20 * gib},
	}
}

func get(t *testing.T, r *preflight.Report, id string) preflight.Finding {
	t.Helper()
	for _, f := range r.Findings {
		if f.ID == id {
			return f
		}
	}
	var ids []string
	for _, f := range r.Findings {
		ids = append(ids, f.ID)
	}
	t.Fatalf("finding %q not in report; have %v", id, ids)
	return preflight.Finding{}
}

func has(r *preflight.Report, id string) bool {
	for _, f := range r.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestHealthyBaselineHasOnlyTheUnverifiableNetworkWarning(t *testing.T) {
	r := Run(healthy())
	for _, f := range r.Findings {
		if f.Severity.Rank() >= preflight.Warn.Rank() && f.ID != "network.target_to_source" {
			t.Errorf("unexpected %s %s: %s", f.Severity, f.ID, f.Message)
		}
	}
	if r.ExitCode() != 2 || r.Summary.Warn != 1 || r.Summary.Blocker != 0 {
		t.Errorf("summary %+v, exit %d", r.Summary, r.ExitCode())
	}
	if len(r.Databases) != 1 || r.Databases[0] != "app" || r.Source != "rds-main" || r.Target != "ovh-new" {
		t.Errorf("report header: %+v", r)
	}
}

// decision is a table-driven case: mutate the healthy input, then expect one
// finding to have a severity and its text to contain the given fragments.
type decision struct {
	name   string
	mutate func(*Input)
	id     string
	want   preflight.Severity
	msg    []string // fragments of Message
	rem    []string // fragments of Remediation
}

func runDecisions(t *testing.T, cases []decision) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := healthy()
			c.mutate(&in)
			f := get(t, Run(in), c.id)
			if f.Severity != c.want {
				t.Errorf("%s: severity %s, want %s\nmessage: %s", c.id, f.Severity, c.want, f.Message)
			}
			for _, frag := range c.msg {
				if !strings.Contains(f.Message, frag) {
					t.Errorf("message lacks %q: %s", frag, f.Message)
				}
			}
			for _, frag := range c.rem {
				if !strings.Contains(f.Remediation, frag) {
					t.Errorf("remediation lacks %q: %s", frag, f.Remediation)
				}
			}
			if f.Severity.Rank() >= preflight.Warn.Rank() && strings.TrimSpace(f.Remediation) == "" {
				t.Errorf("%s: a %s needs actionable remediation", c.id, f.Severity)
			}
		})
	}
}

func setSrc(k, v string) func(*Input) {
	return func(in *Input) { in.Source.Server.Settings[k] = inventory.Setting{Value: v} }
}
func setTgt(k, v string) func(*Input) {
	return func(in *Input) { in.Target.Server.Settings[k] = inventory.Setting{Value: v} }
}

func slots(n int, active bool) []inventory.Slot {
	var out []inventory.Slot
	for i := 0; i < n; i++ {
		out = append(out, inventory.Slot{Name: fmt.Sprintf("s%d", i), Type: "logical", Active: active, Database: "app"})
	}
	return out
}

func TestVersionsAndRecovery(t *testing.T) {
	runDecisions(t, []decision{
		{"target older is a blocker", func(in *Input) { in.Target.Server.Major = 13 }, "version.order", preflight.Blocker, []string{"13", "14"}, []string{"PostgreSQL 14"}},
		{"same major is ok", func(in *Input) { in.Target.Server.Major = 14 }, "version.order", preflight.OK, nil, nil},
		{"target newer is info", func(in *Input) {}, "version.order", preflight.Info, []string{"newer"}, nil},
		{"source standby before 16 is a blocker", func(in *Input) { in.Source.Server.InRecovery = true }, "source.recovery", preflight.Blocker, nil, nil},
		{"source standby on 16 is a warning", func(in *Input) { in.Source.Server.InRecovery = true; in.Source.Server.Major = 16 }, "source.recovery", preflight.Warn, nil, nil},
		{"target standby is a blocker", func(in *Input) { in.Target.Server.InRecovery = true }, "target.recovery", preflight.Blocker, nil, nil},
	})
}

func TestWALLevel(t *testing.T) {
	runDecisions(t, []decision{
		{"logical is ok", func(in *Input) {}, "source.wal_level", preflight.OK, nil, nil},
		{"replica on a plain server", setSrc("wal_level", "replica"), "source.wal_level", preflight.Blocker,
			[]string{`"replica"`}, []string{"ALTER SYSTEM SET wal_level", "restart"}},
		{"replica on RDS needs the parameter group and a reboot", func(in *Input) {
			in.Source.Server.Settings["wal_level"] = inventory.Setting{Value: "replica"}
			in.Source.Server.Settings["rds.logical_replication"] = inventory.Setting{Value: "off"}
			in.Source.Server.IsRDS = true
		}, "source.wal_level", preflight.Blocker, nil,
			[]string{"rds.logical_replication = 1", "STATIC", "reboot", "ParameterName=rds.logical_replication,ParameterValue=1,ApplyMethod=pending-reboot"}},
		{"RDS is recognised from the setting alone", func(in *Input) {
			in.Source.Server.Settings["wal_level"] = inventory.Setting{Value: "replica"}
			in.Source.Server.Settings["rds.logical_replication"] = inventory.Setting{Value: "off"}
		}, "source.wal_level", preflight.Blocker, nil, []string{"rds.logical_replication"}},
		{"logical with a pending restart is a warning", func(in *Input) {
			in.Source.Server.Settings["wal_level"] = inventory.Setting{Value: "logical", PendingRestart: true}
		}, "source.wal_level", preflight.Warn, nil, nil},
		{"replica with a pending restart says so", func(in *Input) {
			in.Source.Server.Settings["wal_level"] = inventory.Setting{Value: "replica", PendingRestart: true}
		}, "source.wal_level", preflight.Blocker, []string{"restart is already pending"}, nil},
	})
}

func TestSlotAndSenderHeadroomBoundaries(t *testing.T) {
	twoDBs := func(in *Input) {
		in.Source.Server.Databases = append(in.Source.Server.Databases, inventory.Database{Name: "billing", Locale: utf8})
	}
	runDecisions(t, []decision{
		{"one slot free of ten used nine is enough", func(in *Input) { in.Source.Server.Slots = slots(9, true) }, "source.max_replication_slots", preflight.OK, []string{"1 free"}, nil},
		{"no slot free is a blocker", func(in *Input) { in.Source.Server.Slots = slots(10, true) }, "source.max_replication_slots", preflight.Blocker, []string{"0 free", "needs 1"}, []string{"max_replication_slots", "restart"}},
		{"limit below usage leaves nothing free", func(in *Input) { in.Source.Server.Slots = slots(12, true) }, "source.max_replication_slots", preflight.Blocker, []string{"0 free"}, nil},
		{"two databases need two slots: two free is ok", func(in *Input) { twoDBs(in); in.Source.Server.Slots = slots(8, true) }, "source.max_replication_slots", preflight.OK, nil, nil},
		{"two databases need two slots: one free is a blocker", func(in *Input) { twoDBs(in); in.Source.Server.Slots = slots(9, true) }, "source.max_replication_slots", preflight.Blocker, []string{"needs 2"}, nil},

		{"senders: two free covers one subscription plus the snapshot sender", func(in *Input) { in.Source.Facts.WALSenders = ptr(8) }, "source.max_wal_senders", preflight.OK, nil, nil},
		{"senders: one free lacks the transient snapshot sender", func(in *Input) { in.Source.Facts.WALSenders = ptr(9) }, "source.max_wal_senders", preflight.Warn, []string{"1 free"}, []string{"max_wal_senders"}},
		{"senders: none free is a blocker", func(in *Input) { in.Source.Facts.WALSenders = ptr(10) }, "source.max_wal_senders", preflight.Blocker, nil, nil},
		{"senders: zero configured is a blocker", setSrc("max_wal_senders", "0"), "source.max_wal_senders", preflight.Blocker, nil, nil},
		{"senders: two databases need three", func(in *Input) { twoDBs(in); in.Source.Facts.WALSenders = ptr(8) }, "source.max_wal_senders", preflight.Warn, nil, nil},
		{"senders unknown: active slots are counted", func(in *Input) {
			in.Source.Facts.WALSenders = nil
			in.Source.Server.Slots = slots(10, true)
		}, "source.max_wal_senders", preflight.Blocker, []string{"could not be read"}, nil},
	})
}

func TestSourceParameters(t *testing.T) {
	runDecisions(t, []decision{
		{"timeout disabled", func(in *Input) {}, "source.wal_sender_timeout", preflight.OK, nil, nil},
		{"timeout default", setSrc("wal_sender_timeout", "60000"), "source.wal_sender_timeout", preflight.Warn, []string{"60000 ms"}, []string{"ALTER ROLE", "wal_sender_timeout = 0"}},
		{"keep size limited", func(in *Input) {}, "source.max_slot_wal_keep_size", preflight.OK, nil, nil},
		{"keep size zero is still a limit", setSrc("max_slot_wal_keep_size", "0"), "source.max_slot_wal_keep_size", preflight.OK, nil, nil},
		{"keep size unlimited", setSrc("max_slot_wal_keep_size", "-1"), "source.max_slot_wal_keep_size", preflight.Warn, []string{"unlimited"}, []string{"max_slot_wal_keep_size", "invalidated"}},
		{"keep size missing before 13", func(in *Input) { delete(in.Source.Server.Settings, "max_slot_wal_keep_size") }, "source.max_slot_wal_keep_size", preflight.Info, []string{"no max_slot_wal_keep_size"}, nil},
	})
}

func TestSourcePrivileges(t *testing.T) {
	noRepl := func(in *Input) { in.Source.Server.Session = inventory.Session{User: "lk_mon", PgMonitor: true} }
	unread := func(in *Input) {
		d := &in.Source.Server.Databases[0]
		d.UnreadableTables = inventory.TableList{Total: 3, Items: []inventory.Table{{Schema: "public", Name: "secret_t"}}}
	}
	runDecisions(t, []decision{
		{"REPLICATION attribute", func(in *Input) {}, "source.replication_privilege", preflight.OK, []string{"REPLICATION attribute"}, nil},
		{"superuser", func(in *Input) { in.Source.Server.Session = inventory.Session{User: "postgres", Superuser: true} }, "source.replication_privilege", preflight.OK, []string{"superuser"}, nil},
		{"rds_replication", func(in *Input) { in.Source.Server.Session = inventory.Session{User: "lk", RDSReplication: true} }, "source.replication_privilege", preflight.OK, []string{"rds_replication"}, nil},
		{"no replication", noRepl, "source.replication_privilege", preflight.Blocker, []string{"lk_mon"}, []string{`ALTER ROLE "lk_mon" REPLICATION`}},
		{"no replication on RDS", func(in *Input) { noRepl(in); in.Source.Server.IsRDS = true }, "source.replication_privilege", preflight.Blocker, nil, []string{`GRANT rds_replication TO "lk_mon"`}},
		{"unreadable tables are a blocker", unread, "source.read_privilege", preflight.Blocker, []string{"3 tables", "app: public.secret_t"}, []string{"pg_read_all_data"}},
		{"readable through pg_read_all_data", func(in *Input) {}, "source.read_privilege", preflight.OK, nil, nil},
		{"readable only through grants", func(in *Input) { in.Source.Server.Session = inventory.Session{User: "lk", Replication: true} }, "source.read_privilege", preflight.Info, []string{"individual grants"}, nil},
	})
}

func TestExistingSlotsUseTheMonitorThresholds(t *testing.T) {
	slot := func(retained int64, active bool) func(*Input) {
		return func(in *Input) {
			in.Source.Server.Slots = []inventory.Slot{{Name: "old", Type: "logical", Active: active, Database: "app", RetainedBytes: retained}}
		}
	}
	runDecisions(t, []decision{
		{"no slots", func(in *Input) {}, "source.slots", preflight.OK, nil, nil},
		{"active and small is informational", slot(1<<20, true), "source.slot.old", preflight.Info, nil, nil},
		{"exactly at the warning threshold is not above it", slot(5*gib, true), "source.slot.old", preflight.Info, nil, nil},
		{"one byte above the warning threshold", slot(5*gib+1, true), "source.slot.old", preflight.Warn, []string{"5.0 GiB"}, []string{"pg_drop_replication_slot('old')", "never drops"}},
		{"exactly at the blocker threshold is a warning", slot(20*gib, true), "source.slot.old", preflight.Warn, nil, nil},
		{"one byte above the blocker threshold", slot(20*gib+1, true), "source.slot.old", preflight.Blocker, []string{"20.0 GiB"}, []string{"pg_drop_replication_slot"}},
		{"inactive is a warning even when small", slot(1024, false), "source.slot.old", preflight.Warn, []string{"INACTIVE"}, []string{"pg_drop_replication_slot"}},
		{"custom thresholds are honoured", func(in *Input) {
			slot(2<<20, true)(in)
			in.Thresholds = Thresholds{SlotWarnBytes: 1 << 20, SlotBlockerBytes: 1 << 30}
		}, "source.slot.old", preflight.Warn, nil, nil},
	})

	t.Run("slot names are quoted in the suggested SQL", func(t *testing.T) {
		in := healthy()
		in.Source.Server.Slots = []inventory.Slot{{Name: "it's", Type: "logical", RetainedBytes: 1}}
		f := get(t, Run(in), "source.slot.it's")
		if !strings.Contains(f.Remediation, `pg_drop_replication_slot('it''s')`) {
			t.Errorf("literal not escaped: %s", f.Remediation)
		}
	})
}

func TestTablesWithoutPrimaryKey(t *testing.T) {
	noPK := func(total int, items ...inventory.Table) func(*Input) {
		return func(in *Input) {
			in.Source.Server.Databases[0].TablesWithoutPK = inventory.TableList{Total: total, Items: items}
		}
	}
	events := inventory.Table{Schema: "public", Name: "events", TotalBytes: 3 << 20, ReplicaIdentity: "default"}
	runDecisions(t, []decision{
		{"all have keys", func(in *Input) {}, "tables.no_pk.app", preflight.OK, nil, nil},
		{"default identity needs action", noPK(1, events), "tables.no_pk.app", preflight.Warn,
			[]string{"1 table", "public.events (3.0 MiB)"},
			[]string{`ALTER TABLE "public"."events" REPLICA IDENTITY FULL;`, "SOURCE", "confirmation"}},
		{"identity nothing needs action", noPK(1, inventory.Table{Schema: "s", Name: "t", ReplicaIdentity: "nothing"}), "tables.no_pk.app", preflight.Warn, nil, nil},
		{"identity full is covered", noPK(1, inventory.Table{Schema: "s", Name: "t", ReplicaIdentity: "full"}), "tables.no_pk.app", preflight.OK, []string{"already have a usable REPLICA IDENTITY"}, nil},
		{"identity index is covered", noPK(1, inventory.Table{Schema: "s", Name: "t", ReplicaIdentity: "index"}), "tables.no_pk.app", preflight.OK, nil, nil},
		{"mixed list counts only uncovered tables", noPK(2, events, inventory.Table{Schema: "s", Name: "t", ReplicaIdentity: "full"}), "tables.no_pk.app", preflight.Warn, []string{"1 table"}, nil},
		{"an unlogged table without a key is not a replica-identity problem", func(in *Input) {
			noPK(1, inventory.Table{Schema: "public", Name: "u", ReplicaIdentity: "default"})(in)
			in.Source.Server.Databases[0].UnloggedTables = inventory.TableList{Total: 1, Items: []inventory.Table{{Schema: "public", Name: "u"}}}
		}, "tables.no_pk.app", preflight.OK, []string{"unlogged"}, nil},
		{"tables beyond the inventory cap are assumed to need action", noPK(50, inventory.Table{Schema: "s", Name: "t", ReplicaIdentity: "full"}), "tables.no_pk.app", preflight.Warn, []string{"49 tables"}, nil},
	})
}

func TestUnloggedLargeObjectsAndInformationalTables(t *testing.T) {
	runDecisions(t, []decision{
		{"no unlogged", func(in *Input) {}, "tables.unlogged.app", preflight.OK, nil, nil},
		{"unlogged", func(in *Input) {
			in.Source.Server.Databases[0].UnloggedTables = inventory.TableList{Total: 1, Items: []inventory.Table{{Schema: "public", Name: "scratch"}}}
		}, "tables.unlogged.app", preflight.Warn, []string{"not written to WAL", "public.scratch"}, []string{`SET LOGGED`, "SOURCE"}},
		{"no large objects", func(in *Input) {}, "objects.large_objects.app", preflight.OK, nil, nil},
		{"large objects", func(in *Input) {
			in.Source.Server.Databases[0].LargeObjects = 42
			in.Source.Server.Databases[0].LargeObjectBytes = 5 << 20
		}, "objects.large_objects.app", preflight.Warn, []string{"42 large object", "5.0 MiB", "does not replicate"}, []string{"cutover", "pg_largeobject_metadata"}},
		{"partitioned", func(in *Input) {
			in.Source.Server.Databases[0].PartitionedTables = inventory.TableList{Total: 1, Items: []inventory.Table{{Schema: "public", Name: "m", Partitions: 12}}}
		}, "tables.partitioned.app", preflight.Info, []string{"public.m (12 partitions)"}, nil},
		{"foreign", func(in *Input) {
			in.Source.Server.Databases[0].ForeignTables = inventory.TableList{Total: 1, Items: []inventory.Table{{Schema: "public", Name: "ft"}}}
		}, "tables.foreign.app", preflight.Info, []string{"public.ft"}, nil},
		{"generated columns", func(in *Input) { in.Source.Server.Databases[0].GeneratedColumns = 2 }, "tables.generated.app", preflight.Info, []string{"2 stored generated"}, nil},
	})
}

func TestExtensions(t *testing.T) {
	withExt := func(name, ver string, avail map[string]string) func(*Input) {
		return func(in *Input) {
			d := &in.Source.Server.Databases[0]
			d.Extensions = append(d.Extensions, inventory.Extension{Name: name, Version: ver})
			for k, v := range avail {
				in.Target.Facts.AvailableExtensions[k] = v
			}
		}
	}
	runDecisions(t, []decision{
		{"all available at the same version", func(in *Input) {}, "extensions.available", preflight.OK, nil, nil},
		{"not available on the target", withExt("postgis", "3.4.0", nil), "extensions.postgis", preflight.Blocker, []string{"not available on the target", "app"}, []string{"package", "PostgreSQL 17"}},
		{"RDS-only extension gets a specific hint", func(in *Input) { in.Source.Server.IsRDS = true; withExt("aws_s3", "1.1", nil)(in) }, "extensions.aws_s3", preflight.Blocker, nil, []string{"RDS-specific", "not verified"}},
		{"version differs from what would be installed", withExt("pg_trgm", "1.5", map[string]string{"pg_trgm": "1.6"}), "extensions.pg_trgm", preflight.Warn, []string{"1.5", "1.6", "available"}, []string{"ALTER EXTENSION"}},
		{"same default version is fine", withExt("pg_trgm", "1.6", map[string]string{"pg_trgm": "1.6"}), "extensions.available", preflight.OK, nil, nil},
		{"installed target version wins over the default", func(in *Input) {
			withExt("pg_trgm", "1.5", map[string]string{"pg_trgm": "1.6"})(in)
			td := &in.Target.Server.Databases[0]
			td.Extensions = append(td.Extensions, inventory.Extension{Name: "pg_trgm", Version: "1.5"})
		}, "extensions.available", preflight.OK, nil, nil},
		{"availability unreadable", func(in *Input) { withExt("pg_trgm", "1.6", nil)(in); in.Target.Facts.AvailableExtensions = nil }, "extensions.unverified", preflight.Warn, nil, []string{"pg_available_extensions"}},
	})
}

func TestSharedPreloadLibraries(t *testing.T) {
	runDecisions(t, []decision{
		{"missing on the target", func(in *Input) {
			setSrc("shared_preload_libraries", "pg_stat_statements,timescaledb")(in)
			setTgt("shared_preload_libraries", "pg_stat_statements")(in)
		}, "extensions.preload", preflight.Warn, []string{"timescaledb"}, []string{"shared_preload_libraries"}},
	})
	t.Run("equal and RDS-only lists raise nothing", func(t *testing.T) {
		in := healthy()
		in.Source.Server.Settings["shared_preload_libraries"] = inventory.Setting{Value: "rdsutils,pg_stat_statements"}
		in.Target.Server.Settings["shared_preload_libraries"] = inventory.Setting{Value: `"pg_stat_statements"`}
		if has(Run(in), "extensions.preload") {
			t.Error("rds* libraries and quoted names must not be reported")
		}
	})
}

func TestLocale(t *testing.T) {
	latin := inventory.Locale{Encoding: "LATIN1", Collate: "en_US.UTF-8", Ctype: "en_US.UTF-8", Provider: "c"}
	runDecisions(t, []decision{
		{"existing database, same settings", func(in *Input) {}, "locale.app", preflight.OK, nil, nil},
		{"existing database, encoding differs", func(in *Input) { in.Target.Server.Databases[0].Locale = latin }, "locale.app", preflight.Blocker,
			[]string{"encoding UTF8 vs LATIN1"}, []string{"CREATE DATABASE", "TEMPLATE template0", "ENCODING 'UTF8'"}},
		{"existing database, collation differs", func(in *Input) {
			l := utf8
			l.Collate = "C"
			in.Target.Server.Databases[0].Locale = l
		}, "locale.app", preflight.Warn, []string{"LC_COLLATE en_US.UTF-8 vs C"}, []string{"CREATE DATABASE"}},
		{"existing database, ctype differs", func(in *Input) {
			l := utf8
			l.Ctype = "C"
			in.Target.Server.Databases[0].Locale = l
		}, "locale.app", preflight.Warn, []string{"LC_CTYPE"}, nil},
		{"existing database, locale provider differs", func(in *Input) {
			l := utf8
			l.Provider, l.ICULocale = "i", "en-US"
			in.Target.Server.Databases[0].Locale = l
		}, "locale.app", preflight.Warn, []string{"provider"}, nil},
		{"missing database, target default matches", func(in *Input) { in.Target.Server.Databases = nil }, "locale.app", preflight.OK, []string{"template1"}, nil},
		{"missing database, target default differs", func(in *Input) {
			in.Target.Server.Databases = nil
			in.Target.Server.DefaultLocale = latin
		}, "locale.app", preflight.Warn, []string{"does not exist on the target yet"}, []string{"template0", "locale -a"}},
	})
}

func TestRoles(t *testing.T) {
	runDecisions(t, []decision{
		{"all owners exist", func(in *Input) {}, "roles.owners", preflight.OK, nil, nil},
		{"owner missing on the target", func(in *Input) {
			in.Target.Server.Roles = []inventory.Role{{Name: "postgres"}}
		}, "roles.owners", preflight.Warn, []string{"app_owner", "owns objects in app"}, []string{`CREATE ROLE "app_owner" NOLOGIN;`, "passwords"}},
		{"database owner counts too", func(in *Input) {
			in.Source.Server.Databases[0].Owner = "dbowner"
		}, "roles.owners", preflight.Warn, []string{"dbowner", "owns database app"}, nil},
		{"truncated target role list is flagged", func(in *Input) {
			in.Target.Server.Roles = []inventory.Role{{Name: "postgres"}}
			in.Target.Server.RolesTotal = 5000
		}, "roles.owners", preflight.Warn, []string{"more roles than were listed"}, nil},
	})
}

func TestTargetPrivilegesWorkersAndConnections(t *testing.T) {
	plain := func(major int) func(*Input) {
		return func(in *Input) {
			in.Target.Server.Session = inventory.Session{User: "lk_t"}
			in.Target.Server.Major = major
		}
	}
	twoDBs := func(in *Input) {
		in.Source.Server.Databases = append(in.Source.Server.Databases, inventory.Database{Name: "billing", Locale: utf8})
	}
	runDecisions(t, []decision{
		{"superuser can subscribe", func(in *Input) {}, "target.subscription_privilege", preflight.OK, nil, nil},
		{"pg_create_subscription can subscribe", func(in *Input) {
			in.Target.Server.Session = inventory.Session{User: "lk_t", PgCreateSubscription: true}
		}, "target.subscription_privilege", preflight.OK, []string{"pg_create_subscription"}, nil},
		{"plain role on 17", plain(17), "target.subscription_privilege", preflight.Blocker, []string{"lk_t"}, []string{`GRANT pg_create_subscription TO "lk_t"`, "GRANT CREATE ON DATABASE"}},
		{"plain role before 16 needs superuser", plain(15), "target.subscription_privilege", preflight.Blocker, nil, []string{"superuser", "Before PostgreSQL 16"}},

		{"one worker free of four", func(in *Input) { in.Target.Facts.LogicalWorkers = ptr(3) }, "target.max_logical_replication_workers", preflight.OK, []string{"1 free"}, nil},
		{"no worker free", func(in *Input) { in.Target.Facts.LogicalWorkers = ptr(4) }, "target.max_logical_replication_workers", preflight.Blocker, []string{"0 free"}, []string{"max_logical_replication_workers", "max_worker_processes"}},
		{"two databases need two workers", func(in *Input) { twoDBs(in); in.Target.Facts.LogicalWorkers = ptr(3) }, "target.max_logical_replication_workers", preflight.Blocker, []string{"needs 2"}, nil},
		{"workers unknown assumes none running", func(in *Input) { in.Target.Facts.LogicalWorkers = nil }, "target.max_logical_replication_workers", preflight.OK, []string{"could not be read"}, nil},
		{"worker processes just enough", setTgt("max_worker_processes", "5"), "target.max_worker_processes", preflight.OK, nil, nil},
		{"worker processes one too few", setTgt("max_worker_processes", "4"), "target.max_worker_processes", preflight.Warn, nil, []string{"max_worker_processes"}},
		{"sync workers zero", setTgt("max_sync_workers_per_subscription", "0"), "target.max_sync_workers_per_subscription", preflight.Warn, nil, []string{"max_sync_workers_per_subscription"}},
		{"sync workers one", setTgt("max_sync_workers_per_subscription", "1"), "target.max_sync_workers_per_subscription", preflight.Info, nil, nil},

		{"connections equal", func(in *Input) {}, "target.max_connections", preflight.OK, nil, nil},
		{"connections lower on the target", setTgt("max_connections", "99"), "target.max_connections", preflight.Warn, []string{"99", "100"}, []string{"max_connections"}},
	})
}

func TestTargetLogging(t *testing.T) {
	runDecisions(t, []decision{
		{"quiet logging", func(in *Input) {}, "target.logging", preflight.OK, []string{"log_min_error_statement"}, nil},
		{"log_statement ddl", setTgt("log_statement", "ddl"), "target.logging", preflight.Warn, []string{`log_statement is "ddl"`, "source password"}, []string{"SET log_statement", "Acknowledge", "dedicated"}},
		{"log_statement all", setTgt("log_statement", "all"), "target.logging", preflight.Warn, nil, nil},
		{"log_statement mod", setTgt("log_statement", "mod"), "target.logging", preflight.Warn, nil, nil},
		{"duration logging at zero logs everything", setTgt("log_min_duration_statement", "0"), "target.logging", preflight.Warn, []string{"0 ms"}, nil},
		{"duration logging at a threshold", setTgt("log_min_duration_statement", "250"), "target.logging", preflight.Warn, nil, nil},
		{"duration logging off is -1", setTgt("log_min_duration_statement", "-1"), "target.logging", preflight.OK, nil, nil},
		{"both settings are reported together", func(in *Input) {
			setTgt("log_statement", "all")(in)
			setTgt("log_min_duration_statement", "0")(in)
		}, "target.logging", preflight.Warn, []string{"log_statement", "log_min_duration_statement"}, nil},
	})
}

func TestTargetEmpty(t *testing.T) {
	tdb := func(mut func(*inventory.Database)) func(*Input) {
		return func(in *Input) { mut(&in.Target.Server.Databases[0]) }
	}
	runDecisions(t, []decision{
		{"empty database", func(in *Input) {}, "target.empty.app", preflight.OK, []string{"is empty"}, nil},
		{"database absent", func(in *Input) { in.Target.Server.Databases = nil }, "target.empty.app", preflight.OK, []string{"will be created"}, nil},
		{"user tables present", tdb(func(d *inventory.Database) {
			d.Tables = 2
			d.LargestTables = []inventory.Table{{Schema: "public", Name: "legacy"}}
		}), "target.empty.app", preflight.Blocker, []string{"2 user tables", "public.legacy"}, []string{"empty database", "never deletes"}},
		{"only partitions present", tdb(func(d *inventory.Database) { d.Partitions = 1 }), "target.empty.app", preflight.Blocker, nil, nil},
		{"only a view present", tdb(func(d *inventory.Database) { d.Views = 1 }), "target.empty.app", preflight.Warn, []string{"1 view"}, nil},
		{"only a sequence present", tdb(func(d *inventory.Database) { d.Sequences = 1 }), "target.empty.app", preflight.Warn, nil, nil},
		{"inspection failed", tdb(func(d *inventory.Database) { d.Error = "connect: permission denied" }), "target.empty.app", preflight.Warn, []string{"permission denied"}, nil},
	})
}

func TestSizesAreInformationalAndComputeTheRuleOfThumb(t *testing.T) {
	in := healthy()
	in.Source.Server.Databases[0].SizeBytes = 10 * gib
	in.Source.Server.Databases = append(in.Source.Server.Databases, inventory.Database{Name: "billing", SizeBytes: 30 * gib, Locale: utf8,
		LargestTables: []inventory.Table{{Schema: "public", Name: "invoices", TotalBytes: 20 * gib}}})
	f := get(t, Run(in), "data.sizes")
	if f.Severity != preflight.Info {
		t.Errorf("severity %s", f.Severity)
	}
	for _, frag := range []string{"40.0 GiB", "60.0 GiB", "1.5 x", "app 10.0 GiB", "billing 30.0 GiB", "public.invoices (20.0 GiB)", "Free disk space cannot be read over SQL", "copy time is not estimated"} {
		if !strings.Contains(f.Message, frag) {
			t.Errorf("sizes message lacks %q:\n%s", frag, f.Message)
		}
	}
	if !strings.Contains(f.Remediation, "df -h") {
		t.Errorf("remediation: %s", f.Remediation)
	}

	in = healthy()
	in.Source.Server.Databases[0].SizeBytes = -1
	if f := get(t, Run(in), "data.sizes"); !strings.Contains(f.Message, "not readable") {
		t.Errorf("unreadable size must be disclosed: %s", f.Message)
	}
}

func TestSchemaFreezeReportsCountsOnly(t *testing.T) {
	runDecisions(t, []decision{
		{"none", func(in *Input) {}, "source.ddl_activity", preflight.Info, []string{"no session"}, nil},
		{"two sessions", func(in *Input) { in.Source.Facts.DDLSessions = ptr(2) }, "source.ddl_activity", preflight.Info, []string{"2 sessions", "frozen"}, nil},
		{"lower bound when sessions are hidden", func(in *Input) { in.Source.Facts.HiddenSessions = 4 }, "source.ddl_activity", preflight.Info, []string{"4 other session", "lower bound", "pg_monitor"}, nil},
		{"unknown", func(in *Input) { in.Source.Facts.DDLSessions = nil }, "source.ddl_activity", preflight.Info, []string{"unknown"}, nil},
	})
}

func TestConnectivityAndTLS(t *testing.T) {
	remote := func(in *Input) {}
	runDecisions(t, []decision{
		{"source reachable", remote, "connect.source", preflight.OK, []string{"rds-main", "db.example.com:5432", "40ms", "14.10"}, nil},
		{"source unreachable", func(in *Input) {
			in.Source.Server = nil
			in.Source.ConnectError = "connection refused"
		}, "connect.source", preflight.Blocker, []string{"connection refused", "db.example.com:5432"}, []string{"psql", "sslmode=verify-full", "security group"}},
		{"target unreachable", func(in *Input) {
			in.Target.Server = nil
			in.Target.ConnectError = "timeout"
		}, "connect.target", preflight.Blocker, []string{"timeout"}, nil},
		{"remote verified TLS", remote, "tls.source", preflight.OK, []string{"TLSv1.3"}, nil},
		{"remote TLS with require mode", func(in *Input) { in.Source.Endpoint.TLSMode = "require" }, "tls.source", preflight.Warn, []string{"not fully verified"}, []string{"verify-full"}},
		{"remote TLS with verify-ca", func(in *Input) { in.Source.Endpoint.TLSMode = "verify-ca" }, "tls.source", preflight.Warn, nil, nil},
		{"remote without TLS", func(in *Input) { in.Source.Facts.SSL = &SSLInfo{} }, "tls.source", preflight.Warn, []string{"NOT encrypted", "clear text"}, []string{"verify-full"}},
		{"loopback without TLS is exempt", func(in *Input) {
			in.Source.Endpoint.Host = "127.0.0.1"
			in.Source.Facts.SSL = &SSLInfo{}
		}, "tls.source", preflight.Info, []string{"loopback"}, nil},
		{"unknown TLS state on a remote host", func(in *Input) { in.Source.Facts.SSL = nil }, "tls.source", preflight.Warn, []string{"could not determine"}, nil},
		{"unknown TLS state on loopback", func(in *Input) { in.Source.Endpoint.Host = "localhost"; in.Source.Facts.SSL = nil }, "tls.source", preflight.Info, nil, nil},
	})
}

func TestUnreachableSidesSkipDependentChecksWithoutPanicking(t *testing.T) {
	for name, mutate := range map[string]func(*Input){
		"source down": func(in *Input) { in.Source.Server, in.Source.ConnectError = nil, "refused" },
		"target down": func(in *Input) { in.Target.Server, in.Target.ConnectError = nil, "refused" },
		"both down": func(in *Input) {
			in.Source.Server, in.Source.ConnectError = nil, "refused"
			in.Target.Server, in.Target.ConnectError = nil, "refused"
		},
	} {
		t.Run(name, func(t *testing.T) {
			in := healthy()
			mutate(&in)
			r := Run(in)
			if r.ExitCode() != 3 || !has(r, "run.incomplete") || !has(r, "network.target_to_source") {
				t.Errorf("exit %d, findings %v", r.ExitCode(), r.Findings)
			}
			if name == "both down" && len(r.Databases) != 0 {
				t.Errorf("no databases are known: %v", r.Databases)
			}
		})
	}
	t.Run("the reachable side is still checked", func(t *testing.T) {
		in := healthy()
		in.Target.Server, in.Target.ConnectError = nil, "refused"
		in.Source.Server.Settings["wal_level"] = inventory.Setting{Value: "replica"}
		if get(t, Run(in), "source.wal_level").Severity != preflight.Blocker {
			t.Error("source checks must still run when only the target is down")
		}
	})
}

func TestTargetToSourceIsAlwaysAnUnverifiableWarningWithoutSecrets(t *testing.T) {
	cases := []struct {
		name string
		ep   Endpoint
		want string
	}{
		{"plain", Endpoint{Host: "db.example.com", Port: 5432, Database: "postgres", User: "lk_mig"},
			`psql 'postgresql://lk_mig@db.example.com:5432/postgres?sslmode=verify-full' -c "SELECT 1"`},
		{"ipv6 and default port", Endpoint{Host: "::1", User: "u", Database: "d"},
			`psql 'postgresql://u@[::1]:5432/d?sslmode=verify-full' -c "SELECT 1"`},
		{"special characters are escaped", Endpoint{Host: "h", Port: 6432, User: "we ird@x", Database: ""},
			`psql 'postgresql://we%20ird%40x@h:6432/postgres?sslmode=verify-full' -c "SELECT 1"`},
		{"single quotes cannot break out of the shell quoting", Endpoint{Host: "h", Port: 1, User: "a'b", Database: "d"},
			`psql 'postgresql://a%27b@h:1/d?sslmode=verify-full' -c "SELECT 1"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := healthy()
			in.Source.Endpoint = c.ep
			f := get(t, Run(in), "network.target_to_source")
			if f.Severity != preflight.Warn || !strings.Contains(f.Message, "cannot be verified read-only") {
				t.Errorf("%+v", f)
			}
			if !strings.Contains(f.Remediation, c.want) {
				t.Errorf("remediation lacks %s:\n%s", c.want, f.Remediation)
			}
			if strings.Contains(strings.ToLower(f.Remediation), "password=") {
				t.Errorf("a password parameter must never be suggested: %s", f.Remediation)
			}
		})
	}
}

func TestLoopbackSourceExplainsWhichAddressToUse(t *testing.T) {
	in := healthy()
	in.Source.Endpoint.Host = "127.0.0.1"
	if f := get(t, Run(in), "network.target_to_source"); !strings.Contains(f.Message, "TARGET server can reach") {
		t.Errorf("a loopback address is useless from the target: %s", f.Message)
	}
}

func TestInspectionGapsAreSurfaced(t *testing.T) {
	in := healthy()
	in.Source.Server.Databases[0].Warnings = []string{"tables without a primary key: canceling statement due to statement timeout"}
	in.Target.Server.Warnings = []string{"x: y"}
	r := Run(in)
	if f := get(t, r, "inspection.source"); f.Severity != preflight.Warn || !strings.Contains(f.Message, "statement timeout") || f.Remediation == "" {
		t.Errorf("%+v", f)
	}
	if get(t, r, "inspection.target").Severity != preflight.Warn {
		t.Error("target gaps must be a warning too")
	}
}

func TestEveryWarningAndBlockerHasRemediationAndNoSecretsOrDataLeak(t *testing.T) {
	in := healthy()
	s, tg := in.Source.Server, in.Target.Server
	s.Settings["wal_level"] = inventory.Setting{Value: "replica"}
	s.Settings["max_wal_senders"] = inventory.Setting{Value: "1"}
	s.Settings["wal_sender_timeout"] = inventory.Setting{Value: "60000"}
	s.Settings["max_slot_wal_keep_size"] = inventory.Setting{Value: "-1"}
	s.Session = inventory.Session{User: "mon"}
	s.Slots = []inventory.Slot{{Name: "a", Type: "logical", RetainedBytes: 30 * gib}, {Name: "b", Type: "logical", RetainedBytes: 6 * gib, Active: true}, {Name: "c", Type: "logical"}}
	d := &s.Databases[0]
	d.TablesWithoutPK = inventory.TableList{Total: 1, Items: []inventory.Table{{Schema: "public", Name: "t", ReplicaIdentity: "default"}}}
	d.UnloggedTables = inventory.TableList{Total: 1, Items: []inventory.Table{{Schema: "public", Name: "u"}}}
	d.LargeObjects = 3
	d.Extensions = append(d.Extensions, inventory.Extension{Name: "postgis", Version: "3"})
	d.UnreadableTables = inventory.TableList{Total: 1, Items: []inventory.Table{{Schema: "public", Name: "x"}}}
	tg.Major = 12
	tg.Session = inventory.Session{User: "t"}
	tg.Settings["log_statement"] = inventory.Setting{Value: "all"}
	tg.Settings["max_worker_processes"] = inventory.Setting{Value: "2"}
	tg.Roles = nil
	tg.Databases[0].Tables = 1
	tg.Databases[0].Locale.Encoding = "LATIN1"
	in.Source.Facts.SSL = &SSLInfo{}

	r := Run(in)
	if r.Summary.Blocker < 5 || r.Summary.Warn < 5 {
		t.Fatalf("scenario too tame: %+v", r.Summary)
	}
	for _, f := range r.Findings {
		if f.Severity.Rank() >= preflight.Warn.Rank() && len(strings.Fields(f.Remediation)) < 5 {
			t.Errorf("%s %s lacks actionable remediation: %q", f.Severity, f.ID, f.Remediation)
		}
		if f.ID == "" || f.Area == "" || f.Message == "" {
			t.Errorf("incomplete finding %+v", f)
		}
	}
	// Findings are ordered worst first.
	for i := 1; i < len(r.Findings); i++ {
		if r.Findings[i].Severity.Rank() > r.Findings[i-1].Severity.Rank() {
			t.Fatalf("not sorted by severity at %d: %s after %s", i, r.Findings[i].Severity, r.Findings[i-1].Severity)
		}
	}
}

func TestReportJSONIsStable(t *testing.T) {
	b, err := json.Marshal(Run(healthy()))
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema_version", "engine", "source", "target", "databases", "findings", "summary"} {
		if _, ok := generic[k]; !ok {
			t.Errorf("missing top-level key %q", k)
		}
	}
	first := generic["findings"].([]any)[0].(map[string]any)
	for _, k := range []string{"id", "area", "severity", "message"} {
		if _, ok := first[k]; !ok {
			t.Errorf("finding lacks %q: %v", k, first)
		}
	}
	// The same input must give byte-identical output.
	b2, _ := json.Marshal(Run(healthy()))
	if string(b) != string(b2) {
		t.Error("report is not deterministic")
	}
}
