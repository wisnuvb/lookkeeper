package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/inventory"
	"github.com/wisnuvb/lockkeeper/internal/preflight"
	"github.com/wisnuvb/lockkeeper/internal/service"
)

func init() {
	commandFactories = append(commandFactories,
		func(a *app) *cobra.Command { return a.inventoryCmd() },
		func(a *app) *cobra.Command { return a.preflightCmd() },
	)
}

// discoveryTimeout bounds one inventory or pre-flight run.
const discoveryTimeout = 10 * time.Minute

// InventoryOutput is the JSON printed by `lockkeeper inventory --json`: the
// name of the configured connection followed by the fields of inventory.Server
// (see its documentation; schema_version is part of it).
type InventoryOutput struct {
	Source string `json:"source"`
	inventory.Server
}

func (a *app) inventoryCmd() *cobra.Command {
	var source string
	var databases []string
	var maxDatabases int
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "Discover what a PostgreSQL server contains (read-only)",
		Long: `Reads, and never changes, one PostgreSQL server: version, the settings that
matter for a migration, roles (names and attributes only, never passwords),
replication slots and retained WAL, and for each database its size, encoding
and collation, extensions, table count, largest tables, tables without a
primary key (with REPLICA IDENTITY), unlogged, partitioned and foreign tables,
large objects and sequences.

Every session is read-only. Per-database detail needs one connection per
database (same server, same role, one at a time); rdsadmin is skipped. No row
data and no query text of other sessions is ever read or printed.

Use --databases to inspect only some databases, and --max-databases to raise
the cap (default 50; exceeding it is an error, never a silent truncation).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, warnings, err := a.loadConfig()
			for _, w := range warnings {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning:", w)
			}
			if err != nil {
				return err
			}
			if source == "" {
				if len(cfg.Databases) != 1 {
					return fmt.Errorf("--source is required when more than one database is configured")
				}
				for name := range cfg.Databases {
					source = name
				}
			}
			svc, err := a.newService(cfg)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), discoveryTimeout)
			defer cancel()
			srv, err := svc.Inventory(ctx, source, service.DiscoveryOptions{Databases: databases, MaxDatabases: maxDatabases})
			if err != nil {
				return err
			}
			if asJSON {
				return pfWriteJSON(cmd.OutOrStdout(), InventoryOutput{Source: source, Server: *srv})
			}
			pfPrintInventory(cmd.OutOrStdout(), source, srv)
			return nil
		},
	}
	cmd.Flags().StringVarP(&source, "source", "s", "", "configured database to inventory (default: the only one configured)")
	cmd.Flags().StringSliceVar(&databases, "databases", nil, "only these databases (comma separated)")
	cmd.Flags().IntVar(&maxDatabases, "max-databases", 0, "most databases to inspect (default 50)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")
	return cmd
}

func (a *app) preflightCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "preflight",
		Short: "Migration pre-flight checks (read-only)",
	}
	var source, target string
	var databases []string
	var maxDatabases int
	var asJSON bool
	pgCmd := &cobra.Command{
		Use:   "pg --source A --target B",
		Short: "Check whether a PostgreSQL source can be migrated to a target (read-only)",
		Long: `Compares two configured PostgreSQL servers and reports what would stop or
complicate a migration with native logical replication: versions, wal_level
and replication slot limits, privileges, existing slots and retained WAL,
tables without a primary key, unlogged tables, large objects, extensions,
encoding and collation, missing roles, target worker limits and statement
logging, sizes and more.

This command only reads. It does not create or change anything on either
server (no slot, publication, extension, setting or temporary table) and it
never contacts a server that is not in your configuration. What cannot be
verified without writing, in particular whether the target server can reach the
source, is reported as a warning together with the command to run by hand.

--source and --target are roles for this run; a configured connection has no
fixed role. Use --databases to restrict the check to some databases.

Exit status: 0 only OK/INFO findings, 2 warnings, 3 any blocker, 1 operational
error (for example a name that is not configured, or --source equal to --target).

JSON output (--json) is a single object with schema_version, engine, source,
target, databases, findings[{id, area, severity, message, remediation}] and
summary{ok, info, warn, blocker, highest}.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, warnings, err := a.loadConfig()
			for _, w := range warnings {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning:", w)
			}
			if err != nil {
				return err
			}
			svc, err := a.newService(cfg)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), discoveryTimeout)
			defer cancel()
			rep, err := svc.PreflightPG(ctx, source, target, service.DiscoveryOptions{Databases: databases, MaxDatabases: maxDatabases})
			if err != nil {
				return err
			}
			if asJSON {
				if err := pfWriteJSON(cmd.OutOrStdout(), rep); err != nil {
					return err
				}
			} else {
				pfPrintReport(cmd.OutOrStdout(), rep)
			}
			if code := rep.ExitCode(); code != 0 {
				return &ExitError{Code: code}
			}
			return nil
		},
	}
	pgCmd.Flags().StringVarP(&source, "source", "s", "", "configured database to migrate from")
	pgCmd.Flags().StringVarP(&target, "target", "t", "", "configured database to migrate to")
	pgCmd.Flags().StringSliceVar(&databases, "databases", nil, "only these databases (comma separated)")
	pgCmd.Flags().IntVar(&maxDatabases, "max-databases", 0, "most databases to inspect per server (default 50)")
	pgCmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")
	_ = pgCmd.MarkFlagRequired("source")
	_ = pgCmd.MarkFlagRequired("target")
	cmd.AddCommand(pgCmd)
	return cmd
}

func pfWriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// pfClean makes a string safe for a terminal: control characters (which a
// database object name may contain) are replaced, so a hostile name cannot
// inject escape sequences into the operator's terminal.
func pfClean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

// pfWrap breaks text at word boundaries so remediation stays readable.
func pfWrap(s string, width int) []string {
	var lines []string
	var cur strings.Builder
	for _, w := range strings.Fields(pfClean(s)) {
		if cur.Len() > 0 && cur.Len()+1+len(w) > width {
			lines = append(lines, cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteByte(' ')
		}
		cur.WriteString(w)
	}
	if cur.Len() > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}

func pfPrintReport(out io.Writer, r *preflight.Report) {
	fmt.Fprintf(out, "Pre-flight (%s): source %q -> target %q\n", r.Engine, pfClean(r.Source), pfClean(r.Target))
	fmt.Fprintf(out, "Databases: %s\n", pfClean(strings.Join(r.Databases, ", ")))
	fmt.Fprintln(out, "Read-only: nothing was created or changed on either server.")
	for _, sev := range []preflight.Severity{preflight.Blocker, preflight.Warn, preflight.Info, preflight.OK} {
		var group []preflight.Finding
		for _, f := range r.Findings {
			if f.Severity == sev {
				group = append(group, f)
			}
		}
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(out, "\n%s (%d)\n", sev, len(group))
		for _, f := range group {
			lines := pfWrap(f.Message, 96)
			fmt.Fprintf(out, "  [%s] %s\n", pfClean(f.ID), strings.Join(lines[:min(1, len(lines))], ""))
			for _, l := range lines[min(1, len(lines)):] {
				fmt.Fprintf(out, "      %s\n", l)
			}
			if f.Remediation != "" && sev != preflight.OK {
				rl := pfWrap(f.Remediation, 92)
				for i, l := range rl {
					if i == 0 {
						fmt.Fprintf(out, "      -> %s\n", l)
					} else {
						fmt.Fprintf(out, "         %s\n", l)
					}
				}
			}
		}
	}
	s := r.Summary
	verdict := "READY (no warnings or blockers)"
	switch s.Highest {
	case preflight.Blocker:
		verdict = "NOT READY: resolve the blockers first"
	case preflight.Warn:
		verdict = "READY WITH WARNINGS: review each warning before continuing"
	}
	fmt.Fprintf(out, "\nSummary: %d blocker, %d warn, %d info, %d ok. %s.\n", s.Blocker, s.Warn, s.Info, s.OK, verdict)
}

func pfPrintInventory(out io.Writer, name string, s *inventory.Server) {
	rds := ""
	if s.IsRDS {
		rds = ", looks like Amazon RDS"
	}
	fmt.Fprintf(out, "Server %q: PostgreSQL %s%s\n", pfClean(name), pfClean(s.Version), rds)
	fmt.Fprintf(out, "Connected as %q (superuser: %v, replication: %v, rds_replication: %v, pg_monitor: %v, read-only session: %v)\n",
		pfClean(s.Session.User), s.Session.Superuser, s.Session.Replication, s.Session.RDSReplication, s.Session.PgMonitor, s.Session.ReadOnly)

	fmt.Fprintln(out, "\nSettings")
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	keys := make([]string, 0, len(s.Settings))
	for k := range s.Settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		st := s.Settings[k]
		v := pfClean(st.Value + " " + st.Unit)
		if st.PendingRestart {
			v += "  (restart pending)"
		}
		fmt.Fprintf(tw, "  %s\t%s\n", k, strings.TrimSpace(v))
	}
	_ = tw.Flush()

	fmt.Fprintf(out, "\nRoles (%d, system roles omitted)\n", s.RolesTotal)
	tw = tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  ROLE\tATTRIBUTES\tMEMBER OF")
	for _, r := range s.Roles {
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", pfClean(r.Name), pfRoleAttrs(r), pfClean(strings.Join(r.MemberOf, ", ")))
	}
	_ = tw.Flush()

	fmt.Fprintln(out, "\nReplication slots")
	if len(s.Slots) == 0 {
		fmt.Fprintln(out, "  none")
	} else {
		tw = tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  SLOT\tTYPE\tACTIVE\tRETAINED WAL\tPLUGIN\tDATABASE")
		for _, sl := range s.Slots {
			fmt.Fprintf(tw, "  %s\t%s\t%v\t%s\t%s\t%s\n", pfClean(sl.Name), sl.Type, sl.Active, rules.FormatBytes(float64(sl.RetainedBytes)), dash(sl.Plugin), dash(pfClean(sl.Database)))
		}
		_ = tw.Flush()
	}

	for _, d := range s.Databases {
		pfPrintDatabase(out, d)
	}
	if len(s.OtherDatabases) > 0 {
		fmt.Fprintf(out, "\nNot inspected (not selected): %s\n", pfClean(strings.Join(s.OtherDatabases, ", ")))
	}
	if len(s.SkippedDatabases) > 0 {
		fmt.Fprintf(out, "Skipped (never inspected): %s\n", pfClean(strings.Join(s.SkippedDatabases, ", ")))
	}
	for _, w := range s.Warnings {
		fmt.Fprintf(out, "warning: %s\n", pfClean(w))
	}
	fmt.Fprintln(out, "\nRead-only: nothing was created or changed on the server.")
}

func pfRoleAttrs(r inventory.Role) string {
	var a []string
	for _, f := range []struct {
		on   bool
		name string
	}{{r.Superuser, "superuser"}, {r.CanLogin, "login"}, {r.CreateRole, "createrole"}, {r.CreateDB, "createdb"}, {r.Replication, "replication"}, {r.BypassRLS, "bypassrls"}} {
		if f.on {
			a = append(a, f.name)
		}
	}
	if len(a) == 0 {
		return "-"
	}
	return strings.Join(a, ",")
}

func pfPrintDatabase(out io.Writer, d inventory.Database) {
	size := "unknown size"
	if d.SizeBytes >= 0 {
		size = rules.FormatBytes(float64(d.SizeBytes))
	}
	fmt.Fprintf(out, "\nDatabase %s (%s, owner %s, %s, collate %s, ctype %s)\n", pfClean(d.Name), size, pfClean(d.Owner), d.Encoding, pfClean(d.Collate), pfClean(d.Ctype))
	if d.Error != "" {
		fmt.Fprintf(out, "  not inspected: %s\n", pfClean(d.Error))
		return
	}
	fmt.Fprintf(out, "  %d tables (+%d partitions), %d sequences, %d views, %d functions, %d large objects (%s), %d stored generated columns\n",
		d.Tables, d.Partitions, d.Sequences, d.Views, d.Functions, d.LargeObjects, rules.FormatBytes(float64(d.LargeObjectBytes)), d.GeneratedColumns)
	exts := make([]string, 0, len(d.Extensions))
	for _, e := range d.Extensions {
		exts = append(exts, e.Name+" "+e.Version)
	}
	fmt.Fprintf(out, "  extensions: %s\n", dash(pfClean(strings.Join(exts, ", "))))
	fmt.Fprintf(out, "  object owners: %s\n", dash(pfClean(strings.Join(d.Owners, ", "))))
	pfPrintTables(out, "largest tables", inventory.TableList{Total: len(d.LargestTables), Items: d.LargestTables}, false)
	pfPrintTables(out, "tables WITHOUT a primary key", d.TablesWithoutPK, true)
	pfPrintTables(out, "unlogged tables", d.UnloggedTables, false)
	pfPrintTables(out, "partitioned tables", d.PartitionedTables, false)
	pfPrintTables(out, "foreign tables", d.ForeignTables, false)
	pfPrintTables(out, "tables the role cannot read", d.UnreadableTables, false)
	for _, w := range d.Warnings {
		fmt.Fprintf(out, "  warning: %s\n", pfClean(w))
	}
}

func pfPrintTables(out io.Writer, title string, l inventory.TableList, identity bool) {
	if l.Total == 0 {
		return
	}
	fmt.Fprintf(out, "  %s (%d):\n", title, l.Total)
	for _, t := range l.Items {
		extra := ""
		if t.TotalBytes > 0 {
			extra = " " + rules.FormatBytes(float64(t.TotalBytes))
		}
		if identity {
			extra += ", replica identity " + t.ReplicaIdentity
		}
		if t.Partitions > 0 {
			extra += fmt.Sprintf(", %d partitions", t.Partitions)
		}
		fmt.Fprintf(out, "    %s.%s%s\n", pfClean(t.Schema), pfClean(t.Name), extra)
	}
	if l.Total > len(l.Items) {
		fmt.Fprintf(out, "    ... and %d more (see --json)\n", l.Total-len(l.Items))
	}
}
