package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/wisnuvb/lockkeeper/internal/action"
	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/service"
)

func init() {
	commandFactories = append(commandFactories, func(a *app) *cobra.Command { return a.migrateCmd() })
}

// Plain statements of what a command changes, printed first by every command.
const (
	noChange      = "This command changes nothing on the source or the target."
	changesSource = "THIS CHANGES THE SOURCE database server."
)

type migrateFlags struct {
	source, target  string
	databases       []string
	maxDatabases    int
	copierKind      string
	tableJobs       int
	indexJobs       int
	noOwner         bool
	peerAddr        string
	peerSSLMode     string
	peerSSLRootCert string
	asJSON          bool

	planHash  string
	migration string
	apply     bool
	dryRun    bool

	clientBinDir  string
	pgcopydb      string
	allowUntested bool

	noWait      bool
	maxLag      string
	caughtUpFor time.Duration
	poll        time.Duration
	slotTimeout time.Duration
	recoveryApp bool
	recoveryH   string
}

func (f *migrateFlags) tools(a *app) service.ToolOptions {
	path, _ := a.env.Getenv("PATH")
	return service.ToolOptions{ToolPath: path, ClientBinDir: f.clientBinDir, Pgcopydb: f.pgcopydb, AllowUntestedPgcopydb: f.allowUntested}
}

func addToolFlags(cmd *cobra.Command, f *migrateFlags) {
	cmd.Flags().StringVar(&f.clientBinDir, "client-bin-dir", "", "directory with the PostgreSQL client tools (pg_dump, pg_restore); must be at least the source's major version")
	cmd.Flags().StringVar(&f.pgcopydb, "pgcopydb", "", "path to the pgcopydb executable (default: found in PATH)")
	cmd.Flags().BoolVar(&f.allowUntested, "allow-untested-pgcopydb", false, "accept a pgcopydb version other than the pinned "+service.PinnedPgcopydbVersion+" (or one that does not report its version)")
}

func (a *app) migrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate PostgreSQL databases with native logical replication (plan, apply, start, status, resume, abort, cleanup)",
		Long: `Moves databases from a source server to an empty target with minimal downtime:
a bulk copy inside an exported snapshot, then native logical replication.

Every command says whether it changes the source or the target. Anything that
changes a server is shown first as a plan (exact SQL, a plan hash), runs as a dry
run unless --apply is given, and needs your confirmation: --plan-hash from a
prior plan, or typing the phrase shown on a terminal. There is no --yes.`,
	}
	cmd.AddCommand(a.migratePlanCmd(), a.migrateApplyCmd(), a.migrateStartCmd("start"), a.migrateStartCmd("resume"),
		a.migrateStatusCmd(), a.migrateEndCmd("abort"), a.migrateEndCmd("cleanup"))
	return cmd
}

func (a *app) migrateService(cmd *cobra.Command) (*service.Service, error) {
	cfg, warnings, err := a.loadConfig()
	for _, w := range warnings {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning:", w)
	}
	if err != nil {
		return nil, err
	}
	return a.newService(cfg)
}

// isTyping reports whether a typed confirmation can be read: a real terminal, or
// (tests only) a reader that is not a file.
func isTyping(in io.Reader) bool {
	f, ok := in.(*os.File)
	if !ok {
		return in != nil
	}
	return term.IsTerminal(int(f.Fd()))
}

// approver turns --plan-hash or a typed phrase into an approval.
func (a *app) approver(cmd *cobra.Command, hash string) service.Approver {
	return func(p *action.Plan) (action.Approval, error) {
		if hash != "" {
			return action.ConfirmHash(p, hash, service.Actor())
		}
		if !isTyping(a.env.Stdin) {
			return action.Approval{}, service.ErrNoApproval
		}
		out := cmd.OutOrStdout()
		fmt.Fprintln(out, p.Summary())
		return action.ConfirmTyped(a.env.Stdin, out, p, service.Actor())
	}
}

func (a *app) migratePlanCmd() *cobra.Command {
	var f migrateFlags
	cmd := &cobra.Command{
		Use:   "plan --source A --target B",
		Short: "Show what a migration would do and its plan hash (changes nothing)",
		Long: `Runs the pre-flight, reads both servers, checks that the connected roles can do
the job, and prints every action with its exact SQL and the plan hash. It refuses
to go on while the pre-flight has BLOCKER findings or a role lacks a privilege.

` + noChange + ` It saves a draft in Lockkeeper's own state
database so that the next commands can find it by its hash.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, err := a.migrateService(cmd)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), discoveryTimeout)
			defer cancel()
			res, err := svc.PlanMigration(ctx, service.MigrateOptions{
				Source: f.source, Target: f.target, Databases: f.databases, MaxDatabases: f.maxDatabases, Copier: f.copierKind,
				TableJobs: f.tableJobs, IndexJobs: f.indexJobs, NoOwner: f.noOwner,
				PeerAddr: f.peerAddr, PeerSSLMode: f.peerSSLMode, PeerSSLRootCert: f.peerSSLRootCert,
			}, f.tools(a))
			out := cmd.OutOrStdout()
			var blocked *service.BlockedError
			if errors.As(err, &blocked) {
				if f.asJSON {
					_ = pfWriteJSON(out, blocked.Report)
				} else {
					pfPrintReport(out, blocked.Report)
				}
				return &ExitError{Code: 3, Err: err}
			}
			if err != nil {
				return err
			}
			if f.asJSON {
				fmt.Fprintln(out, string(res.Plan.DisplayJSON()))
				return nil
			}
			fmt.Fprintln(out, noChange+" (A draft was saved in the local state database.)")
			if res.Existing {
				fmt.Fprintf(out, "This plan already exists as migration %s (state %s).\n", res.MigrationID, res.State)
			}
			fmt.Fprintln(out)
			fmt.Fprintln(out, res.Plan.Summary())
			fmt.Fprintf(out, "\nPlan hash: %s\nMigration: %s (state %s)\n", res.Plan.Hash(), res.MigrationID, res.State)
			fmt.Fprintf(out, "\nNext: lockkeeper migrate apply-source-changes --plan-hash %s          (dry run)\n      lockkeeper migrate apply-source-changes --plan-hash %s --apply\n", res.Plan.Hash(), res.Plan.Hash())
			return nil
		},
	}
	cmd.Flags().StringVarP(&f.source, "source", "s", "", "configured database to migrate from")
	cmd.Flags().StringVarP(&f.target, "target", "t", "", "configured database to migrate to")
	cmd.Flags().StringSliceVar(&f.databases, "databases", nil, "only these databases (comma separated)")
	cmd.Flags().IntVar(&f.maxDatabases, "max-databases", 0, "most databases to inspect per server (default 50)")
	cmd.Flags().StringVar(&f.copierKind, "copier", "pgcopydb", "bulk copy tool: pgcopydb or pgdump (pg_dump + pg_restore)")
	cmd.Flags().IntVar(&f.tableJobs, "table-jobs", 4, "parallel table copy jobs")
	cmd.Flags().IntVar(&f.indexJobs, "index-jobs", 4, "parallel index build jobs")
	cmd.Flags().BoolVar(&f.noOwner, "no-owner", false, "do not restore object ownership (when the owner roles do not exist on the target)")
	cmd.Flags().StringVar(&f.peerAddr, "source-peer-addr", "", "the source as the TARGET server reaches it, host:port (default: the configured address)")
	cmd.Flags().StringVar(&f.peerSSLMode, "source-peer-sslmode", "", "sslmode of the subscription connection (default: the source connection's TLS mode)")
	cmd.Flags().StringVar(&f.peerSSLRootCert, "source-peer-sslrootcert", "", "CA file path ON THE TARGET SERVER for the subscription connection")
	cmd.Flags().BoolVar(&f.asJSON, "json", false, "machine-readable plan (canonical document plus plan_hash)")
	addToolFlags(cmd, &f)
	_ = cmd.MarkFlagRequired("source")
	_ = cmd.MarkFlagRequired("target")
	return cmd
}

func (a *app) migrateApplyCmd() *cobra.Command {
	var f migrateFlags
	cmd := &cobra.Command{
		Use:   "apply-source-changes --plan-hash H [--apply]",
		Short: "Apply the source-side changes of a plan: role, REPLICA IDENTITY, publications (dry run by default)",
		Long: `Applies the source changes of a plan made by ` + "`migrate plan`" + `: it creates the
per-migration role (a random password, only its SCRAM verifier is sent), sets
REPLICA IDENTITY FULL on tables without a usable key, and creates the
publications. ` + changesSource + `

Without --apply this is a dry run: it shows the exact statements and changes
nothing. With --apply it needs your confirmation: --plan-hash must equal the
plan's hash exactly (or, on a terminal without --plan-hash, type the phrase
shown). The schema is checked against the plan first; every action is audited
before and after it runs.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if f.apply && f.dryRun {
				return errors.New("--apply and --dry-run contradict each other")
			}
			svc, err := a.migrateService(cmd)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			out := cmd.OutOrStdout()
			res, err := svc.ApplySourceChanges(ctx, service.ApplyOptions{PlanHash: f.planHash, MigrationID: f.migration, Apply: f.apply, Approver: a.approver(cmd, f.planHash)}, f.tools(a))
			if err != nil && res == nil {
				return err
			}
			if res != nil && res.Plan != nil && !f.apply {
				fmt.Fprintln(out, "DRY RUN: "+noChange)
				fmt.Fprintln(out, "With --apply it would run these source-side actions (changes the SOURCE):")
				for _, l := range res.Lines {
					fmt.Fprintln(out, "  "+l)
				}
				fmt.Fprintf(out, "\nTo apply: lockkeeper migrate apply-source-changes --plan-hash %s --apply\n", res.Plan.Hash())
				return err
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "%s Applied %d action(s), %d already in place. Migration %s is now source_changes_approved.\n", changesSource, len(res.Report.Applied), len(res.Report.Satisfied), res.MigrationID)
			fmt.Fprintf(out, "Next: lockkeeper migrate start --migration %s\n", res.MigrationID)
			return nil
		},
	}
	cmd.Flags().StringVar(&f.planHash, "plan-hash", "", "hash of the plan to apply (also the confirmation)")
	cmd.Flags().StringVar(&f.migration, "migration", "", "migration id (instead of --plan-hash, for a typed confirmation)")
	cmd.Flags().BoolVar(&f.apply, "apply", false, "execute (default: dry run)")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "show what would run and change nothing (the default)")
	addToolFlags(cmd, &f)
	return cmd
}

func (a *app) migrateStartCmd(name string) *cobra.Command {
	var f migrateFlags
	short := "Copy the databases and start replication, then wait until caught up"
	if name == "resume" {
		short = "Reconcile with the real servers and continue an interrupted migration"
	}
	cmd := &cobra.Command{
		Use:   name + " [--migration ID]",
		Short: short,
		Long: `Drives the migration: for each database it creates a replication slot and
exports a snapshot, copies the database inside that snapshot, then creates and
enables a subscription, and finally waits until replication is caught up.
THIS CHANGES THE SOURCE (creates replication slots) AND THE TARGET (copies the
data, creates subscriptions). It runs under the plan approved by
apply-source-changes; nothing new needs confirming, except a recovery.

It is safe to stop (Ctrl-C) and to run again: ` + "`resume`" + ` first looks at the real
servers instead of trusting what was recorded. If a copy was interrupted, its
snapshot is gone and a slot cannot be reused: you get a recovery plan (drop the
old slot, reset the target database, copy again). Review it, then
  lockkeeper migrate resume --apply --recovery-plan-hash <hash>

The source keeps retaining WAL for every slot while the migration runs.
` + "`migrate status`" + ` shows how much; see docs/runbooks/wal-slot-full.md.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, err := a.migrateService(cmd)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			out := cmd.OutOrStdout()
			maxLag := int64(0)
			if f.maxLag != "" {
				v, err := parseSize(f.maxLag)
				if err != nil {
					return fmt.Errorf("--max-lag: %w", err)
				}
				maxLag = v
			}
			fmt.Fprintln(out, "THIS CHANGES THE SOURCE (replication slots) AND THE TARGET (copy, subscriptions). It runs under the approved plan.")
			res, err := svc.RunMigration(ctx, service.RunOptions{
				PlanHash: f.planHash, MigrationID: f.migration, Tools: f.tools(a), Wait: !f.noWait,
				MaxLagBytes: maxLag, CaughtUpFor: f.caughtUpFor, PollInterval: f.poll, SlotTimeout: f.slotTimeout,
				ApplyRecovery: f.recoveryApp, RecoveryHash: f.recoveryH, Approver: a.approver(cmd, f.recoveryH),
				Notify: func(level, msg string) { fmt.Fprintf(out, "[%s] %s\n", level, pfClean(msg)) },
			})
			if res != nil && res.RecoveryPlan != nil && errors.Is(err, service.ErrRecoveryPlanNeeded) {
				fmt.Fprintln(out, "\n"+res.RecoveryWhy)
				fmt.Fprintln(out, "\nRecovery plan (THIS WOULD CHANGE THE SOURCE and DROP AND RECREATE THE TARGET DATABASE; nothing has been changed yet):")
				fmt.Fprintln(out, res.RecoveryPlan.Summary())
				fmt.Fprintf(out, "\nTo apply: lockkeeper migrate resume --migration %s --apply --recovery-plan-hash %s\n", res.MigrationID, res.RecoveryPlan.Hash())
				return &ExitError{Code: 2, Err: err}
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "Migration %s is %s.\n", res.MigrationID, res.State)
			return nil
		},
	}
	cmd.Flags().StringVar(&f.planHash, "plan-hash", "", "hash of the migration's plan")
	cmd.Flags().StringVar(&f.migration, "migration", "", "migration id (default: the only open one)")
	cmd.Flags().BoolVar(&f.noWait, "no-wait", false, "return once every subscription is enabled instead of waiting for caught up")
	cmd.Flags().StringVar(&f.maxLag, "max-lag", "", "caught up means within this much WAL of the source (default 4MiB)")
	cmd.Flags().DurationVar(&f.caughtUpFor, "caught-up-for", 0, "how long every database must stay within --max-lag (default 2m)")
	cmd.Flags().DurationVar(&f.poll, "poll-interval", 0, "how often progress is read (default 10s)")
	cmd.Flags().DurationVar(&f.slotTimeout, "slot-timeout", 10*time.Minute, "how long creating a slot may wait for open transactions on the source")
	cmd.Flags().BoolVar(&f.recoveryApp, "apply", false, "apply a recovery plan (needs --recovery-plan-hash or a typed confirmation)")
	cmd.Flags().StringVar(&f.recoveryH, "recovery-plan-hash", "", "hash of the recovery plan being approved")
	addToolFlags(cmd, &f)
	return cmd
}

func (a *app) migrateStatusCmd() *cobra.Command {
	var f migrateFlags
	cmd := &cobra.Command{
		Use:   "status [--migration ID]",
		Short: "Show a migration's state, retained WAL, lag and per-database progress (read-only)",
		Long:  noChange + ` It reads the servers through read-only sessions.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, err := a.migrateService(cmd)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()
			st, err := svc.MigrationStatus(ctx, f.planHash, f.migration, f.tools(a))
			if err != nil {
				return err
			}
			if f.asJSON {
				return pfWriteJSON(cmd.OutOrStdout(), st)
			}
			printMigrationStatus(cmd.OutOrStdout(), st)
			return nil
		},
	}
	cmd.Flags().StringVar(&f.planHash, "plan-hash", "", "hash of the migration's plan")
	cmd.Flags().StringVar(&f.migration, "migration", "", "migration id (default: the only open one)")
	cmd.Flags().BoolVar(&f.asJSON, "json", false, "machine-readable output")
	addToolFlags(cmd, &f)
	return cmd
}

func printMigrationStatus(out io.Writer, st *service.Status) {
	fmt.Fprintln(out, noChange)
	fmt.Fprintf(out, "Migration %s: %s -> %s\nState: %s\nPlan hash: %s (source changes approved: %v)\n", st.MigrationID, st.Source, st.Target, st.State, st.PlanHash, st.Approved)
	if st.FailedStep != "" {
		fmt.Fprintf(out, "Failed at %s (resumable: %v): %s\n", st.FailedStep, st.FailedResumable, pfClean(st.FailedReason))
	}
	if st.Driver != "" {
		fmt.Fprintf(out, "Driven right now by: %s\n", st.Driver)
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "DATABASE\tATTEMPT\tCOPY\tSLOT\tRETAINED WAL\tLAG\tGUARDRAIL\tSUBSCRIPTION\tWORKER")
	for _, d := range st.Databases {
		slot := "-"
		if d.SlotExists {
			slot = d.Slot
			if d.SlotActive {
				slot += " (active)"
			}
		}
		sub := "none"
		if d.SubExists {
			sub = "disabled"
			if d.SubEnabled {
				sub = "enabled"
			}
		}
		fmt.Fprintf(tw, "%s\t%d\t%v\t%s\t%s\t%s\t%s\t%s\t%v\n", pfClean(d.Database), d.Attempt, d.CopyDone, slot,
			rules.FormatBytes(float64(d.RetainedBytes)), rules.FormatBytes(float64(d.LagBytes)), d.Guardrail, sub, d.WorkerRunning)
	}
	_ = tw.Flush()
	for _, d := range st.Databases {
		if d.Error != "" {
			fmt.Fprintf(out, "warning: %s: %s\n", pfClean(d.Database), pfClean(d.Error))
		}
	}
	for _, w := range st.Warnings {
		fmt.Fprintln(out, "WARNING:", pfClean(w))
	}
	if len(st.LastEvents) > 0 {
		fmt.Fprintln(out, "Recent events:")
		for _, e := range st.LastEvents {
			fmt.Fprintln(out, "  "+pfClean(e))
		}
	}
}

func (a *app) migrateEndCmd(name string) *cobra.Command {
	var f migrateFlags
	use, short, long := "", "", ""
	switch name {
	case "abort":
		use = "abort [--migration ID] [--apply --plan-hash H]"
		short = "Stop consuming changes; leaves the source's slot and publication in place (dry run by default)"
		long = `Disables the subscriptions on the target and marks the migration aborted.
THIS CHANGES THE TARGET (our subscriptions) and leaves the SOURCE untouched: the
replication slots and publications stay, and the source keeps retaining WAL for
them until you run ` + "`migrate cleanup`" + `. An aborted migration cannot be resumed.

Without --apply this is a dry run showing the plan and its hash. With --apply it
needs --plan-hash (the hash of this abort plan) or a typed confirmation. It
refuses while ` + "`migrate start`/`resume`" + ` is running.`
	default:
		use = "cleanup [--migration ID] [--apply --plan-hash H]"
		short = "Drop exactly what the migration created: subscriptions, slots, publications, role (dry run by default)"
		long = changesSource + ` AND THE TARGET: it drops this migration's subscriptions
(target), replication slots, publications and role (source), each only if it
carries this migration's name and marker. Other slots and publications are never
touched; no user data is deleted or modified.

It is only allowed after ` + "`migrate abort`" + `. Dropping the slot ends the migration for
good, so it needs --plan-hash (the hash of this cleanup plan, which states the
consequences) or a typed confirmation.`
	}
	cmd := &cobra.Command{
		Use: use, Short: short, Long: long, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, err := a.migrateService(cmd)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			out := cmd.OutOrStdout()
			o := service.EndOptions{MigrationID: f.migration, Apply: f.apply, Approver: a.approver(cmd, f.planHash), Tools: f.tools(a)}
			var res *service.EndResult
			if name == "abort" {
				res, err = svc.AbortMigration(ctx, o)
			} else {
				res, err = svc.CleanupMigration(ctx, o)
			}
			if res == nil {
				return err
			}
			if !f.apply {
				fmt.Fprintln(out, "DRY RUN: "+noChange)
				fmt.Fprintln(out, res.Plan.Summary())
				fmt.Fprintf(out, "\nTo apply: lockkeeper migrate %s --migration %s --apply --plan-hash %s\n", name, res.MigrationID, res.Plan.Hash())
				return err
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "Migration %s is now %s.\n", res.MigrationID, res.State)
			if name == "abort" {
				fmt.Fprintln(out, "The source's replication slots and publications were left in place; they still retain WAL. Run `lockkeeper migrate cleanup` when you are done with them.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&f.migration, "migration", "", "migration id (default: the only open one)")
	cmd.Flags().StringVar(&f.planHash, "plan-hash", "", "hash of THIS command's plan (the confirmation)")
	cmd.Flags().BoolVar(&f.apply, "apply", false, "execute (default: dry run)")
	addToolFlags(cmd, &f)
	return cmd
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	mult := int64(1)
	for suffix, m := range map[string]int64{"KIB": 1 << 10, "MIB": 1 << 20, "GIB": 1 << 30, "KB": 1 << 10, "MB": 1 << 20, "GB": 1 << 30} {
		if strings.HasSuffix(s, suffix) {
			mult, s = m, strings.TrimSuffix(s, suffix)
			break
		}
	}
	var n int64
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n); err != nil || n <= 0 {
		return 0, fmt.Errorf("want a size such as 4MiB, got %q", s)
	}
	return n * mult, nil
}
