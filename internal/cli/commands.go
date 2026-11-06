package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/service"
)

func (a *app) initCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write an example configuration file (contains no secrets)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if path == "" {
				path = a.resolveConfigPath()
			}
			// O_EXCL: never overwrite an existing config.
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				if errors.Is(err, os.ErrExist) {
					return fmt.Errorf("%s already exists; refusing to overwrite it", path)
				}
				return fmt.Errorf("create %s: %w", path, err)
			}
			if _, err := f.WriteString(ExampleConfig); err != nil {
				_ = f.Close()
				return fmt.Errorf("write %s: %w", path, err)
			}
			if err := f.Close(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s (mode 600).\nNext: edit it, export the secrets it references, then run: lockkeeper config validate\n", path)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "where to write the file (default: the --config path)")
	return cmd
}

func (a *app) configCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Work with the configuration file"}
	cmd.AddCommand(&cobra.Command{
		Use:   "validate",
		Short: "Validate the configuration and check that referenced secrets are available",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
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
			sc := svc.VerifySecrets(cmd.Context())
			for _, p := range sc.Prompts {
				fmt.Fprintf(out, "note: %s will be requested interactively at run time\n", p)
			}
			if len(sc.Problems) > 0 {
				for _, p := range sc.Problems {
					fmt.Fprintln(cmd.ErrOrStderr(), "secret problem:", p)
				}
				return fmt.Errorf("%d referenced secret(s) are not available", len(sc.Problems))
			}
			fmt.Fprintf(out, "Configuration OK: %d database(s), monitoring %s, %d channel(s) (%s), %d alert rules.\n",
				len(cfg.Databases), strings.Join(cfg.Monitor.Targets, ", "), len(cfg.ChannelNames()),
				strings.Join(cfg.ChannelNames(), ", "), len(svc.Rules()))
			return nil
		},
	})
	return cmd
}

func (a *app) checkCmd() *cobra.Command {
	var targets []string
	var asJSON, withSamples bool
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Collect metrics once and report problems (exit 0 ok, 2 warning, 3 critical)",
		Long: `Connects to each target once, reads its metrics and judges them against the
alert thresholds. A one-shot check has no history, so the "for" durations of
the rules are ignored: it reports what is wrong right now.

Exit status: 0 healthy, 2 warnings, 3 critical findings, 1 operational error.`,
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
			ctx, cancel := context.WithTimeout(cmd.Context(), 90*time.Second)
			defer cancel()
			res, err := svc.Check(ctx, targets, withSamples)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(res); err != nil {
					return err
				}
			} else {
				printCheck(cmd, res)
			}
			if code := res.ExitCode(); code != 0 {
				return &ExitError{Code: code}
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVarP(&targets, "target", "t", nil, "database(s) to check (default: all monitor targets)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")
	cmd.Flags().BoolVar(&withSamples, "samples", false, "include the raw samples in --json output")
	return cmd
}

func printCheck(cmd *cobra.Command, res *service.CheckResult) {
	out := cmd.OutOrStdout()
	for _, t := range res.Targets {
		status := "ok"
		if !t.Up {
			status = "UNREACHABLE"
		} else if len(t.Findings) > 0 {
			status = strings.ToUpper(string(t.Findings[0].Severity))
		}
		fmt.Fprintf(out, "%s: %s\n", t.Name, status)
		if t.Error != "" {
			fmt.Fprintf(out, "  error: %s\n", oneLine(t.Error))
		}
		for _, f := range t.Findings {
			fmt.Fprintf(out, "  [%s] %s\n", f.Severity, f.Summary)
		}
		for _, w := range t.RoleWarnings {
			fmt.Fprintf(out, "  role: %s\n", w)
		}
	}
	fmt.Fprintf(out, "\nOverall: %s. (One-shot check: \"for\" durations are not applied.)\n", res.Severity)
	if len(res.Skipped) > 0 {
		fmt.Fprintf(out, "Not evaluated here (needs history; checked by `monitor run`): %s.\n", strings.Join(res.Skipped, ", "))
	}
}

func (a *app) monitorCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "monitor", Short: "Continuous monitoring"}
	cmd.AddCommand(&cobra.Command{
		Use:   "run",
		Short: "Collect, evaluate alert rules and send notifications until stopped",
		Long: `Runs in the foreground until it receives SIGINT or SIGTERM, then shuts down
gracefully: it saves alert state and flushes queued notifications.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, warnings, err := a.loadConfig()
			if err != nil {
				return err
			}
			svc, err := a.newService(cfg)
			if err != nil {
				return err
			}
			log, _ := a.logger()
			for _, w := range warnings {
				log.Warn(w)
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return svc.MonitorRun(ctx)
		},
	})
	return cmd
}

func (a *app) alertsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "alerts", Short: "Work with alert notifications"}
	var channel string
	test := &cobra.Command{
		Use:   "test",
		Short: "Send a test notification to verify tokens and chat IDs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, err := a.loadConfig()
			if err != nil {
				return err
			}
			svc, err := a.newService(cfg)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()
			results, err := svc.AlertsTest(ctx, channel)
			if err != nil {
				return err
			}
			failed := 0
			for _, r := range results {
				if r.Err != nil {
					failed++
					fmt.Fprintf(cmd.OutOrStdout(), "%s: FAILED: %v\n", r.Channel, r.Err)
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "%s: sent\n", r.Channel)
				}
			}
			if failed > 0 {
				return &ExitError{Code: 1, Err: fmt.Errorf("%d channel(s) failed", failed)}
			}
			return nil
		},
	}
	test.Flags().StringVar(&channel, "channel", "", "only this channel (default: all configured)")
	cmd.AddCommand(test)
	return cmd
}

func (a *app) slotsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "slots", Short: "Inspect replication slots (read-only)"}
	var target string
	var asJSON bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List replication slots and the WAL each one retains",
		Long: `Lists replication slots, largest retained WAL first. An inactive slot that
retains a lot of WAL can fill the server's disk: this is the first thing to
look at during a migration. This command only reads; it never drops a slot.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, err := a.loadConfig()
			if err != nil {
				return err
			}
			if target == "" {
				if len(cfg.Databases) != 1 {
					return fmt.Errorf("--target is required when more than one database is configured")
				}
				for name := range cfg.Databases {
					target = name
				}
			}
			svc, err := a.newService(cfg)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			slots, err := svc.SlotsList(ctx, target)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(slots)
			}
			if len(slots) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "No replication slots on %s.\n", target)
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "SLOT\tTYPE\tACTIVE\tRETAINED WAL\tPLUGIN\tDATABASE")
			for _, s := range slots {
				fmt.Fprintf(tw, "%s\t%s\t%v\t%s\t%s\t%s\n", s.Name, s.Type, s.Active, rules.FormatBytes(s.RetainedBytes), dash(s.Plugin), dash(s.Database))
			}
			return tw.Flush()
		},
	}
	list.Flags().StringVarP(&target, "target", "t", "", "database to inspect")
	list.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")
	cmd.AddCommand(list)
	return cmd
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
