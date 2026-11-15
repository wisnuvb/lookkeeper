// Package cli defines the lockkeeper command line. It parses flags and formats
// output; every behaviour lives in the service layer.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"

	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/migrate/runner"
	"github.com/wisnuvb/lockkeeper/internal/redact"
	"github.com/wisnuvb/lockkeeper/internal/secret"
	"github.com/wisnuvb/lockkeeper/internal/service"
)

// Version is set at build time with -ldflags "-X .../internal/cli.Version=...".
var Version = "dev"

// ExitError carries a specific process exit code.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit status %d", e.Code)
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error { return e.Err }

// Env holds the process-level inputs of the CLI, injectable for tests.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) (string, bool)
	// Prompt reads a secret interactively; nil when no terminal is available.
	Prompt func(label string) (string, error)
	// Deps lets tests substitute service dependencies. It receives the defaults.
	Deps func(service.Deps) service.Deps
}

// OSEnv returns the real process environment.
func OSEnv() Env {
	return Env{
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		Getenv: os.LookupEnv,
		Prompt: terminalPrompt(os.Stderr),
	}
}

// commandFactories lets a feature register its commands from its own file
// (in an init function) instead of editing newRoot, which keeps parallel work
// from colliding.
var commandFactories []func(*app) *cobra.Command

type app struct {
	env        Env
	configPath string
	logFormat  string
	logLevel   string
	redactor   *redact.Redactor
}

// Execute runs the CLI and returns the process exit code.
func Execute(ctx context.Context, env Env, args []string) int {
	root := newRoot(env)
	root.SetArgs(args)
	root.SetOut(env.Stdout)
	root.SetErr(env.Stderr)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		if ee.Err != nil {
			fmt.Fprintln(env.Stderr, "Error:", ee.Err)
			printToolTail(env.Stderr, ee.Err)
		}
		return ee.Code
	}
	fmt.Fprintln(env.Stderr, "Error:", err)
	printToolTail(env.Stderr, err)
	return 1
}

// printToolTail shows the last lines of a failed tool's output on the terminal
// only. The error value (which is stored in the audit log and the state
// database) deliberately does not carry them; lines that can quote table rows
// are already removed from the tail.
func printToolTail(w io.Writer, err error) {
	var te *runner.ToolError
	if errors.As(err, &te) && te.Tail() != "" {
		fmt.Fprintf(w, "Last output of %s (shown here only, not stored; the full log is %s): %s\n", te.Tool, te.LogPath, te.Tail())
	}
}

func newRoot(env Env) *cobra.Command {
	a := &app{env: env, redactor: redact.New()}
	root := &cobra.Command{
		Use:   "lockkeeper",
		Short: "Monitor PostgreSQL health and (soon) migrate databases safely",
		Long: `Lockkeeper watches database health and alerts you, and is designed to move
databases between servers with minimal downtime.

It is read-only by default: no command here changes a monitored database.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVarP(&a.configPath, "config", "c", "", "config file (default: $LOCKKEEPER_CONFIG, then ./lockkeeper.yaml)")
	root.PersistentFlags().StringVar(&a.logFormat, "log-format", "text", "log format: text or json")
	root.PersistentFlags().StringVar(&a.logLevel, "log-level", "info", "log level: debug, info, warn or error")

	root.AddCommand(a.versionCmd(), a.initCmd(), a.configCmd(), a.checkCmd(), a.monitorCmd(), a.alertsCmd(), a.slotsCmd())
	for _, f := range commandFactories {
		root.AddCommand(f(a))
	}
	return root
}

func (a *app) resolveConfigPath() string {
	if a.configPath != "" {
		return a.configPath
	}
	if v, ok := a.env.Getenv("LOCKKEEPER_CONFIG"); ok && v != "" {
		return v
	}
	return "lockkeeper.yaml"
}

func (a *app) loadConfig() (*config.Config, []string, error) {
	path := a.resolveConfigPath()
	cfg, warnings, err := config.Load(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("config file %s not found; create one with: lockkeeper init", path)
		}
		return nil, warnings, err
	}
	return cfg, warnings, nil
}

func (a *app) logger() (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(a.logLevel)); err != nil {
		return nil, fmt.Errorf("invalid --log-level %q", a.logLevel)
	}
	w := a.redactor.Writer(a.env.Stderr)
	opts := &slog.HandlerOptions{Level: level}
	switch a.logFormat {
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("invalid --log-format %q (use text or json)", a.logFormat)
	}
}

func (a *app) newService(cfg *config.Config) (*service.Service, error) {
	log, err := a.logger()
	if err != nil {
		return nil, err
	}
	deps := service.Deps{
		Secrets:  secret.Resolver{Getenv: a.env.Getenv, ReadFile: os.ReadFile, Stat: os.Stat, Prompt: a.env.Prompt},
		Log:      log,
		Redactor: a.redactor,
		Version:  Version,
	}
	if a.env.Deps != nil {
		deps = a.env.Deps(deps)
	}
	return service.New(cfg, deps)
}

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := Version
			if v == "dev" {
				if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
					v = bi.Main.Version
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "lockkeeper %s (%s, %s/%s)\n", v, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}
}

// oneLine collapses whitespace for compact table cells.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
