// Package service is Lockkeeper's use-case layer. The CLI (and later the web
// API) are thin front ends over it; authorisation and safety rules belong here,
// never in a front end.
package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/wisnuvb/lockkeeper/internal/alert/notify"
	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/collector"
	"github.com/wisnuvb/lockkeeper/internal/collector/pg"
	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/dbconn"
	"github.com/wisnuvb/lockkeeper/internal/redact"
	"github.com/wisnuvb/lockkeeper/internal/secret"
)

// Deps are the injected side effects. Zero values select production defaults.
type Deps struct {
	Secrets  secret.Resolver
	Log      *slog.Logger
	Redactor *redact.Redactor
	Now      func() time.Time
	HTTP     notify.HTTPDoer
	// OpenPG opens a Postgres connection (default dbconn.OpenPG).
	OpenPG func(ctx context.Context, spec dbconn.PGSpec) (*pgx.Conn, error)
	// OpenMySQL opens a MySQL connection pool (default dbconn.OpenMySQL).
	OpenMySQL func(ctx context.Context, spec dbconn.MySQLSpec) (*sql.DB, error)
	// NewCollector overrides collector construction (tests).
	NewCollector func(target string) collector.Collector
	// RetrySleep overrides retry backoff sleeping (tests).
	RetrySleep func(context.Context, time.Duration) error
	// TelegramBaseURL overrides the Telegram API endpoint (tests).
	TelegramBaseURL string
}

// Service implements Lockkeeper's use cases.
type Service struct {
	cfg  *config.Config
	deps Deps
	log  *slog.Logger

	rules []rules.Rule

	mu          sync.Mutex
	promptCache map[string]secret.Value
}

// New builds a Service from a validated configuration.
func New(cfg *config.Config, deps Deps) (*Service, error) {
	if deps.Log == nil {
		deps.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if deps.Redactor == nil {
		deps.Redactor = redact.New()
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.HTTP == nil {
		deps.HTTP = notify.NewHTTPClient()
	}
	if deps.OpenPG == nil {
		deps.OpenPG = dbconn.OpenPG
	}
	if deps.OpenMySQL == nil {
		deps.OpenMySQL = dbconn.OpenMySQL
	}
	rs, err := rules.ApplyOverrides(rules.Defaults(), cfg.Alerts.Rules)
	if err != nil {
		return nil, err
	}
	return &Service{cfg: cfg, deps: deps, log: deps.Log, rules: rs, promptCache: map[string]secret.Value{}}, nil
}

// Config returns the configuration the service was built with.
func (s *Service) Config() *config.Config { return s.cfg }

// Rules returns the effective alert rules (defaults plus overrides).
func (s *Service) Rules() []rules.Rule { return s.rules }

// StorePath returns the state database path with "~" expanded.
func (s *Service) StorePath() (string, error) { return ExpandHome(s.cfg.Store.Path) }

// ExpandHome expands a leading "~/" to the user's home directory.
func ExpandHome(p string) (string, error) {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		return filepath.Join(home, strings.TrimPrefix(p, "~")), nil
	}
	return p, nil
}

// resolveSecret resolves a reference, registers the value with the redactor, and
// caches interactive prompts so a reconnect does not ask again. Env and file
// secrets are re-read each time, which allows credential rotation without a restart.
func (s *Service) resolveSecret(ctx context.Context, ref secret.Ref, label string) (secret.Value, error) {
	if ref.Prompt {
		s.mu.Lock()
		v, ok := s.promptCache[label]
		s.mu.Unlock()
		if ok {
			return v, nil
		}
	}
	v, err := s.deps.Secrets.Resolve(ctx, ref, label)
	if err != nil {
		return secret.Value{}, err
	}
	s.deps.Redactor.Add(v.Reveal())
	if ref.Prompt {
		s.mu.Lock()
		s.promptCache[label] = v
		s.mu.Unlock()
	}
	return v, nil
}

// openFunc returns a pg.OpenFunc for a configured database. Errors are redacted.
func (s *Service) openFunc(name string) pg.OpenFunc {
	return func(ctx context.Context) (*pgx.Conn, error) {
		db, ok := s.cfg.Databases[name]
		if !ok {
			return nil, fmt.Errorf("unknown database %q", name)
		}
		pw, err := s.resolveSecret(ctx, db.Password, "password for "+name)
		if err != nil {
			return nil, err
		}
		spec := dbconn.SpecFromConfig(db, pw, s.cfg.Monitor.QueryTimeout.D())
		conn, err := s.deps.OpenPG(ctx, spec)
		if err != nil {
			return nil, s.deps.Redactor.Error(err)
		}
		return conn, nil
	}
}

// newCollector builds the collector for a target: the engine collector plus any
// extra collectors (for example cloud metrics), merged into one.
func (s *Service) newCollector(target string) collector.Collector {
	if s.deps.NewCollector != nil {
		return s.deps.NewCollector(target)
	}
	db := s.cfg.Databases[target]
	members := []collector.Collector{s.newEngineCollector(target, db)}
	members = append(members, s.extraCollectors(target, db)...)
	return collector.NewGroup(target, members...)
}

// redactErr scrubs secrets from an error before it is logged or shown.
func (s *Service) redactErr(err error) error { return s.deps.Redactor.Error(err) }

// validateTargets checks names against the configuration.
func (s *Service) validateTargets(targets []string) error {
	var errs []error
	for _, t := range targets {
		if _, ok := s.cfg.Databases[t]; !ok {
			errs = append(errs, fmt.Errorf("unknown database %q (configured: %s)", t, strings.Join(s.databaseNames(), ", ")))
		}
	}
	return errors.Join(errs...)
}

func (s *Service) databaseNames() []string {
	out := make([]string, 0, len(s.cfg.Databases))
	for n := range s.cfg.Databases {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// engineOptions maps alert settings to rule-engine options.
func (s *Service) engineOptions() rules.Options {
	return rules.Options{RepeatInterval: s.cfg.Alerts.RepeatInterval.D(), Cooldown: s.cfg.Alerts.Cooldown.D()}
}

// httpClient is the shared HTTP client for notifiers.
func (s *Service) httpClient() notify.HTTPDoer { return s.deps.HTTP }
