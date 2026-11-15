package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/wisnuvb/lockkeeper/internal/action"
	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/dbconn"
	"github.com/wisnuvb/lockkeeper/internal/migrate"
	"github.com/wisnuvb/lockkeeper/internal/migrate/copier"
	"github.com/wisnuvb/lockkeeper/internal/migrate/pgnative"
	toolrunner "github.com/wisnuvb/lockkeeper/internal/migrate/runner"
	"github.com/wisnuvb/lockkeeper/internal/secret"
	"github.com/wisnuvb/lockkeeper/internal/store"
)

// migrationStatementTimeout bounds one statement of a migration action.
const migrationStatementTimeout = 5 * time.Minute

// migrationLockTimeout bounds how long an action waits for a lock held by the
// application.
const migrationLockTimeout = 10 * time.Second

// stateDir is the directory of the state database; migrations keep their files
// below it.
func (s *Service) stateDir() (string, error) {
	p, err := s.StorePath()
	if err != nil {
		return "", err
	}
	return filepath.Dir(p), nil
}

// migrationDir is the private directory of one migration (0700): lock file,
// generated role password, tool work directories, tool logs.
func (s *Service) migrationDir(id string) (string, error) {
	d, err := s.stateDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(d, "migrations", id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}
	return dir, nil
}

func (s *Service) migrationsRoot() (string, error) {
	d, err := s.stateDir()
	if err != nil {
		return "", err
	}
	root := filepath.Join(d, "migrations")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	return root, nil
}

func (s *Service) openState(ctx context.Context) (*store.Store, error) {
	path, err := s.StorePath()
	if err != nil {
		return nil, err
	}
	return store.Open(ctx, path)
}

// migrateConns implements pgnative.Conns over the configured connections.
type migrateConns struct {
	s        *Service
	srcName  string
	tgtName  string
	src, tgt config.Database
	srcPW    secret.Value
	tgtPW    secret.Value
}

func (s *Service) newMigrateConns(ctx context.Context, source, target string) (*migrateConns, error) {
	srcDB, ok := s.cfg.Databases[source]
	if !ok {
		return nil, fmt.Errorf("unknown database %q", source)
	}
	tgtDB, ok := s.cfg.Databases[target]
	if !ok {
		return nil, fmt.Errorf("unknown database %q", target)
	}
	spw, err := s.resolveSecret(ctx, srcDB.Password, "password for "+source)
	if err != nil {
		return nil, err
	}
	tpw, err := s.resolveSecret(ctx, tgtDB.Password, "password for "+target)
	if err != nil {
		return nil, err
	}
	return &migrateConns{s: s, srcName: source, tgtName: target, src: srcDB, tgt: tgtDB, srcPW: spw, tgtPW: tpw}, nil
}

func (c *migrateConns) spec(db config.Database, pw secret.Value, database string) dbconn.PGSpec {
	spec := dbconn.SpecFromConfig(db, pw, migrationStatementTimeout)
	if database != "" {
		spec.Database = database
	}
	return spec
}

func (c *migrateConns) Source(ctx context.Context, database string) (*pgx.Conn, error) {
	conn, err := dbconn.OpenPGWrite(ctx, c.spec(c.src, c.srcPW, database), migrationLockTimeout)
	if err != nil {
		return nil, c.s.redactErr(err)
	}
	return conn, nil
}

func (c *migrateConns) SourceRepl(ctx context.Context, database string) (*pgconn.PgConn, error) {
	conn, err := dbconn.OpenReplication(ctx, c.spec(c.src, c.srcPW, database))
	if err != nil {
		return nil, c.s.redactErr(err)
	}
	return conn, nil
}

func (c *migrateConns) Target(ctx context.Context, database string) (*pgx.Conn, error) {
	conn, err := dbconn.OpenPGWrite(ctx, c.spec(c.tgt, c.tgtPW, database), migrationLockTimeout)
	if err != nil {
		return nil, c.s.redactErr(err)
	}
	return conn, nil
}

func tlsMode(db config.Database) string {
	if db.TLS.Mode == "" {
		return config.TLSVerifyFull
	}
	return db.TLS.Mode
}

func endpointOf(name string, db config.Database, pw secret.Value, database string) migrate.Endpoint {
	port := db.Port
	if port == 0 {
		port = 5432
	}
	return migrate.Endpoint{Name: name, Host: db.Host, Port: port, Database: database, User: db.User, Password: pw, TLSMode: tlsMode(db), CAFile: db.TLS.CAFile}
}

func (c *migrateConns) SourceEndpoint(database string) migrate.Endpoint {
	return endpointOf(c.srcName, c.src, c.srcPW, database)
}

func (c *migrateConns) TargetEndpoint(database string) migrate.Endpoint {
	return endpointOf(c.tgtName, c.tgt, c.tgtPW, database)
}

var _ pgnative.Conns = (*migrateConns)(nil)

// actionConns opens the connection an action needs, by the role and database of
// its endpoint (the connection is the operator's configured one; the plan only
// names the database).
func (c *migrateConns) actionConns() action.ConnFunc {
	return func(ctx context.Context, e action.Endpoint) (action.Conn, func(), error) {
		var conn *pgx.Conn
		var err error
		switch e.Role {
		case "source":
			conn, err = c.Source(ctx, e.Database)
		case "target":
			conn, err = c.Target(ctx, e.Database)
		default:
			return nil, nil, fmt.Errorf("unknown endpoint role %q", e.Role)
		}
		if err != nil {
			return nil, nil, err
		}
		return conn, func() {
			cctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = conn.Close(cctx)
		}, nil
	}
}

// newToolRunner builds the runner for a migration's tools.
func (s *Service) newToolRunner(id string, t ToolOptions) (*toolrunner.Runner, error) {
	dir, err := s.stateDir()
	if err != nil {
		return nil, err
	}
	mdir, err := s.migrationDir(id)
	if err != nil {
		return nil, err
	}
	path := t.ToolPath
	if path == "" {
		path = "/usr/local/bin:/usr/bin:/bin"
	}
	if t.ClientBinDir != "" {
		path = t.ClientBinDir + string(os.PathListSeparator) + path
	}
	return &toolrunner.Runner{
		BaseDir: filepath.Join(dir, "run"), LogDir: filepath.Join(mdir, "logs"),
		Launcher: s.deps.Launcher, Redactor: s.deps.Redactor, Grace: 15 * time.Second, Path: path,
	}, nil
}

// newCopier builds the Copier of a kind. A nil runner is allowed for planning,
// which only needs Name and Describe.
func (s *Service) newCopier(kind string, r *toolrunner.Runner, t ToolOptions) (migrate.Copier, error) {
	if kind == "" {
		kind = copier.KindPgcopydb
	}
	if r == nil {
		r = &toolrunner.Runner{}
	}
	pin := t.PinnedPgcopydb
	if pin == "" {
		pin = PinnedPgcopydbVersion
	}
	return copier.New(copier.Config{
		Kind: kind, Runner: r, Pgcopydb: t.Pgcopydb, PgDump: t.PgDump, PgRestore: t.PgRestore,
		PinnedVersion: pin, AllowUntested: t.AllowUntestedPgcopydb,
	})
}
