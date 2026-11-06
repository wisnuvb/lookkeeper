package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"sort"
	"strconv"
	"strings"

	"github.com/wisnuvb/lockkeeper/internal/action"
	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/migrate/machine"
	"github.com/wisnuvb/lockkeeper/internal/migrate/pgnative"
	"github.com/wisnuvb/lockkeeper/internal/preflight"
	"github.com/wisnuvb/lockkeeper/internal/store"
)

// actor names the operator in the audit log: user@host.
func actor() string {
	name := "unknown"
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "localhost"
	}
	return name + "@" + host
}

func portOrDefault(p int) int {
	if p == 0 {
		return 5432
	}
	return p
}

func sideOf(name string, db config.Database, version string, major int) pgnative.Side {
	return pgnative.Side{Name: name, Host: db.Host, Port: portOrDefault(db.Port), User: db.User, Database: db.Database, TLSMode: tlsMode(db), Version: version, Major: major}
}

// peerFor decides how the target server reaches the source and refuses a
// connection that would not authenticate the source.
func peerFor(opts MigrateOptions, src config.Database) (pgnative.Peer, error) {
	p := pgnative.Peer{Host: src.Host, Port: portOrDefault(src.Port), SSLMode: opts.PeerSSLMode, SSLRootCert: opts.PeerSSLRootCert}
	if opts.PeerAddr != "" {
		host, port, err := net.SplitHostPort(opts.PeerAddr)
		if err != nil {
			return p, fmt.Errorf("--source-peer-addr %q: want host:port", opts.PeerAddr)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n <= 0 || n > 65535 {
			return p, fmt.Errorf("--source-peer-addr %q: bad port", opts.PeerAddr)
		}
		p.Host, p.Port = host, n
	}
	if p.SSLMode == "" {
		p.SSLMode = tlsMode(src)
	}
	if !config.IsLocalHost(p.Host) && (p.SSLMode == config.TLSDisable || p.SSLMode == config.TLSRequire) && !src.TLS.AllowInsecure {
		return p, fmt.Errorf("the target would connect to the source at %s:%d with sslmode=%s, which does not authenticate the server (or uses no TLS): use verify-full or verify-ca (with --source-peer-sslrootcert, the CA file path on the TARGET server), or set tls.allow_insecure on the source connection to accept the risk", p.Host, p.Port, p.SSLMode)
	}
	return p, nil
}

// discoverInput runs the pre-flight, reads what the plan needs from both servers
// (read-only) and checks that the connected roles can do the job. Any BLOCKER
// finding or missing privilege is returned as an error before anything changes.
func (s *Service) discoverInput(ctx context.Context, opts MigrateOptions, tools ToolOptions) (pgnative.PlanInput, *preflight.Report, error) {
	var in pgnative.PlanInput
	rep, err := s.PreflightPG(ctx, opts.Source, opts.Target, DiscoveryOptions{Databases: opts.Databases, MaxDatabases: opts.MaxDatabases})
	if err != nil {
		return in, nil, err
	}
	if rep.Summary.Blocker > 0 {
		return in, rep, &BlockedError{Report: rep}
	}
	dbs := append([]string(nil), rep.Databases...)
	sort.Strings(dbs)
	if len(dbs) == 0 {
		return in, rep, errors.New("no database to migrate")
	}
	srcCfg, tgtCfg := s.cfg.Databases[opts.Source], s.cfg.Databases[opts.Target]
	peer, err := peerFor(opts, srcCfg)
	if err != nil {
		return in, rep, err
	}

	src, err := s.openInventoryDB(ctx, opts.Source, "")
	if err != nil {
		return in, rep, fmt.Errorf("connect to the source %s: %w", opts.Source, err)
	}
	defer pfCloseConn(src)
	sf, err := pgnative.DiscoverSource(ctx, src)
	if err != nil {
		return in, rep, s.redactErr(err)
	}
	tgt, err := s.openInventoryDB(ctx, opts.Target, "")
	if err != nil {
		return in, rep, fmt.Errorf("connect to the target %s: %w", opts.Target, err)
	}
	defer pfCloseConn(tgt)
	tf, err := pgnative.DiscoverTarget(ctx, tgt)
	if err != nil {
		return in, rep, s.redactErr(err)
	}

	var facts []pgnative.DBFacts
	var problems []string
	for _, d := range dbs {
		df, err := s.discoverDB(ctx, opts.Source, d)
		if err != nil {
			return in, rep, err
		}
		facts = append(facts, df)
		tc, err := s.openInventoryDB(ctx, opts.Target, d)
		if err != nil {
			problems = append(problems, fmt.Sprintf("cannot connect to database %q on the target %s (does it exist? create it first, empty: CREATE DATABASE %s): %v", d, opts.Target, strings.ReplaceAll(d, `"`, `""`), s.redactErr(err)))
			continue
		}
		n, uerr := pgnative.UserTables(ctx, tc)
		pfCloseConn(tc)
		if uerr != nil {
			return in, rep, s.redactErr(uerr)
		}
		if n > 0 {
			problems = append(problems, fmt.Sprintf("target database %q already has %d user table(s): a migration needs an empty database", d, n))
		}
	}
	problems = append(problems, pgnative.CheckSource(sf, facts)...)
	problems = append(problems, pgnative.CheckTarget(tf, sf, dbs)...)
	if len(problems) > 0 {
		return in, rep, &PrivilegeError{Problems: problems}
	}

	cp, err := s.newCopier(opts.Copier, nil, tools)
	if err != nil {
		return in, rep, err
	}
	tj, ij := opts.TableJobs, opts.IndexJobs
	if tj <= 0 {
		tj = 4
	}
	if ij <= 0 {
		ij = 4
	}
	in = pgnative.PlanInput{
		LockkeeperVersion: s.deps.Version,
		Source:            sideOf(opts.Source, srcCfg, sf.Version, sf.Major),
		Target:            sideOf(opts.Target, tgtCfg, tf.Version, tf.Major),
		SourceFacts:       sf, TargetFacts: tf, SourceIsRDS: sf.RDSSuperuser || sf.RDSReplicate,
		Peer: peer, DBs: facts, Copier: cp, CopierKind: cp.Name(), TableJobs: tj, IndexJobs: ij, NoOwner: opts.NoOwner,
	}
	return in, rep, nil
}

func (s *Service) discoverDB(ctx context.Context, source, database string) (pgnative.DBFacts, error) {
	c, err := s.openInventoryDB(ctx, source, database)
	if err != nil {
		return pgnative.DBFacts{}, fmt.Errorf("connect to source database %s: %w", database, err)
	}
	defer pfCloseConn(c)
	f, err := pgnative.DiscoverDatabase(ctx, c, database)
	if err != nil {
		return f, s.redactErr(err)
	}
	return f, nil
}

// finishInput attaches what cannot be stored: the Copier and the password file.
func (s *Service) finishInput(in *pgnative.PlanInput, id string, tools ToolOptions) error {
	root, err := s.migrationsRoot()
	if err != nil {
		return err
	}
	r, err := s.newToolRunner(id, tools)
	if err != nil {
		return err
	}
	cp, err := s.newCopier(in.CopierKind, r, tools)
	if err != nil {
		return err
	}
	in.Copier = cp
	in.Password = pgnative.PasswordFileFor(root, id)
	return nil
}

// PlanMigration creates the migration plan (and a local draft record). It
// changes nothing on the source or the target: it reads, runs the pre-flight,
// refuses on BLOCKER findings and missing privileges, and prints what would be
// done. Planning the same thing twice gives the same plan hash.
func (s *Service) PlanMigration(ctx context.Context, opts MigrateOptions, tools ToolOptions) (*PlanResult, error) {
	in, rep, err := s.discoverInput(ctx, opts, tools)
	if err != nil {
		return &PlanResult{Report: rep}, err
	}
	plan, err := pgnative.BuildPlan(in)
	if err != nil {
		return nil, err
	}
	if err := s.finishInput(&in, plan.MigrationID, tools); err != nil {
		return nil, err
	}
	// Rebuild with the final input (same result; the password file only matters at apply).
	if plan, err = pgnative.BuildPlan(in); err != nil {
		return nil, err
	}
	inputJSON, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	st, err := s.openState(ctx)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	now := s.deps.Now()
	m, created, err := st.CreateMigration(ctx, store.Migration{
		ID: plan.MigrationID, SourceName: opts.Source, TargetName: opts.Target, Databases: plan.Databases,
		PlanHash: plan.Hash(), PlanJSON: string(plan.DisplayJSON()), InputJSON: string(inputJSON),
	}, now)
	if err != nil {
		return nil, err
	}
	res := &PlanResult{MigrationID: m.ID, State: m.State, Plan: plan, Report: rep, Existing: !created}
	if created {
		ss := machine.SQLStore{DB: st, Actor: actor(), Now: s.deps.Now}
		_ = ss.Audit(ctx, m.ID, "plan.created", fmt.Sprintf("plan %s: source %s -> target %s, databases %s", plan.Hash(), opts.Source, opts.Target, strings.Join(plan.Databases, ", ")))
		if err := machine.Move(ctx, ss, m.ID, machine.PreflightOK, "pre-flight has no blockers", machine.Facts{PreflightBlockers: rep.Summary.Blocker}); err != nil {
			return res, err
		}
		res.State = string(machine.PreflightOK)
	}
	return res, nil
}

// loaded is a migration with its stored plan input and rebuilt plan.
type loaded struct {
	m     store.Migration
	in    pgnative.PlanInput
	plan  *action.Plan
	state machine.State
}

// findMigration resolves a plan hash or a migration id.
func findMigration(ctx context.Context, st *store.Store, planHash, id string) (store.Migration, error) {
	switch {
	case planHash != "":
		return st.FindMigrationByPlanHash(ctx, strings.ToLower(strings.TrimSpace(planHash)))
	case id != "":
		return st.GetMigration(ctx, id)
	default:
		all, err := st.ListMigrations(ctx)
		if err != nil {
			return store.Migration{}, err
		}
		var open []store.Migration
		for _, m := range all {
			if machine.State(m.State) != machine.Cleaned && machine.State(m.State) != machine.Aborted {
				open = append(open, m)
			}
		}
		if len(open) == 1 {
			return open[0], nil
		}
		return store.Migration{}, fmt.Errorf("%d migrations are open: say which one with --migration ID or --plan-hash", len(open))
	}
}

// loadMigration restores the plan input of a stored migration, rebuilds its plan
// and proves it still hashes to the stored hash (the state database was not
// altered).
func (s *Service) loadMigration(ctx context.Context, st *store.Store, m store.Migration, tools ToolOptions) (*loaded, error) {
	var in pgnative.PlanInput
	if err := json.Unmarshal([]byte(m.InputJSON), &in); err != nil {
		return nil, fmt.Errorf("the stored plan input of %s is unreadable: %w", m.ID, err)
	}
	if err := s.finishInput(&in, m.ID, tools); err != nil {
		return nil, err
	}
	plan, err := pgnative.BuildPlan(in)
	if err != nil {
		return nil, err
	}
	if plan.Hash() != m.PlanHash || plan.MigrationID != m.ID {
		return nil, fmt.Errorf("the stored plan of %s no longer matches its hash (%s): the state database or this Lockkeeper version changed; refusing to continue", m.ID, m.PlanHash[:12])
	}
	return &loaded{m: m, in: in, plan: plan, state: machine.State(m.State)}, nil
}

// driftCheck compares the live source with the plan: the tables that are
// published must still be exactly the tables that exist, and every table that
// needed REPLICA IDENTITY FULL must have it. Anything else means the schema
// changed after approval, and a new or dropped table would be copied but not
// replicated (or replicated wrongly).
//
// preApply is true before the source changes were applied: tables that need
// REPLICA IDENTITY FULL are then expected, but only the planned ones.
func (s *Service) driftCheck(ctx context.Context, l *loaded, preApply bool) error {
	var problems []string
	for _, d := range l.in.DBs {
		live, err := s.discoverDB(ctx, l.in.Source.Name, d.Database)
		if err != nil {
			return err
		}
		want, have := tableSet(d.Publish), tableSet(live.Publish)
		for t := range have {
			if !want[t] {
				problems = append(problems, fmt.Sprintf("database %s: table %s was created after the plan and is not in the publication", d.Database, t))
			}
		}
		for t := range want {
			if !have[t] {
				problems = append(problems, fmt.Sprintf("database %s: published table %s no longer exists", d.Database, t))
			}
		}
		if preApply {
			planned := tableSet(d.NeedFull)
			for _, t := range live.NeedFull {
				if !planned[t.String()] {
					problems = append(problems, fmt.Sprintf("database %s: table %s needs REPLICA IDENTITY FULL but the plan does not set it", d.Database, t))
				}
			}
		} else if len(live.NeedFull) > 0 {
			problems = append(problems, fmt.Sprintf("database %s: %d table(s) cannot identify rows for updates and deletes (REPLICA IDENTITY changed after the plan)", d.Database, len(live.NeedFull)))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("the source schema changed after the plan was approved (schema freeze was not respected); nothing was changed. Abort and clean up this migration, then plan again:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

func tableSet(ts []pgnative.Table) map[string]bool {
	m := make(map[string]bool, len(ts))
	for _, t := range ts {
		m[t.String()] = true
	}
	return m
}
