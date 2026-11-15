package pgnative

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/wisnuvb/lockkeeper/internal/action"
	"github.com/wisnuvb/lockkeeper/internal/migrate"
	"github.com/wisnuvb/lockkeeper/internal/migrate/machine"
)

// Conns opens the connections the engine needs. Sessions to the source and the
// target are read-write (the actions in the approved plan are the only thing
// that changes anything); the replication session is for the snapshot only.
type Conns interface {
	Source(ctx context.Context, database string) (*pgx.Conn, error)
	SourceRepl(ctx context.Context, database string) (*pgconn.PgConn, error)
	Target(ctx context.Context, database string) (*pgx.Conn, error)
	// SourceEndpoint and TargetEndpoint are the databases as the bulk-copy tool
	// must reach them (the peer address, with the credentials for the passfile).
	SourceEndpoint(database string) migrate.Endpoint
	TargetEndpoint(database string) migrate.Endpoint
}

// Engine implements machine.World against real PostgreSQL servers. Every change
// goes through an Authorization, so it only happens for an action of a plan the
// operator approved, and is audited before and after.
type Engine struct {
	Conns  Conns
	Names  migrate.Names
	DBs    []string
	Copier migrate.Copier
	// AuthFor returns the authorisation of the plan that covers the start
	// actions of database db at the given attempt (the migration plan for
	// attempt 1, the recovery plan afterwards).
	AuthFor func(db, attempt int) (*action.Authorization, error)
	// WorkRoot is the private directory for per-attempt copy work directories.
	WorkRoot    string
	SourceMajor int
	TableJobs   int
	IndexJobs   int
	NoOwner     bool
	// SlotTimeout bounds how long creating a slot may wait for open transactions.
	SlotTimeout time.Duration
	// Record stores facts (slot name, consistent point); optional.
	Record func(ctx context.Context, db int, key, value string)
	Log    func(format string, args ...any)
}

var _ machine.World = (*Engine)(nil)

func (e *Engine) logf(format string, args ...any) {
	if e.Log != nil {
		e.Log(format, args...)
	}
}

// Databases implements machine.World.
func (e *Engine) Databases() []string { return e.DBs }

func (e *Engine) dbName(db int) (string, error) {
	if db < 1 || db > len(e.DBs) {
		return "", fmt.Errorf("no database #%d", db)
	}
	return e.DBs[db-1], nil
}

func (e *Engine) slotPrefix(db int) string {
	return fmt.Sprintf("lk_%s_d%d_a", e.Names.MigrationID, db)
}

func closeConn(c *pgx.Conn) {
	if c == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = c.Close(ctx)
}

// Observe implements machine.World: it reads the real servers, read-only.
func (e *Engine) Observe(ctx context.Context, db, attempt int) (machine.DBState, error) {
	name, err := e.dbName(db)
	if err != nil {
		return machine.DBState{}, err
	}
	var st machine.DBState
	src, err := e.Conns.Source(ctx, name)
	if err != nil {
		return st, fmt.Errorf("connect to the source database %s: %w", name, err)
	}
	defer closeConn(src)
	slots, err := SlotsWithPrefix(ctx, src, e.slotPrefix(db))
	if err != nil {
		return st, err
	}
	for _, s := range slots {
		ss, err := ReadSlot(ctx, src, s)
		if err != nil {
			return st, err
		}
		st.SlotExists = true
		st.SlotActive = st.SlotActive || ss.Active
		if ss.WALStatus == "lost" {
			st.SlotWALStatus = "lost"
		} else if st.SlotWALStatus == "" {
			st.SlotWALStatus = ss.WALStatus
		}
	}
	tgt, err := e.Conns.Target(ctx, name)
	if err != nil {
		return st, fmt.Errorf("connect to the target database %s: %w", name, err)
	}
	defer closeConn(tgt)
	sub, err := ReadSub(ctx, tgt, e.Names.Subscription(db))
	if err != nil {
		return st, err
	}
	st.SubExists, st.SubEnabled = sub.Exists, sub.Enabled
	n, err := UserTables(ctx, tgt)
	if err != nil {
		return st, err
	}
	st.TargetHasTables = n > 0
	return st, nil
}

// Copy implements machine.World. It creates the slot and exports its snapshot,
// keeps that connection open and idle while the Copier runs inside the snapshot,
// removes the publication the schema copy brought along, checks that the slot
// survived, and only then releases the snapshot (the slot stays).
func (e *Engine) Copy(ctx context.Context, db, attempt int) error {
	name, err := e.dbName(db)
	if err != nil {
		return err
	}
	auth, err := e.AuthFor(db, attempt)
	if err != nil {
		return err
	}
	slot := e.Names.Slot(db, attempt)

	var holder *SlotHolder
	err = auth.Do(ctx, IDSlotSnapshot(db), func(ctx context.Context) error {
		conn, err := e.Conns.SourceRepl(ctx, name)
		if err != nil {
			return fmt.Errorf("open the replication connection: %w", err)
		}
		cctx := ctx
		if e.SlotTimeout > 0 {
			var cancel context.CancelFunc
			cctx, cancel = context.WithTimeout(ctx, e.SlotTimeout)
			defer cancel()
		}
		holder, err = CreateSlot(cctx, conn, slot)
		return err
	})
	if err != nil {
		return err
	}
	defer holder.Close()
	e.logf("slot %s created at %s; snapshot %s held open for the copy of %s", slot, holder.ConsistentPoint, holder.SnapshotID, name)
	if e.Record != nil {
		e.Record(ctx, db, "slot", slot)
		e.Record(ctx, db, "consistent_point", holder.ConsistentPoint.String())
	}

	workDir := filepath.Join(e.WorkRoot, fmt.Sprintf("d%d-a%d", db, attempt))
	if err := os.MkdirAll(e.WorkRoot, 0o700); err != nil {
		return err
	}
	err = auth.Do(ctx, IDCopy(db), func(ctx context.Context) error {
		return e.Copier.Copy(ctx, migrate.CopyInput{
			Source: e.Conns.SourceEndpoint(name), Target: e.Conns.TargetEndpoint(name),
			SnapshotID: holder.SnapshotID, WorkDir: workDir, SourceMajor: e.SourceMajor,
			TableJobs: e.TableJobs, IndexJobs: e.IndexJobs, NoOwner: e.NoOwner,
		})
	})
	if err != nil {
		return err
	}
	if !holder.Alive() {
		return errors.New("the snapshot connection closed during the copy: the copy cannot be trusted")
	}

	// The schema copy brought the source's publication along; the target must not keep it.
	tgt, err := e.Conns.Target(ctx, name)
	if err != nil {
		return fmt.Errorf("connect to the target database %s: %w", name, err)
	}
	defer closeConn(tgt)
	if err := auth.Apply(ctx, IDDropCopiedPublication(db), tgt); err != nil && !errors.Is(err, action.ErrAlreadySatisfied) {
		return err
	}

	// The slot must still exist and still retain WAL from before the snapshot.
	src, err := e.Conns.Source(ctx, name)
	if err != nil {
		return err
	}
	defer closeConn(src)
	ss, err := ReadSlot(ctx, src, slot)
	if err != nil {
		return err
	}
	if !ss.Exists || ss.WALStatus == "lost" {
		return fmt.Errorf("slot %s vanished or lost its WAL during the copy: the change stream would have a gap", slot)
	}
	return nil
}

// CreateSubscription implements machine.World.
func (e *Engine) CreateSubscription(ctx context.Context, db, attempt int) error {
	return e.applyTarget(ctx, db, attempt, IDCreateSubscription(db))
}

// EnableSubscription implements machine.World.
func (e *Engine) EnableSubscription(ctx context.Context, db, attempt int) error {
	return e.applyTarget(ctx, db, attempt, IDEnableSubscription(db))
}

func (e *Engine) applyTarget(ctx context.Context, db, attempt int, id string) error {
	name, err := e.dbName(db)
	if err != nil {
		return err
	}
	auth, err := e.AuthFor(db, attempt)
	if err != nil {
		return err
	}
	tgt, err := e.Conns.Target(ctx, name)
	if err != nil {
		return fmt.Errorf("connect to the target database %s: %w", name, err)
	}
	defer closeConn(tgt)
	return auth.Apply(ctx, id, tgt)
}

// Progress implements machine.World.
func (e *Engine) Progress(ctx context.Context, db, attempt int) (machine.Progress, error) {
	name, err := e.dbName(db)
	if err != nil {
		return machine.Progress{}, err
	}
	src, err := e.Conns.Source(ctx, name)
	if err != nil {
		return machine.Progress{}, err
	}
	defer closeConn(src)
	ss, err := ReadSlot(ctx, src, e.Names.Slot(db, attempt))
	if err != nil {
		return machine.Progress{}, err
	}
	if !ss.Exists {
		return machine.Progress{WALStatus: "lost"}, nil
	}
	tgt, err := e.Conns.Target(ctx, name)
	if err != nil {
		return machine.Progress{}, err
	}
	defer closeConn(tgt)
	sub, err := ReadSub(ctx, tgt, e.Names.Subscription(db))
	if err != nil {
		return machine.Progress{}, err
	}
	return machine.Progress{
		LagBytes: ss.LagBytes, RetainedBytes: ss.RetainedBytes, WALStatus: ss.WALStatus,
		SubEnabled: sub.Exists && sub.Enabled, WorkerRunning: sub.WorkerPID > 0,
	}, nil
}
