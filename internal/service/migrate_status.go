package service

import (
	"context"
	"fmt"
	"strconv"

	"github.com/wisnuvb/lockkeeper/internal/migrate"
	"github.com/wisnuvb/lockkeeper/internal/migrate/machine"
	"github.com/wisnuvb/lockkeeper/internal/migrate/pgnative"
)

// MigrationStatus is the read-only view behind `migrate status`: the recorded
// state plus, for each database, what the servers say right now (slot, retained
// WAL, lag, subscription) and the WAL guardrail level. It changes nothing.
func (s *Service) MigrationStatus(ctx context.Context, planHash, id string, tools ToolOptions) (*Status, error) {
	st, err := s.openState(ctx)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	m, err := findMigration(ctx, st, planHash, id)
	if err != nil {
		return nil, err
	}
	l, err := s.loadMigration(ctx, st, m, tools)
	if err != nil {
		return nil, err
	}
	out := &Status{
		MigrationID: m.ID, State: m.State, Source: m.SourceName, Target: m.TargetName, PlanHash: m.PlanHash,
		Approved: m.ApprovedHash == m.PlanHash, FailedStep: m.FailedStep, FailedReason: m.FailedReason,
		FailedResumable: m.FailedResumable, Updated: m.UpdatedAt,
	}
	if m.LeaseOwner != "" && m.LeaseUntil.After(s.deps.Now()) {
		out.Driver = m.LeaseOwner
	}
	cps, _ := st.Checkpoints(ctx, m.ID)
	th := s.slotThresholds()
	guard := machine.Guardrail{Warn: th.SlotWarnBytes, Critical: th.SlotBlockerBytes}
	names := migrate.Names{MigrationID: m.ID}
	live := false
	switch machine.State(m.State) {
	case machine.Copying, machine.Following, machine.CaughtUp, machine.Failed, machine.Aborted, machine.CleanupPending:
		live = true
	}
	for i, d := range l.in.DBs {
		db := i + 1
		attempt := 1
		if v := cps[d.Database]["attempt"]; v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				attempt = n
			}
		}
		ds := DBStatus{
			Database: d.Database, Index: db, Attempt: attempt, CopyDone: cps[d.Database]["copy_done"] == strconv.Itoa(attempt),
			Slot: names.Slot(db, attempt), Subscription: names.Subscription(db), Guardrail: "ok", ApplyErrors: -1,
		}
		if live {
			s.fillLive(ctx, l, &ds, guard)
		}
		out.Databases = append(out.Databases, ds)
		switch ds.Guardrail {
		case "warning", "critical":
			out.Warnings = append(out.Warnings, fmt.Sprintf("database %s: the source retains %d bytes of WAL for slot %s (guardrail %s). Nothing is done automatically: see docs/runbooks/wal-slot-full.md", d.Database, ds.RetainedBytes, ds.Slot, ds.Guardrail))
		}
		if machine.State(m.State) == machine.Aborted && ds.SlotExists {
			out.Warnings = append(out.Warnings, fmt.Sprintf("database %s: the migration is aborted but slot %s still retains %d bytes of WAL on the source; run `lockkeeper migrate cleanup` when you are done with it", d.Database, ds.Slot, ds.RetainedBytes))
		}
	}
	evs, _ := st.AuditEvents(ctx, m.ID, 100000)
	for i := len(evs) - 1; i >= 0 && len(out.LastEvents) < 5; i-- {
		out.LastEvents = append(out.LastEvents, fmt.Sprintf("%s %s %s %s", evs[i].At.Format("2006-01-02T15:04:05Z"), evs[i].Kind, evs[i].ActionID, evs[i].Detail))
	}
	return out, nil
}

// fillLive reads the servers (read-only sessions) into ds; errors are recorded
// in ds.Error rather than failing the whole status.
func (s *Service) fillLive(ctx context.Context, l *loaded, ds *DBStatus, guard machine.Guardrail) {
	src, err := s.openInventoryDB(ctx, l.in.Source.Name, ds.Database)
	if err != nil {
		ds.Error = "source: " + err.Error()
		return
	}
	defer pfCloseConn(src)
	ss, err := pgnative.ReadSlot(ctx, src, ds.Slot)
	if err != nil {
		ds.Error = s.redactErr(err).Error()
		return
	}
	ds.SlotExists, ds.SlotActive, ds.WALStatus = ss.Exists, ss.Active, ss.WALStatus
	ds.RetainedBytes, ds.LagBytes = ss.RetainedBytes, ss.LagBytes
	if ss.Exists {
		ds.SourceLSN = ss.CurrentLSN.String()
	}
	ds.Guardrail = guard.Level(ds.RetainedBytes, ds.WALStatus)
	tgt, err := s.openInventoryDB(ctx, l.in.Target.Name, ds.Database)
	if err != nil {
		ds.Error = "target: " + err.Error()
		return
	}
	defer pfCloseConn(tgt)
	sub, err := pgnative.ReadSub(ctx, tgt, ds.Subscription)
	if err != nil {
		ds.Error = s.redactErr(err).Error()
		return
	}
	ds.SubExists, ds.SubEnabled, ds.WorkerRunning, ds.ApplyErrors = sub.Exists, sub.Enabled, sub.WorkerPID > 0, sub.ApplyError
	if sub.Exists {
		ds.RemoteLSN = sub.RemoteLSN.String()
	}
}
