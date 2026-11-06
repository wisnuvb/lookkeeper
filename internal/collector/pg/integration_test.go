//go:build integration

package pg_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/collector/pg"
	"github.com/wisnuvb/lockkeeper/internal/dbconn"
	"github.com/wisnuvb/lockkeeper/internal/model"
	"github.com/wisnuvb/lockkeeper/internal/secret"
	"github.com/wisnuvb/lockkeeper/internal/testutil"
)

func newCollector(t *testing.T, p *testutil.PG) *pg.Collector {
	t.Helper()
	c := pg.New("test", func(ctx context.Context) (*pgx.Conn, error) { return dbconn.OpenPG(ctx, p.Spec()) },
		pg.Options{QueryTimeout: 10 * time.Second})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func find(samples []model.Sample, metric string, labels map[string]string) (model.Sample, bool) {
	for _, s := range samples {
		if s.Metric != metric {
			continue
		}
		match := true
		for k, v := range labels {
			if s.Labels[k] != v {
				match = false
			}
		}
		if match {
			return s, true
		}
	}
	return model.Sample{}, false
}

func exec(t *testing.T, conn *pgx.Conn, sql string) {
	t.Helper()
	if _, err := conn.Exec(context.Background(), sql); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func TestCollectAgainstRealPostgres(t *testing.T) {
	p := testutil.StartPG(t)
	c := newCollector(t, p)

	samples, complete, err := c.Collect(context.Background())
	if err != nil || !complete {
		t.Fatalf("collect: complete=%v err=%v", complete, err)
	}
	if up, ok := find(samples, rules.MetricPGUp, nil); !ok || up.Value != 1 {
		t.Fatalf("pg.up must be 1: %+v", up)
	}
	ratio, ok := find(samples, rules.MetricPGConnectionsRatio, nil)
	if !ok || ratio.Value <= 0 || ratio.Value >= 1 {
		t.Errorf("connection ratio must be in (0,1): %+v", ratio)
	}
	for _, m := range []string{rules.MetricPGIdleInTxAge, rules.MetricPGLongestQuery, rules.MetricPGBlockedSeconds} {
		if s, ok := find(samples, m, nil); !ok || s.Value != 0 {
			t.Errorf("%s should be present and 0 on an idle server: %+v", m, s)
		}
	}
	if s, ok := find(samples, rules.MetricPGXIDAge, map[string]string{"database": "postgres"}); !ok || s.Value < 0 {
		t.Errorf("xid age for the postgres database missing: %+v", s)
	}
	if _, ok := find(samples, rules.MetricPGMXIDAge, map[string]string{"database": "postgres"}); !ok {
		t.Error("multixact age missing")
	}
	for _, s := range samples {
		if s.Target != "test" || s.At.IsZero() {
			t.Errorf("sample without target/time: %+v", s)
		}
	}
}

func TestSessionsRefuseWrites(t *testing.T) {
	p := testutil.StartPG(t)
	conn, err := dbconn.OpenPG(context.Background(), p.Spec())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	_, err = conn.Exec(context.Background(), "CREATE TABLE must_not_exist (id int)")
	if err == nil || !strings.Contains(err.Error(), "read-only transaction") {
		t.Fatalf("a Lockkeeper session must refuse writes, got %v", err)
	}
	// NOTE: the read-only session setting is defence in depth, not a security
	// boundary. Postgres still lets a role with the privilege call functions such
	// as pg_create_logical_replication_slot() from a read-only session. That is
	// why AuditRole exists and why the docs require a least-privilege role.
}

func TestAuditRoleFlagsOverPrivilegedRoles(t *testing.T) {
	p := testutil.StartPG(t)
	admin := p.Admin(t)

	// The container's default user is a superuser: must be flagged.
	warnings, err := pg.AuditRole(context.Background(), admin)
	if err != nil || len(warnings) == 0 || !strings.Contains(warnings[0], "superuser") {
		t.Fatalf("superuser must be flagged, got %v (err %v)", warnings, err)
	}

	exec(t, admin, "CREATE ROLE lk_plain LOGIN PASSWORD 'plainpw'")
	exec(t, admin, "CREATE ROLE lk_good LOGIN PASSWORD 'goodpw'")
	exec(t, admin, "GRANT pg_monitor TO lk_good")
	exec(t, admin, "CREATE ROLE lk_repl LOGIN REPLICATION PASSWORD 'replpw'")
	exec(t, admin, "GRANT pg_monitor TO lk_repl")

	open := func(user, pw string) *pgx.Conn {
		spec := p.Spec()
		spec.User, spec.Password = user, secret.New(pw)
		conn, err := dbconn.OpenPG(context.Background(), spec)
		if err != nil {
			t.Fatalf("connect as %s: %v", user, err)
		}
		t.Cleanup(func() { _ = conn.Close(context.Background()) })
		return conn
	}

	if w, err := pg.AuditRole(context.Background(), open("lk_good", "goodpw")); err != nil || len(w) != 0 {
		t.Errorf("a LOGIN + pg_monitor role must be clean, got %v (err %v)", w, err)
	}
	if w, _ := pg.AuditRole(context.Background(), open("lk_plain", "plainpw")); len(w) != 1 || !strings.Contains(w[0], "pg_monitor") {
		t.Errorf("a role without pg_monitor must be flagged, got %v", w)
	}
	if w, _ := pg.AuditRole(context.Background(), open("lk_repl", "replpw")); len(w) != 1 || !strings.Contains(w[0], "REPLICATION") {
		t.Errorf("a REPLICATION role must be flagged, got %v", w)
	}
}

func TestReplicationSlotRetainedWAL(t *testing.T) {
	p := testutil.StartPG(t)
	admin := p.Admin(t)
	exec(t, admin, "SELECT pg_create_logical_replication_slot('lk_test_slot','pgoutput')")
	exec(t, admin, "CREATE TABLE bulk (id serial primary key, payload text)")
	exec(t, admin, "INSERT INTO bulk (payload) SELECT repeat('x', 200) FROM generate_series(1, 50000)")

	c := newCollector(t, p)
	samples, complete, err := c.Collect(context.Background())
	if err != nil || !complete {
		t.Fatalf("collect: complete=%v err=%v", complete, err)
	}
	labels := map[string]string{"slot": "lk_test_slot", "type": "logical"}
	retained, ok := find(samples, rules.MetricPGSlotRetainedWAL, labels)
	if !ok || retained.Value < 1<<20 {
		t.Fatalf("expected at least 1 MiB of retained WAL for an unread slot, got %+v", retained)
	}
	if active, ok := find(samples, rules.MetricPGSlotActive, labels); !ok || active.Value != 0 {
		t.Errorf("an unread slot must be inactive: %+v", active)
	}
	if _, ok := find(samples, "pg.slot.confirmed_flush_lag_bytes", labels); !ok {
		t.Error("logical slots must report confirmed flush lag")
	}

	// The same data feeds `slots list`.
	slots, err := pg.ListSlots(context.Background(), admin)
	if err != nil || len(slots) != 1 || slots[0].Name != "lk_test_slot" || slots[0].Plugin != "pgoutput" || slots[0].Database != "postgres" {
		t.Fatalf("ListSlots = %+v, %v", slots, err)
	}

	// Dropping the slot removes the series; a complete collection reports that.
	exec(t, admin, "SELECT pg_drop_replication_slot('lk_test_slot')")
	samples, _, err = c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := find(samples, rules.MetricPGSlotRetainedWAL, labels); ok {
		t.Error("dropped slot must disappear from the samples")
	}
}

func TestIdleInTransactionAndBlockedLocks(t *testing.T) {
	p := testutil.StartPG(t)
	setup := p.Admin(t)
	exec(t, setup, "CREATE TABLE t (id int)")

	holder := p.Admin(t)
	exec(t, holder, "BEGIN")
	exec(t, holder, "LOCK TABLE t IN ACCESS EXCLUSIVE MODE") // holds the lock and stays idle in transaction

	var wg sync.WaitGroup
	waiter := p.Admin(t)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = waiter.Exec(context.Background(), "SELECT count(*) FROM t") // blocks on the lock
	}()
	t.Cleanup(func() {
		_, _ = holder.Exec(context.Background(), "ROLLBACK")
		wg.Wait()
	})

	c := newCollector(t, p)
	deadline := time.Now().Add(20 * time.Second)
	for {
		time.Sleep(1500 * time.Millisecond)
		samples, _, err := c.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		idle, _ := find(samples, rules.MetricPGIdleInTxAge, nil)
		blocked, _ := find(samples, rules.MetricPGBlockedSeconds, nil)
		if idle.Value >= 1 && blocked.Value >= 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected idle-in-tx and blocked ages >= 1s, got idle=%v blocked=%v", idle.Value, blocked.Value)
		}
	}
}

func TestOutageIsReportedAsDownThenRecoversAfterReconnect(t *testing.T) {
	p := testutil.StartPG(t)
	c := newCollector(t, p)
	if _, complete, err := c.Collect(context.Background()); err != nil || !complete {
		t.Fatalf("baseline collect failed: %v", err)
	}
	p.Stop(t)
	samples, complete, err := c.Collect(context.Background())
	if err == nil || complete {
		t.Fatalf("collect during an outage must fail and be incomplete (complete=%v err=%v)", complete, err)
	}
	if up, ok := find(samples, rules.MetricPGUp, nil); !ok || up.Value != 0 {
		t.Fatalf("pg.up must be 0 during an outage: %+v", samples)
	}
}
