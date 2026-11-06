// Package pg collects PostgreSQL health metrics using only read-only queries
// against the standard catalog views. No extension is required.
package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/model"
)

// MinServerVersion is the oldest supported server (PostgreSQL 12).
const MinServerVersion = 120000

// OpenFunc opens a fresh connection. The collector calls it lazily and again
// after a connection failure.
type OpenFunc func(ctx context.Context) (*pgx.Conn, error)

// Options tunes a Collector.
type Options struct {
	// QueryTimeout bounds each query group. Default 10s.
	QueryTimeout time.Duration
	// Now is injectable for tests. Default time.Now.
	Now func() time.Time
	// LargeTableBytes is the size from which a table counts as large for the
	// autovacuum age metric. Default 1 GiB; lowered only by tests.
	LargeTableBytes int64
}

// Collector implements collector.Collector for PostgreSQL.
type Collector struct {
	target string
	open   OpenFunc
	opts   Options

	conn      *pgx.Conn
	prevCache map[string]cacheCounters
	extra     extraState // state of the extra metrics (extras.go)
}

// New returns a Collector for the named target.
func New(target string, open OpenFunc, opts Options) *Collector {
	if opts.QueryTimeout == 0 {
		opts.QueryTimeout = 10 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Collector{target: target, open: open, opts: opts, prevCache: map[string]cacheCounters{}}
}

// Target implements collector.Collector.
func (c *Collector) Target() string { return c.target }

// Close implements collector.Collector.
func (c *Collector) Close() error {
	if c.conn == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := c.conn.Close(ctx)
	c.conn = nil
	return err
}

type serverInfo struct {
	versionNum  int
	inRecovery  bool
	maxConns    int
	versionText string
}

// Collect implements collector.Collector.
func (c *Collector) Collect(ctx context.Context) ([]model.Sample, bool, error) {
	now := c.opts.Now()
	b := &batch{target: c.target, at: now}

	if err := c.ensureConn(ctx); err != nil {
		b.add(rules.MetricPGUp, 0, nil)
		return b.samples, false, fmt.Errorf("connect: %w", err)
	}

	var errs []error
	info, err := c.serverInfo(ctx)
	if err != nil {
		c.dropConn()
		b.add(rules.MetricPGUp, 0, nil)
		return b.samples, false, fmt.Errorf("server info: %w", err)
	}
	if info.versionNum < MinServerVersion {
		c.dropConn()
		b.add(rules.MetricPGUp, 0, nil)
		return b.samples, false, fmt.Errorf("unsupported PostgreSQL version %s (need 12 or newer)", info.versionText)
	}
	b.add(rules.MetricPGUp, 1, nil)

	groups := []struct {
		name string
		fn   func(context.Context, *batch, serverInfo) error
	}{
		{"activity", c.activity},
		{"slots", c.slots},
		{"replication", c.replication},
		{"xid age", c.xidAge},
		{"cache", c.cache},
		// Extra metrics (extras.go). The expensive catalog groups are rate-limited.
		{"dead tuples", c.slow("dead tuples", c.deadTuples)},
		{"autovacuum", c.slow("autovacuum", c.autovacuumAge)},
		{"checkpoints", c.checkpoints},
		{"temp files", c.tempBytes},
		{"database size", c.slow("database size", c.dbSize)},
		{"statements", c.statements},
	}
	for _, g := range groups {
		gctx, cancel := context.WithTimeout(ctx, c.opts.QueryTimeout)
		err := g.fn(gctx, b, info)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", g.name, err))
			if c.conn != nil && c.conn.IsClosed() {
				c.dropConn()
				break
			}
		}
	}
	if len(errs) > 0 {
		return b.samples, false, errors.Join(errs...)
	}
	return b.samples, true, nil
}

func (c *Collector) ensureConn(ctx context.Context) error {
	if c.conn != nil && !c.conn.IsClosed() {
		return nil
	}
	c.conn = nil
	conn, err := c.open(ctx)
	if err != nil {
		return err
	}
	c.conn = conn
	return nil
}

func (c *Collector) dropConn() {
	if c.conn != nil {
		_ = c.Close()
	}
}

func (c *Collector) serverInfo(ctx context.Context) (serverInfo, error) {
	gctx, cancel := context.WithTimeout(ctx, c.opts.QueryTimeout)
	defer cancel()
	var si serverInfo
	err := c.conn.QueryRow(gctx, `
		SELECT current_setting('server_version_num')::int,
		       current_setting('server_version'),
		       pg_is_in_recovery(),
		       current_setting('max_connections')::int`).
		Scan(&si.versionNum, &si.versionText, &si.inRecovery, &si.maxConns)
	return si, err
}

// batch accumulates samples for one Collect call.
type batch struct {
	target  string
	at      time.Time
	samples []model.Sample
}

func (b *batch) add(metric string, v float64, labels map[string]string) {
	b.samples = append(b.samples, model.Sample{Target: b.target, Metric: metric, Labels: labels, Value: v, At: b.at})
}

// currentLSN is the WAL position to measure against: the write position on a
// primary, the receive position on a standby.
const currentLSN = `CASE WHEN pg_is_in_recovery() THEN pg_last_wal_receive_lsn() ELSE pg_current_wal_lsn() END`

func (c *Collector) activity(ctx context.Context, b *batch, si serverInfo) error {
	var clients int64
	var idleInTx, longest, blocked float64
	// Own session is excluded from the age metrics. Walsenders and background
	// workers are excluded from the client count (backend_type = 'client backend').
	err := c.conn.QueryRow(ctx, `
		SELECT
		  count(*) FILTER (WHERE backend_type = 'client backend'),
		  COALESCE(max(EXTRACT(EPOCH FROM (now() - state_change)))
		    FILTER (WHERE state IN ('idle in transaction', 'idle in transaction (aborted)')
		              AND pid <> pg_backend_pid()), 0)::float8,
		  COALESCE(max(EXTRACT(EPOCH FROM (now() - query_start)))
		    FILTER (WHERE state = 'active' AND backend_type = 'client backend'
		              AND pid <> pg_backend_pid()), 0)::float8,
		  COALESCE(max(EXTRACT(EPOCH FROM (now() - query_start)))
		    FILTER (WHERE cardinality(pg_blocking_pids(pid)) > 0), 0)::float8
		FROM pg_stat_activity`).Scan(&clients, &idleInTx, &longest, &blocked)
	if err != nil {
		return err
	}
	if si.maxConns > 0 {
		b.add(rules.MetricPGConnectionsRatio, float64(clients)/float64(si.maxConns), nil)
	}
	b.add(rules.MetricPGIdleInTxAge, idleInTx, nil)
	b.add(rules.MetricPGLongestQuery, longest, nil)
	b.add(rules.MetricPGBlockedSeconds, blocked, nil)
	return nil
}

func (c *Collector) slots(ctx context.Context, b *batch, _ serverInfo) error {
	slots, err := listSlots(ctx, c.conn)
	if err != nil {
		return err
	}
	for _, s := range slots {
		labels := map[string]string{"slot": s.Name, "type": s.Type}
		b.add(rules.MetricPGSlotRetainedWAL, s.RetainedBytes, labels)
		active := 0.0
		if s.Active {
			active = 1
		}
		b.add(rules.MetricPGSlotActive, active, labels)
		if s.Type == "logical" {
			b.add("pg.slot.confirmed_flush_lag_bytes", s.ConfirmedFlushLagBytes, labels)
		}
	}
	return nil
}

func (c *Collector) replication(ctx context.Context, b *batch, si serverInfo) error {
	if si.inRecovery {
		var lag float64
		err := c.conn.QueryRow(ctx, `
			SELECT CASE WHEN pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn() THEN 0
			            ELSE COALESCE(EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp())), 0)
			       END::float8`).Scan(&lag)
		if err != nil {
			return err
		}
		b.add(rules.MetricPGStandbyLagSeconds, lag, nil)
		return nil
	}
	rows, err := c.conn.Query(ctx, `
		SELECT COALESCE(application_name, ''), COALESCE(client_addr::text, ''),
		       COALESCE(pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn), 0)::float8,
		       COALESCE(EXTRACT(EPOCH FROM replay_lag), 0)::float8
		FROM pg_stat_replication`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var app, addr string
		var lagBytes, lagSecs float64
		if err := rows.Scan(&app, &addr, &lagBytes, &lagSecs); err != nil {
			return err
		}
		labels := map[string]string{"application": app, "client": addr}
		b.add(rules.MetricPGReplLagBytes, lagBytes, labels)
		b.add(rules.MetricPGReplLagSeconds, lagSecs, labels)
	}
	return rows.Err()
}

func (c *Collector) xidAge(ctx context.Context, b *batch, _ serverInfo) error {
	// rdsadmin is managed by AWS and would only add noise.
	rows, err := c.conn.Query(ctx, `
		SELECT datname, age(datfrozenxid)::float8, mxid_age(datminmxid)::float8
		FROM pg_database
		WHERE datallowconn AND datname <> 'rdsadmin'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var db string
		var xid, mxid float64
		if err := rows.Scan(&db, &xid, &mxid); err != nil {
			return err
		}
		labels := map[string]string{"database": db}
		b.add(rules.MetricPGXIDAge, xid, labels)
		b.add(rules.MetricPGMXIDAge, mxid, labels)
	}
	return rows.Err()
}

func (c *Collector) cache(ctx context.Context, b *batch, _ serverInfo) error {
	rows, err := c.conn.Query(ctx, `
		SELECT datname, blks_hit, blks_read
		FROM pg_stat_database
		WHERE datname IS NOT NULL AND datname NOT IN ('template0', 'template1', 'rdsadmin')`)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var db string
		var cur cacheCounters
		if err := rows.Scan(&db, &cur.hit, &cur.read); err != nil {
			return err
		}
		seen[db] = true
		if prev, ok := c.prevCache[db]; ok {
			if ratio, ok := cacheRatio(prev, cur); ok {
				b.add(rules.MetricPGCacheHitRatio, ratio, map[string]string{"database": db})
			}
		}
		c.prevCache[db] = cur
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for db := range c.prevCache {
		if !seen[db] {
			delete(c.prevCache, db)
		}
	}
	return nil
}

// cacheCounters are the cumulative block counters of one database.
type cacheCounters struct{ hit, read int64 }

// minCacheBlocks is the smallest number of block accesses between two
// collections for which a hit ratio is meaningful.
const minCacheBlocks = 10_000

// cacheRatio computes the hit ratio over the interval between two readings.
// ok is false when the counters were reset or too little traffic occurred.
func cacheRatio(prev, cur cacheCounters) (ratio float64, ok bool) {
	dh, dr := cur.hit-prev.hit, cur.read-prev.read
	if dh < 0 || dr < 0 { // statistics were reset
		return 0, false
	}
	total := dh + dr
	if total < minCacheBlocks {
		return 0, false
	}
	return float64(dh) / float64(total), true
}
