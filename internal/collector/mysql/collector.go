// Package mysql collects MySQL health metrics using only read-only statements:
// SHOW GLOBAL STATUS, a few information_schema views and the replication
// status. It supports MySQL 8.0 and 8.4; MariaDB and older versions are refused.
// It never uses SHOW ENGINE INNODB STATUS and never reads statement text of
// other sessions (threat T10).
package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	drv "github.com/go-sql-driver/mysql"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/model"
)

// OpenFunc opens a fresh connection pool (limited to one connection). The
// collector calls it lazily and again after a connection failure, which also
// picks up a rotated password.
type OpenFunc func(ctx context.Context) (*sql.DB, error)

// Options tunes a Collector.
type Options struct {
	// QueryTimeout bounds each query group. Default 10s.
	QueryTimeout time.Duration
	// Now is injectable for tests. Default time.Now.
	Now func() time.Time
}

// Collector implements collector.Collector for MySQL.
type Collector struct {
	target string
	open   OpenFunc
	opts   Options

	db   *sql.DB
	prev *snapshot
}

// New returns a Collector for the named target.
func New(target string, open OpenFunc, opts Options) *Collector {
	if opts.QueryTimeout == 0 {
		opts.QueryTimeout = 10 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Collector{target: target, open: open, opts: opts}
}

// Target implements collector.Collector.
func (c *Collector) Target() string { return c.target }

// Close implements collector.Collector.
func (c *Collector) Close() error {
	if c.db == nil {
		return nil
	}
	err := c.db.Close()
	c.db = nil
	return err
}

// Collect implements collector.Collector.
func (c *Collector) Collect(ctx context.Context) ([]model.Sample, bool, error) {
	now := c.opts.Now()
	b := &batch{target: c.target, at: now}

	if err := c.ensureConn(ctx); err != nil {
		b.add(rules.MetricMySQLUp, 0, nil)
		return b.samples, false, fmt.Errorf("connect: %w", err)
	}

	info, err := c.serverInfo(ctx)
	if err != nil {
		c.dropConn()
		b.add(rules.MetricMySQLUp, 0, nil)
		return b.samples, false, fmt.Errorf("server info: %w", err)
	}
	if err := info.supported(); err != nil {
		c.dropConn()
		b.add(rules.MetricMySQLUp, 0, nil)
		return b.samples, false, err
	}
	b.add(rules.MetricMySQLUp, 1, nil)

	groups := []struct {
		name string
		fn   func(context.Context, *batch, serverInfo) error
	}{
		{"status", c.status},
		{"transactions", c.transactions},
		{"history list", c.historyList},
		{"replication", c.replication},
		{"binary logs", c.binlogs},
	}
	var errs []error
	for _, g := range groups {
		gctx, cancel := context.WithTimeout(ctx, c.opts.QueryTimeout)
		err := g.fn(gctx, b, info)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", g.name, err))
			if !isServerError(err) {
				// Not an error answered by the server (timeout, broken
				// connection): do not trust the connection any further.
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
	if c.db != nil {
		return nil
	}
	db, err := c.open(ctx)
	if err != nil {
		return err
	}
	c.db = db
	return nil
}

func (c *Collector) dropConn() {
	if c.db != nil {
		_ = c.Close()
	}
}

// isServerError reports whether err is an error reply from the MySQL server (as
// opposed to a transport, timeout or driver problem).
func isServerError(err error) bool {
	var me *drv.MySQLError
	return errors.As(err, &me)
}

// serverErrNumber returns the MySQL error number of err, or 0.
func serverErrNumber(err error) uint16 {
	var me *drv.MySQLError
	if errors.As(err, &me) {
		return me.Number
	}
	return 0
}

// MySQL error numbers the collector reacts to.
const (
	errAccessDenied    = 1227 // ER_SPECIFIC_ACCESS_DENIED_ERROR: a required privilege is missing
	errNoBinaryLogging = 1381 // ER_NO_BINARY_LOGGING: SHOW BINARY LOGS with log_bin off
)

// batch accumulates samples for one Collect call.
type batch struct {
	target  string
	at      time.Time
	samples []model.Sample
}

func (b *batch) add(metric string, v float64, labels map[string]string) {
	b.samples = append(b.samples, model.Sample{Target: b.target, Metric: metric, Labels: labels, Value: v, At: b.at})
}

// serverInfo is what the first statement tells us about the server.
type serverInfo struct {
	version  string // VERSION(), e.g. "8.4.13"
	comment  string // @@version_comment
	major    int
	minor    int
	patch    int
	maxConns int64
}

func (c *Collector) serverInfo(ctx context.Context) (serverInfo, error) {
	gctx, cancel := context.WithTimeout(ctx, c.opts.QueryTimeout)
	defer cancel()
	var si serverInfo
	var comment sql.NullString
	err := c.db.QueryRowContext(gctx, `SELECT VERSION(), @@version_comment, @@global.max_connections`).
		Scan(&si.version, &comment, &si.maxConns)
	if err != nil {
		return si, err
	}
	si.comment = comment.String
	si.major, si.minor, si.patch = parseVersion(si.version)
	return si, nil
}

// parseVersion extracts major.minor.patch from a version string such as
// "8.0.36", "8.4.0-commercial" or "8.0.mysql_aurora.3.05.2" (patch -1 when it is
// not a number). Unparsable input yields zeros.
func parseVersion(v string) (major, minor, patch int) {
	parts := strings.SplitN(v, ".", 4)
	num := func(s string) int {
		end := 0
		for end < len(s) && s[end] >= '0' && s[end] <= '9' {
			end++
		}
		if end == 0 {
			return -1
		}
		n, _ := strconv.Atoi(s[:end])
		return n
	}
	major, minor, patch = 0, 0, -1
	if len(parts) > 0 {
		major = max(num(parts[0]), 0)
	}
	if len(parts) > 1 {
		minor = max(num(parts[1]), 0)
	}
	if len(parts) > 2 {
		patch = num(parts[2])
	}
	return major, minor, patch
}

// supported returns an error unless the server is MySQL 8.0 or 8.4. Other
// versions are refused rather than guessed at: the statements and columns used
// here were only verified on those two series.
func (si serverInfo) supported() error {
	if strings.Contains(strings.ToLower(si.version+" "+si.comment), "mariadb") {
		return fmt.Errorf("unsupported server %q: MariaDB is not supported (MySQL 8.0 and 8.4 only)", si.version)
	}
	if si.major == 0 {
		return fmt.Errorf("unsupported server: cannot parse the version %q (MySQL 8.0 and 8.4 only)", si.version)
	}
	if si.major < 8 {
		return fmt.Errorf("unsupported MySQL version %s: too old (MySQL 8.0 and 8.4 only)", si.version)
	}
	if si.major == 8 && (si.minor == 0 || si.minor == 4) {
		return nil
	}
	return fmt.Errorf("unsupported MySQL version %s (MySQL 8.0 and 8.4 only; this release is not validated)", si.version)
}

// legacyReplicaSyntax reports whether the server predates SHOW REPLICA STATUS
// (MySQL 8.0.22). A version whose patch level is not a number (Aurora MySQL 3 is
// "8.0.mysql_aurora.3.x" and is newer than 8.0.22) gets the modern syntax.
func (si serverInfo) legacyReplicaSyntax() bool {
	return si.major == 8 && si.minor == 0 && si.patch >= 0 && si.patch < 22
}

// Status variables read from SHOW GLOBAL STATUS.
const (
	varThreadsConnected  = "Threads_connected"
	varThreadsRunning    = "Threads_running"
	varSlowQueries       = "Slow_queries"
	varBufferPoolReads   = "Innodb_buffer_pool_reads"
	varBufferPoolRequest = "Innodb_buffer_pool_read_requests"
	varRowLockWaits      = "Innodb_row_lock_waits"
	varUptime            = "Uptime"
)

var statusVars = []string{
	varThreadsConnected, varThreadsRunning, varSlowQueries, varBufferPoolReads,
	varBufferPoolRequest, varRowLockWaits, varUptime,
}

// snapshot is one reading of the cumulative counters, kept for interval maths.
type snapshot struct {
	at   time.Time
	vars map[string]int64
}

func (c *Collector) readStatus(ctx context.Context) (map[string]int64, error) {
	quoted := make([]string, len(statusVars))
	for i, v := range statusVars {
		quoted[i] = "'" + v + "'"
	}
	rows, err := c.db.QueryContext(ctx, `SHOW GLOBAL STATUS WHERE Variable_name IN (`+strings.Join(quoted, ",")+`)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	vars := map[string]int64{}
	for rows.Next() {
		var name, val string
		if err := rows.Scan(&name, &val); err != nil {
			return nil, err
		}
		if n, err := strconv.ParseInt(val, 10, 64); err == nil {
			vars[name] = n
		}
	}
	return vars, rows.Err()
}

func (c *Collector) status(ctx context.Context, b *batch, si serverInfo) error {
	vars, err := c.readStatus(ctx)
	if err != nil {
		return err
	}
	cur := snapshot{at: b.at, vars: vars}
	addStatusSamples(b, si, c.prev, cur)
	c.prev = &cur
	return nil
}

// addStatusSamples turns two consecutive readings into samples. prev is nil on
// the first collection (no rates yet).
func addStatusSamples(b *batch, si serverInfo, prev *snapshot, cur snapshot) {
	if n, ok := cur.vars[varThreadsConnected]; ok && si.maxConns > 0 {
		b.add(rules.MetricMySQLConnectionsRatio, float64(n)/float64(si.maxConns), nil)
	}
	if n, ok := cur.vars[varThreadsRunning]; ok {
		// The status statement itself runs on a thread that is counted as
		// running; do not report our own session.
		if n > 0 {
			n--
		}
		b.add(rules.MetricMySQLThreadsRunning, float64(n), nil)
	}

	if prev == nil {
		return
	}
	elapsed := cur.at.Sub(prev.at).Seconds()
	if elapsed <= 0 {
		return
	}
	// A server restart resets every counter; a reading that went backwards is
	// never turned into a (negative or wildly wrong) rate.
	if cur.vars[varUptime] < prev.vars[varUptime] {
		return
	}
	if rate, ok := counterRate(prev.vars, cur.vars, varSlowQueries, elapsed); ok {
		b.add(rules.MetricMySQLSlowQueriesRate, rate, nil)
	}
	if rate, ok := counterRate(prev.vars, cur.vars, varRowLockWaits, elapsed); ok {
		b.add(rules.MetricMySQLRowLockWaitsRate, rate, nil)
	}
	if ratio, ok := bufferPoolHit(prev.vars, cur.vars); ok {
		b.add(rules.MetricMySQLBufferPoolHit, ratio, nil)
	}
}

// counterRate is the per-second increase of a cumulative counter. ok is false
// when the counter is missing or went backwards (reset).
func counterRate(prev, cur map[string]int64, name string, elapsedSeconds float64) (rate float64, ok bool) {
	p, okp := prev[name]
	c, okc := cur[name]
	if !okp || !okc || c < p || elapsedSeconds <= 0 {
		return 0, false
	}
	return float64(c-p) / elapsedSeconds, true
}

// minBufferPoolRequests is the smallest number of logical reads between two
// collections for which a hit ratio is meaningful (same idea as the Postgres
// cache ratio guard).
const minBufferPoolRequests = 10_000

// bufferPoolHit computes the InnoDB buffer pool hit ratio over the interval:
// 1 - (reads that went to disk / logical read requests). ok is false when the
// counters are missing or were reset, or when too little traffic occurred.
func bufferPoolHit(prev, cur map[string]int64) (ratio float64, ok bool) {
	pr, ok1 := prev[varBufferPoolReads]
	pq, ok2 := prev[varBufferPoolRequest]
	cr, ok3 := cur[varBufferPoolReads]
	cq, ok4 := cur[varBufferPoolRequest]
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return 0, false
	}
	dr, dq := cr-pr, cq-pq
	if dr < 0 || dq < 0 || dq < minBufferPoolRequests {
		return 0, false
	}
	ratio = 1 - float64(dr)/float64(dq)
	if ratio < 0 {
		ratio = 0
	}
	return ratio, true
}

// transactions reports the age of the oldest InnoDB transaction. information_schema
// .INNODB_TRX needs the PROCESS privilege; without it the statement is refused
// and the batch is incomplete (the role audit explains why).
func (c *Collector) transactions(ctx context.Context, b *batch, _ serverInfo) error {
	var age float64
	// Our own session is excluded. Only ages are read, never statement text.
	//
	// trx_started is printed in the system time zone, so the session must use it
	// too (dbconn sets time_zone = SYSTEM); both sides are converted to epoch
	// seconds under that one zone. Only a transaction started inside the repeated
	// hour of a daylight-saving change can be off, by up to an hour.
	err := c.db.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(UNIX_TIMESTAMP() - UNIX_TIMESTAMP(trx_started)), 0)
		FROM information_schema.INNODB_TRX
		WHERE trx_mysql_thread_id <> CONNECTION_ID()`).Scan(&age)
	if err != nil {
		return err
	}
	if age < 0 {
		age = 0
	}
	b.add(rules.MetricMySQLTrxOldest, age, nil)
	return nil
}

// historyList reads the InnoDB history list length. The counter can be disabled
// (innodb_monitor_disable); then there is simply no sample.
func (c *Collector) historyList(ctx context.Context, b *batch, _ serverInfo) error {
	var n int64
	err := c.db.QueryRowContext(ctx, "SELECT `count` FROM information_schema.INNODB_METRICS WHERE name = 'trx_rseg_history_len' AND status = 'enabled'").Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	b.add(rules.MetricMySQLHistoryListLength, float64(n), nil)
	return nil
}

// binlogs sums the size of the binary log files. It is informational: when binary
// logging is off or the privilege (REPLICATION CLIENT) is missing the metric is
// skipped and the batch stays complete.
func (c *Collector) binlogs(ctx context.Context, b *batch, _ serverInfo) error {
	rows, err := c.db.QueryContext(ctx, "SHOW BINARY LOGS")
	if err != nil {
		if n := serverErrNumber(err); n == errNoBinaryLogging || n == errAccessDenied {
			return nil
		}
		return err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	var total float64
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		// Columns: Log_name, File_size[, Encrypted].
		if len(vals) >= 2 {
			if n, err := strconv.ParseFloat(vals[1].String, 64); err == nil {
				total += n
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	b.add(rules.MetricMySQLBinlogDiskBytes, total, nil)
	return nil
}
