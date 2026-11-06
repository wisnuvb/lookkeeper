package pg

// Extra PostgreSQL metrics: table health, autovacuum, checkpoints, temp files,
// database size and (optionally) pg_stat_statements. SPEC section 10.1.
//
// All queries are read-only SELECTs against catalog and statistics views, and
// none of them reads query text: pg_stat_statements is only ever read by
// queryid (threat T10).
//
// Informational metrics (no default alert rule, see rules.PostgresDefaults):
//
//	pg.temp.bytes_rate               bytes/second spilled to temp files, per database
//	pg.db.size_bytes                 database size in bytes, per database
//	pg.autovacuum.never_vacuumed     1 for a large table with no recorded vacuum
//	pg.statements.total_exec_time_s  top 10 statements by total execution time
//	pg.statements.calls              (same series, labels database + queryid)
//	pg.statements.rows               (same series, labels database + queryid)
//
// Table-level metrics (dead tuples, autovacuum age) only see the database the
// collector is connected to: per-table statistics are not visible across
// databases. The configured `database` is the one monitored.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/model"
)

const (
	// deadTupleMinCount is the smallest n_dead_tup for which a table is reported.
	// With the 20% / 40% ratio thresholds it expresses the SPEC's "and > 100k rows"
	// absolute condition (the "> 1M rows" condition for critical is not applied
	// separately).
	deadTupleMinCount = 100_000
	// topTables bounds the cardinality of the per-table metrics.
	topTables = 20
	// defaultLargeTableBytes is the size (table + indexes + TOAST) from which a
	// table counts as large for the autovacuum age metric.
	defaultLargeTableBytes = int64(1) << 30
	// topStatements bounds the pg_stat_statements series.
	topStatements = 10
	// checkpointMinCount is the least number of checkpoints a ratio is computed over.
	checkpointMinCount = 5
	// checkpointLookback bounds how far back a checkpoint window may reach.
	checkpointLookback = time.Hour
	// slowGroupEvery is how often the expensive catalog groups (table sizes,
	// database sizes, table statistics) are queried. Between refreshes the last
	// result is re-emitted, so series do not flap and the server is not asked to
	// stat every relation file every 30 seconds.
	slowGroupEvery = 5 * time.Minute
	// minRateWindow is the shortest interval a per-second rate is computed over.
	minRateWindow = time.Second
)

// excludedDatabases are not monitored: templates carry no workload and rdsadmin
// is managed by AWS.
const excludedDatabases = `('template0', 'template1', 'rdsadmin')`

// userSchemaFilter keeps system and temporary schemas out of per-table metrics.
// pg_stat_user_tables already hides most of them; this makes the intent explicit
// and also covers other sessions' temporary schemas.
const userSchemaFilter = `schemaname NOT IN ('pg_catalog', 'information_schema')
		  AND schemaname NOT LIKE 'pg\_toast%' AND schemaname NOT LIKE 'pg\_temp\_%'`

type groupFunc = func(context.Context, *batch, serverInfo) error

// extraState is the cross-collection memory of the extra metrics. The zero value
// is ready to use.
type extraState struct {
	ckpt []ckptSnap
	temp map[string]tempCounters
	slow map[string]slowEntry
}

// ---- dead tuples ------------------------------------------------------------

func (c *Collector) deadTuples(ctx context.Context, b *batch, _ serverInfo) error {
	rows, err := c.conn.Query(ctx, `
		SELECT current_database()::text, schemaname::text, relname::text, n_dead_tup::float8, n_live_tup::float8
		FROM pg_stat_user_tables
		WHERE n_dead_tup >= $1::bigint AND `+userSchemaFilter+`
		ORDER BY n_dead_tup DESC, schemaname, relname
		LIMIT $2::int`, deadTupleMinCount, topTables)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var db, schema, table string
		var dead, live float64
		if err := rows.Scan(&db, &schema, &table, &dead, &live); err != nil {
			return err
		}
		if dead+live <= 0 {
			continue
		}
		b.add(rules.MetricPGTableDeadRatio, dead/(dead+live),
			map[string]string{"database": db, "schema": schema, "table": table})
	}
	return rows.Err()
}

// ---- autovacuum -------------------------------------------------------------

// autovacuumAge reports, for the largest tables, how long ago they were last
// vacuumed (manually or by autovacuum).
//
// A table with no recorded vacuum gets NO pg.autovacuum.last_age_s sample, not a
// 0 (which would read as "just vacuumed") and not a huge number (which would
// raise a false critical): vacuum timestamps live in the statistics, which are
// reset by a crash and are not carried over by pg_upgrade, and a freshly loaded
// table has none yet. Instead pg.autovacuum.never_vacuumed = 1 is emitted for it
// (informational), so the case stays visible without a misleading age.
func (c *Collector) autovacuumAge(ctx context.Context, b *batch, _ serverInfo) error {
	minSize := c.opts.LargeTableBytes
	if minSize <= 0 {
		minSize = defaultLargeTableBytes
	}
	rows, err := c.conn.Query(ctx, autovacuumSQL, minSize, topTables)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var db, schema, table string
		var age *float64
		if err := rows.Scan(&db, &schema, &table, &age); err != nil {
			return err
		}
		labels := map[string]string{"database": db, "schema": schema, "table": table}
		if age == nil {
			b.add(rules.MetricPGAutovacuumNeverVacuumed, 1, labels)
			continue
		}
		b.add(rules.MetricPGAutovacuumAge, max(*age, 0), labels)
	}
	return rows.Err()
}

// autovacuumSQL lists the largest tables with their time since the last vacuum.
//
// pg_total_relation_size() takes an ACCESS SHARE lock on the table and on each of
// its indexes, so it would queue behind an ACCESS EXCLUSIVE lock (a long
// transaction that ran LOCK/ALTER/REINDEX/VACUUM FULL) and then stall every
// collection until the query timeout, exactly when the database is in trouble.
// Tables, indexes or TOAST tables that currently hold or await such a lock are
// therefore skipped for this refresh. The check is a snapshot, so a lock taken a
// moment later can still make the query wait; the statement and lock timeouts
// bound that.
const autovacuumSQL = `
		WITH locked AS MATERIALIZED (
		  SELECT relation FROM pg_locks
		  WHERE locktype = 'relation' AND mode = 'AccessExclusiveLock'
		    AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
		)
		SELECT db, schemaname, relname, EXTRACT(EPOCH FROM now() - last_vac)::float8
		FROM (
		  SELECT current_database()::text AS db, s.schemaname::text AS schemaname, s.relname::text AS relname,
		         GREATEST(s.last_autovacuum, s.last_vacuum) AS last_vac,
		         pg_total_relation_size(s.relid) AS total_size
		  FROM pg_stat_user_tables s
		  JOIN pg_class c ON c.oid = s.relid
		  WHERE s.schemaname NOT IN ('pg_catalog', 'information_schema')
		    AND s.schemaname NOT LIKE 'pg\_toast%' AND s.schemaname NOT LIKE 'pg\_temp\_%'
		    AND s.relid NOT IN (SELECT relation FROM locked)
		    AND NOT EXISTS (SELECT 1 FROM pg_index i
		                    WHERE i.indrelid = s.relid AND i.indexrelid IN (SELECT relation FROM locked))
		    AND (c.reltoastrelid = 0 OR c.reltoastrelid NOT IN (SELECT relation FROM locked))
		) t
		WHERE total_size >= $1::bigint
		ORDER BY total_size DESC, schemaname, relname
		LIMIT $2::int`

// ---- checkpoints ------------------------------------------------------------

// ckptSnap is one reading of the cumulative checkpoint counters.
type ckptSnap struct {
	at         time.Time
	timed, req int64
	reset      time.Time // stats_reset; zero when NULL
}

// checkpointSQL returns the query for the checkpoint counters: the
// pg_stat_checkpointer view exists from PostgreSQL 17, earlier versions keep the
// counters in pg_stat_bgwriter. Both return (timed, requested, stats_reset).
func checkpointSQL(versionNum int) string {
	if versionNum >= 170000 {
		return `SELECT num_timed, num_requested, stats_reset FROM pg_stat_checkpointer`
	}
	return `SELECT checkpoints_timed, checkpoints_req, stats_reset FROM pg_stat_bgwriter`
}

// advanceCheckpoints records cur in the history and returns the requested-
// checkpoint ratio over the shortest trailing window that holds at least
// checkpointMinCount checkpoints, or ok=false when no such window exists.
//
// For a busy server this is the interval delta between two collections. When an
// interval holds fewer than five checkpoints (the usual case: checkpoint_timeout
// defaults to 5 minutes and collection runs every 30 seconds) the window reaches
// further back, up to checkpointLookback, instead of reporting nothing. That keeps
// the series continuous, so the alert engine does not resolve and re-fire it.
//
// A counter that went backwards or a changed stats_reset means the statistics
// were reset (or the server restarted): the history is discarded and the ratio
// starts afresh, so a reset never produces a negative or bogus delta.
func advanceCheckpoints(hist []ckptSnap, cur ckptSnap) (newHist []ckptSnap, ratio float64, ok bool) {
	if n := len(hist); n > 0 {
		last := hist[n-1]
		if cur.timed < last.timed || cur.req < last.req || !cur.reset.Equal(last.reset) {
			return []ckptSnap{cur}, 0, false
		}
	}
	for _, s := range hist {
		if cur.at.Sub(s.at) <= checkpointLookback {
			newHist = append(newHist, s)
		}
	}
	for i := len(newHist) - 1; i >= 0; i-- {
		s := newHist[i]
		req := cur.req - s.req
		total := req + (cur.timed - s.timed)
		if total >= checkpointMinCount {
			ratio, ok = float64(req)/float64(total), true
			break
		}
	}
	return append(newHist, cur), ratio, ok
}

func (c *Collector) checkpoints(ctx context.Context, b *batch, si serverInfo) error {
	cur := ckptSnap{at: b.at}
	var reset *time.Time
	if err := c.conn.QueryRow(ctx, checkpointSQL(si.versionNum)).Scan(&cur.timed, &cur.req, &reset); err != nil {
		return err
	}
	if reset != nil {
		cur.reset = *reset
	}
	hist, ratio, ok := advanceCheckpoints(c.extra.ckpt, cur)
	c.extra.ckpt = hist
	if ok {
		b.add(rules.MetricPGCheckpointReqRatio, ratio, nil)
	}
	return nil
}

// ---- temp files and database size -------------------------------------------

// tempCounters is one reading of a database's cumulative temp_bytes.
type tempCounters struct {
	at    time.Time
	bytes int64
	reset time.Time // stats_reset; zero when NULL
}

// tempRate is the bytes-per-second rate between two readings. ok is false when
// the statistics were reset (counter went backwards or stats_reset changed) or
// the readings are too close together for a meaningful rate.
func tempRate(prev, cur tempCounters) (rate float64, ok bool) {
	d := cur.bytes - prev.bytes
	elapsed := cur.at.Sub(prev.at)
	if d < 0 || !cur.reset.Equal(prev.reset) || elapsed < minRateWindow {
		return 0, false
	}
	return float64(d) / elapsed.Seconds(), true
}

func (c *Collector) tempBytes(ctx context.Context, b *batch, _ serverInfo) error {
	rows, err := c.conn.Query(ctx, `
		SELECT datname::text, temp_bytes, stats_reset
		FROM pg_stat_database
		WHERE datname IS NOT NULL AND datname NOT IN `+excludedDatabases)
	if err != nil {
		return err
	}
	defer rows.Close()
	if c.extra.temp == nil {
		c.extra.temp = map[string]tempCounters{}
	}
	seen := map[string]bool{}
	for rows.Next() {
		var db string
		cur := tempCounters{at: b.at}
		var reset *time.Time
		if err := rows.Scan(&db, &cur.bytes, &reset); err != nil {
			return err
		}
		if reset != nil {
			cur.reset = *reset
		}
		seen[db] = true
		if prev, ok := c.extra.temp[db]; ok {
			if rate, ok := tempRate(prev, cur); ok {
				b.add(rules.MetricPGTempBytesRate, rate, map[string]string{"database": db})
			}
		}
		c.extra.temp[db] = cur
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for db := range c.extra.temp {
		if !seen[db] {
			delete(c.extra.temp, db)
		}
	}
	return nil
}

func (c *Collector) dbSize(ctx context.Context, b *batch, _ serverInfo) error {
	// pg_database_size needs CONNECT on the database or pg_read_all_stats
	// (pg_monitor includes it); skip databases it would refuse instead of failing
	// the whole group.
	rows, err := c.conn.Query(ctx, `
		SELECT datname::text, pg_database_size(oid)::float8
		FROM pg_database
		WHERE datallowconn AND datname NOT IN `+excludedDatabases+`
		  AND (has_database_privilege(oid, 'CONNECT') OR pg_has_role(current_user, 'pg_read_all_stats', 'USAGE'))
		ORDER BY datname`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var db string
		var size float64
		if err := rows.Scan(&db, &size); err != nil {
			return err
		}
		b.add(rules.MetricPGDBSize, size, map[string]string{"database": db})
	}
	return rows.Err()
}

// ---- pg_stat_statements -----------------------------------------------------

// statementsSQL returns the top-statements query. The total time column was
// renamed from total_time (PostgreSQL 12) to total_exec_time (13+). Statements
// are grouped by queryid across roles. The query text column is never selected.
func statementsSQL(versionNum int) string {
	col := "total_time"
	if versionNum >= 130000 {
		col = "total_exec_time"
	}
	return fmt.Sprintf(`
		SELECT COALESCE(d.datname::text, ''), s.queryid::text,
		       (sum(s.%s) / 1000.0)::float8, sum(s.calls)::float8, sum(s.rows)::float8
		FROM pg_stat_statements s
		LEFT JOIN pg_database d ON d.oid = s.dbid
		WHERE s.queryid IS NOT NULL
		GROUP BY d.datname, s.queryid
		ORDER BY 3 DESC, 1, 2
		LIMIT %d`, col, topStatements)
}

// statements reports the top statements by total execution time, only when the
// pg_stat_statements extension is installed in the connected database and loaded
// by the server. Labels are the database and the queryid, never the query text.
func (c *Collector) statements(ctx context.Context, b *batch, si serverInfo) error {
	var installed bool
	if err := c.conn.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements')`).Scan(&installed); err != nil {
		return err
	}
	if !installed {
		return nil
	}
	rows, err := c.conn.Query(ctx, statementsSQL(si.versionNum))
	if err != nil {
		return statementsErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		var db, queryID string
		var secs, calls, nrows float64
		if err := rows.Scan(&db, &queryID, &secs, &calls, &nrows); err != nil {
			return err
		}
		labels := map[string]string{"database": db, "queryid": queryID}
		b.add(rules.MetricPGStatementsTime, secs, labels)
		b.add(rules.MetricPGStatementsCalls, calls, labels)
		b.add(rules.MetricPGStatementsRows, nrows, labels)
	}
	return statementsErr(rows.Err())
}

// statementsErr turns "the extension is created but not loaded" (SQLSTATE 55000,
// object_not_in_prerequisite_state: shared_preload_libraries lacks
// pg_stat_statements) into "no data": that is a configuration state, not a
// collection failure that should mark every batch incomplete.
func statementsErr(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "55000" {
		return nil
	}
	return err
}

// ---- slow-group cache -------------------------------------------------------

type slowEntry struct {
	at      time.Time
	samples []model.Sample
}

// slow wraps an expensive group so it queries the server at most every
// slowGroupEvery. In between, the previous samples are re-emitted with the
// current timestamp. A failed refresh drops the cached entry (stale data is not
// served after an error) and reports the error.
func (c *Collector) slow(key string, fn groupFunc) groupFunc {
	return func(ctx context.Context, b *batch, si serverInfo) error {
		if e, ok := c.extra.slow[key]; ok {
			if age := b.at.Sub(e.at); age >= 0 && age < slowGroupEvery {
				for _, s := range e.samples {
					b.add(s.Metric, s.Value, cloneLabels(s.Labels))
				}
				return nil
			}
			delete(c.extra.slow, key)
		}
		sub := &batch{target: b.target, at: b.at}
		if err := fn(ctx, sub, si); err != nil {
			return err
		}
		if c.extra.slow == nil {
			c.extra.slow = map[string]slowEntry{}
		}
		c.extra.slow[key] = slowEntry{at: b.at, samples: sub.samples}
		b.samples = append(b.samples, sub.samples...)
		return nil
	}
}

func cloneLabels(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
