package mysql

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	drv "github.com/go-sql-driver/mysql"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/model"
)

var t0 = time.Unix(1_700_000_000, 0)

func get(samples []model.Sample, metric string) (model.Sample, bool) {
	for _, s := range samples {
		if s.Metric == metric {
			return s, true
		}
	}
	return model.Sample{}, false
}

func mustGet(t *testing.T, samples []model.Sample, metric string) float64 {
	t.Helper()
	s, ok := get(samples, metric)
	if !ok {
		t.Fatalf("metric %s missing from %+v", metric, samples)
	}
	return s.Value
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func serverErr(n uint16, msg string) error { return &drv.MySQLError{Number: n, Message: msg} }

func TestCollectReportsDownAsData(t *testing.T) {
	boom := errors.New("connection refused")
	c := New("my-main", func(context.Context) (*sql.DB, error) { return nil, boom }, Options{
		Now: func() time.Time { return t0 },
	})
	samples, complete, err := c.Collect(context.Background())
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("expected the connect error to be wrapped, got %v", err)
	}
	if complete {
		t.Error("a failed collection must not be complete")
	}
	if len(samples) != 1 || samples[0].Metric != rules.MetricMySQLUp || samples[0].Value != 0 || samples[0].Target != "my-main" {
		t.Fatalf("expected a single my.up=0 sample, got %+v", samples)
	}
	if !samples[0].At.Equal(t0) {
		t.Errorf("sample time not taken from the injected clock: %v", samples[0].At)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close without a connection must be a no-op: %v", err)
	}
}

func TestCollectHealthyPrimary(t *testing.T) {
	f := healthyServer()
	ck := &clock{t0}
	c := newTestCollector(t, f, ck)

	samples, complete, err := c.Collect(context.Background())
	if err != nil || !complete {
		t.Fatalf("collect: complete=%v err=%v", complete, err)
	}
	if mustGet(t, samples, rules.MetricMySQLUp) != 1 {
		t.Error("my.up must be 1")
	}
	if got := mustGet(t, samples, rules.MetricMySQLConnectionsRatio); !near(got, 0.25) {
		t.Errorf("connections ratio = %v, want 0.25", got)
	}
	// Threads_running 3 includes the collector's own thread.
	if got := mustGet(t, samples, rules.MetricMySQLThreadsRunning); got != 2 {
		t.Errorf("threads running = %v, want 2 (own session excluded)", got)
	}
	if got := mustGet(t, samples, rules.MetricMySQLTrxOldest); got != 42 {
		t.Errorf("oldest trx = %v", got)
	}
	if got := mustGet(t, samples, rules.MetricMySQLHistoryListLength); got != 12345 {
		t.Errorf("history list = %v", got)
	}
	if got := mustGet(t, samples, rules.MetricMySQLBinlogDiskBytes); got != 3500 {
		t.Errorf("binlog bytes = %v", got)
	}
	// A primary has no replication samples; the first collection has no rates.
	for _, m := range []string{
		rules.MetricMySQLReplIORunning, rules.MetricMySQLReplSQLRunning, rules.MetricMySQLReplLag,
		rules.MetricMySQLSlowQueriesRate, rules.MetricMySQLRowLockWaitsRate, rules.MetricMySQLBufferPoolHit,
	} {
		if _, ok := get(samples, m); ok {
			t.Errorf("%s must not be emitted here: %+v", m, samples)
		}
	}
	for _, s := range samples {
		if s.Target != "my-main" || !s.At.Equal(t0) {
			t.Errorf("sample without target/time: %+v", s)
		}
	}
}

func TestCollectNeverIssuesHeavyOrWritingStatements(t *testing.T) {
	f := healthyServer()
	c := newTestCollector(t, f, &clock{t0})
	if _, _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.onRows("SELECT CURRENT_USER()", []string{"u"}, []any{"lockkeeper@%"})
	f.onRows("SHOW GRANTS", []string{"g"},
		[]any{"GRANT PROCESS, REPLICATION CLIENT ON *.* TO `lockkeeper`@`%`"})
	if _, err := c.Audit(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, q := range f.executed() {
		u := strings.ToUpper(strings.TrimSpace(q))
		for _, bad := range []string{"INSERT", "UPDATE ", "DELETE", "CREATE ", "DROP ", "ALTER ", "GRANT ", "SET ", "KILL", "FLUSH", "PURGE", "INNODB STATUS", "PROCESSLIST", "PERFORMANCE_SCHEMA.EVENTS_STATEMENTS", "SQL_TEXT", "INFO "} {
			if strings.Contains(u, bad) {
				t.Errorf("statement %q must not contain %q", q, bad)
			}
		}
		if !strings.HasPrefix(u, "SELECT") && !strings.HasPrefix(u, "SHOW") {
			t.Errorf("only SELECT and SHOW are allowed, got %q", q)
		}
	}
}

func TestRatesFromCounterDeltas(t *testing.T) {
	f := healthyServer()
	ck := &clock{t0}
	c := newTestCollector(t, f, ck)
	if _, _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}

	// 60 s later: 120 more slow queries, 600 more lock waits, and 100_000 more
	// logical reads of which 500 went to disk.
	ck.advance(60 * time.Second)
	f.onRows("SHOW GLOBAL STATUS", []string{"Variable_name", "Value"},
		[]any{"Threads_connected", "50"}, []any{"Threads_running", "1"}, []any{"Uptime", "1060"},
		[]any{"Slow_queries", "130"}, []any{"Innodb_row_lock_waits", "605"},
		[]any{"Innodb_buffer_pool_reads", "600"}, []any{"Innodb_buffer_pool_read_requests", "200000"})
	samples, complete, err := c.Collect(context.Background())
	if err != nil || !complete {
		t.Fatalf("collect: %v %v", complete, err)
	}
	if got := mustGet(t, samples, rules.MetricMySQLSlowQueriesRate); !near(got, 2) {
		t.Errorf("slow query rate = %v, want 2/s", got)
	}
	if got := mustGet(t, samples, rules.MetricMySQLRowLockWaitsRate); !near(got, 10) {
		t.Errorf("row lock wait rate = %v, want 10/s", got)
	}
	if got := mustGet(t, samples, rules.MetricMySQLBufferPoolHit); !near(got, 0.995) {
		t.Errorf("buffer pool hit = %v, want 0.995", got)
	}
	if got := mustGet(t, samples, rules.MetricMySQLThreadsRunning); got != 0 {
		t.Errorf("an idle server must read 0 running threads, got %v", got)
	}
}

func TestRatesSurviveServerRestart(t *testing.T) {
	f := healthyServer()
	ck := &clock{t0}
	c := newTestCollector(t, f, ck)
	if _, _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The server restarted: Uptime went down and every counter restarted from 0.
	ck.advance(30 * time.Second)
	f.onRows("SHOW GLOBAL STATUS", []string{"Variable_name", "Value"},
		[]any{"Threads_connected", "5"}, []any{"Threads_running", "1"}, []any{"Uptime", "12"},
		[]any{"Slow_queries", "0"}, []any{"Innodb_row_lock_waits", "0"},
		[]any{"Innodb_buffer_pool_reads", "50"}, []any{"Innodb_buffer_pool_read_requests", "500000"})
	samples, complete, err := c.Collect(context.Background())
	if err != nil || !complete {
		t.Fatalf("collect: %v %v", complete, err)
	}
	for _, m := range []string{rules.MetricMySQLSlowQueriesRate, rules.MetricMySQLRowLockWaitsRate, rules.MetricMySQLBufferPoolHit} {
		if _, ok := get(samples, m); ok {
			t.Errorf("%s must be skipped across a restart", m)
		}
	}
	// The new baseline is used from the next collection on.
	ck.advance(30 * time.Second)
	f.onRows("SHOW GLOBAL STATUS", []string{"Variable_name", "Value"},
		[]any{"Threads_connected", "5"}, []any{"Threads_running", "1"}, []any{"Uptime", "42"},
		[]any{"Slow_queries", "30"}, []any{"Innodb_row_lock_waits", "0"},
		[]any{"Innodb_buffer_pool_reads", "50"}, []any{"Innodb_buffer_pool_read_requests", "600000"})
	samples, _, err = c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := mustGet(t, samples, rules.MetricMySQLSlowQueriesRate); !near(got, 1) {
		t.Errorf("rate after the restart = %v, want 1/s", got)
	}
}

func TestBufferPoolHitGuards(t *testing.T) {
	mk := func(reads, req int64) map[string]int64 {
		return map[string]int64{varBufferPoolReads: reads, varBufferPoolRequest: req}
	}
	cases := []struct {
		name      string
		prev, cur map[string]int64
		want      float64
		ok        bool
	}{
		{"healthy", mk(0, 0), mk(100, 100_000), 0.999, true},
		{"poor", mk(1000, 1_000_000), mk(21_000, 1_100_000), 0.8, true},
		{"too little traffic", mk(0, 0), mk(5, 500), 0, false},
		{"reset", mk(900, 9_000_000), mk(10, 1_000), 0, false},
		{"no change", mk(5, 5), mk(5, 5), 0, false},
		{"missing counter", map[string]int64{}, mk(1, 1), 0, false},
	}
	for _, c := range cases {
		got, ok := bufferPoolHit(c.prev, c.cur)
		if ok != c.ok || (ok && !near(got, c.want)) {
			t.Errorf("%s: got (%v,%v), want (%v,%v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestCounterRateHandlesResetsAndGaps(t *testing.T) {
	prev := map[string]int64{"a": 100}
	if r, ok := counterRate(prev, map[string]int64{"a": 160}, "a", 30); !ok || !near(r, 2) {
		t.Errorf("got %v %v", r, ok)
	}
	if _, ok := counterRate(prev, map[string]int64{"a": 5}, "a", 30); ok {
		t.Error("a counter that went backwards must be skipped")
	}
	if _, ok := counterRate(prev, map[string]int64{}, "a", 30); ok {
		t.Error("a missing counter must be skipped")
	}
	if _, ok := counterRate(prev, map[string]int64{"a": 160}, "a", 0); ok {
		t.Error("zero elapsed time must be skipped")
	}
}

func TestUnsupportedServersAreRefused(t *testing.T) {
	cases := []struct {
		version, comment, want string
	}{
		{"10.11.6-MariaDB-1:10.11.6+maria~ubu2204", "mariadb.org binary distribution", "MariaDB"},
		{"5.5.5-10.6.12-MariaDB", "MariaDB Server", "MariaDB"},
		{"8.0.36", "MariaDB compatible", "MariaDB"},
		{"5.7.44", "MySQL Community Server (GPL)", "too old"},
		{"5.6.51", "MySQL", "too old"},
		{"8.1.0", "MySQL Community Server - GPL", "8.0 and 8.4 only"},
		{"9.0.1", "MySQL Community Server - GPL", "8.0 and 8.4 only"},
		{"", "", "cannot parse"},
	}
	for _, c := range cases {
		f := healthyServer()
		f.onRows("SELECT VERSION()", []string{"v", "c", "m"}, []any{c.version, c.comment, 100})
		col := newTestCollector(t, f, &clock{t0})
		samples, complete, err := col.Collect(context.Background())
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: error %v does not mention %q", c.version, err, c.want)
		}
		if complete {
			t.Errorf("%q: must be incomplete", c.version)
		}
		if len(samples) != 1 || samples[0].Metric != rules.MetricMySQLUp || samples[0].Value != 0 {
			t.Errorf("%q: expected only my.up=0, got %+v", c.version, samples)
		}
		for _, q := range f.executed() {
			if !strings.Contains(q, "VERSION()") {
				t.Errorf("%q: nothing but the version probe may run on an unsupported server, got %q", c.version, q)
			}
		}
	}
	for _, v := range []string{"8.0.36", "8.0.46", "8.4.0", "8.4.13", "8.0.mysql_aurora.3.05.2", "8.4.0-commercial"} {
		f := healthyServer()
		f.onRows("SELECT VERSION()", []string{"v", "c", "m"}, []any{v, "MySQL Community Server - GPL", 100})
		samples, _, err := newTestCollector(t, f, &clock{t0}).Collect(context.Background())
		if err != nil || mustGet(t, samples, rules.MetricMySQLUp) != 1 {
			t.Errorf("%s must be supported: %v", v, err)
		}
	}
}

func TestParseVersion(t *testing.T) {
	for in, want := range map[string][3]int{
		"8.0.36": {8, 0, 36}, "8.4.0-commercial": {8, 4, 0}, "8.0.mysql_aurora.3.05.2": {8, 0, -1},
		"10.11.6-MariaDB": {10, 11, 6}, "garbage": {0, 0, -1}, "": {0, 0, -1},
	} {
		a, b, c := parseVersion(in)
		if [3]int{a, b, c} != want {
			t.Errorf("parseVersion(%q) = %d.%d.%d, want %v", in, a, b, c, want)
		}
	}
}

func TestMissingProcessPrivilegeFailsOnlyItsGroups(t *testing.T) {
	f := healthyServer()
	denied := serverErr(1227, "Access denied; you need (at least one of) the PROCESS privilege(s) for this operation")
	f.onErr("INNODB_TRX", denied)
	f.onErr("INNODB_METRICS", denied)
	c := newTestCollector(t, f, &clock{t0})
	samples, complete, err := c.Collect(context.Background())
	if complete || err == nil {
		t.Fatalf("a missing privilege must make the batch incomplete (complete=%v err=%v)", complete, err)
	}
	if !strings.Contains(err.Error(), "PROCESS") || !strings.Contains(err.Error(), "transactions") || !strings.Contains(err.Error(), "history list") {
		t.Errorf("error should name the failing groups and the privilege: %v", err)
	}
	// Independent groups still delivered.
	for _, m := range []string{rules.MetricMySQLUp, rules.MetricMySQLConnectionsRatio, rules.MetricMySQLThreadsRunning, rules.MetricMySQLBinlogDiskBytes} {
		if _, ok := get(samples, m); !ok {
			t.Errorf("%s must still be collected: %+v", m, samples)
		}
	}
	if _, ok := get(samples, rules.MetricMySQLTrxOldest); ok {
		t.Error("no trx sample when the statement was refused")
	}
	// The connection is fine, so it is kept (no needless reconnect).
	if f.opens != 1 {
		t.Errorf("connection opened %d times", f.opens)
	}
}

func TestBinlogSkippedCleanly(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"binary logging off", serverErr(1381, "You are not using binary logging")},
		{"privilege missing", serverErr(1227, "Access denied; you need (at least one of) the SUPER, REPLICATION CLIENT privilege(s)")},
	} {
		f := healthyServer()
		f.onErr("SHOW BINARY LOGS", tc.err)
		samples, complete, err := newTestCollector(t, f, &clock{t0}).Collect(context.Background())
		if err != nil || !complete {
			t.Errorf("%s: must not fail the batch (complete=%v err=%v)", tc.name, complete, err)
		}
		if _, ok := get(samples, rules.MetricMySQLBinlogDiskBytes); ok {
			t.Errorf("%s: no binlog sample expected", tc.name)
		}
		if _, ok := get(samples, rules.MetricMySQLConnectionsRatio); !ok {
			t.Errorf("%s: other metrics must be unaffected", tc.name)
		}
	}
	// Any other error is a real failure.
	f := healthyServer()
	f.onErr("SHOW BINARY LOGS", serverErr(1064, "syntax"))
	if _, complete, err := newTestCollector(t, f, &clock{t0}).Collect(context.Background()); err == nil || complete {
		t.Error("an unexpected error must be reported")
	}
}

func TestHistoryListSkippedWhenCounterDisabled(t *testing.T) {
	f := healthyServer()
	f.onRows("INNODB_METRICS", []string{"count"}) // status = 'enabled' matches nothing
	samples, complete, err := newTestCollector(t, f, &clock{t0}).Collect(context.Background())
	if err != nil || !complete {
		t.Fatalf("a disabled counter is not an error: %v %v", complete, err)
	}
	if _, ok := get(samples, rules.MetricMySQLHistoryListLength); ok {
		t.Error("no history sample expected")
	}
}

func TestReplicationMissingPrivilegeIsIncompleteNotHealthy(t *testing.T) {
	f := healthyServer()
	f.onErr("SHOW REPLICA STATUS", serverErr(1227, "Access denied; you need (at least one of) the SUPER, REPLICATION CLIENT privilege(s)"))
	samples, complete, err := newTestCollector(t, f, &clock{t0}).Collect(context.Background())
	if complete || err == nil || !strings.Contains(err.Error(), "replication") {
		t.Errorf("an unreadable replica status must make the batch incomplete: %v %v", complete, err)
	}
	if _, ok := get(samples, rules.MetricMySQLReplIORunning); ok {
		t.Error("must not invent replication samples")
	}
}

func replicaCols(names ...string) []string { return names }

func TestReplicaSamples(t *testing.T) {
	cols := replicaCols("Replica_IO_State", "Replica_IO_Running", "Replica_SQL_Running", "Seconds_Behind_Source", "Channel_Name")
	for _, tc := range []struct {
		name         string
		row          []any
		io, sql, lag float64
		hasLag       bool
		labels       map[string]string
	}{
		{"healthy", []any{"Waiting for source", "Yes", "Yes", "7", ""}, 1, 1, 7, true, nil},
		{"caught up is a real 0", []any{"Waiting for source", "Yes", "Yes", "0", ""}, 1, 1, 0, true, nil},
		{"sql thread stopped: NULL lag", []any{"Waiting for source", "Yes", "No", nil, ""}, 1, 0, 0, false, nil},
		{"io thread stopped: NULL lag", []any{"", "No", "Yes", nil, ""}, 0, 1, 0, false, nil},
		{"connecting counts as not running", []any{"Connecting to source", "Connecting", "Yes", nil, ""}, 0, 1, 0, false, nil},
		{"named channel", []any{"Waiting for source", "Yes", "Yes", "3", "east"}, 1, 1, 3, true, map[string]string{"channel": "east"}},
	} {
		f := healthyServer()
		f.onRows("SHOW REPLICA STATUS", cols, tc.row)
		samples, complete, err := newTestCollector(t, f, &clock{t0}).Collect(context.Background())
		if err != nil || !complete {
			t.Fatalf("%s: %v %v", tc.name, complete, err)
		}
		if got := mustGet(t, samples, rules.MetricMySQLReplIORunning); got != tc.io {
			t.Errorf("%s: io_running = %v", tc.name, got)
		}
		if got := mustGet(t, samples, rules.MetricMySQLReplSQLRunning); got != tc.sql {
			t.Errorf("%s: sql_running = %v", tc.name, got)
		}
		lag, ok := get(samples, rules.MetricMySQLReplLag)
		if ok != tc.hasLag {
			t.Errorf("%s: lag present = %v, want %v (a NULL lag must NEVER become 0)", tc.name, ok, tc.hasLag)
		}
		if ok && lag.Value != tc.lag {
			t.Errorf("%s: lag = %v, want %v", tc.name, lag.Value, tc.lag)
		}
		io, _ := get(samples, rules.MetricMySQLReplIORunning)
		if model.SeriesKey("", io.Labels) != model.SeriesKey("", tc.labels) {
			t.Errorf("%s: labels = %v, want %v", tc.name, io.Labels, tc.labels)
		}
	}
}

func TestLegacyReplicaStatusOnOldEightZero(t *testing.T) {
	// 8.0.21 and earlier only know SHOW SLAVE STATUS and the old column names.
	f := healthyServer()
	f.onRows("SELECT VERSION()", []string{"v", "c", "m"}, []any{"8.0.21", "MySQL Community Server - GPL", 100})
	f.onRows("SHOW SLAVE STATUS", []string{"Slave_IO_Running", "Slave_SQL_Running", "Seconds_Behind_Master"}, []any{"Yes", "Yes", "12"})
	samples, complete, err := newTestCollector(t, f, &clock{t0}).Collect(context.Background())
	if err != nil || !complete {
		t.Fatalf("%v %v", complete, err)
	}
	if mustGet(t, samples, rules.MetricMySQLReplIORunning) != 1 || mustGet(t, samples, rules.MetricMySQLReplLag) != 12 {
		t.Errorf("legacy columns not understood: %+v", samples)
	}
	for _, q := range f.executed() {
		if strings.Contains(q, "SHOW REPLICA STATUS") {
			t.Errorf("SHOW REPLICA STATUS does not exist before 8.0.22: %q", q)
		}
	}

	// 8.0.22 and later (and 8.4, where SHOW SLAVE STATUS is gone) use the new syntax.
	for _, v := range []string{"8.0.22", "8.0.46", "8.4.13"} {
		f := healthyServer()
		f.onRows("SELECT VERSION()", []string{"v", "c", "m"}, []any{v, "MySQL Community Server - GPL", 100})
		if _, _, err := newTestCollector(t, f, &clock{t0}).Collect(context.Background()); err != nil {
			t.Fatal(err)
		}
		for _, q := range f.executed() {
			if strings.Contains(q, "SLAVE") {
				t.Errorf("%s must not use SHOW SLAVE STATUS: %q", v, q)
			}
		}
	}
}

func TestParseReplicaRowRecordedColumnSets(t *testing.T) {
	// Column sets as printed by SHOW REPLICA STATUS on 8.0.22+ / 8.4 and by
	// SHOW SLAVE STATUS on older 8.0 (abridged to the columns that matter, in the
	// real order). Values mirror a healthy replica.
	row := func(kv ...string) map[string]sql.NullString {
		m := map[string]sql.NullString{}
		for i := 0; i < len(kv); i += 2 {
			if kv[i+1] == "<NULL>" {
				m[kv[i]] = sql.NullString{}
			} else {
				m[kv[i]] = sql.NullString{String: kv[i+1], Valid: true}
			}
		}
		return m
	}
	st, err := parseReplicaRow(row("Replica_IO_State", "Waiting for source to send event", "Source_Host", "src", "Replica_IO_Running", "Yes", "Replica_SQL_Running", "Yes", "Seconds_Behind_Source", "0", "Channel_Name", ""))
	if err != nil || !st.IORunning || !st.SQLRunning || !st.LagValid || st.Lag != 0 {
		t.Errorf("8.4 layout: %+v %v", st, err)
	}
	st, err = parseReplicaRow(row("Slave_IO_State", "Waiting for master to send event", "Master_Host", "src", "Slave_IO_Running", "Yes", "Slave_SQL_Running", "No", "Seconds_Behind_Master", "<NULL>", "Channel_Name", ""))
	if err != nil || !st.IORunning || st.SQLRunning || st.LagValid {
		t.Errorf("legacy layout: %+v %v", st, err)
	}
	// A layout we do not know must be an error, not a silent "not running".
	if _, err := parseReplicaRow(row("Something_Else", "Yes")); err == nil {
		t.Error("an unknown column layout must fail loudly")
	}
	if _, err := parseReplicaRow(row("Replica_IO_Running", "Yes")); err == nil {
		t.Error("a missing SQL thread column must fail loudly")
	}
	// Negative lag (clock skew) is clamped, garbage is ignored.
	if st, _ := parseReplicaRow(row("Replica_IO_Running", "Yes", "Replica_SQL_Running", "Yes", "Seconds_Behind_Source", "-3")); !st.LagValid || st.Lag != 0 {
		t.Errorf("negative lag: %+v", st)
	}
	if st, _ := parseReplicaRow(row("Replica_IO_Running", "Yes", "Replica_SQL_Running", "Yes", "Seconds_Behind_Source", "abc")); st.LagValid {
		t.Errorf("unparsable lag must not become a sample: %+v", st)
	}
}

func TestBrokenConnectionIsDroppedAndReopened(t *testing.T) {
	f := healthyServer()
	c := newTestCollector(t, f, &clock{t0})
	if _, _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A transport-level failure (not an answer from the server) in the middle of
	// the batch: the remaining groups are skipped and the next call reconnects.
	f.onErr("INNODB_TRX", errors.New("invalid connection"))
	samples, complete, err := c.Collect(context.Background())
	if complete || err == nil {
		t.Fatalf("expected an incomplete batch: %v %v", complete, err)
	}
	if _, ok := get(samples, rules.MetricMySQLBinlogDiskBytes); ok {
		t.Error("groups after a transport failure must be skipped")
	}
	f.onRows("INNODB_TRX", []string{"age"}, []any{1})
	if _, complete, err := c.Collect(context.Background()); err != nil || !complete {
		t.Fatalf("must recover on the next collection: %v %v", complete, err)
	}
	if f.opens != 2 {
		t.Errorf("expected a reconnect, opens = %d", f.opens)
	}
}

func TestServerInfoFailureReportsDown(t *testing.T) {
	f := healthyServer()
	f.onErr("SELECT VERSION()", errors.New("driver: bad connection"))
	samples, complete, err := newTestCollector(t, f, &clock{t0}).Collect(context.Background())
	if err == nil || complete {
		t.Fatalf("%v %v", complete, err)
	}
	if len(samples) != 1 || samples[0].Metric != rules.MetricMySQLUp || samples[0].Value != 0 {
		t.Errorf("got %+v", samples)
	}
}

func TestDefaultRulesCoverEveryEmittedMetric(t *testing.T) {
	have := map[string]bool{}
	for _, r := range rules.MySQLDefaults() {
		if err := r.Validate(); err != nil {
			t.Errorf("invalid default rule: %v", err)
		}
		have[r.Metric] = true
	}
	for _, m := range []string{
		rules.MetricMySQLUp, rules.MetricMySQLConnectionsRatio, rules.MetricMySQLThreadsRunning, rules.MetricMySQLTrxOldest,
		rules.MetricMySQLReplIORunning, rules.MetricMySQLReplSQLRunning, rules.MetricMySQLReplLag, rules.MetricMySQLSlowQueriesRate,
		rules.MetricMySQLBufferPoolHit, rules.MetricMySQLRowLockWaitsRate, rules.MetricMySQLHistoryListLength, rules.MetricMySQLBinlogDiskBytes,
	} {
		if !have[m] {
			t.Errorf("no default rule for %s", m)
		}
		if !strings.HasPrefix(m, "my.") {
			t.Errorf("metric %s is not under my.", m)
		}
	}
}
