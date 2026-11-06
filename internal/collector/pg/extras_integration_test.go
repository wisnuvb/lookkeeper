//go:build integration

package pg_test

import (
	"context"
	"fmt"
	"strconv"
	"strings"
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

// stepClock advances by step on every call, so each Collect sees a later time:
// rate windows are not empty and the five-minute cache of the slow groups never
// serves a stale result between polls.
type stepClock struct {
	t    time.Time
	step time.Duration
}

func (c *stepClock) Now() time.Time { c.t = c.t.Add(c.step); return c.t }

func newClock(step time.Duration) *stepClock {
	return &stepClock{t: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC), step: step}
}

func newCollectorWith(t *testing.T, spec dbconn.PGSpec, opts pg.Options) *pg.Collector {
	t.Helper()
	opts.QueryTimeout = 10 * time.Second
	c := pg.New("test", func(ctx context.Context) (*pgx.Conn, error) { return dbconn.OpenPG(ctx, spec) }, opts)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// flush closes a session so the server flushes its pending statistics at once
// (otherwise they can lag by several seconds).
func flush(t *testing.T, conn *pgx.Conn) {
	t.Helper()
	if err := conn.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func serverVersion(t *testing.T, conn *pgx.Conn) int {
	t.Helper()
	var v int
	if err := conn.QueryRow(context.Background(), "SELECT current_setting('server_version_num')::int").Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// pollCollect collects every 100ms until ready returns true, failing the test
// after 40s. It returns the samples of the last, successful collection.
func pollCollect(t *testing.T, c *pg.Collector, what string, ready func([]model.Sample) bool) []model.Sample {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	for {
		samples, complete, err := c.Collect(context.Background())
		if err != nil || !complete {
			t.Fatalf("collect while waiting for %s: complete=%v err=%v", what, complete, err)
		}
		if ready(samples) {
			return samples
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func all(samples []model.Sample, metric string) []model.Sample {
	var out []model.Sample
	for _, s := range samples {
		if s.Metric == metric {
			out = append(out, s)
		}
	}
	return out
}

func TestDeadTupleRatio(t *testing.T) {
	p := testutil.StartPG(t)
	admin := p.Admin(t)
	for _, q := range []string{
		"CREATE TABLE dead_big (id int) WITH (autovacuum_enabled = false)",
		"INSERT INTO dead_big SELECT g FROM generate_series(1, 150000) g",
		"DELETE FROM dead_big WHERE id <= 120000", // 120k dead, 30k live
		"CREATE TABLE dead_small (id int) WITH (autovacuum_enabled = false)",
		"INSERT INTO dead_small SELECT g FROM generate_series(1, 2000) g",
		"DELETE FROM dead_small WHERE id <= 1800", // far below the 100k floor
		"CREATE SCHEMA other",
		"CREATE TABLE other.dead_other (id int) WITH (autovacuum_enabled = false)",
		"INSERT INTO other.dead_other SELECT g FROM generate_series(1, 110000) g",
		"DELETE FROM other.dead_other WHERE id <= 100000", // 100k dead (the floor), 10k live
	} {
		exec(t, admin, q)
	}
	flush(t, admin)

	c := newCollectorWith(t, p.Spec(), pg.Options{Now: newClock(6 * time.Minute).Now})
	big := map[string]string{"database": "postgres", "schema": "public", "table": "dead_big"}
	samples := pollCollect(t, c, "dead_big", func(s []model.Sample) bool {
		_, ok := find(s, rules.MetricPGTableDeadRatio, big)
		return ok
	})
	if s, _ := find(samples, rules.MetricPGTableDeadRatio, big); s.Value < 0.75 || s.Value > 0.85 {
		t.Errorf("dead_big ratio = %v, want about 0.8", s.Value)
	}
	other, ok := find(samples, rules.MetricPGTableDeadRatio, map[string]string{"schema": "other", "table": "dead_other"})
	if !ok || other.Value < 0.85 || other.Value > 0.95 {
		t.Errorf("a table exactly at the floor must be reported (ratio about 0.91): %+v", other)
	}
	for _, s := range all(samples, rules.MetricPGTableDeadRatio) {
		switch s.Labels["table"] {
		case "dead_big", "dead_other":
		default:
			t.Errorf("unexpected dead-tuple series (below the floor or a system table): %+v", s)
		}
		if s.Labels["schema"] == "pg_catalog" || s.Labels["schema"] == "information_schema" || strings.HasPrefix(s.Labels["schema"], "pg_toast") {
			t.Errorf("system schema leaked: %+v", s)
		}
	}
}

func TestDeadTuplesAreLimitedToTheTopTwenty(t *testing.T) {
	p := testutil.StartPG(t)
	admin := p.Admin(t)
	for i := 0; i < 22; i++ {
		exec(t, admin, fmt.Sprintf("CREATE UNLOGGED TABLE top_%02d (id int) WITH (autovacuum_enabled = false)", i))
		// Table i ends up with 100000 + i*500 dead tuples and no live ones.
		exec(t, admin, fmt.Sprintf("INSERT INTO top_%02d SELECT g FROM generate_series(1, %d) g", i, 100000+i*500))
		exec(t, admin, fmt.Sprintf("DELETE FROM top_%02d", i))
	}
	flush(t, admin)

	c := newCollectorWith(t, p.Spec(), pg.Options{Now: newClock(6 * time.Minute).Now})
	samples := pollCollect(t, c, "all 22 tables to be counted", func(s []model.Sample) bool {
		_, ok := find(s, rules.MetricPGTableDeadRatio, map[string]string{"table": "top_21"})
		return ok
	})
	got := all(samples, rules.MetricPGTableDeadRatio)
	if len(got) != 20 {
		t.Fatalf("want exactly the top 20 tables, got %d", len(got))
	}
	for _, s := range got {
		if s.Labels["table"] == "top_00" || s.Labels["table"] == "top_01" {
			t.Errorf("the two tables with the fewest dead tuples must be cut: %+v", s)
		}
	}
}

func TestAutovacuumAge(t *testing.T) {
	p := testutil.StartPG(t)
	admin := p.Admin(t)
	for _, q := range []string{
		"CREATE TABLE av_vacuumed (id int, pad text) WITH (autovacuum_enabled = false)",
		"INSERT INTO av_vacuumed SELECT g, repeat('x', 100) FROM generate_series(1, 100000) g",
		"VACUUM av_vacuumed",
		"CREATE TABLE av_never (id int, pad text) WITH (autovacuum_enabled = false)",
		"INSERT INTO av_never SELECT g, repeat('x', 100) FROM generate_series(1, 100000) g",
		"CREATE TABLE av_small (id int) WITH (autovacuum_enabled = false)",
		"INSERT INTO av_small SELECT g FROM generate_series(1, 10) g",
		"VACUUM av_small",
	} {
		exec(t, admin, q)
	}
	flush(t, admin)

	// The real threshold is 1 GiB; the test lowers it so it needs no huge table.
	c := newCollectorWith(t, p.Spec(), pg.Options{Now: newClock(6 * time.Minute).Now, LargeTableBytes: 1 << 20})
	vac := map[string]string{"database": "postgres", "schema": "public", "table": "av_vacuumed"}
	samples := pollCollect(t, c, "the vacuum of av_vacuumed to appear in the statistics", func(s []model.Sample) bool {
		_, ok := find(s, rules.MetricPGAutovacuumAge, vac)
		return ok
	})
	age, _ := find(samples, rules.MetricPGAutovacuumAge, vac)
	if age.Value < 0 || age.Value > 300 {
		t.Errorf("age of a table vacuumed seconds ago = %v", age.Value)
	}
	never := map[string]string{"table": "av_never"}
	if _, ok := find(samples, rules.MetricPGAutovacuumAge, never); ok {
		t.Error("a never-vacuumed table must not get an age (0 would look healthy, a big number would be a false alarm)")
	}
	if s, ok := find(samples, rules.MetricPGAutovacuumNeverVacuumed, never); !ok || s.Value != 1 {
		t.Errorf("a never-vacuumed large table must be flagged: %+v", s)
	}
	if _, ok := find(samples, rules.MetricPGAutovacuumNeverVacuumed, vac); ok {
		t.Error("a vacuumed table must not be flagged as never vacuumed")
	}
	for _, m := range []string{rules.MetricPGAutovacuumAge, rules.MetricPGAutovacuumNeverVacuumed} {
		if _, ok := find(samples, m, map[string]string{"table": "av_small"}); ok {
			t.Errorf("%s: a table below the size threshold must not be reported", m)
		}
	}

	// With the production threshold (1 GiB) none of these small tables qualifies.
	c2 := newCollectorWith(t, p.Spec(), pg.Options{})
	samples, complete, err := c2.Collect(context.Background())
	if err != nil || !complete {
		t.Fatal(err)
	}
	if n := len(all(samples, rules.MetricPGAutovacuumAge)) + len(all(samples, rules.MetricPGAutovacuumNeverVacuumed)); n != 0 {
		t.Errorf("no table is 1 GiB here, got %d autovacuum samples", n)
	}
}

func TestCheckpointRatioAndReset(t *testing.T) {
	p := testutil.StartPG(t)
	admin := p.Admin(t)
	version := serverVersion(t, admin)
	resetTarget := "bgwriter"
	if version >= 170000 {
		resetTarget = "checkpointer" // the counters moved to pg_stat_checkpointer in 17
	}

	clock := newClock(30 * time.Second)
	c := newCollectorWith(t, p.Spec(), pg.Options{Now: clock.Now})
	collect := func() []model.Sample {
		s, complete, err := c.Collect(context.Background())
		if err != nil || !complete {
			t.Fatalf("collect: complete=%v err=%v", complete, err)
		}
		return s
	}
	if _, ok := find(collect(), rules.MetricPGCheckpointReqRatio, nil); ok {
		t.Fatal("the first collection has no baseline and must not report a ratio")
	}

	// Manual CHECKPOINT commands are counted as requested checkpoints.
	runCheckpoints := func(n int) {
		for i := 0; i < n; i++ {
			exec(t, admin, "CHECKPOINT")
		}
	}
	runCheckpoints(7)
	samples := pollCollect(t, c, "checkpoint ratio", func(s []model.Sample) bool {
		_, ok := find(s, rules.MetricPGCheckpointReqRatio, nil)
		return ok
	})
	ratio, _ := find(samples, rules.MetricPGCheckpointReqRatio, nil)
	if ratio.Value < 0.5 || ratio.Value > 1 {
		t.Errorf("ratio after 7 manual checkpoints = %v, want > 0.5 (version %d, view %s)", ratio.Value, version, resetTarget)
	}

	// A statistics reset must discard the history instead of yielding a bogus delta.
	exec(t, admin, fmt.Sprintf("SELECT pg_stat_reset_shared('%s')", resetTarget))
	deadline := time.Now().Add(20 * time.Second)
	for { // wait until the reset is visible, then the next collection must be silent
		var n int64
		q := "SELECT checkpoints_req FROM pg_stat_bgwriter"
		if version >= 170000 {
			q = "SELECT num_requested FROM pg_stat_checkpointer"
		}
		if err := admin.QueryRow(context.Background(), q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n < 7 || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, ok := find(collect(), rules.MetricPGCheckpointReqRatio, nil); ok {
		t.Error("the collection right after a statistics reset must not report a ratio")
	}
	runCheckpoints(6)
	pollCollect(t, c, "the ratio to resume after the reset", func(s []model.Sample) bool {
		v, ok := find(s, rules.MetricPGCheckpointReqRatio, nil)
		if ok && (v.Value < 0 || v.Value > 1) {
			t.Fatalf("ratio out of range after a reset: %v", v.Value)
		}
		return ok
	})
}

func TestTempBytesRateAndDatabaseSize(t *testing.T) {
	p := testutil.StartPG(t)
	clock := newClock(10 * time.Second)
	c := newCollectorWith(t, p.Spec(), pg.Options{Now: clock.Now})

	samples, complete, err := c.Collect(context.Background())
	if err != nil || !complete {
		t.Fatalf("baseline collect: complete=%v err=%v", complete, err)
	}
	if size, ok := find(samples, rules.MetricPGDBSize, map[string]string{"database": "postgres"}); !ok || size.Value < 5<<20 {
		t.Errorf("pg.db.size_bytes for postgres missing or implausible: %+v", size)
	}
	for _, db := range []string{"template0", "template1"} {
		if _, ok := find(samples, rules.MetricPGDBSize, map[string]string{"database": db}); ok {
			t.Errorf("template database %s must not be reported", db)
		}
	}
	if len(all(samples, rules.MetricPGTempBytesRate)) != 0 {
		t.Error("a rate needs two readings: the first collection must not report one")
	}

	// Force a sort to spill to temporary files.
	spill := p.Admin(t)
	exec(t, spill, "SET work_mem = '64kB'")
	exec(t, spill, "SELECT count(*) FROM (SELECT g FROM generate_series(1, 300000) g ORDER BY g DESC) s")
	flush(t, spill)

	samples = pollCollect(t, c, "temp_bytes to grow", func(s []model.Sample) bool {
		r, ok := find(s, rules.MetricPGTempBytesRate, map[string]string{"database": "postgres"})
		return ok && r.Value > 0
	})
	rate, _ := find(samples, rules.MetricPGTempBytesRate, map[string]string{"database": "postgres"})
	// A 300k-row sort with 64kB of work_mem writes megabytes; the clock steps 10s per collect.
	if rate.Value <= 0 || rate.Value > 1e9 {
		t.Errorf("implausible temp rate %v", rate.Value)
	}
}

func TestStatementsOnlyWhenTheExtensionExists(t *testing.T) {
	p := testutil.StartPG(t, "shared_preload_libraries=pg_stat_statements")
	admin := p.Admin(t)
	c := newCollectorWith(t, p.Spec(), pg.Options{Now: newClock(6 * time.Minute).Now})

	samples, complete, err := c.Collect(context.Background())
	if err != nil || !complete {
		t.Fatalf("collect without the extension must be clean: complete=%v err=%v", complete, err)
	}
	for _, s := range samples {
		if strings.HasPrefix(s.Metric, "pg.statements.") {
			t.Fatalf("no pg_stat_statements extension, yet %+v", s)
		}
	}

	exec(t, admin, "CREATE EXTENSION pg_stat_statements")
	for i := 0; i < 12; i++ { // 12 distinct statements (distinct relations give distinct queryids)
		exec(t, admin, fmt.Sprintf("CREATE TABLE st_%02d AS SELECT g FROM generate_series(1, %d) g", i, 1000*(i+1)))
		exec(t, admin, fmt.Sprintf("SELECT count(*), 'CANARY-LITERAL-8842' FROM st_%02d", i))
	}
	flush(t, admin)

	samples, complete, err = c.Collect(context.Background())
	if err != nil || !complete {
		t.Fatalf("collect with the extension: complete=%v err=%v", complete, err)
	}
	times := all(samples, rules.MetricPGStatementsTime)
	if len(times) != 10 {
		t.Fatalf("want the top 10 statements, got %d", len(times))
	}
	prev := -1.0
	for _, s := range times {
		if len(s.Labels) != 2 || s.Labels["database"] == "" {
			t.Errorf("labels must be exactly database + queryid: %v", s.Labels)
		}
		if _, err := strconv.ParseInt(s.Labels["queryid"], 10, 64); err != nil {
			t.Errorf("queryid %q is not an integer", s.Labels["queryid"])
		}
		if s.Value < 0 {
			t.Errorf("negative total time: %+v", s)
		}
		if prev >= 0 && s.Value > prev {
			t.Errorf("statements must be ordered by total time, descending")
		}
		prev = s.Value
		if _, ok := find(samples, rules.MetricPGStatementsCalls, s.Labels); !ok {
			t.Errorf("no calls series for %v", s.Labels)
		}
		if _, ok := find(samples, rules.MetricPGStatementsRows, s.Labels); !ok {
			t.Errorf("no rows series for %v", s.Labels)
		}
	}
	for _, s := range samples { // T10: no query text, not even a literal, anywhere
		if strings.Contains(s.Metric, "CANARY") {
			t.Errorf("query text leaked into a metric name: %+v", s)
		}
		for k, v := range s.Labels {
			if strings.Contains(k, "CANARY") || strings.Contains(v, "CANARY") || strings.Contains(strings.ToLower(v), "select ") {
				t.Errorf("query text leaked into a label: %+v", s)
			}
		}
	}
}

func TestStatementsExtensionCreatedButNotPreloaded(t *testing.T) {
	p := testutil.StartPG(t) // no shared_preload_libraries
	exec(t, p.Admin(t), "CREATE EXTENSION pg_stat_statements")
	c := newCollectorWith(t, p.Spec(), pg.Options{})
	samples, complete, err := c.Collect(context.Background())
	if err != nil || !complete {
		t.Fatalf("an extension that is created but not loaded is a configuration state, not a failure: complete=%v err=%v", complete, err)
	}
	if n := len(all(samples, rules.MetricPGStatementsTime)); n != 0 {
		t.Errorf("expected no statements samples, got %d", n)
	}
}

// The extra metrics must work for the least-privilege role the docs recommend
// (LOGIN + pg_monitor), not only for a superuser.
func TestExtraMetricsAsLeastPrivilegeRole(t *testing.T) {
	p := testutil.StartPG(t, "shared_preload_libraries=pg_stat_statements")
	admin := p.Admin(t)
	for _, q := range []string{
		"CREATE EXTENSION pg_stat_statements",
		"CREATE ROLE lk_mon LOGIN PASSWORD 'monpw'",
		"GRANT pg_monitor TO lk_mon",
		"CREATE TABLE mon_dead (id int, pad text) WITH (autovacuum_enabled = false)",
		"INSERT INTO mon_dead SELECT g, repeat('x', 50) FROM generate_series(1, 150000) g",
		"DELETE FROM mon_dead WHERE id <= 120000",
		"CREATE TABLE mon_vac (id int, pad text) WITH (autovacuum_enabled = false)",
		"INSERT INTO mon_vac SELECT g, repeat('x', 100) FROM generate_series(1, 100000) g",
		"VACUUM mon_vac",
		"SELECT count(*) FROM mon_dead",
	} {
		exec(t, admin, q)
	}
	flush(t, admin)

	spec := p.Spec()
	spec.User, spec.Password = "lk_mon", secret.New("monpw")
	c := newCollectorWith(t, spec, pg.Options{Now: newClock(6 * time.Minute).Now, LargeTableBytes: 1 << 20})
	samples := pollCollect(t, c, "dead tuples as pg_monitor", func(s []model.Sample) bool {
		_, ok := find(s, rules.MetricPGTableDeadRatio, map[string]string{"table": "mon_dead"})
		return ok
	})
	if _, ok := find(samples, rules.MetricPGDBSize, map[string]string{"database": "postgres"}); !ok {
		t.Error("database size must be readable with pg_monitor")
	}
	if len(all(samples, rules.MetricPGStatementsTime)) == 0 {
		t.Error("pg_monitor (pg_read_all_stats) must be able to read pg_stat_statements")
	}
	pollCollect(t, c, "autovacuum age as pg_monitor", func(s []model.Sample) bool {
		_, ok := find(s, rules.MetricPGAutovacuumAge, map[string]string{"table": "mon_vac"})
		return ok
	})
}
