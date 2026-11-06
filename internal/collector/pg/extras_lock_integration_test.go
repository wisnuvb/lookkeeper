//go:build integration

package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/collector/pg"
	"github.com/wisnuvb/lockkeeper/internal/model"
	"github.com/wisnuvb/lockkeeper/internal/testutil"
)

// pg_total_relation_size() locks the table and its indexes; behind an ACCESS
// EXCLUSIVE lock it would stall every collection. The query must skip such
// tables instead of failing the whole batch.
func TestAutovacuumSkipsRelationsUnderAccessExclusiveLock(t *testing.T) {
	p := testutil.StartPG(t)
	admin := p.Admin(t)
	for _, q := range []string{
		"CREATE TABLE lk_locked (id int PRIMARY KEY, pad text) WITH (autovacuum_enabled = false)",
		"INSERT INTO lk_locked SELECT g, repeat('x', 100) FROM generate_series(1, 100000) g",
		"VACUUM lk_locked",
		"CREATE TABLE lk_free (id int PRIMARY KEY, pad text) WITH (autovacuum_enabled = false)",
		"INSERT INTO lk_free SELECT g, repeat('x', 100) FROM generate_series(1, 100000) g",
		"VACUUM lk_free",
	} {
		exec(t, admin, q)
	}
	flush(t, admin)

	holder := p.Admin(t)
	exec(t, holder, "BEGIN")
	exec(t, holder, "LOCK TABLE lk_locked IN ACCESS EXCLUSIVE MODE")
	t.Cleanup(func() { _, _ = holder.Exec(context.Background(), "ROLLBACK") })

	c := newCollectorWith(t, p.Spec(), pg.Options{Now: newClock(6 * time.Minute).Now, LargeTableBytes: 1 << 20})
	// A collection that stalled behind the lock would hit the 10s query timeout and
	// pollCollect would fail the test on the resulting error.
	samples := pollCollect(t, c, "lk_free to be reported", func(s []model.Sample) bool {
		_, ok := find(s, rules.MetricPGAutovacuumAge, map[string]string{"table": "lk_free"})
		return ok
	})
	if _, ok := find(samples, rules.MetricPGAutovacuumAge, map[string]string{"table": "lk_locked"}); ok {
		t.Error("a table under ACCESS EXCLUSIVE lock must be skipped")
	}
}
