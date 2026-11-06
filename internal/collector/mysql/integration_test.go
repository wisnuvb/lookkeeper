//go:build integration

package mysql_test

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	drv "github.com/go-sql-driver/mysql"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/collector/mysql"
	"github.com/wisnuvb/lockkeeper/internal/dbconn"
	"github.com/wisnuvb/lockkeeper/internal/model"
	"github.com/wisnuvb/lockkeeper/internal/secret"
	"github.com/wisnuvb/lockkeeper/internal/testutil"
)

func newCollector(t *testing.T, spec dbconn.MySQLSpec) *mysql.Collector {
	t.Helper()
	c := mysql.New("test", func(ctx context.Context) (*sql.DB, error) { return dbconn.OpenMySQL(ctx, spec) },
		mysql.Options{QueryTimeout: 10 * time.Second})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func find(samples []model.Sample, metric string) (model.Sample, bool) {
	for _, s := range samples {
		if s.Metric == metric {
			return s, true
		}
	}
	return model.Sample{}, false
}

func must(t *testing.T, samples []model.Sample, metric string) float64 {
	t.Helper()
	s, ok := find(samples, metric)
	if !ok {
		t.Fatalf("metric %s missing: %+v", metric, samples)
	}
	return s.Value
}

func collectOK(t *testing.T, c *mysql.Collector) []model.Sample {
	t.Helper()
	samples, complete, err := c.Collect(context.Background())
	if err != nil || !complete {
		t.Fatalf("collect: complete=%v err=%v", complete, err)
	}
	return samples
}

// collectUntil collects every second until cond holds.
func collectUntil(t *testing.T, c *mysql.Collector, timeout time.Duration, what string, cond func([]model.Sample) bool) []model.Sample {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		samples := collectOK(t, c)
		if cond(samples) {
			return samples
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s; last samples: %+v", what, samples)
		}
		time.Sleep(time.Second)
	}
}

func TestCollectAgainstRealMySQL(t *testing.T) {
	// A system zone (New York) that differs from the server's default zone (+09:00)
	// catches clock mix-ups in the transaction age: INNODB_TRX prints times in the
	// system zone. The long_query_time makes slow queries easy to produce.
	m := testutil.StartMySQLWith(t, testutil.MySQLOptions{
		Env:  []string{"TZ=America/New_York"},
		Args: []string{"--default-time-zone=+09:00", "--long-query-time=0.2"},
	})
	t.Logf("image under test: %s", testutil.MySQLImage())
	admin := m.Admin(t)
	c := newCollector(t, m.Spec())

	m.MustExec(t, admin,
		"CREATE DATABASE lk_it",
		"CREATE TABLE lk_it.t (id INT AUTO_INCREMENT PRIMARY KEY, payload VARCHAR(200)) ENGINE=InnoDB",
	)
	loader := m.Session(t)
	for _, q := range []string{
		"SET SESSION cte_max_recursion_depth = 100000",
		"INSERT INTO lk_it.t (payload) WITH RECURSIVE n AS (SELECT 1 AS i UNION ALL SELECT i + 1 FROM n WHERE i < 30000) SELECT REPEAT('x', 100) FROM n",
	} {
		if _, err := loader.ExecContext(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("baseline", func(t *testing.T) {
		samples := collectOK(t, c)
		if must(t, samples, rules.MetricMySQLUp) != 1 {
			t.Error("my.up must be 1")
		}
		if r := must(t, samples, rules.MetricMySQLConnectionsRatio); r <= 0 || r >= 1 {
			t.Errorf("connection ratio must be in (0,1), got %v", r)
		}
		// An otherwise idle server: the background threads of the server may
		// count, our own session must not.
		if r := must(t, samples, rules.MetricMySQLThreadsRunning); r < 0 || r > 2 {
			t.Errorf("running threads on an idle server = %v", r)
		}
		if v := must(t, samples, rules.MetricMySQLTrxOldest); v != 0 {
			t.Errorf("no transaction is open, got %v", v)
		}
		if v := must(t, samples, rules.MetricMySQLHistoryListLength); v < 0 {
			t.Errorf("history list length = %v", v)
		}
		if v := must(t, samples, rules.MetricMySQLBinlogDiskBytes); v <= 0 {
			t.Errorf("binary logging is on, size must be > 0: %v", v)
		}
		for _, mtr := range []string{rules.MetricMySQLReplIORunning, rules.MetricMySQLReplSQLRunning, rules.MetricMySQLReplLag} {
			if _, ok := find(samples, mtr); ok {
				t.Errorf("a primary must not report %s", mtr)
			}
		}
		for _, s := range samples {
			if s.Target != "test" || s.At.IsZero() {
				t.Errorf("sample without target/time: %+v", s)
			}
		}
	})

	t.Run("running threads", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = admin.ExecContext(context.Background(), "SELECT SLEEP(6)")
			}()
		}
		defer wg.Wait()
		samples := collectUntil(t, c, 5*time.Second, "3 more running threads", func(s []model.Sample) bool {
			return must(t, s, rules.MetricMySQLThreadsRunning) >= 3
		})
		t.Logf("threads running with 3 sleepers: %v", must(t, samples, rules.MetricMySQLThreadsRunning))
	})

	t.Run("open transaction", func(t *testing.T) {
		holder := m.Session(t)
		if _, err := holder.ExecContext(context.Background(), "START TRANSACTION WITH CONSISTENT SNAPSHOT"); err != nil {
			t.Fatal(err)
		}
		samples := collectUntil(t, c, 20*time.Second, "oldest transaction >= 2s", func(s []model.Sample) bool {
			return must(t, s, rules.MetricMySQLTrxOldest) >= 2
		})
		// A mix-up between the zones (session +09:00, system New York) would show up as hours.
		if age := must(t, samples, rules.MetricMySQLTrxOldest); age > 60 {
			t.Errorf("transaction age %vs is implausible (time zone mix-up?)", age)
		}
		if _, err := holder.ExecContext(context.Background(), "ROLLBACK"); err != nil {
			t.Fatal(err)
		}
		collectUntil(t, c, 10*time.Second, "transaction gone", func(s []model.Sample) bool {
			return must(t, s, rules.MetricMySQLTrxOldest) == 0
		})
	})

	t.Run("rates from slow queries, row lock waits and buffer pool traffic", func(t *testing.T) {
		m.MustExec(t, admin, `CREATE PROCEDURE lk_it.burn() BEGIN
			DECLARE i INT DEFAULT 0;
			WHILE i < 20000 DO
				SELECT COUNT(*) INTO @x FROM lk_it.t WHERE id = (i % 1000) + 1;
				SET i = i + 1;
			END WHILE;
		END`)
		collectOK(t, c) // baseline for the counters
		start := time.Now()

		for i := 0; i < 3; i++ {
			if _, err := admin.ExecContext(context.Background(), "SELECT SLEEP(0.5)"); err != nil {
				t.Fatal(err)
			}
		}

		// A row lock wait: A holds the row, B waits for it.
		a := m.Session(t)
		b := m.Session(t)
		if _, err := a.ExecContext(context.Background(), "BEGIN"); err != nil {
			t.Fatal(err)
		}
		if _, err := a.ExecContext(context.Background(), "UPDATE lk_it.t SET payload = 'a' WHERE id = 1"); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := b.ExecContext(context.Background(), "UPDATE lk_it.t SET payload = 'b' WHERE id = 1")
			done <- err
		}()
		time.Sleep(1500 * time.Millisecond)
		if _, err := a.ExecContext(context.Background(), "COMMIT"); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}

		if _, err := admin.ExecContext(context.Background(), "CALL lk_it.burn()"); err != nil {
			t.Fatal(err)
		}
		if rest := 1200*time.Millisecond - time.Since(start); rest > 0 {
			time.Sleep(rest)
		}

		samples := collectOK(t, c)
		if v := must(t, samples, rules.MetricMySQLSlowQueriesRate); v <= 0 {
			t.Errorf("3 slow queries must give a positive rate, got %v", v)
		}
		if v := must(t, samples, rules.MetricMySQLRowLockWaitsRate); v <= 0 {
			t.Errorf("a row lock wait must give a positive rate, got %v", v)
		}
		hit := must(t, samples, rules.MetricMySQLBufferPoolHit)
		if hit < 0.5 || hit > 1 {
			t.Errorf("buffer pool hit ratio out of range: %v", hit)
		}
		t.Logf("slow=%v/s lockwaits=%v/s hit=%v", must(t, samples, rules.MetricMySQLSlowQueriesRate), must(t, samples, rules.MetricMySQLRowLockWaitsRate), hit)

		// With no further activity the rates fall back to zero.
		time.Sleep(1200 * time.Millisecond)
		samples = collectOK(t, c)
		if v := must(t, samples, rules.MetricMySQLSlowQueriesRate); v != 0 {
			t.Errorf("rate must return to 0 when nothing happens, got %v", v)
		}
	})

	t.Run("history list length grows behind an old read view", func(t *testing.T) {
		reader := m.Session(t)
		if _, err := reader.ExecContext(context.Background(), "START TRANSACTION WITH CONSISTENT SNAPSHOT"); err != nil {
			t.Fatal(err)
		}
		base := must(t, collectOK(t, c), rules.MetricMySQLHistoryListLength)
		m.MustExec(t, admin, `CREATE PROCEDURE lk_it.churn() BEGIN
			DECLARE i INT DEFAULT 0;
			WHILE i < 5000 DO
				UPDATE lk_it.t SET payload = CONCAT('v', i) WHERE id = 2;
				SET i = i + 1;
			END WHILE;
		END`)
		if _, err := admin.ExecContext(context.Background(), "CALL lk_it.churn()"); err != nil {
			t.Fatal(err)
		}
		samples := collectUntil(t, c, 20*time.Second, "history list growth", func(s []model.Sample) bool {
			return must(t, s, rules.MetricMySQLHistoryListLength) >= base+1000
		})
		t.Logf("history list length: %v -> %v", base, must(t, samples, rules.MetricMySQLHistoryListLength))
		_, _ = reader.ExecContext(context.Background(), "ROLLBACK")
	})

	t.Run("a disabled history counter is skipped, not an error", func(t *testing.T) {
		m.MustExec(t, admin, "SET GLOBAL innodb_monitor_disable = 'trx_rseg_history_len'")
		defer m.MustExec(t, admin, "SET GLOBAL innodb_monitor_enable = 'trx_rseg_history_len'")
		samples := collectOK(t, c) // collectOK fails on error or incomplete
		if _, ok := find(samples, rules.MetricMySQLHistoryListLength); ok {
			t.Error("a disabled counter must not produce a sample")
		}
		if _, ok := find(samples, rules.MetricMySQLTrxOldest); !ok {
			t.Error("other metrics must be unaffected")
		}
	})
}

func TestSessionsAreReadOnlyAndBounded(t *testing.T) {
	m := testutil.StartMySQL(t)
	admin := m.Admin(t)
	m.MustExec(t, admin, "CREATE DATABASE lk_ro", "CREATE TABLE lk_ro.t (id INT)")

	spec := m.Spec()
	spec.QueryTimeout = 2 * time.Second
	db, err := dbconn.OpenMySQL(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()

	var ro int
	var maxExec, lockWait int64
	if err := db.QueryRowContext(ctx, "SELECT @@transaction_read_only, @@max_execution_time, @@lock_wait_timeout").Scan(&ro, &maxExec, &lockWait); err != nil {
		t.Fatal(err)
	}
	if ro != 1 || maxExec != 2000 || lockWait != 2 {
		t.Errorf("session variables = read_only %d, max_execution_time %d, lock_wait_timeout %d", ro, maxExec, lockWait)
	}

	var prog string
	if err := db.QueryRowContext(ctx, "SELECT ATTR_VALUE FROM performance_schema.session_connect_attrs WHERE PROCESSLIST_ID = CONNECTION_ID() AND ATTR_NAME = 'program_name'").Scan(&prog); err != nil || prog != "lockkeeper" {
		t.Errorf("program_name attribute = %q (%v)", prog, err)
	}

	for _, stmt := range []string{
		"INSERT INTO lk_ro.t VALUES (1)",
		"UPDATE lk_ro.t SET id = 2",
		"DELETE FROM lk_ro.t",
		"CREATE TABLE lk_ro.must_not_exist (id INT)",
		"DROP TABLE lk_ro.t",
		"ALTER TABLE lk_ro.t ADD COLUMN c INT",
		"TRUNCATE TABLE lk_ro.t",
		"CREATE USER 'nope'@'%'",
		"GRANT SELECT ON *.* TO 'nope'@'%'",
	} {
		_, err := db.ExecContext(ctx, stmt)
		var me *drv.MySQLError
		if !errors.As(err, &me) || me.Number != 1792 {
			t.Errorf("%q must be refused as a READ ONLY transaction (1792), got %v", stmt, err)
		}
	}

	// max_execution_time cancels a long SELECT; the client-side timeouts are the
	// second line of defence.
	start := time.Now()
	var one int
	err = db.QueryRowContext(ctx, "SELECT 1 FROM (SELECT SLEEP(20)) s").Scan(&one)
	if time.Since(start) > 10*time.Second {
		t.Errorf("a 20s statement must be cut off by the 2s limit, took %v (err %v)", time.Since(start), err)
	}
	t.Logf("long SELECT ended after %v with %v", time.Since(start).Round(time.Millisecond), err)

	// A read-only session is NOT a security boundary: an account that may do so
	// can still change server settings. This documents the known limit; the
	// least-privilege account (see the audit) is the real protection.
	pool, err := dbconn.OpenMySQL(ctx, m.Spec())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.ExecContext(ctx, "SET GLOBAL max_connections = 160"); err != nil {
		t.Logf("SET GLOBAL was refused (%v); the known gap did not reproduce on this version", err)
	} else {
		t.Log("confirmed: SET GLOBAL succeeds from a read-only session when the account has the privilege")
	}

	// And the table is untouched.
	var n int
	if err := admin.QueryRow("SELECT COUNT(*) FROM lk_ro.t").Scan(&n); err != nil || n != 0 {
		t.Errorf("table changed: %d %v", n, err)
	}
	if err := admin.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'lk_ro' AND table_name = 'must_not_exist'").Scan(&n); err != nil || n != 0 {
		t.Errorf("a table was created: %d %v", n, err)
	}
}

func TestTLSModesAgainstRealServer(t *testing.T) {
	m := testutil.StartMySQL(t)
	admin := m.Admin(t)
	m.MustExec(t, admin,
		"CREATE USER 'lk_tls'@'%' IDENTIFIED BY 'tlspw' REQUIRE SSL",
		"GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'lk_tls'@'%'",
	)
	ctx := context.Background()
	tryOpen := func(mut func(*dbconn.MySQLSpec)) error {
		spec := m.SpecFor("lk_tls", "tlspw")
		mut(&spec)
		db, err := dbconn.OpenMySQL(ctx, spec)
		if err == nil {
			defer db.Close()
			var one int
			err = db.QueryRowContext(ctx, "SELECT 1").Scan(&one)
		}
		return err
	}

	if err := tryOpen(func(s *dbconn.MySQLSpec) { s.TLSMode = "disable" }); err == nil {
		t.Error("an account that REQUIRES SSL must be refused over plaintext")
	}
	if err := tryOpen(func(s *dbconn.MySQLSpec) { s.TLSMode = "require" }); err != nil {
		t.Errorf("require (encrypted, unauthenticated) on loopback: %v", err)
	}
	ca := m.CACertFile(t)
	if err := tryOpen(func(s *dbconn.MySQLSpec) { s.TLSMode = "verify-ca"; s.CAFile = ca }); err != nil {
		t.Errorf("verify-ca with the server's CA must work: %v", err)
	}
	// The auto-generated certificate carries no IP address, so full verification
	// against 127.0.0.1 must fail: proof that the hostname check is really done.
	if err := tryOpen(func(s *dbconn.MySQLSpec) { s.TLSMode = "verify-full"; s.CAFile = ca }); err == nil {
		t.Error("verify-full must reject a certificate that does not match the host")
	}
	// A CA that did not sign the server certificate is rejected.
	other := testutil.StartMySQL(t)
	if err := tryOpen(func(s *dbconn.MySQLSpec) { s.TLSMode = "verify-ca"; s.CAFile = other.CACertFile(t) }); err == nil {
		t.Error("verify-ca must reject a foreign CA")
	}

	// The wrong password never ends up in an error.
	err := tryOpen(func(s *dbconn.MySQLSpec) { s.TLSMode = "require"; s.Password = secret.New("not-the-password-123") })
	if err == nil || strings.Contains(err.Error(), "not-the-password-123") {
		t.Errorf("expected an access denied error without the password: %v", err)
	}
}

func TestAuditAgainstRealAccounts(t *testing.T) {
	m := testutil.StartMySQL(t)
	admin := m.Admin(t)
	m.MustExec(t, admin,
		"CREATE USER 'lk_good'@'%' IDENTIFIED BY 'goodpw' REQUIRE SSL",
		"GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'lk_good'@'%'",
		"CREATE USER 'lk_plain'@'%' IDENTIFIED BY 'plainpw'",
		"CREATE USER 'lk_over'@'%' IDENTIFIED BY 'overpw'",
		"GRANT PROCESS, REPLICATION CLIENT, INSERT, UPDATE, DELETE, CREATE, DROP ON *.* TO 'lk_over'@'%' WITH GRANT OPTION",
		"CREATE USER 'lk_repl'@'%' IDENTIFIED BY 'replpw'",
		"GRANT PROCESS, REPLICATION CLIENT, REPLICATION SLAVE ON *.* TO 'lk_repl'@'%'",
		"CREATE USER 'lk_super'@'%' IDENTIFIED BY 'superpw'",
		"GRANT PROCESS, REPLICATION CLIENT, SUPER ON *.* TO 'lk_super'@'%'",
		"CREATE USER 'lk_all'@'%' IDENTIFIED BY 'allpw'",
		"GRANT ALL PRIVILEGES ON *.* TO 'lk_all'@'%'",
		"CREATE ROLE 'lk_writer'",
		"GRANT INSERT ON *.* TO 'lk_writer'",
		"CREATE USER 'lk_role'@'%' IDENTIFIED BY 'rolepw'",
		"GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'lk_role'@'%'",
		"GRANT 'lk_writer' TO 'lk_role'@'%'",
		"SET DEFAULT ROLE ALL TO 'lk_role'@'%'",
	)
	audit := func(user, pw string, mut ...func(*dbconn.MySQLSpec)) []string {
		spec := m.SpecFor(user, pw)
		spec.TLSMode = "require" // lk_good REQUIRES SSL; loopback allows it
		c := newCollector(t, spec)
		w, err := c.Audit(context.Background())
		if err != nil {
			t.Fatalf("audit %s: %v", user, err)
		}
		return w
	}
	has := func(w []string, parts ...string) bool {
		for _, s := range w {
			ok := true
			for _, p := range parts {
				ok = ok && strings.Contains(s, p)
			}
			if ok {
				return true
			}
		}
		return false
	}

	if w := audit("lk_good", "goodpw"); len(w) != 0 {
		t.Errorf("a PROCESS + REPLICATION CLIENT account must be clean, got %v", w)
	}
	if w := audit("lk_plain", "plainpw"); !has(w, "lacks the PROCESS", "my.trx.oldest_s") || !has(w, "lacks the REPLICATION CLIENT", "would NOT alert") || len(w) != 2 {
		t.Errorf("an account without privileges must get the two missing-privilege warnings, got %v", w)
	}
	if w := audit("lk_over", "overpw"); !has(w, "INSERT on *.*", "DROP on *.*") || !has(w, "WITH GRANT OPTION") || has(w, "lacks") {
		t.Errorf("write/DDL/grant option must be flagged: %v", w)
	}
	if w := audit("lk_repl", "replpw"); !has(w, "REPLICATION SLAVE") || len(w) != 1 {
		t.Errorf("REPLICATION SLAVE must be flagged: %v", w)
	}
	if w := audit("lk_super", "superpw"); !has(w, "has SUPER") {
		t.Errorf("SUPER must be flagged: %v", w)
	}
	if w := audit("lk_all", "allpw"); !has(w, "ALL PRIVILEGES on *.*", "REQUIRE SSL") || len(w) != 1 {
		t.Errorf("ALL PRIVILEGES must be flagged once: %v", w)
	}
	if w := audit("lk_role", "rolepw"); !has(w, "INSERT on *.*") {
		t.Errorf("privileges granted through a role must be flagged: %v", w)
	}
	if w := audit("root", m.RootPassword); !has(w, "has SUPER") && !has(w, "ALL PRIVILEGES") {
		t.Errorf("root must be flagged: %v", w)
	}

	// What a missing privilege really does to collection: the batch is incomplete,
	// the unaffected metrics are still delivered, and nothing is invented.
	plain := newCollector(t, m.SpecFor("lk_plain", "plainpw"))
	samples, complete, err := plain.Collect(context.Background())
	if complete || err == nil || !strings.Contains(err.Error(), "PROCESS") {
		t.Fatalf("an account without PROCESS must give an incomplete batch naming the privilege: %v %v", complete, err)
	}
	if must(t, samples, rules.MetricMySQLUp) != 1 {
		t.Error("the server is up")
	}
	if _, ok := find(samples, rules.MetricMySQLConnectionsRatio); !ok {
		t.Error("status metrics need no privilege and must still be collected")
	}
	if _, ok := find(samples, rules.MetricMySQLTrxOldest); ok {
		t.Error("no trx sample without PROCESS")
	}

	// The least-privilege account collects everything.
	spec := m.SpecFor("lk_good", "goodpw")
	spec.TLSMode = "require"
	good := newCollector(t, spec)
	samples = collectOK(t, good)
	for _, mtr := range []string{rules.MetricMySQLTrxOldest, rules.MetricMySQLHistoryListLength, rules.MetricMySQLBinlogDiskBytes, rules.MetricMySQLThreadsRunning} {
		if _, ok := find(samples, mtr); !ok {
			t.Errorf("least-privilege account: %s missing", mtr)
		}
	}
}

func TestBinaryLoggingOffIsSkippedCleanly(t *testing.T) {
	m := testutil.StartMySQLWith(t, testutil.MySQLOptions{NoBinlog: true})
	c := newCollector(t, m.Spec())
	samples := collectOK(t, c) // complete and error-free
	if _, ok := find(samples, rules.MetricMySQLBinlogDiskBytes); ok {
		t.Error("no binlog sample when binary logging is off")
	}
	if must(t, samples, rules.MetricMySQLUp) != 1 || must(t, samples, rules.MetricMySQLTrxOldest) != 0 {
		t.Errorf("other metrics must be unaffected: %+v", samples)
	}
}

func TestOutageIsReportedAsDownAndConnectionRecovers(t *testing.T) {
	m := testutil.StartMySQL(t)
	admin := m.Admin(t)
	c := newCollector(t, m.Spec())
	collectOK(t, c)

	// Kill Lockkeeper's own server session: the collector must recover.
	rows, err := admin.Query("SELECT PROCESSLIST_ID FROM performance_schema.session_connect_attrs WHERE ATTR_NAME = 'program_name' AND ATTR_VALUE = 'lockkeeper'")
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for rows.Next() {
		var pid int64
		if err := rows.Scan(&pid); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, pid)
	}
	rows.Close()
	if len(ids) == 0 {
		t.Fatal("could not find the collector's server session")
	}
	for _, pid := range ids {
		if _, err := admin.Exec("KILL CONNECTION " + strconv.FormatInt(pid, 10)); err != nil {
			t.Fatal(err)
		}
	}
	var recovered bool
	for i := 0; i < 3 && !recovered; i++ {
		_, complete, err := c.Collect(context.Background())
		recovered = err == nil && complete
	}
	if !recovered {
		t.Fatal("the collector must recover within a few collections after its session was killed")
	}

	m.Stop(t)
	samples, complete, err := c.Collect(context.Background())
	if err == nil || complete {
		t.Fatalf("collect during an outage must fail and be incomplete (complete=%v err=%v)", complete, err)
	}
	if up, ok := find(samples, rules.MetricMySQLUp); !ok || up.Value != 0 {
		t.Fatalf("my.up must be 0 during an outage: %+v", samples)
	}
	if strings.Contains(err.Error(), m.RootPassword) {
		t.Error("the error must not contain the password")
	}
}

func TestReplicationMetrics(t *testing.T) {
	source, replica := testutil.StartMySQLPair(t)
	testutil.ConfigureReplica(t, source, replica)
	sdb, rdb := source.Admin(t), replica.Admin(t)
	source.MustExec(t, sdb, "CREATE DATABASE lk_repl", "CREATE TABLE lk_repl.t (id INT AUTO_INCREMENT PRIMARY KEY, v INT)", "INSERT INTO lk_repl.t (v) VALUES (1)")

	// Record the real column set so the unit-test fixtures can be checked against it.
	rows, err := rdb.Query("SHOW REPLICA STATUS")
	if err != nil {
		t.Fatal(err)
	}
	cols, _ := rows.Columns()
	rows.Close()
	t.Logf("SHOW REPLICA STATUS columns (%s): %s", testutil.MySQLImage(), strings.Join(cols, ","))
	for _, want := range []string{"Replica_IO_Running", "Replica_SQL_Running", "Seconds_Behind_Source", "Channel_Name"} {
		found := false
		for _, c := range cols {
			found = found || c == want
		}
		if !found {
			t.Errorf("column %s not in SHOW REPLICA STATUS", want)
		}
	}

	rc := newCollector(t, replica.Spec())
	sc := newCollector(t, source.Spec())

	// The source is not a replica.
	ssamples := collectOK(t, sc)
	for _, mtr := range []string{rules.MetricMySQLReplIORunning, rules.MetricMySQLReplSQLRunning, rules.MetricMySQLReplLag} {
		if _, ok := find(ssamples, mtr); ok {
			t.Errorf("source must not report %s", mtr)
		}
	}

	// Healthy replica.
	samples := collectUntil(t, rc, 30*time.Second, "a caught-up replica", func(s []model.Sample) bool {
		_, ok := find(s, rules.MetricMySQLReplLag)
		return ok
	})
	if must(t, samples, rules.MetricMySQLReplIORunning) != 1 || must(t, samples, rules.MetricMySQLReplSQLRunning) != 1 {
		t.Errorf("both threads must run: %+v", samples)
	}
	if lag := must(t, samples, rules.MetricMySQLReplLag); lag < 0 || lag > 30 {
		t.Errorf("lag on an idle replica = %v", lag)
	}

	// SQL thread stopped: Seconds_Behind_Source is NULL and must NOT become 0.
	replica.MustExec(t, rdb, "STOP REPLICA SQL_THREAD")
	samples = collectOK(t, rc)
	if must(t, samples, rules.MetricMySQLReplIORunning) != 1 || must(t, samples, rules.MetricMySQLReplSQLRunning) != 0 {
		t.Errorf("only the SQL thread is stopped: %+v", samples)
	}
	if s, ok := find(samples, rules.MetricMySQLReplLag); ok {
		t.Errorf("a NULL lag must not be reported, got %+v", s)
	}

	// Both stopped.
	replica.MustExec(t, rdb, "STOP REPLICA")
	samples = collectOK(t, rc)
	if must(t, samples, rules.MetricMySQLReplIORunning) != 0 || must(t, samples, rules.MetricMySQLReplSQLRunning) != 0 {
		t.Errorf("both threads are stopped: %+v", samples)
	}
	if _, ok := find(samples, rules.MetricMySQLReplLag); ok {
		t.Error("no lag sample while replication is stopped")
	}

	// A delayed replica shows real lag once an event is waiting.
	replica.MustExec(t, rdb, "CHANGE REPLICATION SOURCE TO SOURCE_DELAY = 8", "START REPLICA")
	source.MustExec(t, sdb, "INSERT INTO lk_repl.t (v) VALUES (2)")
	samples = collectUntil(t, rc, 30*time.Second, "lag from a delayed replica", func(s []model.Sample) bool {
		l, ok := find(s, rules.MetricMySQLReplLag)
		return ok && l.Value >= 2
	})
	t.Logf("lag with SOURCE_DELAY=8: %v", must(t, samples, rules.MetricMySQLReplLag))
	if must(t, samples, rules.MetricMySQLReplIORunning) != 1 || must(t, samples, rules.MetricMySQLReplSQLRunning) != 1 {
		t.Errorf("threads run on a delayed replica: %+v", samples)
	}

	// A least-privilege account can read the replica status, too.
	replica.MustExec(t, rdb, "CREATE USER 'lk_mon'@'%' IDENTIFIED BY 'monpw'", "GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'lk_mon'@'%'")
	lc := newCollector(t, replica.SpecFor("lk_mon", "monpw"))
	if _, ok := find(collectOK(t, lc), rules.MetricMySQLReplIORunning); !ok {
		t.Error("REPLICATION CLIENT must be enough to read the replica status")
	}
}
