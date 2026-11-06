//go:build integration

package pgnative_test

// The Phase 3 spike (ADR 0002, item 7), kept as a permanent regression test.
//
// It deliberately uses raw SQL and the replication protocol, not Lockkeeper's own
// orchestration code, so that it proves the facts the design rests on:
//
//   - a replication-protocol connection can create a logical slot and export a
//     snapshot, and the snapshot stays usable only while that connection is open;
//   - a bulk copy that runs inside that snapshot, followed by a subscription that
//     starts at the slot (copy_data=false), yields exactly the source data under
//     concurrent writes, overlapping transactions and a transaction that spans
//     the snapshot point;
//   - what is left behind when the copy is killed.
//
// Everything runs in throwaway containers on a private Docker network.

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/wisnuvb/lockkeeper/internal/testutil"
)

const spikeSlot = "lk_spike"

// spikeEnv is a source/target pair on a private network with the app schema.
type spikeEnv struct {
	net      *testutil.Net
	src, tgt *testutil.NetPG
}

var spikeTables = []struct{ name, order string }{
	{"accounts", "id"},
	{"ledger", "id"},
	{"events", "payload"},
}

func newSpikeEnv(t *testing.T) *spikeEnv {
	t.Helper()
	n := testutil.StartNet(t)
	src, tgt := testutil.StartPairNet(t, n, testutil.PairOptions{})
	mustExecT(t, src.Admin(t), "CREATE DATABASE app")
	mustExecT(t, tgt.Admin(t), "CREATE DATABASE app")
	app := src.AdminDB(t, "app")
	for _, q := range []string{
		`CREATE TABLE accounts (id bigserial PRIMARY KEY, balance int NOT NULL DEFAULT 0, note text)`,
		`CREATE TABLE ledger (id bigserial PRIMARY KEY, account_id bigint NOT NULL, amount int NOT NULL)`,
		`CREATE TABLE events (payload text NOT NULL, n int NOT NULL DEFAULT 0)`, // no primary key
		`ALTER TABLE events REPLICA IDENTITY FULL`,
		`INSERT INTO accounts (balance, note) SELECT g, 'seed' || g FROM generate_series(1, 2000) g`,
		`INSERT INTO ledger (account_id, amount) SELECT 1 + g % 2000, g FROM generate_series(1, 5000) g`,
		`INSERT INTO events (payload) SELECT 'seed-' || g FROM generate_series(1, 3000) g`,
	} {
		mustExecT(t, app, q)
	}
	return &spikeEnv{net: n, src: src, tgt: tgt}
}

func mustExecT(t testing.TB, c *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := c.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func queryStr(t testing.TB, c *pgx.Conn, sql string, args ...any) string {
	t.Helper()
	var s string
	if err := c.QueryRow(context.Background(), sql, args...).Scan(&s); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return s
}

func (e *spikeEnv) replDSN() string {
	return fmt.Sprintf("postgres://postgres:%s@%s:%d/app?sslmode=disable", e.src.Password, e.src.Host, e.src.Port)
}

// snapshotHolder is the replication connection that owns the exported snapshot.
type snapshotHolder struct {
	conn         *pgconn.PgConn
	ConsistentAt string
	SnapshotID   string
}

// createSlotWithSnapshot runs CREATE_REPLICATION_SLOT ... (SNAPSHOT 'export') on
// a replication=database connection and keeps the connection open and idle.
func createSlotWithSnapshot(ctx context.Context, dsn, slot string) (*snapshotHolder, error) {
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.RuntimeParams["replication"] = "database"
	c, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	// PostgreSQL 14 only knows the legacy option syntax; 15+ also accepts it, but
	// the parenthesised form is the documented one.
	cmd := fmt.Sprintf(`CREATE_REPLICATION_SLOT %s LOGICAL pgoutput EXPORT_SNAPSHOT`, slot)
	if v := c.ParameterStatus("server_version"); !strings.HasPrefix(v, "14.") {
		cmd = fmt.Sprintf(`CREATE_REPLICATION_SLOT %s LOGICAL pgoutput (SNAPSHOT 'export')`, slot)
	}
	rs, err := c.Exec(ctx, cmd).ReadAll()
	if err != nil {
		_ = c.Close(ctx)
		return nil, err
	}
	row := rs[0].Rows[0]
	return &snapshotHolder{conn: c, ConsistentAt: string(row[1]), SnapshotID: string(row[2])}, nil
}

func (h *snapshotHolder) Close() { _ = h.conn.Close(context.Background()) }

// runCopy performs the bulk copy of database app inside snapshot, with one of the
// two Copier candidates, in a container on the private network.
func (e *spikeEnv) runCopy(t *testing.T, copier, snapshot string) (string, error) {
	out, _, err := e.runCopyDir(t, copier, snapshot)
	return out, err
}

// runCopyDir is runCopy that also returns the host work directory of the tool.
func (e *spikeEnv) runCopyDir(t *testing.T, copier, snapshot string) (string, string, error) {
	t.Helper()
	dir := t.TempDir()
	pass := testutil.WritePassfile(t, dir,
		[5]string{"src", "5432", "*", "postgres", e.src.Password},
		[5]string{"tgt", "5432", "*", "postgres", e.tgt.Password})
	env := map[string]string{"PGPASSFILE": pass, "HOME": dir}
	srcURI, tgtURI := "postgres://postgres@src:5432/app", "postgres://postgres@tgt:5432/app"
	switch copier {
	case "pgdump":
		out, err := e.net.RunTool(t, testutil.ToolRun{Image: testutil.PGToolsImage, Entrypoint: "pg_dump", Dir: dir, Env: env,
			Args: []string{"--snapshot=" + snapshot, "-Fd", "-j", "4", "-f", filepath.Join(dir, "dump"), srcURI}})
		if err != nil {
			return out, dir, err
		}
		out2, err := e.net.RunTool(t, testutil.ToolRun{Image: testutil.PGToolsImage, Entrypoint: "pg_restore", Dir: dir, Env: env,
			Args: []string{"-j", "4", "--exit-on-error", "-d", tgtURI, filepath.Join(dir, "dump")}})
		return out + out2, dir, err
	case "pgcopydb":
		out, err := e.net.RunTool(t, testutil.ToolRun{Image: testutil.PgcopydbImage, Entrypoint: "pgcopydb", Dir: dir, Env: env,
			Args: []string{"clone", "--source", srcURI, "--target", tgtURI, "--dir", filepath.Join(dir, "work"),
				"--snapshot", snapshot, "--table-jobs", "4", "--index-jobs", "4"}})
		return out, dir, err
	}
	t.Fatalf("unknown copier %q", copier)
	return "", "", nil
}

// sourceCatalogFingerprint summarises every user-visible object of the source
// that a bulk-copy tool could have created: schemas, relations, functions,
// triggers, event triggers, publications, extensions, roles, and the
// replication slots other than ours.
func sourceCatalogFingerprint(t testing.TB, c *pgx.Conn) string {
	t.Helper()
	return queryStr(t, c, `SELECT md5(string_agg(x, ',' ORDER BY x)) FROM (
		SELECT 'ns:' || nspname AS x FROM pg_namespace
		UNION ALL SELECT 'rel:' || n.nspname || '.' || c.relname || ':' || c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
		UNION ALL SELECT 'proc:' || n.nspname || '.' || p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
		UNION ALL SELECT 'trg:' || tgname FROM pg_trigger WHERE NOT tgisinternal
		UNION ALL SELECT 'evt:' || evtname FROM pg_event_trigger
		UNION ALL SELECT 'pub:' || pubname FROM pg_publication
		UNION ALL SELECT 'ext:' || extname FROM pg_extension
		UNION ALL SELECT 'role:' || rolname FROM pg_roles
		UNION ALL SELECT 'slot:' || slot_name FROM pg_replication_slots WHERE slot_name <> 'lk_spike'
	) q`)
}

// scanTreeFor reports every file under dir (and the tool output) that contains
// needle, except files named in skip.
func scanTreeFor(dir, needle, output string, skip ...string) []string {
	var hits []string
	if strings.Contains(output, needle) {
		hits = append(hits, "<tool output>")
	}
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		for _, s := range skip {
			if d.Name() == s {
				return nil
			}
		}
		if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), needle) {
			hits = append(hits, p)
		}
		return nil
	})
	return hits
}

// writers runs random committed and rolled-back transactions against the source
// until stop is called, and returns how many committed.
type writers struct {
	wg        sync.WaitGroup
	cancel    context.CancelFunc
	committed atomic.Int64
	seq       atomic.Int64
}

func (e *spikeEnv) startWriters(t *testing.T, n int) *writers {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	w := &writers{cancel: cancel}
	for i := 0; i < n; i++ {
		conn, err := pgx.Connect(ctx, e.replDSN())
		if err != nil {
			t.Fatalf("writer connect: %v", err)
		}
		rng := rand.New(rand.NewSource(int64(i) + 1))
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			defer conn.Close(context.Background())
			for ctx.Err() == nil {
				if w.oneTx(ctx, conn, rng) {
					w.committed.Add(1)
				}
				time.Sleep(time.Duration(rng.Intn(3)) * time.Millisecond)
			}
		}()
	}
	return w
}

func (w *writers) oneTx(ctx context.Context, c *pgx.Conn, rng *rand.Rand) bool {
	tx, err := c.Begin(ctx)
	if err != nil {
		return false
	}
	ok := func() bool {
		for i, ops := 0, 1+rng.Intn(4); i < ops; i++ {
			var err error
			switch rng.Intn(8) {
			case 0:
				_, err = tx.Exec(ctx, `INSERT INTO accounts (balance, note) VALUES ($1, $2)`, rng.Intn(1000), fmt.Sprintf("w%d", w.seq.Add(1)))
			case 1, 2:
				_, err = tx.Exec(ctx, `UPDATE accounts SET balance = balance + 1, note = note || 'u' WHERE id = 1 + $1::int`, rng.Intn(2500))
			case 3:
				_, err = tx.Exec(ctx, `DELETE FROM accounts WHERE id = 1 + $1::int AND id > 100`, rng.Intn(2500))
			case 4, 5:
				_, err = tx.Exec(ctx, `INSERT INTO ledger (account_id, amount) VALUES ($1, $2)`, 1+rng.Intn(2000), rng.Intn(100))
			case 6:
				_, err = tx.Exec(ctx, `INSERT INTO events (payload) VALUES ($1)`, fmt.Sprintf("ev-%d", w.seq.Add(1)))
			case 7:
				// Update or delete on the table without a primary key
				// (REPLICA IDENTITY FULL).
				if rng.Intn(2) == 0 {
					_, err = tx.Exec(ctx, `UPDATE events SET n = n + 1 WHERE payload = $1`, fmt.Sprintf("seed-%d", 1+rng.Intn(3000)))
				} else {
					_, err = tx.Exec(ctx, `DELETE FROM events WHERE payload = $1`, fmt.Sprintf("seed-%d", 1+rng.Intn(3000)))
				}
			}
			if err != nil {
				return false
			}
		}
		if rng.Intn(10) == 0 {
			return false // roll back some transactions
		}
		return true
	}()
	if !ok {
		_ = tx.Rollback(context.Background())
		return false
	}
	return tx.Commit(ctx) == nil
}

func (w *writers) stop() {
	w.cancel()
	w.wg.Wait()
}

// tableFingerprint returns row count and md5 of the ordered row texts.
func tableFingerprint(t testing.TB, c *pgx.Conn, table, order string) string {
	t.Helper()
	return queryStr(t, c, fmt.Sprintf(
		`SELECT count(*) || ':' || coalesce(md5(string_agg(x::text, E'\n' ORDER BY x.%s, x::text)), 'empty') FROM %s x`, order, table))
}

func assertIdentical(t testing.TB, src, tgt *pgx.Conn) {
	t.Helper()
	for _, tb := range spikeTables {
		s, g := tableFingerprint(t, src, tb.name, tb.order), tableFingerprint(t, tgt, tb.name, tb.order)
		if s != g {
			t.Errorf("table %s differs: source %s, target %s", tb.name, s, g)
		}
	}
}

// waitCaughtUp waits until the slot's confirmed_flush_lsn has reached the source's
// current WAL position (taken after all writers have stopped).
func waitCaughtUp(t testing.TB, src *pgx.Conn, slot string, within time.Duration) {
	t.Helper()
	target := queryStr(t, src, `SELECT pg_current_wal_lsn()::text`)
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		var behind int64
		if err := src.QueryRow(context.Background(),
			`SELECT coalesce(pg_wal_lsn_diff($1::pg_lsn, confirmed_flush_lsn), -1)::bigint FROM pg_replication_slots WHERE slot_name = $2`,
			target, slot).Scan(&behind); err != nil {
			t.Fatalf("read slot: %v", err)
		}
		if behind <= 0 && behind != -1 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("subscription did not catch up to %s within %s", target, within)
}

func (e *spikeEnv) subscribe(t *testing.T, tgt *pgx.Conn, enable bool) {
	t.Helper()
	conninfo := fmt.Sprintf("host=src port=5432 dbname=app user=postgres password=%s sslmode=disable", e.src.Password)
	mustExecT(t, tgt, fmt.Sprintf(
		`CREATE SUBSCRIPTION lk_spike_sub CONNECTION '%s' PUBLICATION lk_spike WITH (create_slot = false, slot_name = '%s', copy_data = false, enabled = false)`,
		conninfo, spikeSlot))
	if enable {
		mustExecT(t, tgt, `ALTER SUBSCRIPTION lk_spike_sub ENABLE`)
	}
}

func TestSpikeHandoffUnderConcurrentWrites(t *testing.T) {
	for _, copier := range []string{"pgdump", "pgcopydb"} {
		t.Run(copier, func(t *testing.T) {
			if copier == "pgcopydb" {
				testutil.EnsurePgcopydbImage(t)
			}
			e := newSpikeEnv(t)
			ctx := context.Background()
			srcApp := e.src.AdminDB(t, "app")
			mustExecT(t, srcApp, `CREATE PUBLICATION lk_spike FOR TABLE accounts, ledger, events`)

			w := e.startWriters(t, 4)
			defer w.stop()
			time.Sleep(300 * time.Millisecond)

			// O1: transaction A begins BEFORE the slot is created and commits while
			// slot creation is waiting for it. It spans the snapshot point.
			txA, err := srcApp.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := txA.Exec(ctx, `INSERT INTO events (payload) VALUES ('A-spans-snapshot-point')`); err != nil {
				t.Fatal(err)
			}
			type created struct {
				h   *snapshotHolder
				err error
			}
			ch := make(chan created, 1)
			go func() {
				h, err := createSlotWithSnapshot(ctx, e.replDSN(), spikeSlot)
				ch <- created{h, err}
			}()
			select {
			case <-ch:
				t.Fatal("slot creation must wait for the open transaction A")
			case <-time.After(1500 * time.Millisecond):
			}
			if err := txA.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			c := <-ch
			if c.err != nil {
				t.Fatalf("create slot: %v", c.err)
			}
			h := c.h
			defer h.Close()
			t.Logf("slot %s consistent point %s, snapshot %s", spikeSlot, h.ConsistentAt, h.SnapshotID)

			// O2: after the snapshot was exported but before the copy ends, C begins,
			// D begins later and commits first, E begins and stays open across the
			// copy and the subscription start.
			open := func(payload string) pgx.Tx {
				conn, err := pgx.Connect(ctx, e.replDSN())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = conn.Close(context.Background()) })
				tx, err := conn.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, `INSERT INTO events (payload) VALUES ($1)`, payload); err != nil {
					t.Fatal(err)
				}
				return tx
			}
			txC := open("C-begins-first-commits-last")
			txD := open("D-begins-second-commits-first")
			txE := open("E-open-across-copy-and-subscription")
			if err := txD.Commit(ctx); err != nil {
				t.Fatal(err)
			}

			catBefore := sourceCatalogFingerprint(t, srcApp)
			out, dir, err := e.runCopyDir(t, copier, h.SnapshotID)
			if err != nil {
				t.Fatalf("copy with %s failed: %v\n%s", copier, err, out)
			}
			if after := sourceCatalogFingerprint(t, srcApp); after != catBefore {
				t.Errorf("%s changed the source catalog (schemas, relations, triggers, publications, slots or roles)", copier)
			}
			// ADR 0004: the passwords must not be in the tool's output or work
			// directory (the passfile itself is the one allowed place).
			for _, pw := range []string{e.src.Password, e.tgt.Password} {
				if hits := scanTreeFor(dir, pw, out, "pgpass"); len(hits) > 0 {
					t.Errorf("a database password was found in %v", hits)
				}
			}
			if err := txC.Commit(ctx); err != nil { // commits after the copy, before the subscription exists
				t.Fatal(err)
			}

			// The snapshot connection is released only after the copy; the slot stays.
			h.Close()
			tgtApp := e.tgt.AdminDB(t, "app")
			e.subscribe(t, tgtApp, false)
			time.Sleep(500 * time.Millisecond) // writers keep running while it is disabled
			mustExecT(t, tgtApp, `ALTER SUBSCRIPTION lk_spike_sub ENABLE`)
			time.Sleep(500 * time.Millisecond)
			if err := txE.Commit(ctx); err != nil { // commits after the subscription started
				t.Fatal(err)
			}
			time.Sleep(700 * time.Millisecond)

			w.stop()
			t.Logf("writers committed %d transactions", w.committed.Load())
			if w.committed.Load() < 200 {
				t.Errorf("writers only committed %d transactions: the test did not exercise concurrency", w.committed.Load())
			}
			waitCaughtUp(t, srcApp, spikeSlot, 60*time.Second)
			assertIdentical(t, srcApp, tgtApp)

			for _, p := range []string{"A-spans-snapshot-point", "C-begins-first-commits-last", "D-begins-second-commits-first", "E-open-across-copy-and-subscription"} {
				if n := queryStr(t, tgtApp, `SELECT count(*) FROM events WHERE payload = $1`, p); n != "1" {
					t.Errorf("marker %q appears %s times on the target, want exactly 1", p, n)
				}
			}
		})
	}
}

// TestSpikeSnapshotLifetimeAndKilledCopy proves what happens to the snapshot and
// to the slot when the holder connection goes away or the copy dies, and what
// the safe recovery rule is.
func TestSpikeSnapshotLifetimeAndKilledCopy(t *testing.T) {
	e := newSpikeEnv(t)
	ctx := context.Background()
	srcApp := e.src.AdminDB(t, "app")
	mustExecT(t, srcApp, `CREATE PUBLICATION lk_spike FOR TABLE accounts, ledger, events`)

	h, err := createSlotWithSnapshot(ctx, e.replDSN(), spikeSlot)
	if err != nil {
		t.Fatal(err)
	}
	snap := h.SnapshotID

	// While the holder is open the snapshot imports in another session.
	other, err := pgx.Connect(ctx, e.replDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(ctx)
	tx, err := other.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf(`SET TRANSACTION SNAPSHOT '%s'`, snap)); err != nil {
		t.Fatalf("import while holder is open: %v", err)
	}
	_ = tx.Rollback(ctx)

	// Writes after the slot: the slot must retain them.
	mustExecT(t, srcApp, `INSERT INTO events (payload) SELECT 'after-slot-' || g FROM generate_series(1, 500) g`)
	restart0 := queryStr(t, srcApp, `SELECT restart_lsn::text FROM pg_replication_slots WHERE slot_name = $1`, spikeSlot)

	// Simulate the copy process dying mid-copy: the holder goes away too.
	h.Close()
	time.Sleep(500 * time.Millisecond)

	// Fact 1: the exported snapshot is not usable any more.
	tx, err = other.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, fmt.Sprintf(`SET TRANSACTION SNAPSHOT '%s'`, snap))
	_ = tx.Rollback(ctx)
	if err == nil || !(strings.Contains(err.Error(), "does not exist") || strings.Contains(err.Error(), "invalid snapshot identifier")) {
		t.Fatalf("snapshot must be gone after the holder closed, got err=%v", err)
	}

	// Fact 2: the slot survives, inactive, and keeps retaining WAL.
	var active bool
	var retained int64
	if err := srcApp.QueryRow(ctx, `SELECT active, pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)::bigint FROM pg_replication_slots WHERE slot_name = $1`, spikeSlot).
		Scan(&active, &retained); err != nil {
		t.Fatal(err)
	}
	if active || retained <= 0 {
		t.Errorf("slot should be inactive and retaining WAL: active=%v retained=%d", active, retained)
	}
	restart1 := queryStr(t, srcApp, `SELECT restart_lsn::text FROM pg_replication_slots WHERE slot_name = $1`, spikeSlot)
	if restart0 != restart1 {
		t.Errorf("an unconsumed slot must not advance: %s -> %s", restart0, restart1)
	}

	// Fact 3 (the recovery rule): re-using the old slot for a NEW copy is unsafe.
	// The new copy's snapshot is later than the slot's consistent point, so the
	// subscription would replay changes that the copy already contains. On a table
	// without a primary key that is silent duplication.
	h2, err := createSlotWithSnapshot(ctx, e.replDSN(), "lk_spike_second")
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()
	if out, err := e.runCopy(t, "pgdump", h2.SnapshotID); err != nil {
		t.Fatalf("copy with the new snapshot: %v\n%s", err, out)
	}
	tgtApp := e.tgt.AdminDB(t, "app")
	e.subscribe(t, tgtApp, false) // points at the OLD slot lk_spike
	h2.Close()
	mustExecT(t, tgtApp, `ALTER SUBSCRIPTION lk_spike_sub ENABLE`)
	waitCaughtUp(t, srcApp, spikeSlot, 60*time.Second)
	dupSrc := queryStr(t, srcApp, `SELECT count(*) FROM events`)
	dupTgt := queryStr(t, tgtApp, `SELECT count(*) FROM events`)
	if dupSrc == dupTgt {
		t.Errorf("expected the old slot to replay already-copied rows (duplicates on a table without PK); counts are equal (%s): the recovery rule in the notes needs revisiting", dupSrc)
	}
	t.Logf("old-slot reuse: source has %s events, target has %s (duplicates)", dupSrc, dupTgt)
}
