package testutil

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Writers runs random transactions against the tables accounts(id PK), ledger(id
// PK) and events(payload, n; no primary key, REPLICA IDENTITY FULL) of a
// database, until Stop: inserts, updates, deletes and rollbacks, including
// updates and deletes on the table without a primary key.
type Writers struct {
	wg        sync.WaitGroup
	cancel    context.CancelFunc
	committed atomic.Int64
	seq       atomic.Int64
}

// StartWriters opens n connections to dsn (a throwaway container on loopback)
// and starts writing.
func StartWriters(t testing.TB, dsn string, n int) *Writers {
	t.Helper()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("writers: bad DSN: %v", err)
	}
	RequireLoopback(t, cfg.Host) // a test must never write to a server it did not start
	ctx, cancel := context.WithCancel(context.Background())
	w := &Writers{cancel: cancel}
	for i := 0; i < n; i++ {
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			cancel()
			t.Fatalf("writer connect: %v", err)
		}
		rng := rand.New(rand.NewSource(int64(i) + 7))
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			defer conn.Close(context.Background())
			for ctx.Err() == nil {
				if w.oneTx(ctx, conn, rng) {
					w.committed.Add(1)
				}
				time.Sleep(time.Duration(rng.Intn(4)) * time.Millisecond)
			}
		}()
	}
	t.Cleanup(w.Stop)
	return w
}

// Committed is the number of committed transactions so far.
func (w *Writers) Committed() int64 { return w.committed.Load() }

// Stop stops the writers and waits for them (idempotent).
func (w *Writers) Stop() {
	w.cancel()
	w.wg.Wait()
}

func (w *Writers) oneTx(ctx context.Context, c *pgx.Conn, rng *rand.Rand) bool {
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
		return rng.Intn(10) != 0
	}()
	if !ok {
		_ = tx.Rollback(context.Background())
		return false
	}
	return tx.Commit(ctx) == nil
}

// Fingerprint returns "count:md5" of the ordered row texts of a table, for
// comparing source and target row by row.
func Fingerprint(t testing.TB, c *pgx.Conn, table, order string) string {
	t.Helper()
	var s string
	q := fmt.Sprintf(`SELECT count(*) || ':' || coalesce(md5(string_agg(x::text, E'\n' ORDER BY x.%s, x::text)), 'empty') FROM %s x`, order, table)
	if err := c.QueryRow(context.Background(), q).Scan(&s); err != nil {
		t.Fatalf("fingerprint %s: %v", table, err)
	}
	return s
}
