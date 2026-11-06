package mysql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// result is a canned answer to one statement.
type result struct {
	cols []string
	rows [][]any // nil = SQL NULL
}

// fakeServer is a scripted MySQL server behind database/sql, so the collector's
// control flow (error classification, partial failures, rates) can be tested
// without a container. Handlers are matched by substring of the statement.
type fakeServer struct {
	mu       sync.Mutex
	handlers []handler
	queries  []string
	opens    int
}

type handler struct {
	match string
	fn    func() (result, error)
}

// on registers a handler; the first registered match wins, so register specific
// statements before general ones. Re-registering the same match replaces it.
func (f *fakeServer) on(match string, fn func() (result, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.handlers {
		if f.handlers[i].match == match {
			f.handlers[i].fn = fn
			return
		}
	}
	f.handlers = append(f.handlers, handler{match, fn})
}

func (f *fakeServer) onRows(match string, cols []string, rows ...[]any) {
	f.on(match, func() (result, error) { return result{cols: cols, rows: rows}, nil })
}

func (f *fakeServer) onErr(match string, err error) {
	f.on(match, func() (result, error) { return result{}, err })
}

func (f *fakeServer) executed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

func (f *fakeServer) Connect(context.Context) (driver.Conn, error) {
	f.mu.Lock()
	f.opens++
	f.mu.Unlock()
	return &fakeConn{srv: f}, nil
}

func (f *fakeServer) Driver() driver.Driver { return fakeDriver{} }

type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) { return nil, fmt.Errorf("not used") }

type fakeConn struct{ srv *fakeServer }

func (c *fakeConn) Prepare(string) (driver.Stmt, error) {
	return nil, fmt.Errorf("prepare not supported")
}
func (c *fakeConn) Close() error              { return nil }
func (c *fakeConn) Begin() (driver.Tx, error) { return nil, fmt.Errorf("begin not supported") }

func (c *fakeConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.srv.mu.Lock()
	c.srv.queries = append(c.srv.queries, query)
	var fn func() (result, error)
	for _, h := range c.srv.handlers {
		if strings.Contains(query, h.match) {
			fn = h.fn
			break
		}
	}
	c.srv.mu.Unlock()
	if fn == nil {
		return nil, fmt.Errorf("fake server: unexpected statement %q", query)
	}
	res, err := fn()
	if err != nil {
		return nil, err
	}
	return &fakeRows{res: res}, nil
}

type fakeRows struct {
	res result
	i   int
}

func (r *fakeRows) Columns() []string { return r.res.cols }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.i >= len(r.res.rows) {
		return io.EOF
	}
	for j, v := range r.res.rows[r.i] {
		switch x := v.(type) {
		case nil:
			dest[j] = nil
		case int:
			dest[j] = int64(x)
		case string:
			dest[j] = []byte(x) // the MySQL text protocol delivers bytes
		default:
			dest[j] = v
		}
	}
	r.i++
	return nil
}

// open returns an OpenFunc over the fake server.
func (f *fakeServer) open() OpenFunc {
	return func(context.Context) (*sql.DB, error) {
		db := sql.OpenDB(f)
		db.SetMaxOpenConns(1)
		return db, nil
	}
}

// healthyServer scripts an 8.4 primary with sane values. Tests override parts.
func healthyServer() *fakeServer {
	f := &fakeServer{}
	f.onRows("SELECT VERSION()", []string{"VERSION()", "@@version_comment", "@@global.max_connections"},
		[]any{"8.4.13", "MySQL Community Server - GPL", 200})
	f.onRows("SHOW GLOBAL STATUS", []string{"Variable_name", "Value"},
		[]any{"Threads_connected", "50"}, []any{"Threads_running", "3"}, []any{"Uptime", "1000"},
		[]any{"Slow_queries", "10"}, []any{"Innodb_row_lock_waits", "5"},
		[]any{"Innodb_buffer_pool_reads", "100"}, []any{"Innodb_buffer_pool_read_requests", "100000"})
	f.onRows("INNODB_TRX", []string{"age"}, []any{42})
	f.onRows("INNODB_METRICS", []string{"count"}, []any{12345})
	f.onRows("SHOW REPLICA STATUS", []string{"Replica_IO_Running", "Replica_SQL_Running"}) // not a replica
	f.onRows("SHOW BINARY LOGS", []string{"Log_name", "File_size", "Encrypted"},
		[]any{"bin.000001", "1000", "No"}, []any{"bin.000002", "2500", "No"})
	return f
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestCollector(t *testing.T, f *fakeServer, ck *clock) *Collector {
	t.Helper()
	c := New("my-main", f.open(), Options{QueryTimeout: 2 * time.Second, Now: ck.now})
	t.Cleanup(func() { _ = c.Close() })
	return c
}
