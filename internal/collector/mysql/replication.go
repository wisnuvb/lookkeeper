package mysql

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
)

// replicaState is the part of SHOW REPLICA STATUS Lockkeeper cares about.
type replicaState struct {
	Channel    string
	IORunning  bool
	SQLRunning bool
	// Lag is Seconds_Behind_Source; LagValid is false when the server reports
	// NULL. NULL means replication is broken (a thread is not running or the IO
	// thread is not connected), so it must never be turned into a 0.
	Lag      float64
	LagValid bool
}

// firstColumn returns the first of names present in row. MySQL 8.0.22 renamed
// the columns of SHOW SLAVE STATUS (Slave_IO_Running -> Replica_IO_Running,
// Seconds_Behind_Master -> Seconds_Behind_Source, ...); 8.0.22 and later output the
// new names, older 8.0 releases the old ones.
func firstColumn(row map[string]sql.NullString, names ...string) (sql.NullString, bool) {
	for _, n := range names {
		if v, ok := row[n]; ok {
			return v, true
		}
	}
	return sql.NullString{}, false
}

// parseReplicaRow interprets one row of SHOW REPLICA STATUS (or SHOW SLAVE
// STATUS on 8.0 before 8.0.22). It fails loudly when the expected columns are
// absent: silently reading "not running" or "running" from a layout we do not
// understand would be worse than an error.
func parseReplicaRow(row map[string]sql.NullString) (replicaState, error) {
	var st replicaState
	io, ok := firstColumn(row, "Replica_IO_Running", "Slave_IO_Running")
	if !ok {
		return st, errors.New("unexpected replica status output: no Replica_IO_Running column")
	}
	sqlr, ok := firstColumn(row, "Replica_SQL_Running", "Slave_SQL_Running")
	if !ok {
		return st, errors.New("unexpected replica status output: no Replica_SQL_Running column")
	}
	// "Yes" is the only healthy value: "No", "Connecting" and "" all count as
	// not running.
	st.IORunning = strings.EqualFold(io.String, "Yes")
	st.SQLRunning = strings.EqualFold(sqlr.String, "Yes")
	if ch, ok := row["Channel_Name"]; ok {
		st.Channel = ch.String
	}
	if lag, ok := firstColumn(row, "Seconds_Behind_Source", "Seconds_Behind_Master"); ok && lag.Valid {
		if f, err := strconv.ParseFloat(strings.TrimSpace(lag.String), 64); err == nil {
			if f < 0 {
				f = 0 // clock skew between source and replica
			}
			st.Lag, st.LagValid = f, true
		}
	}
	return st, nil
}

// replication reports replica health. A server that is not a replica returns no
// rows and produces no samples. With several channels each row is labelled with
// its channel; the unnamed default channel gets no label.
//
// SHOW REPLICA STATUS needs the REPLICATION CLIENT privilege. Without it the
// statement is refused and the batch is incomplete: a broken replica must not be
// mistaken for a healthy primary.
func (c *Collector) replication(ctx context.Context, b *batch, si serverInfo) error {
	stmt := "SHOW REPLICA STATUS"
	if si.legacyReplicaSyntax() {
		stmt = "SHOW SLAVE STATUS"
	}
	rows, err := c.db.QueryContext(ctx, stmt)
	if err != nil {
		return err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		row := make(map[string]sql.NullString, len(cols))
		for i, name := range cols {
			row[name] = vals[i]
		}
		st, err := parseReplicaRow(row)
		if err != nil {
			return err
		}
		var labels map[string]string
		if st.Channel != "" {
			labels = map[string]string{"channel": st.Channel}
		}
		b.add(rules.MetricMySQLReplIORunning, flag(st.IORunning), labels)
		b.add(rules.MetricMySQLReplSQLRunning, flag(st.SQLRunning), labels)
		if st.LagValid {
			b.add(rules.MetricMySQLReplLag, st.Lag, labels)
		}
	}
	return rows.Err()
}

func flag(v bool) float64 {
	if v {
		return 1
	}
	return 0
}
