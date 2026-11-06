package pg

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Slot describes a replication slot.
type Slot struct {
	Name     string
	Type     string // physical | logical
	Plugin   string
	Database string
	Active   bool
	// RetainedBytes is the WAL kept on disk because of this slot (distance from
	// the current WAL position back to restart_lsn).
	RetainedBytes float64
	// ConfirmedFlushLagBytes is how far a logical slot's consumer is behind.
	ConfirmedFlushLagBytes float64
}

// Querier is the subset of pgx used for read-only queries.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// ListSlots returns all replication slots, largest retained WAL first. It is
// read-only and shared by the collector and the `slots list` command.
func ListSlots(ctx context.Context, q Querier) ([]Slot, error) {
	return listSlots(ctx, q)
}

func listSlots(ctx context.Context, q Querier) ([]Slot, error) {
	rows, err := q.Query(ctx, `
		SELECT slot_name::text, slot_type::text, COALESCE(plugin::text, ''), COALESCE(database::text, ''), active,
		       COALESCE(pg_wal_lsn_diff(`+currentLSN+`, restart_lsn), 0)::float8,
		       COALESCE(pg_wal_lsn_diff(`+currentLSN+`, confirmed_flush_lsn), 0)::float8
		FROM pg_replication_slots
		ORDER BY 6 DESC, slot_name`)
	if err != nil {
		return nil, fmt.Errorf("list replication slots: %w", err)
	}
	defer rows.Close()
	var out []Slot
	for rows.Next() {
		var s Slot
		if err := rows.Scan(&s.Name, &s.Type, &s.Plugin, &s.Database, &s.Active, &s.RetainedBytes, &s.ConfirmedFlushLagBytes); err != nil {
			return nil, fmt.Errorf("scan replication slot: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
