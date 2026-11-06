package pg

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// RowQuerier is the subset of pgx used for single-row read-only queries.
type RowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// AuditRole inspects the privileges of the connected role and returns
// human-readable warnings.
//
// Why this matters: the session is forced read-only (default_transaction_read_only),
// but that is defence in depth, not a security boundary. For example, creating or
// dropping a replication slot is a function call that a read-only session may still
// perform if the role has the privilege. The real boundary is a least-privilege
// role: LOGIN plus membership of pg_monitor, nothing else.
func AuditRole(ctx context.Context, q RowQuerier) ([]string, error) {
	var (
		name                                       string
		super, repl, createRole, createDB, monitor bool
		rdsSuper                                   bool
	)
	err := q.QueryRow(ctx, `
		SELECT r.rolname::text, r.rolsuper, r.rolreplication, r.rolcreaterole, r.rolcreatedb,
		       pg_has_role(current_user, 'pg_monitor', 'member'),
		       COALESCE((SELECT pg_has_role(current_user, 'rds_superuser', 'member')
		                 FROM pg_roles WHERE rolname = 'rds_superuser'), false)
		FROM pg_roles r WHERE r.rolname = current_user`).
		Scan(&name, &super, &repl, &createRole, &createDB, &monitor, &rdsSuper)
	if err != nil {
		return nil, fmt.Errorf("audit role privileges: %w", err)
	}

	var w []string
	switch {
	case super:
		w = append(w, fmt.Sprintf("role %q is a superuser; Lockkeeper only needs LOGIN + pg_monitor. Create a dedicated role (CREATE ROLE lockkeeper LOGIN PASSWORD '...'; GRANT pg_monitor TO lockkeeper;)", name))
	case rdsSuper:
		w = append(w, fmt.Sprintf("role %q is a member of rds_superuser; Lockkeeper only needs LOGIN + pg_monitor. Create a dedicated role instead", name))
	case !monitor:
		w = append(w, fmt.Sprintf("role %q is not a member of pg_monitor; sessions of other users will be invisible and metrics will read 0. Run: GRANT pg_monitor TO %s;", name, name))
	}
	var extra []string
	if repl && !super {
		extra = append(extra, "REPLICATION (can create and drop replication slots)")
	}
	if createRole && !super {
		extra = append(extra, "CREATEROLE")
	}
	if createDB && !super {
		extra = append(extra, "CREATEDB")
	}
	if len(extra) > 0 {
		w = append(w, fmt.Sprintf("role %q has unnecessary privileges: %s", name, strings.Join(extra, ", ")))
	}
	return w, nil
}

// Audit runs AuditRole on the collector's connection, connecting if necessary.
func (c *Collector) Audit(ctx context.Context) ([]string, error) {
	if err := c.ensureConn(ctx); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	gctx, cancel := context.WithTimeout(ctx, c.opts.QueryTimeout)
	defer cancel()
	return AuditRole(gctx, c.conn)
}
