// Package migrate holds the types shared by the PostgreSQL migration
// orchestrator: the Copier seam (bulk copy inside an exported snapshot) and the
// Replicator seam (change streaming), LSN helpers, and naming of everything
// Lockkeeper creates. The implementations live in subpackages:
//
//	machine   the state machine and the step driver
//	copier    pgcopydb and pg_dump/pg_restore
//	pgnative  publication, slot and snapshot handoff, subscription lifecycle
//	runner    external process execution (passfile, process group, redaction)
package migrate

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/wisnuvb/lockkeeper/internal/secret"
)

// LSN is a PostgreSQL write-ahead log position.
type LSN uint64

// ParseLSN parses the "X/Y" hexadecimal form.
func ParseLSN(s string) (LSN, error) {
	hi, lo, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok {
		return 0, fmt.Errorf("invalid LSN %q", s)
	}
	h, err := strconv.ParseUint(hi, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid LSN %q", s)
	}
	l, err := strconv.ParseUint(lo, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid LSN %q", s)
	}
	return LSN(h<<32 | l), nil
}

// String returns the "X/Y" form.
func (l LSN) String() string { return fmt.Sprintf("%X/%X", uint64(l)>>32, uint64(l)&0xFFFFFFFF) }

// Endpoint is a database Lockkeeper (or a tool it runs) connects to. The
// password is only ever used to fill a 0600 passfile.
type Endpoint struct {
	Name     string
	Host     string
	Port     int
	Database string
	User     string
	Password secret.Value
	// TLSMode is a libpq sslmode (verify-full, verify-ca, require, disable).
	TLSMode string
	CAFile  string
}

// CopyInput is everything a Copier needs to copy one database.
type CopyInput struct {
	Source, Target Endpoint
	// SnapshotID is the snapshot exported by the slot-creating replication
	// connection, which the caller keeps open for the duration of the copy.
	SnapshotID string
	// WorkDir is a fresh empty directory (0700) private to this attempt.
	WorkDir string
	// SourceMajor is the source server's major version (for tool checks).
	SourceMajor int
	TableJobs   int
	IndexJobs   int
	// NoOwner skips restoring object ownership (use when the owner roles do not
	// exist on the target).
	NoOwner bool
}

// Copier performs the bulk copy of one database inside an exported snapshot:
// schema, data, indexes and constraints. Implementations must never pass
// options that restart or reuse earlier state, and must not create anything on
// the source.
type Copier interface {
	// Name is "pgcopydb" or "pgdump".
	Name() string
	// Check verifies that the tool is present, usable for this source and, where
	// applicable, the pinned version. It runs the tool's version command only.
	Check(ctx context.Context, sourceMajor int) error
	// Describe returns the command lines Copy would run, with passwords absent
	// (they never appear), for the plan.
	Describe(in CopyInput) []string
	// Copy runs the copy and returns when it finished or failed.
	Copy(ctx context.Context, in CopyInput) error
}

// Names of what Lockkeeper creates. Everything carries the migration id so it
// can be recognised and removed exactly, and never collides with user objects.
type Names struct {
	MigrationID string
}

// Role is the per-migration role the target uses to read the source.
func (n Names) Role() string { return "lk_" + n.MigrationID }

// Publication is the per-database publication on the source.
func (n Names) Publication(dbIndex int) string {
	return fmt.Sprintf("lk_%s_d%d", n.MigrationID, dbIndex)
}

// Slot is the replication slot of database dbIndex for a copy attempt.
func (n Names) Slot(dbIndex, attempt int) string {
	return fmt.Sprintf("lk_%s_d%d_a%d", n.MigrationID, dbIndex, attempt)
}

// Subscription is the per-database subscription on the target.
func (n Names) Subscription(dbIndex int) string {
	return fmt.Sprintf("lk_%s_d%d", n.MigrationID, dbIndex)
}

// Marker is written as a comment on the publication and the role so that
// cleanup only removes objects that carry it.
func (n Names) Marker() string { return "lockkeeper:" + n.MigrationID }
