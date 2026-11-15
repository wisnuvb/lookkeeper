package service

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/action"
	"github.com/wisnuvb/lockkeeper/internal/migrate/machine"
	"github.com/wisnuvb/lockkeeper/internal/preflight"
)

// MigrateOptions says what to migrate and how. It is the input of planning;
// everything that matters afterwards is stored with the plan.
type MigrateOptions struct {
	// Source and Target are configured connection names (roles for this
	// migration only).
	Source, Target string
	// Databases restricts the migration to these databases (default: all that
	// the pre-flight inspects).
	Databases    []string
	MaxDatabases int
	// Copier is "pgcopydb" (default) or "pgdump".
	Copier    string
	TableJobs int
	IndexJobs int
	// NoOwner skips restoring object ownership (when the owner roles do not
	// exist on the target).
	NoOwner bool
	// PeerAddr is the source as the TARGET server reaches it ("host:port"); the
	// default is the configured host and port. PeerSSLMode and PeerSSLRootCert
	// (a path on the target server) default to the source connection's TLS mode.
	PeerAddr        string
	PeerSSLMode     string
	PeerSSLRootCert string
}

// ToolOptions locate the external tools. They are not part of a plan.
type ToolOptions struct {
	// ToolPath is the PATH the tools get (default /usr/local/bin:/usr/bin:/bin);
	// ClientBinDir, if set, is put first (the PostgreSQL client tools must be at
	// least the source's major version).
	ToolPath     string
	ClientBinDir string
	// Pgcopydb, PgDump, PgRestore override the tool names.
	Pgcopydb, PgDump, PgRestore string
	// PinnedPgcopydb is the pgcopydb version Lockkeeper was tested with.
	PinnedPgcopydb string
	// AllowUntestedPgcopydb accepts another pgcopydb version.
	AllowUntestedPgcopydb bool
}

// PinnedPgcopydbVersion is the pgcopydb release the orchestrator was developed
// against (ADR 0002, SPEC Appendix A).
const PinnedPgcopydbVersion = "0.18"

// BlockedError means the pre-flight reported BLOCKER findings: planning refuses
// to go on, and nothing was changed.
type BlockedError struct{ Report *preflight.Report }

func (e *BlockedError) Error() string {
	var ids []string
	for _, f := range e.Report.Findings {
		if f.Severity == preflight.Blocker {
			ids = append(ids, f.ID)
		}
	}
	return fmt.Sprintf("the pre-flight has %d BLOCKER finding(s) (%s): fix them first (run `lockkeeper preflight pg` for the details); nothing was changed", len(ids), strings.Join(ids, ", "))
}

// PrivilegeError lists what the connected roles lack. It is returned before any
// change is made.
type PrivilegeError struct{ Problems []string }

func (e *PrivilegeError) Error() string {
	return "the migration cannot start with these connections; nothing was changed:\n  - " + strings.Join(e.Problems, "\n  - ")
}

// ErrNoApproval is returned when a mutating command is not confirmed.
var ErrNoApproval = errors.New("refusing: this changes a database and needs confirmation: pass --plan-hash from the plan (or run it on a terminal and type the phrase shown)")

// PlanResult is what `migrate plan` returns.
type PlanResult struct {
	MigrationID string
	State       string
	Plan        *action.Plan
	Report      *preflight.Report
	// Existing is true when the same plan had been made before.
	Existing bool
}

// Approver turns the operator's consent into an action.Approval for a plan. The
// CLI implements it with --plan-hash or a typed phrase; a nil Approver means
// dry run.
type Approver func(p *action.Plan) (action.Approval, error)

// ApplyOptions are the inputs of `migrate apply-source-changes`.
type ApplyOptions struct {
	// PlanHash identifies the plan (and is itself the approval when used with
	// HashApproval). MigrationID may be used instead on a terminal.
	PlanHash    string
	MigrationID string
	// Apply is false for a dry run (the default of the command).
	Apply    bool
	Approver Approver
}

// ApplyResult describes what apply-source-changes did or would do.
type ApplyResult struct {
	MigrationID string
	Plan        *action.Plan
	DryRun      bool
	Lines       []string
	Report      action.Report
}

// RunOptions are the inputs of `migrate start` and `migrate resume`.
type RunOptions struct {
	PlanHash    string
	MigrationID string
	Tools       ToolOptions
	// Wait keeps running until caught up (default for the commands).
	Wait bool
	// MaxLagBytes and CaughtUpFor define "caught up". PollInterval is how often
	// progress is read.
	MaxLagBytes  int64
	CaughtUpFor  time.Duration
	PollInterval time.Duration
	// SlotTimeout bounds the wait for open transactions when creating a slot.
	SlotTimeout time.Duration
	// ApplyRecovery executes a recovery plan whose hash is RecoveryHash (or that
	// the Approver confirms).
	ApplyRecovery bool
	RecoveryHash  string
	Approver      Approver
	// Notify receives progress lines.
	Notify func(level, msg string)
}

// RunResult is the outcome of start/resume.
type RunResult struct {
	MigrationID string
	State       machine.State
	// RecoveryPlan is set when a new copy is needed and has not been approved.
	RecoveryPlan *action.Plan
	RecoveryWhy  string
}

// ErrRecoveryPlanNeeded is returned with RunResult.RecoveryPlan set.
var ErrRecoveryPlanNeeded = errors.New("a new copy is required: review the recovery plan, then run resume again with --apply and its --plan-hash")

// ErrDriverBusy is returned when another process is driving the migration.
var ErrDriverBusy = machine.ErrLocked

// DBStatus is the live state of one database of a migration.
type DBStatus struct {
	Database      string `json:"database"`
	Index         int    `json:"index"`
	Attempt       int    `json:"attempt"`
	CopyDone      bool   `json:"copy_done"`
	Slot          string `json:"slot"`
	SlotExists    bool   `json:"slot_exists"`
	SlotActive    bool   `json:"slot_active"`
	WALStatus     string `json:"wal_status,omitempty"`
	RetainedBytes int64  `json:"retained_wal_bytes"`
	LagBytes      int64  `json:"lag_bytes"`
	Guardrail     string `json:"wal_guardrail"`
	Subscription  string `json:"subscription"`
	SubExists     bool   `json:"subscription_exists"`
	SubEnabled    bool   `json:"subscription_enabled"`
	WorkerRunning bool   `json:"apply_worker_running"`
	ApplyErrors   int64  `json:"apply_errors"`
	SourceLSN     string `json:"source_lsn,omitempty"`
	RemoteLSN     string `json:"target_remote_lsn,omitempty"`
	Error         string `json:"error,omitempty"`
}

// Status is the read-only view `migrate status` prints.
type Status struct {
	MigrationID     string     `json:"migration_id"`
	State           string     `json:"state"`
	Source          string     `json:"source"`
	Target          string     `json:"target"`
	PlanHash        string     `json:"plan_hash"`
	Approved        bool       `json:"source_changes_approved"`
	FailedStep      string     `json:"failed_step,omitempty"`
	FailedReason    string     `json:"failed_reason,omitempty"`
	FailedResumable bool       `json:"failed_resumable,omitempty"`
	Driver          string     `json:"driver,omitempty"`
	Databases       []DBStatus `json:"databases"`
	Warnings        []string   `json:"warnings,omitempty"`
	LastEvents      []string   `json:"last_events,omitempty"`
	Updated         time.Time  `json:"updated"`
}

// EndOptions are the inputs of abort and cleanup.
type EndOptions struct {
	PlanHash    string
	MigrationID string
	Apply       bool
	Approver    Approver
	Tools       ToolOptions
}

// EndResult describes an abort or cleanup (or its dry run).
type EndResult struct {
	MigrationID string
	Plan        *action.Plan
	DryRun      bool
	Lines       []string
	State       machine.State
}
