// Package machine is the migration state machine (SPEC section 9) for the part
// of the lifecycle Phase 3 owns: draft, preflight_ok, source_changes_approved,
// copying, following, caught_up, plus failed, aborted, cleanup_pending and
// cleaned. Cutover states belong to Phase 4 and are added by appending to the
// transition table.
//
// Rules the code enforces (and the tests prove):
//
//   - Intent first: the intent of every effect is persisted before the effect,
//     and its result after. A crash between the two leaves an "intent" step
//     with no result, which resume treats as unknown and reconciles with the
//     real world instead of trusting.
//   - Transitions are compare-and-swap on (id, from state): two drivers cannot
//     both move a migration, and a stale one loses.
//   - Exactly one driver per migration: a lease in the state database plus a
//     lock file with the owner's pid and start time.
//   - Resume never trusts the last recorded step. It observes the real servers
//     (does the slot exist? is the subscription enabled? are there tables on the
//     target?) and decides from that. Every step is idempotent.
package machine

import (
	"errors"
	"fmt"
	"time"
)

// State is a migration state.
type State string

// States of the migration lifecycle owned by Phase 3.
const (
	Draft                 State = "draft"
	PreflightOK           State = "preflight_ok"
	SourceChangesApproved State = "source_changes_approved"
	Copying               State = "copying"
	Following             State = "following"
	CaughtUp              State = "caught_up"
	Failed                State = "failed"
	Aborted               State = "aborted"
	CleanupPending        State = "cleanup_pending"
	Cleaned               State = "cleaned"
)

// transitions is the table of allowed moves. Failed is reachable from every
// state that is still in progress and leaves only to the state it failed from
// (see Facts.FailedFrom); that rule is a guard because the target depends on
// the record.
var transitions = map[State][]State{
	Draft:                 {PreflightOK, Aborted, Failed},
	PreflightOK:           {SourceChangesApproved, Aborted, Failed},
	SourceChangesApproved: {Copying, Aborted, Failed},
	Copying:               {Following, Aborted, Failed},
	Following:             {CaughtUp, Aborted, Failed},
	CaughtUp:              {Aborted, Failed},
	Failed:                {Draft, PreflightOK, SourceChangesApproved, Copying, Following, CaughtUp, CleanupPending, Aborted},
	Aborted:               {CleanupPending},
	CleanupPending:        {Cleaned, Failed},
	Cleaned:               {},
}

// States returns every state in lifecycle order.
func States() []State {
	return []State{Draft, PreflightOK, SourceChangesApproved, Copying, Following, CaughtUp, Failed, Aborted, CleanupPending, Cleaned}
}

// CanTransition reports whether from -> to is in the transition table.
func CanTransition(from, to State) bool {
	for _, t := range transitions[from] {
		if t == to {
			return true
		}
	}
	return false
}

// Terminal reports whether no move leaves the state.
func (s State) Terminal() bool { return len(transitions[s]) == 0 }

// InProgress reports whether a migration in this state can still fail or be
// aborted (it has not reached aborted, cleanup or cleaned).
func (s State) InProgress() bool {
	switch s {
	case Draft, PreflightOK, SourceChangesApproved, Copying, Following, CaughtUp:
		return true
	}
	return false
}

// Facts are the recorded facts a guard may look at. Guards are pure functions
// of Facts, so every one of them is tested without any I/O.
type Facts struct {
	State State
	// FailedFrom, FailedResumable describe a failure (State == Failed).
	FailedFrom      State
	FailedResumable bool
	// PlanHash is the hash of the plan the migration was created from;
	// ApprovedHash is the hash the operator approved for source changes.
	PlanHash     string
	ApprovedHash string
	// PreflightBlockers is the number of BLOCKER findings of the pre-flight run
	// that accompanied the plan (0 when it was clean).
	PreflightBlockers int
	// Databases is the number of databases; SubscriptionsEnabled how many have an
	// enabled subscription (observed, not recorded).
	Databases            int
	SubscriptionsEnabled int
	// CaughtUp is true when every database stayed within the lag threshold for
	// the whole hold period.
	CaughtUp bool
	// CleanupApprovedHash is the hash of the approved cleanup plan, and
	// CleanupDone whether every cleanup action is satisfied.
	CleanupApprovedHash string
	CleanupPlanHash     string
	CleanupDone         bool
}

// Guard errors.
var (
	ErrNoTransition = errors.New("transition is not allowed")
	ErrGuard        = errors.New("guard refused the transition")
)

// Check validates a move from facts.State to `to`: it must be in the table and
// its guard must hold.
func Check(f Facts, to State) error {
	from := f.State
	if !CanTransition(from, to) {
		return fmt.Errorf("%w: %s -> %s", ErrNoTransition, from, to)
	}
	g := func(msg string) error { return fmt.Errorf("%w: %s -> %s: %s", ErrGuard, from, to, msg) }
	switch {
	case from == Failed && to == Aborted:
		// Abort is always possible: it is the way out of a failure that cannot be resumed.
	case from == Failed:
		if !f.FailedResumable {
			return g("the failure is not resumable")
		}
		if to != f.FailedFrom && to != Aborted {
			return g(fmt.Sprintf("a failed migration can only return to %s (where it failed) or be aborted", f.FailedFrom))
		}
	case from == Draft && to == PreflightOK:
		if f.PlanHash == "" {
			return g("there is no plan")
		}
		if f.PreflightBlockers > 0 {
			return g(fmt.Sprintf("the pre-flight has %d BLOCKER finding(s)", f.PreflightBlockers))
		}
	case from == PreflightOK && to == SourceChangesApproved:
		if f.ApprovedHash == "" || f.ApprovedHash != f.PlanHash {
			return g("the plan has not been approved with its exact hash")
		}
	case from == Copying && to == Following:
		if f.Databases == 0 || f.SubscriptionsEnabled != f.Databases {
			return g(fmt.Sprintf("%d of %d databases have an enabled subscription", f.SubscriptionsEnabled, f.Databases))
		}
	case from == Following && to == CaughtUp:
		if !f.CaughtUp {
			return g("replication has not stayed within the lag threshold for the hold period")
		}
	case from == Aborted && to == CleanupPending:
		if f.CleanupApprovedHash == "" || f.CleanupApprovedHash != f.CleanupPlanHash {
			return g("cleanup has not been approved with the exact hash of its plan")
		}
	case from == CleanupPending && to == Cleaned:
		if !f.CleanupDone {
			return g("not every cleanup action is satisfied")
		}
	}
	return nil
}

// Record is a migration as the machine sees it.
type Record struct {
	ID    string
	State State

	FailedFrom      State
	FailedStep      string
	FailedResumable bool
	FailedReason    string

	PlanHash     string
	ApprovedHash string
	Databases    []string

	LeaseOwner string
	LeaseUntil time.Time
}

// Facts converts a record into guard facts (the observed fields are set by the
// caller).
func (r Record) Facts() Facts {
	return Facts{
		State: r.State, FailedFrom: r.FailedFrom, FailedResumable: r.FailedResumable,
		PlanHash: r.PlanHash, ApprovedHash: r.ApprovedHash, Databases: len(r.Databases),
	}
}
