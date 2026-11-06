package machine

import (
	"errors"
	"strings"
	"testing"
)

// allowed is the complete, independent statement of the transition table: the
// test checks every (from, to) pair of every known state against it, so adding
// a transition to the code without updating the spec fails here.
var allowed = map[State][]State{
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

func TestEveryPairIsCheckedAgainstTheTable(t *testing.T) {
	for _, from := range States() {
		for _, to := range States() {
			want := false
			for _, a := range allowed[from] {
				if a == to {
					want = true
				}
			}
			if got := CanTransition(from, to); got != want {
				t.Errorf("CanTransition(%s, %s) = %v, want %v", from, to, got, want)
			}
		}
	}
	for _, s := range []State{Cleaned} {
		if !s.Terminal() {
			t.Errorf("%s must be terminal", s)
		}
	}
	for _, s := range []State{Copying, Failed, Aborted} {
		if s.Terminal() {
			t.Errorf("%s must not be terminal", s)
		}
	}
}

func TestNoStateReachesCleanedOrCleanupWithoutAbortOrCutover(t *testing.T) {
	// Phase 3 can only reach cleanup through aborted (or a failed cleanup):
	// following and caught_up cannot jump to cleanup, so the source's slot is
	// never dropped by a state change alone.
	for _, from := range []State{Draft, PreflightOK, SourceChangesApproved, Copying, Following, CaughtUp} {
		for _, to := range []State{CleanupPending, Cleaned} {
			if CanTransition(from, to) {
				t.Errorf("%s -> %s must not be allowed", from, to)
			}
		}
	}
}

func TestGuards(t *testing.T) {
	ok := func() Facts {
		return Facts{PlanHash: "h", ApprovedHash: "h", Databases: 2, SubscriptionsEnabled: 2, CaughtUp: true,
			CleanupApprovedHash: "c", CleanupPlanHash: "c", CleanupDone: true}
	}
	type tc struct {
		name    string
		from    State
		to      State
		mut     func(*Facts)
		wantErr string // "" means allowed; otherwise a substring
	}
	cases := []tc{
		{"draft->preflight_ok clean", Draft, PreflightOK, nil, ""},
		{"draft->preflight_ok no plan", Draft, PreflightOK, func(f *Facts) { f.PlanHash = "" }, "no plan"},
		{"draft->preflight_ok blockers", Draft, PreflightOK, func(f *Facts) { f.PreflightBlockers = 2 }, "BLOCKER"},
		{"preflight_ok->approved exact hash", PreflightOK, SourceChangesApproved, nil, ""},
		{"preflight_ok->approved no approval", PreflightOK, SourceChangesApproved, func(f *Facts) { f.ApprovedHash = "" }, "not been approved"},
		{"preflight_ok->approved other hash", PreflightOK, SourceChangesApproved, func(f *Facts) { f.ApprovedHash = "x" }, "not been approved"},
		{"approved->copying", SourceChangesApproved, Copying, nil, ""},
		{"copying->following all enabled", Copying, Following, nil, ""},
		{"copying->following one missing", Copying, Following, func(f *Facts) { f.SubscriptionsEnabled = 1 }, "1 of 2"},
		{"copying->following none", Copying, Following, func(f *Facts) { f.SubscriptionsEnabled = 0 }, "0 of 2"},
		{"copying->following no databases", Copying, Following, func(f *Facts) { f.Databases, f.SubscriptionsEnabled = 0, 0 }, "0 of 0"},
		{"following->caught_up held", Following, CaughtUp, nil, ""},
		{"following->caught_up not held", Following, CaughtUp, func(f *Facts) { f.CaughtUp = false }, "lag threshold"},
		{"any->aborted from draft", Draft, Aborted, nil, ""},
		{"any->aborted from copying", Copying, Aborted, nil, ""},
		{"any->aborted from caught_up", CaughtUp, Aborted, nil, ""},
		{"aborted->cleanup_pending approved", Aborted, CleanupPending, nil, ""},
		{"aborted->cleanup_pending unapproved", Aborted, CleanupPending, func(f *Facts) { f.CleanupApprovedHash = "" }, "cleanup has not been approved"},
		{"aborted->cleanup_pending other plan", Aborted, CleanupPending, func(f *Facts) { f.CleanupApprovedHash = "z" }, "cleanup has not been approved"},
		{"cleanup_pending->cleaned done", CleanupPending, Cleaned, nil, ""},
		{"cleanup_pending->cleaned not done", CleanupPending, Cleaned, func(f *Facts) { f.CleanupDone = false }, "not every cleanup"},
		{"copying->caught_up skips following", Copying, CaughtUp, nil, "not allowed"},
		{"following->copying goes back", Following, Copying, nil, "not allowed"},
		{"caught_up->cleaned never", CaughtUp, Cleaned, nil, "not allowed"},
		{"following->cleanup_pending never", Following, CleanupPending, nil, "not allowed"},
		{"cleaned->anything", Cleaned, Draft, nil, "not allowed"},
		{"aborted->copying no resume after abort", Aborted, Copying, nil, "not allowed"},
		{"draft->copying skips approval", Draft, Copying, nil, "not allowed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := ok()
			f.State = c.from
			if c.mut != nil {
				c.mut(&f)
			}
			err := Check(f, c.to)
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("want allowed, got %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Fatalf("want error containing %q, got %v", c.wantErr, err)
			}
			if c.wantErr == "not allowed" && !errors.Is(err, ErrNoTransition) {
				t.Errorf("want ErrNoTransition, got %v", err)
			}
		})
	}
}

func TestFailedMayOnlyReturnToWhereItFailed(t *testing.T) {
	f := Facts{State: Failed, FailedFrom: Copying, FailedResumable: true}
	if err := Check(f, Copying); err != nil {
		t.Fatalf("resume to the failing state: %v", err)
	}
	for _, to := range []State{Draft, PreflightOK, SourceChangesApproved, Following, CaughtUp, CleanupPending} {
		if err := Check(f, to); !errors.Is(err, ErrGuard) {
			t.Errorf("failed(copying) -> %s must be refused by the guard, got %v", to, err)
		}
	}
	if err := Check(f, Aborted); err != nil {
		t.Fatalf("a failed migration may always be aborted: %v", err)
	}
	f.FailedResumable = false
	if err := Check(f, Copying); !errors.Is(err, ErrGuard) {
		t.Fatalf("a non-resumable failure cannot resume: %v", err)
	}
	if err := Check(f, Aborted); err != nil {
		t.Fatalf("abort works for a non-resumable failure: %v", err)
	}
	// A failed cleanup returns to cleanup_pending, not to aborted.
	f = Facts{State: Failed, FailedFrom: CleanupPending, FailedResumable: true}
	if err := Check(f, CleanupPending); err != nil {
		t.Fatal(err)
	}
}

func TestGuardrailLevels(t *testing.T) {
	g := Guardrail{Warn: 5 << 30, Critical: 20 << 30}
	for _, tc := range []struct {
		retained int64
		status   string
		want     string
	}{
		{0, "reserved", "ok"}, {5<<30 - 1, "", "ok"}, {5 << 30, "", "warning"}, {20<<30 - 1, "", "warning"},
		{20 << 30, "", "critical"}, {0, "lost", "critical"},
	} {
		if got := g.Level(tc.retained, tc.status); got != tc.want {
			t.Errorf("Level(%d, %q) = %s, want %s", tc.retained, tc.status, got, tc.want)
		}
	}
	if (Guardrail{}).Level(1<<40, "") != "ok" {
		t.Error("zero thresholds disable the size guardrail")
	}
}

func TestNeedsRecoveryDecisionTable(t *testing.T) {
	for _, tc := range []struct {
		name     string
		copyDone bool
		o        DBState
		want     bool
	}{
		{"fresh database", false, DBState{}, false},
		{"copy finished, slot present", true, DBState{SlotExists: true}, false},
		{"copy finished, sub enabled", true, DBState{SlotExists: true, SubExists: true, SubEnabled: true}, false},
		{"copy finished, slot dropped by someone", true, DBState{SubExists: true}, true},
		{"copy finished, slot lost its WAL", true, DBState{SlotExists: true, SlotWALStatus: "lost"}, true},
		{"copy not finished, slot left over", false, DBState{SlotExists: true}, true},
		{"copy not finished, partial tables on the target", false, DBState{TargetHasTables: true}, true},
		{"copy not finished, a subscription exists", false, DBState{SubExists: true}, true},
		{"copy finished, target has tables (expected)", true, DBState{SlotExists: true, TargetHasTables: true}, false},
	} {
		if _, got := needsRecovery(tc.copyDone, tc.o); got != tc.want {
			t.Errorf("%s: needsRecovery = %v, want %v", tc.name, got, tc.want)
		}
	}
}
