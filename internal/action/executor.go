package action

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Approval methods.
const (
	MethodPlanHash = "plan-hash"
	MethodTyped    = "typed"
)

// Approval is the operator's consent to one plan.
type Approval struct {
	Method   string
	Approver string
}

// ConfirmHash approves p if given is exactly its plan hash. The comparison is
// constant-time. A hash of a different plan, or a prefix, is refused.
func ConfirmHash(p *Plan, given, approver string) (Approval, error) {
	want := p.Hash()
	given = strings.TrimSpace(strings.ToLower(given))
	if subtle.ConstantTimeCompare([]byte(want), []byte(given)) != 1 {
		return Approval{}, fmt.Errorf("plan hash %q does not match this plan (%s): the plan changed or the hash belongs to another plan; run the plan command again", short(given), short(want))
	}
	return Approval{Method: MethodPlanHash, Approver: approver}, nil
}

// TypedPhrase is what an operator must type to approve p interactively.
func TypedPhrase(p *Plan) string { return "approve " + p.Hash()[:12] }

// ConfirmTyped shows the plan summary and a prompt on out and reads one line
// from in. Only the exact phrase approves.
func ConfirmTyped(in io.Reader, out io.Writer, p *Plan, approver string) (Approval, error) {
	phrase := TypedPhrase(p)
	fmt.Fprintf(out, "\nTo approve this plan, type exactly: %s\n> ", phrase)
	line, err := readLine(in)
	if err != nil {
		return Approval{}, fmt.Errorf("read confirmation: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(line)), []byte(phrase)) != 1 {
		return Approval{}, errors.New("confirmation text did not match; nothing was changed")
	}
	return Approval{Method: MethodTyped, Approver: approver}, nil
}

func readLine(in io.Reader) (string, error) {
	var b []byte
	buf := make([]byte, 1)
	for {
		n, err := in.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				return strings.TrimRight(string(b), "\r"), nil
			}
			b = append(b, buf[0])
			if len(b) > 4096 {
				return "", errors.New("confirmation line too long")
			}
		}
		if err != nil {
			if err == io.EOF && len(b) > 0 {
				return string(b), nil
			}
			return "", err
		}
	}
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12] + "..."
	}
	return s
}

// Event is one audit record.
type Event struct {
	At          time.Time
	MigrationID string
	Actor       string
	Kind        string
	ActionID    string
	PlanHash    string
	Method      string
	Detail      string
}

// AuditLog is append-only. Append must be durable before it returns: callers
// write the intent of an effect before performing it.
type AuditLog interface {
	Append(ctx context.Context, e Event) error
}

// ActionRecord is the row kept for every action that was attempted.
type ActionRecord struct {
	MigrationID string
	PlanHash    string
	ActionID    string
	Phase       Phase
	Endpoint    Endpoint
	SQL         string
	Mutates     bool
	// Status is "intent", "applied", "satisfied" or "failed".
	Status   string
	Method   string
	Approver string
	At       time.Time
	Error    string
}

// ActionRecorder stores ActionRecords (the `actions` table).
type ActionRecorder interface {
	RecordAction(ctx context.Context, r ActionRecord) error
}

// ConnFunc opens a connection to an endpoint and returns it with its closer.
type ConnFunc func(ctx context.Context, e Endpoint) (Conn, func(), error)

// Executor applies approved plans.
type Executor struct {
	Audit    AuditLog
	Recorder ActionRecorder
	Now      func() time.Time
	// Actor identifies the process in the audit log (user and host).
	Actor string
	// Scrub removes secrets from error text before it is stored.
	Scrub func(string) string
}

func (x *Executor) now() time.Time {
	if x.Now != nil {
		return x.Now()
	}
	return time.Now()
}

func (x *Executor) scrub(s string) string {
	if x.Scrub != nil {
		return x.Scrub(s)
	}
	return s
}

// Authorization is proof that a specific plan was approved. It can only be
// obtained from Executor.Authorize, which verifies the plan hash.
type Authorization struct {
	x        *Executor
	plan     *Plan
	hash     string
	approval Approval
}

// Authorize verifies that the plan still hashes to approvedHash and that the
// approval is complete. A plan changed after approval (one SQL character, an
// endpoint, a database name) has a different hash and is refused.
func (x *Executor) Authorize(p *Plan, approvedHash string, ap Approval) (*Authorization, error) {
	if x.Audit == nil {
		return nil, errors.New("an audit log is required to apply a plan")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if ap.Method != MethodPlanHash && ap.Method != MethodTyped {
		return nil, fmt.Errorf("unknown approval method %q", ap.Method)
	}
	if strings.TrimSpace(ap.Approver) == "" {
		return nil, errors.New("approval has no approver")
	}
	got := p.Hash()
	if subtle.ConstantTimeCompare([]byte(got), []byte(approvedHash)) != 1 {
		return nil, fmt.Errorf("refusing to apply: the plan hashes to %s but %s was approved; the plan was changed after approval", short(got), short(approvedHash))
	}
	return &Authorization{x: x, plan: p, hash: got, approval: ap}, nil
}

// Plan returns the authorised plan.
func (a *Authorization) Plan() *Plan { return a.plan }

// Hash returns the approved plan hash.
func (a *Authorization) Hash() string { return a.hash }

func (a *Authorization) event(ctx context.Context, kind, actionID, detail string) error {
	return a.x.Audit.Append(ctx, Event{
		At: a.x.now(), MigrationID: a.plan.MigrationID, Actor: a.x.Actor, Kind: kind,
		ActionID: actionID, PlanHash: a.hash, Method: a.approval.Method, Detail: a.x.scrub(detail),
	})
}

func (a *Authorization) record(ctx context.Context, act Action, status, errText string) error {
	if a.x.Recorder == nil {
		return nil
	}
	return a.x.Recorder.RecordAction(ctx, ActionRecord{
		MigrationID: a.plan.MigrationID, PlanHash: a.hash, ActionID: act.ID(), Phase: act.Phase(),
		Endpoint: act.Target(), SQL: act.SQL(), Mutates: act.Mutates(), Status: status,
		Method: a.approval.Method, Approver: a.approval.Approver, At: a.x.now(), Error: a.x.scrub(errText),
	})
}

// Do performs fn as the effect of action id of the authorised plan. The intent
// is recorded (audit log and actions table) before fn runs and the result
// after. fn that returns ErrAlreadySatisfied is recorded as satisfied and
// reported to the caller as success.
func (a *Authorization) Do(ctx context.Context, id string, fn func(context.Context) error) error {
	act, ok := a.plan.Find(id)
	if !ok {
		return fmt.Errorf("action %q is not part of the approved plan", id)
	}
	if err := a.event(ctx, "action.intent", id, act.Describe()); err != nil {
		return fmt.Errorf("record intent of %s (nothing was done): %w", id, err)
	}
	if err := a.record(ctx, act, "intent", ""); err != nil {
		return fmt.Errorf("record intent of %s (nothing was done): %w", id, err)
	}
	err := fn(ctx)
	switch {
	case err == nil:
		if e := a.event(ctx, "action.applied", id, ""); e != nil {
			return fmt.Errorf("%s was applied but recording it failed: %w", id, e)
		}
		return a.record(ctx, act, "applied", "")
	case errors.Is(err, ErrAlreadySatisfied):
		if e := a.event(ctx, "action.satisfied", id, "effect already in place"); e != nil {
			return e
		}
		return a.record(ctx, act, "satisfied", "")
	default:
		_ = a.event(ctx, "action.failed", id, err.Error())
		_ = a.record(ctx, act, "failed", err.Error())
		return err
	}
}

// Apply runs one SQL action of the plan on c.
func (a *Authorization) Apply(ctx context.Context, id string, c Conn) error {
	act, ok := a.plan.Find(id)
	if !ok {
		return fmt.Errorf("action %q is not part of the approved plan", id)
	}
	return a.Do(ctx, id, func(ctx context.Context) error { return act.Apply(ctx, c) })
}

// Report says what Run did.
type Report struct {
	Applied   []string
	Satisfied []string
	// Skipped are actions of the phase that the engine runs itself.
	Skipped []string
}

// Run applies, in plan order, every SQL action of phase that changes its
// endpoint. It stops at the first failure. Connections are opened through
// conns, one per distinct endpoint, and closed before Run returns.
func (a *Authorization) Run(ctx context.Context, phase Phase, conns ConnFunc) (Report, error) {
	var rep Report
	type open struct {
		c     Conn
		close func()
	}
	cache := map[Endpoint]open{}
	defer func() {
		for _, o := range cache {
			o.close()
		}
	}()
	for _, act := range a.plan.ActionsOf(phase) {
		if !act.Mutates() {
			continue
		}
		if _, isStep := act.(*Step); isStep {
			rep.Skipped = append(rep.Skipped, act.ID())
			continue
		}
		ep := act.Target()
		o, ok := cache[ep]
		if !ok {
			c, closer, err := conns(ctx, ep)
			if err != nil {
				return rep, fmt.Errorf("%s: connect to %s: %w", act.ID(), ep, err)
			}
			o = open{c, closer}
			cache[ep] = o
		}
		satisfied := false
		err := a.Do(ctx, act.ID(), func(ctx context.Context) error {
			e := act.Apply(ctx, o.c)
			if errors.Is(e, ErrAlreadySatisfied) {
				satisfied = true
			}
			return e
		})
		if err != nil {
			return rep, err
		}
		if satisfied {
			rep.Satisfied = append(rep.Satisfied, act.ID())
		} else {
			rep.Applied = append(rep.Applied, act.ID())
		}
	}
	return rep, nil
}

// DryRun lists what Run would do for phase, without connecting anywhere.
func DryRun(p *Plan, phase Phase) []string {
	var lines []string
	for _, act := range p.ActionsOf(phase) {
		verb := "would run"
		if !act.Mutates() {
			verb = "read-only"
		}
		lines = append(lines, fmt.Sprintf("%s [%s] %s: %s", verb, act.ID(), act.Target(), strings.ReplaceAll(act.SQL(), "\n", " ")))
	}
	return lines
}
