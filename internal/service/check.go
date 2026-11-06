package service

import (
	"context"
	"fmt"
	"sort"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/collector/pg"
	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/model"
)

// TargetResult is the outcome of checking one database.
type TargetResult struct {
	Name         string         `json:"name"`
	Up           bool           `json:"up"`
	Error        string         `json:"error,omitempty"`
	Findings     []model.Event  `json:"findings"`
	Samples      []model.Sample `json:"samples,omitempty"`
	RoleWarnings []string       `json:"role_warnings,omitempty"`
}

// CheckResult is the outcome of a one-shot check.
type CheckResult struct {
	Targets  []TargetResult `json:"targets"`
	Severity model.Severity `json:"severity"`
	// Skipped lists checks that need history and are only evaluated by
	// `monitor run` (a snapshot cannot say how long a condition has lasted).
	Skipped []string `json:"skipped,omitempty"`
}

// ExitCode maps the overall severity to a process exit code: 0 ok, 2 warning,
// 3 critical. (1 is reserved for operational errors.)
func (r *CheckResult) ExitCode() int {
	switch r.Severity {
	case model.SeverityCritical:
		return 3
	case model.SeverityWarning:
		return 2
	default:
		return 0
	}
}

// instantRules prepares rules for a one-shot check. A snapshot has no history, so
// "for" durations are dropped (they are flap damping) and rules whose meaning is
// the duration itself are left out; their descriptions are returned as skipped.
func instantRules(in []rules.Rule) (out []rules.Rule, skipped []string) {
	for _, r := range in {
		if r.NeedsHistory {
			skipped = append(skipped, r.Description)
			continue
		}
		c := r
		c.Levels = append([]rules.Level(nil), r.Levels...)
		for j := range c.Levels {
			c.Levels[j].For = 0
		}
		out = append(out, c)
	}
	return out, skipped
}

// Check collects once from each target and evaluates the rules against the
// current values. If targets is empty, the configured monitor targets are used.
func (s *Service) Check(ctx context.Context, targets []string, withSamples bool) (*CheckResult, error) {
	if len(targets) == 0 {
		targets = s.cfg.Monitor.Targets
	}
	if err := s.validateTargets(targets); err != nil {
		return nil, err
	}
	instant, skipped := instantRules(s.rules)
	engine, err := rules.New(instant, rules.Options{})
	if err != nil {
		return nil, err
	}
	res := &CheckResult{Severity: model.SeverityOK, Skipped: skipped}
	for _, name := range targets {
		tr := s.checkOne(ctx, engine, name, withSamples)
		for _, f := range tr.Findings {
			if f.Severity.Rank() > res.Severity.Rank() {
				res.Severity = f.Severity
			}
		}
		res.Targets = append(res.Targets, tr)
	}
	return res, nil
}

func (s *Service) checkOne(ctx context.Context, engine *rules.Engine, name string, withSamples bool) TargetResult {
	tr := TargetResult{Name: name, Findings: []model.Event{}}
	col := s.newCollector(name)
	defer col.Close()

	samples, complete, err := col.Collect(ctx)
	if err != nil {
		tr.Error = s.redactErr(err).Error()
	}
	for _, sm := range samples {
		if (sm.Metric == rules.MetricPGUp || sm.Metric == rules.MetricMySQLUp) && sm.Value == 1 {
			tr.Up = true
		}
	}
	if auditor, ok := col.(interface {
		Audit(context.Context) ([]string, error)
	}); ok && tr.Up {
		if w, aerr := auditor.Audit(ctx); aerr != nil {
			tr.RoleWarnings = append(tr.RoleWarnings, "could not audit role privileges: "+s.redactErr(aerr).Error())
		} else {
			tr.RoleWarnings = w
		}
	}

	engine.Eval(s.deps.Now(), name, samples, complete)
	for _, ev := range engine.Active() {
		if ev.Target == name {
			tr.Findings = append(tr.Findings, ev)
		}
	}
	sort.SliceStable(tr.Findings, func(i, j int) bool {
		if tr.Findings[i].Severity.Rank() != tr.Findings[j].Severity.Rank() {
			return tr.Findings[i].Severity.Rank() > tr.Findings[j].Severity.Rank()
		}
		return tr.Findings[i].Key() < tr.Findings[j].Key()
	})
	if withSamples {
		tr.Samples = samples
	}
	return tr
}

// SlotsList lists replication slots on a database. It is read-only.
func (s *Service) SlotsList(ctx context.Context, target string) ([]pg.Slot, error) {
	if err := s.validateTargets([]string{target}); err != nil {
		return nil, err
	}
	if engine := s.cfg.Databases[target].Engine; engine != config.EnginePostgres {
		return nil, fmt.Errorf("replication slots are a PostgreSQL concept and do not apply to %s target %q", engine, target)
	}
	conn, err := s.openFunc(target)(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", target, err)
	}
	defer conn.Close(ctx)
	slots, err := pg.ListSlots(ctx, conn)
	if err != nil {
		return nil, s.redactErr(err)
	}
	return slots, nil
}
