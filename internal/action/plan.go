package action

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// FormatVersion is the version of the canonical plan layout. Changing the
// layout changes every hash, so it is part of the hashed document.
const FormatVersion = 1

// PlanKind says what a plan is for.
type PlanKind string

// Plan kinds.
const (
	KindMigrate PlanKind = "migrate"
	KindAbort   PlanKind = "abort"
	KindRecover PlanKind = "recover"
	KindCleanup PlanKind = "cleanup"
)

// Identity names a server without any secret.
type Identity struct {
	Name          string `json:"name"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	User          string `json:"user"`
	ServerVersion string `json:"server_version"`
}

// Spec is the serialised, reviewable form of an Action.
type Spec struct {
	ID       string   `json:"id"`
	Phase    Phase    `json:"phase"`
	Endpoint Endpoint `json:"endpoint"`
	Mutates  bool     `json:"mutates"`
	Describe string   `json:"describe"`
	SQL      string   `json:"sql"`
}

// SpecOf returns the serialised form of a.
func SpecOf(a Action) Spec {
	return Spec{ID: a.ID(), Phase: a.Phase(), Endpoint: a.Target(), Mutates: a.Mutates(), Describe: a.Describe(), SQL: a.SQL()}
}

// Plan is an ordered list of actions between a source and a target.
type Plan struct {
	Kind          PlanKind
	LockkeeperVer string
	// MigrationID names the migration; it is derived from the first plan's hash
	// and appears in the names of everything Lockkeeper creates.
	MigrationID string
	Source      Identity
	Target      Identity
	Databases   []string
	// Settings holds the plan-wide choices that change behaviour (bulk copier,
	// address the target uses to reach the source, ...). No secrets.
	Settings map[string]string
	// Notices are warnings the operator acknowledges by approving the plan.
	Notices []string
	Actions []Action
}

// planDoc is the canonical document that is hashed. Field order is fixed by
// the struct; map keys are sorted by encoding/json.
type planDoc struct {
	Format      int               `json:"format"`
	Kind        PlanKind          `json:"kind"`
	Lockkeeper  string            `json:"lockkeeper_version"`
	MigrationID string            `json:"migration_id"`
	Source      Identity          `json:"source"`
	Target      Identity          `json:"target"`
	Databases   []string          `json:"databases"`
	Settings    map[string]string `json:"settings"`
	Notices     []string          `json:"notices"`
	Actions     []Spec            `json:"actions"`
}

func (p *Plan) doc() planDoc {
	d := planDoc{
		Format: FormatVersion, Kind: p.Kind, Lockkeeper: p.LockkeeperVer, MigrationID: p.MigrationID,
		Source: p.Source, Target: p.Target,
		Databases: append([]string{}, p.Databases...),
		Settings:  map[string]string{},
		Notices:   append([]string{}, p.Notices...),
		Actions:   make([]Spec, 0, len(p.Actions)),
	}
	for k, v := range p.Settings {
		d.Settings[k] = v
	}
	for _, a := range p.Actions {
		d.Actions = append(d.Actions, SpecOf(a))
	}
	return d
}

// CanonicalJSON returns the byte-exact document that Hash covers: compact, with
// a fixed field order and sorted map keys. Order of databases and of actions is
// significant (it is the order of execution).
func (p *Plan) CanonicalJSON() []byte {
	b, err := json.Marshal(p.doc())
	if err != nil { // only strings, ints and bools: cannot happen
		panic("action: canonical plan: " + err.Error())
	}
	return b
}

// Hash returns the hex SHA-256 of the canonical JSON.
func (p *Plan) Hash() string {
	sum := sha256.Sum256(p.CanonicalJSON())
	return hex.EncodeToString(sum[:])
}

// DisplayJSON is the canonical document plus its hash, indented for people.
func (p *Plan) DisplayJSON() []byte {
	type shown struct {
		PlanHash string `json:"plan_hash"`
		planDoc
	}
	b, err := json.MarshalIndent(shown{PlanHash: p.Hash(), planDoc: p.doc()}, "", "  ")
	if err != nil {
		panic("action: plan json: " + err.Error())
	}
	return b
}

// Specs returns the serialised actions in order.
func (p *Plan) Specs() []Spec { return p.doc().Actions }

// ActionsOf returns the actions of one phase in plan order.
func (p *Plan) ActionsOf(ph Phase) []Action {
	var out []Action
	for _, a := range p.Actions {
		if a.Phase() == ph {
			out = append(out, a)
		}
	}
	return out
}

// Find returns the action with the given id.
func (p *Plan) Find(id string) (Action, bool) {
	for _, a := range p.Actions {
		if a.ID() == id {
			return a, true
		}
	}
	return nil, false
}

// Validate checks structural rules: unique non-empty action ids and only known
// phases.
func (p *Plan) Validate() error {
	seen := map[string]bool{}
	for _, a := range p.Actions {
		if a.ID() == "" {
			return fmt.Errorf("plan has an action without an id")
		}
		if seen[a.ID()] {
			return fmt.Errorf("plan has two actions with id %q", a.ID())
		}
		seen[a.ID()] = true
		switch a.Phase() {
		case PhaseSource, PhaseStart, PhaseAbort, PhaseRecover, PhaseCleanup:
		default:
			return fmt.Errorf("action %s has unknown phase %q", a.ID(), a.Phase())
		}
	}
	return nil
}

// Summary renders the plan for a terminal: every action with its exact SQL, the
// plan hash and what each action changes.
func (p *Plan) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Plan %s (%s) for migration %s\n", p.Hash(), p.Kind, p.MigrationID)
	fmt.Fprintf(&b, "  source: %s (%s:%d, user %s, PostgreSQL %s)\n", p.Source.Name, p.Source.Host, p.Source.Port, p.Source.User, p.Source.ServerVersion)
	fmt.Fprintf(&b, "  target: %s (%s:%d, user %s, PostgreSQL %s)\n", p.Target.Name, p.Target.Host, p.Target.Port, p.Target.User, p.Target.ServerVersion)
	fmt.Fprintf(&b, "  databases: %s\n", strings.Join(p.Databases, ", "))
	keys := make([]string, 0, len(p.Settings))
	for k := range p.Settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "  %s: %s\n", k, p.Settings[k])
	}
	for _, n := range p.Notices {
		fmt.Fprintf(&b, "  NOTICE: %s\n", n)
	}
	for i, a := range p.Actions {
		change := "READ-ONLY"
		if a.Mutates() {
			change = "CHANGES " + strings.ToUpper(a.Target().Role)
		}
		fmt.Fprintf(&b, "\n%2d. [%s] %s (%s)\n    %s\n", i+1, a.ID(), a.Describe(), change, a.Phase())
		for _, line := range strings.Split(a.SQL(), "\n") {
			fmt.Fprintf(&b, "      | %s\n", line)
		}
	}
	return b.String()
}
