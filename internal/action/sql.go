package action

import (
	"context"
	"fmt"
	"strings"
)

// Statement is an Action that runs SQL on a connection.
type Statement struct {
	// Key, Summary, At, Where and Changes populate the Action methods.
	Key     string
	Summary string
	At      Phase
	Where   Endpoint
	// Changes is false for read-only statements shown for information.
	Changes bool
	// Session statements run first on the same connection (for example
	// SET log_statement = 'none'). They are part of the displayed SQL.
	Session []Template
	// Main is the statement itself.
	Main Template
	// After statements run on the same connection once Main succeeded (for
	// example COMMENT ON ... to mark what Lockkeeper created). They are shown
	// and hashed like the others.
	After []Template
	// Secrets supplies the values of the placeholders at apply time. It is
	// never serialised and never part of the plan.
	Secrets func() (map[string]string, error)
	// Satisfied, if set, is asked before Main runs: true means the effect is
	// already in place and Main is skipped (idempotence on resume).
	Satisfied func(ctx context.Context, c Conn) (bool, error)
}

// ID implements Action.
func (s *Statement) ID() string { return s.Key }

// Describe implements Action.
func (s *Statement) Describe() string { return s.Summary }

// Target implements Action.
func (s *Statement) Target() Endpoint { return s.Where }

// Mutates implements Action.
func (s *Statement) Mutates() bool { return s.Changes }

// Phase implements Action.
func (s *Statement) Phase() Phase { return s.At }

// SQL implements Action: the session statements and the main statement, secrets masked.
func (s *Statement) SQL() string {
	var b strings.Builder
	for _, t := range s.Session {
		b.WriteString(strings.TrimRight(t.Text(), "; \n"))
		b.WriteString(";\n")
	}
	b.WriteString(strings.TrimRight(s.Main.Text(), "; \n"))
	b.WriteString(";")
	for _, t := range s.After {
		b.WriteString("\n")
		b.WriteString(strings.TrimRight(t.Text(), "; \n"))
		b.WriteString(";")
	}
	return b.String()
}

// Apply implements Action.
func (s *Statement) Apply(ctx context.Context, c Conn) error {
	if s.Satisfied != nil {
		done, err := s.Satisfied(ctx, c)
		if err != nil {
			return fmt.Errorf("%s: check whether already applied: %w", s.Key, err)
		}
		if done {
			return ErrAlreadySatisfied
		}
	}
	secrets := map[string]string{}
	if s.Secrets != nil {
		var err error
		if secrets, err = s.Secrets(); err != nil {
			return fmt.Errorf("%s: %w", s.Key, err)
		}
	}
	for _, t := range s.Session {
		q, err := t.Render(secrets)
		if err != nil {
			return fmt.Errorf("%s: %w", s.Key, err)
		}
		if _, err := c.Exec(ctx, q); err != nil {
			return fmt.Errorf("%s: session setup: %w", s.Key, err)
		}
	}
	q, err := s.Main.Render(secrets)
	if err != nil {
		return fmt.Errorf("%s: %w", s.Key, err)
	}
	if _, err := c.Exec(ctx, q); err != nil {
		return fmt.Errorf("%s: %w", s.Key, err)
	}
	for _, t := range s.After {
		q, err := t.Render(secrets)
		if err != nil {
			return fmt.Errorf("%s: %w", s.Key, err)
		}
		if _, err := c.Exec(ctx, q); err != nil {
			return fmt.Errorf("%s: follow-up statement: %w", s.Key, err)
		}
	}
	return nil
}

// ErrAlreadySatisfied is returned by Apply when the action's effect is already
// in place. The executor records that as "already satisfied", not as a failure.
var ErrAlreadySatisfied = fmt.Errorf("already satisfied")

// Step is an Action that the migration engine runs itself, because it needs a
// held replication connection or an external tool. It is in the plan so it is
// reviewed, hashed and audited like any other; it executes through
// Authorization.Do.
type Step struct {
	Key     string
	Summary string
	At      Phase
	Where   Endpoint
	Changes bool
	// Display is the replication command or command line, secrets masked.
	Display string
}

// ID implements Action.
func (s *Step) ID() string { return s.Key }

// Describe implements Action.
func (s *Step) Describe() string { return s.Summary }

// SQL implements Action.
func (s *Step) SQL() string { return s.Display }

// Target implements Action.
func (s *Step) Target() Endpoint { return s.Where }

// Mutates implements Action.
func (s *Step) Mutates() bool { return s.Changes }

// Phase implements Action.
func (s *Step) Phase() Phase { return s.At }

// Apply implements Action; a Step is never applied as plain SQL.
func (s *Step) Apply(context.Context, Conn) error { return ErrNotSQL }
