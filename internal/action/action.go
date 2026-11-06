// Package action makes every change Lockkeeper may perform on a database a
// first-class, typed, reviewable thing.
//
// An Action describes one change (what it does, the exact SQL with secrets
// masked, which endpoint it touches). A Plan is an ordered list of Actions plus
// the identity of the source and the target and the Lockkeeper version. A Plan
// has a canonical JSON form and a SHA-256 hash; the hash is what an operator
// approves. Nothing is applied without an Approval that matches the plan's hash
// (an interactively typed confirmation or the hash itself), and every effect is
// written to an append-only audit log before and after it happens.
//
// The package never holds a secret: SQL shown to people and written to the plan
// is a template in which secrets are placeholders (see Template).
package action

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Phase says when an action of a plan runs.
type Phase string

// Phases of a migration plan.
const (
	// PhaseSource actions are applied by `migrate apply-source-changes`.
	PhaseSource Phase = "source-changes"
	// PhaseStart actions are applied by `migrate start` under the already
	// approved plan (slot creation holding the snapshot, copy, subscription).
	PhaseStart Phase = "start"
	// PhaseAbort actions are applied by `migrate abort`.
	PhaseAbort Phase = "abort"
	// PhaseRecover actions are applied by `migrate resume` after an interrupted copy.
	PhaseRecover Phase = "recover"
	// PhaseCleanup actions are applied by `migrate cleanup`.
	PhaseCleanup Phase = "cleanup"
)

// Endpoint identifies the server and database an action touches. It never holds
// a password. Role is "source" or "target" for this plan only: a configured
// connection has no fixed role.
type Endpoint struct {
	Role     string `json:"role"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	User     string `json:"user"`
}

// String is a short human form such as "source rds-main (db.example:5432/app)".
func (e Endpoint) String() string {
	return fmt.Sprintf("%s %s (%s:%d/%s)", e.Role, e.Name, e.Host, e.Port, e.Database)
}

// Conn is the part of a database connection an action needs. *pgx.Conn
// implements it.
type Conn interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Action is one reviewable change.
type Action interface {
	// ID is unique within a plan and stable: "source.create-publication", ...
	ID() string
	// Describe says in one line what the action does and why.
	Describe() string
	// SQL is the exact text shown to the operator, with secrets masked. For
	// actions that are not SQL (a bulk copy) it is the command line, also masked.
	SQL() string
	// Target is the endpoint the action changes.
	Target() Endpoint
	// Mutates reports whether the action changes the target endpoint. A false
	// action is informational (a read-only check shown in the plan).
	Mutates() bool
	// Phase says which command applies it.
	Phase() Phase
	// Apply performs the action on c. It must be idempotent: applying an action
	// whose effect is already in place succeeds without doing it twice.
	Apply(ctx context.Context, c Conn) error
}

// ErrNotSQL is returned by Apply on actions that the engine runs itself (they
// need a held replication connection or an external tool) through
// Authorization.Do.
var ErrNotSQL = errors.New("this action is executed by the migration engine, not as a plain SQL statement")

// Template is a statement in which secrets are placeholders of the form
// {{name}}. Text() is what is displayed and hashed; Render substitutes the real
// values. Because the real statement is always rendered from the displayed
// template, the operator approves exactly what runs.
type Template string

// Text returns the template with every placeholder shown as "***".
func (t Template) Text() string {
	return renderTemplate(string(t), func(string) string { return "***" })
}

// Render substitutes secrets by name. A placeholder without a value is an error.
func (t Template) Render(secrets map[string]string) (string, error) {
	var missing []string
	out := renderTemplate(string(t), func(name string) string {
		v, ok := secrets[name]
		if !ok {
			missing = append(missing, name)
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("no value for secret placeholder(s) %s", strings.Join(missing, ", "))
	}
	return out, nil
}

func renderTemplate(s string, val func(name string) string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "{{")
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		j := strings.Index(s[i:], "}}")
		if j < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteString(val(s[i+2 : i+j]))
		s = s[i+j+2:]
	}
}

// QuoteIdent quotes a Postgres identifier.
func QuoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// QuoteLiteral quotes a Postgres string literal.
func QuoteLiteral(s string) string {
	if strings.ContainsRune(s, '\\') {
		return " E'" + strings.NewReplacer(`\`, `\\`, `'`, `''`).Replace(s) + "'"
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
