// Package preflight defines the report produced by migration pre-flight checks.
// The checks themselves live in engine subpackages (preflight/pg); they are
// strictly read-only and never change either server.
//
// # JSON layout
//
// `lockkeeper preflight pg --json` prints one Report object. The layout is a
// stable interface (see SchemaVersion):
//
//	{
//	  "schema_version": 1,
//	  "engine": "postgres",
//	  "source": "rds-main",              // configured connection names
//	  "target": "ovh-new",
//	  "databases": ["app", "billing"],   // databases checked
//	  "findings": [                      // worst first, then in check order
//	    {
//	      "id": "source.wal_level",      // stable identifier, safe to match on
//	      "area": "source-params",
//	      "severity": "BLOCKER",         // OK | INFO | WARN | BLOCKER
//	      "message": "...",              // what was found (object names, counts, sizes only)
//	      "remediation": "..."           // what to do; empty only for OK and INFO
//	    }
//	  ],
//	  "summary": {"ok": 9, "info": 6, "warn": 4, "blocker": 1, "highest": "BLOCKER"}
//	}
//
// Messages contain names of schema objects, roles and settings, counts and
// sizes; never passwords, SQL text of other sessions or row data. Remediation
// text may contain SQL or shell commands for the operator to run manually; none
// of them contains a password.
//
// Exit codes of the command: 0 only OK/INFO findings, 2 at least one WARN,
// 3 at least one BLOCKER, 1 operational error (no report).
package preflight

import "sort"

// SchemaVersion is the version of the JSON layout of Report.
const SchemaVersion = 1

// Severity is how serious a finding is.
type Severity string

// Severities, from least to most serious.
const (
	OK      Severity = "OK"
	Info    Severity = "INFO"
	Warn    Severity = "WARN"
	Blocker Severity = "BLOCKER"
)

// Rank returns an integer for ordering (higher is more serious).
func (s Severity) Rank() int {
	switch s {
	case Blocker:
		return 3
	case Warn:
		return 2
	case Info:
		return 1
	default:
		return 0
	}
}

// Finding is the result of one check.
type Finding struct {
	ID          string   `json:"id"`
	Area        string   `json:"area"`
	Severity    Severity `json:"severity"`
	Message     string   `json:"message"`
	Remediation string   `json:"remediation,omitempty"`
}

// Summary counts findings by severity.
type Summary struct {
	OK      int      `json:"ok"`
	Info    int      `json:"info"`
	Warn    int      `json:"warn"`
	Blocker int      `json:"blocker"`
	Highest Severity `json:"highest"`
}

// Report is the outcome of a pre-flight run.
type Report struct {
	SchemaVersion int       `json:"schema_version"`
	Engine        string    `json:"engine"`
	Source        string    `json:"source"`
	Target        string    `json:"target"`
	Databases     []string  `json:"databases"`
	Findings      []Finding `json:"findings"`
	Summary       Summary   `json:"summary"`
}

// NewReport builds a Report from findings: it orders them worst first (stable,
// so the order within a severity is the order the checks ran in) and fills in
// the summary.
func NewReport(engine, source, target string, databases []string, findings []Finding) *Report {
	fs := append([]Finding(nil), findings...)
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Severity.Rank() > fs[j].Severity.Rank() })
	if databases == nil {
		databases = []string{}
	}
	r := &Report{SchemaVersion: SchemaVersion, Engine: engine, Source: source, Target: target, Databases: databases, Findings: fs}
	r.Summary.Highest = OK
	for _, f := range fs {
		switch f.Severity {
		case Blocker:
			r.Summary.Blocker++
		case Warn:
			r.Summary.Warn++
		case Info:
			r.Summary.Info++
		default:
			r.Summary.OK++
		}
		if f.Severity.Rank() > r.Summary.Highest.Rank() {
			r.Summary.Highest = f.Severity
		}
	}
	return r
}

// ExitCode maps the report to a process exit code: 0 only OK/INFO, 2 warnings,
// 3 any blocker. (1 is reserved for operational errors.)
func (r *Report) ExitCode() int {
	switch r.Summary.Highest {
	case Blocker:
		return 3
	case Warn:
		return 2
	default:
		return 0
	}
}
