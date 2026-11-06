package preflight

import (
	"encoding/json"
	"testing"
)

func TestNewReportSummaryOrderAndExitCode(t *testing.T) {
	cases := []struct {
		name     string
		in       []Severity
		wantExit int
		highest  Severity
	}{
		{"empty is ok", nil, 0, OK},
		{"only ok and info", []Severity{OK, Info, OK}, 0, Info},
		{"a warning", []Severity{OK, Warn, Info}, 2, Warn},
		{"a blocker wins over warnings", []Severity{Warn, Blocker, Warn}, 3, Blocker},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var fs []Finding
			for i, s := range c.in {
				fs = append(fs, Finding{ID: string(rune('a' + i)), Severity: s})
			}
			r := NewReport("postgres", "s", "t", nil, fs)
			if r.ExitCode() != c.wantExit || r.Summary.Highest != c.highest {
				t.Errorf("exit %d highest %s, want %d %s", r.ExitCode(), r.Summary.Highest, c.wantExit, c.highest)
			}
			total := r.Summary.OK + r.Summary.Info + r.Summary.Warn + r.Summary.Blocker
			if total != len(c.in) {
				t.Errorf("summary counts %d findings, want %d", total, len(c.in))
			}
			for i := 1; i < len(r.Findings); i++ {
				if r.Findings[i].Severity.Rank() > r.Findings[i-1].Severity.Rank() {
					t.Errorf("not worst first: %v", r.Findings)
				}
			}
			if r.Databases == nil {
				t.Error("databases must serialise as [] not null")
			}
		})
	}
}

func TestSortIsStableWithinASeverity(t *testing.T) {
	r := NewReport("postgres", "s", "t", nil, []Finding{
		{ID: "w1", Severity: Warn}, {ID: "b1", Severity: Blocker}, {ID: "w2", Severity: Warn}, {ID: "b2", Severity: Blocker},
	})
	var ids string
	for _, f := range r.Findings {
		ids += f.ID + " "
	}
	if ids != "b1 b2 w1 w2 " {
		t.Errorf("order %q", ids)
	}
}

func TestJSONKeys(t *testing.T) {
	r := NewReport("postgres", "s", "t", []string{"app"}, []Finding{{ID: "x", Area: "a", Severity: Warn, Message: "m", Remediation: "r"}})
	b, _ := json.Marshal(r)
	want := `{"schema_version":1,"engine":"postgres","source":"s","target":"t","databases":["app"],"findings":[{"id":"x","area":"a","severity":"WARN","message":"m","remediation":"r"}],"summary":{"ok":0,"info":0,"warn":1,"blocker":0,"highest":"WARN"}}`
	if string(b) != want {
		t.Errorf("JSON layout changed:\n got %s\nwant %s", b, want)
	}
}
