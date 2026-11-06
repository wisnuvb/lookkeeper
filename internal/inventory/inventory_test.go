package inventory

import (
	"errors"
	"reflect"
	"testing"
)

func TestQuoting(t *testing.T) {
	cases := []struct{ in, ident, lit string }{
		{"orders", `"orders"`, `'orders'`},
		{`we"ird`, `"we""ird"`, `'we"ird'`},
		{"it's", `"it's"`, `'it''s'`},
		{"", `""`, `''`},
	}
	for _, c := range cases {
		if got := QuoteIdent(c.in); got != c.ident {
			t.Errorf("QuoteIdent(%q) = %s, want %s", c.in, got, c.ident)
		}
		if got := QuoteLiteral(c.in); got != c.lit {
			t.Errorf("QuoteLiteral(%q) = %s, want %s", c.in, got, c.lit)
		}
	}
	if got := (Table{Schema: "public", Name: "My Table"}).QualifiedName(); got != `"public"."My Table"` {
		t.Errorf("QualifiedName = %s", got)
	}
}

func TestSettingHelpers(t *testing.T) {
	s := &Server{Settings: map[string]Setting{
		"max_wal_senders": {Value: "10"},
		"wal_level":       {Value: "logical"},
		"neg":             {Value: "-1", Unit: "MB"},
	}}
	if v, ok := s.SettingInt("max_wal_senders"); !ok || v != 10 {
		t.Errorf("SettingInt = %d %v", v, ok)
	}
	if v, ok := s.SettingInt("neg"); !ok || v != -1 {
		t.Errorf("negative setting = %d %v", v, ok)
	}
	if _, ok := s.SettingInt("wal_level"); ok {
		t.Error("a non-numeric setting must not parse as an integer")
	}
	if _, ok := s.SettingInt("absent"); ok {
		t.Error("an absent setting must report ok=false")
	}
	if v, ok := s.SettingString("wal_level"); !ok || v != "logical" {
		t.Errorf("SettingString = %q %v", v, ok)
	}
}

func rows(names ...string) []dbRow {
	var out []dbRow
	for _, n := range names {
		out = append(out, dbRow{Database: Database{Name: n}, allowConn: true, canConnect: true})
	}
	return out
}

func names(ds []dbRow) []string {
	var out []string
	for _, d := range ds {
		out = append(out, d.Name)
	}
	return out
}

func TestSelectDatabases(t *testing.T) {
	all := rows("app", "postgres", "rdsadmin", "zeta")
	tmpl := dbRow{Database: Database{Name: "template0"}, isTemplate: true, allowConn: false}
	noConn := dbRow{Database: Database{Name: "locked"}, allowConn: false}
	all = append(all, tmpl, noConn)

	t.Run("default selects connectable non-template databases and skips rdsadmin", func(t *testing.T) {
		s := &Server{}
		got, err := selectDatabases(s, all, Options{MaxDatabases: 10})
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"app", "postgres", "zeta"}; !reflect.DeepEqual(names(got), want) {
			t.Errorf("selected %v, want %v", names(got), want)
		}
		if want := []string{"rdsadmin", "locked"}; !reflect.DeepEqual(s.SkippedDatabases, want) {
			t.Errorf("skipped %v, want %v", s.SkippedDatabases, want)
		}
	})
	t.Run("explicit list keeps order-independent, reports unknown and left-out", func(t *testing.T) {
		s := &Server{}
		got, err := selectDatabases(s, all, Options{Databases: []string{"zeta", "app", "app", "ghost"}, MaxDatabases: 10})
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"app", "zeta"}; !reflect.DeepEqual(names(got), want) {
			t.Errorf("selected %v, want %v", names(got), want)
		}
		if !reflect.DeepEqual(s.NotFound, []string{"ghost"}) {
			t.Errorf("NotFound = %v", s.NotFound)
		}
		if want := []string{"locked", "postgres"}; !reflect.DeepEqual(sorted(s.OtherDatabases), want) {
			t.Errorf("OtherDatabases = %v, want %v", s.OtherDatabases, want)
		}
	})
	t.Run("rdsadmin and templates are never selectable", func(t *testing.T) {
		s := &Server{}
		got, err := selectDatabases(s, all, Options{Databases: []string{"rdsadmin", "template0"}, MaxDatabases: 10})
		if err != nil || len(got) != 0 {
			t.Fatalf("got %v, %v", names(got), err)
		}
		if len(s.SkippedDatabases) != 2 {
			t.Errorf("skipped = %v", s.SkippedDatabases)
		}
	})
	t.Run("the cap is an error at the boundary, not a truncation", func(t *testing.T) {
		if _, err := selectDatabases(&Server{}, all, Options{MaxDatabases: 3}); err != nil {
			t.Errorf("exactly at the cap must pass: %v", err)
		}
		if _, err := selectDatabases(&Server{}, all, Options{MaxDatabases: 2}); !errors.Is(err, ErrTooManyDatabases) {
			t.Errorf("over the cap must fail with ErrTooManyDatabases, got %v", err)
		}
	})
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestOptionsDefaults(t *testing.T) {
	var o Options
	o.defaults()
	if o.MaxDatabases != DefaultMaxDatabases || o.TopTables != DefaultTopTables || o.ListCap != DefaultListCap || o.PerDatabaseTimeout != DefaultPerDatabaseTimeout {
		t.Errorf("defaults: %+v", o)
	}
}
