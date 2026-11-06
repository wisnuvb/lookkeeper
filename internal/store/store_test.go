package store

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/model"
)

var base = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "lockkeeper.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func TestOpenCreatesRestrictedFilesAndIsReopenable(t *testing.T) {
	s, path := openTemp(t)
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm()&0o077 != 0 {
			t.Fatalf("db file must be 0600, got %v (%v)", fi.Mode(), err)
		}
		di, _ := os.Stat(filepath.Dir(path))
		if di.Mode().Perm()&0o077 != 0 {
			t.Errorf("created directory must be 0700, got %v", di.Mode().Perm())
		}
	}
	_ = s.Close()
	s2, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	_ = s2.Close()
}

func TestOpenRefusesAccessibleFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	path := filepath.Join(t.TempDir(), "lockkeeper.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("group/world-readable state must be refused, got %v", err)
	}
}

func TestSamplesRoundTripLatestAndPrune(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	lab := map[string]string{"slot": "a", "type": "logical"}
	err := s.AppendSamples(ctx, []model.Sample{
		{Target: "db", Metric: "m1", Value: 1, At: base},
		{Target: "db", Metric: "m1", Value: 2, At: base.Add(time.Minute)},
		{Target: "db", Metric: "m2", Labels: lab, Value: 10, At: base},
		{Target: "db", Metric: "m2", Labels: lab, Value: 20, At: base.Add(time.Minute)},
		{Target: "other", Metric: "m1", Value: 99, At: base.Add(2 * time.Minute)},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.LatestSamples(ctx, "db")
	if err != nil || len(got) != 2 {
		t.Fatalf("latest = %+v, %v", got, err)
	}
	if got[0].Metric != "m1" || got[0].Value != 2 || got[1].Metric != "m2" || got[1].Value != 20 || got[1].Labels["slot"] != "a" {
		t.Errorf("wrong latest samples: %+v", got)
	}
	if !got[0].At.Equal(base.Add(time.Minute)) {
		t.Errorf("timestamp not preserved: %v", got[0].At)
	}
	n, err := s.PruneSamples(ctx, base.Add(30*time.Second))
	if err != nil || n != 2 {
		t.Fatalf("pruned %d, %v (want 2)", n, err)
	}
	if err := s.AppendSamples(ctx, nil); err != nil {
		t.Errorf("empty append must be a no-op: %v", err)
	}
}

func TestAlertStateSurvivesRestart(t *testing.T) {
	s, path := openTemp(t)
	ctx := context.Background()
	snaps := []rules.Snapshot{{
		Target: "db", Metric: "pg.slot.retained_wal_bytes", Labels: map[string]string{"slot": "x"},
		Pending: map[model.Severity]time.Time{model.SeverityWarning: base},
		Active:  model.SeverityCritical, Since: base, LastNotified: base.Add(time.Hour), LastValue: 42, Threshold: 7,
	}}
	if err := s.SaveAlertState(ctx, snaps); err != nil {
		t.Fatal(err)
	}
	// Saving replaces, not appends.
	if err := s.SaveAlertState(ctx, snaps); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.LoadAlertState(ctx)
	if err != nil || len(got) != 1 {
		t.Fatalf("loaded %+v, %v", got, err)
	}
	g := got[0]
	if g.Active != model.SeverityCritical || !g.Since.Equal(base) || g.LastValue != 42 || g.Labels["slot"] != "x" ||
		!g.Pending[model.SeverityWarning].Equal(base) || !g.LastNotified.Equal(base.Add(time.Hour)) {
		t.Errorf("state not preserved: %+v", g)
	}

	// An engine restored from it must not re-fire.
	e, err := rules.New(rules.Defaults(), rules.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e.Import(got)
	if len(e.Active()) != 1 {
		t.Error("restored engine should report the alert as active")
	}
}

func TestEventsNewestFirstAndPrune(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		err := s.AppendEvent(ctx, model.Event{
			Rule: "r", Target: "db", Labels: map[string]string{"k": "v"}, State: model.StateFiring,
			Severity: model.SeverityWarning, Value: float64(i), Threshold: 1, At: base.Add(time.Duration(i) * time.Minute), Summary: "s",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.RecentEvents(ctx, 2)
	if err != nil || len(got) != 2 || got[0].Value != 2 || got[1].Value != 1 || got[0].Labels["k"] != "v" || got[0].State != model.StateFiring {
		t.Fatalf("recent = %+v, %v", got, err)
	}
	if n, err := s.PruneEvents(ctx, base.Add(90*time.Second)); err != nil || n != 2 {
		t.Errorf("pruned %d, %v (want 2)", n, err)
	}
}

func TestMigrationsBackUpExistingDatabaseAndRefuseDowngrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lockkeeper.db")
	ctx := context.Background()

	v1 := []string{`CREATE TABLE a (id INTEGER)`}
	s, err := open(ctx, path, v1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO a VALUES (7)`); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err := os.Stat(path + ".bak-v1"); err == nil {
		t.Fatal("a fresh database must not produce a backup")
	}

	v2 := append(append([]string{}, v1...), `CREATE TABLE b (id INTEGER)`)
	s, err = open(ctx, path, v2)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM b`).Scan(&n); err != nil {
		t.Errorf("new table missing after upgrade: %v", err)
	}
	_ = s.Close()

	bak := path + ".bak-v1"
	fi, err := os.Stat(bak)
	if err != nil {
		t.Fatalf("expected a pre-upgrade backup: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("backup must be 0600, got %v", fi.Mode().Perm())
	}
	// The backup is a valid database holding the pre-upgrade data.
	bs, err := open(ctx, bak, v1)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	var v int
	if err := bs.db.QueryRow(`SELECT id FROM a`).Scan(&v); err != nil || v != 7 {
		t.Errorf("backup content wrong: %v %v", v, err)
	}
	_ = bs.Close()

	if _, err := open(ctx, path, v1); err == nil || !strings.Contains(err.Error(), "refusing to downgrade") {
		t.Fatalf("opening a newer database with an older build must fail, got %v", err)
	}
}
