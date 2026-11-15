package testutil

import (
	"testing"

	"github.com/wisnuvb/lockkeeper/internal/migrate/runner"
)

// recorder is a testing.TB whose Fatalf records instead of stopping, so the
// refusals can be asserted.
type recorder struct {
	testing.TB
	failed bool
}

func (r *recorder) Helper()               {}
func (r *recorder) Fatalf(string, ...any) { r.failed = true; panic(r) }
func (r *recorder) refused(f func(testing.TB)) (refused bool) {
	defer func() {
		if recover() != nil {
			refused = r.failed
		}
	}()
	f(r)
	return false
}

func TestRequireLoopbackRefusesEverythingElse(t *testing.T) {
	for _, host := range []string{"10.0.0.5", "db.example.com", "203.0.113.10", "", "127.0.0.1.nip.io", "0.0.0.0"} {
		if !(&recorder{TB: t}).refused(func(tb testing.TB) { RequireLoopback(tb, host) }) {
			t.Errorf("RequireLoopback must refuse %q", host)
		}
	}
	for _, host := range []string{"127.0.0.1", "localhost", "::1"} {
		if (&recorder{TB: t}).refused(func(tb testing.TB) { RequireLoopback(tb, host) }) {
			t.Errorf("RequireLoopback must accept %q", host)
		}
	}
}

func TestWritersRefuseANonLoopbackDSN(t *testing.T) {
	if !(&recorder{TB: t}).refused(func(tb testing.TB) {
		StartWriters(tb, "postgres://u:p@db.example.com:5432/app", 1)
	}) {
		t.Fatal("StartWriters must refuse a DSN whose host is not loopback, before connecting")
	}
}

func TestDockerLauncherRefusesUnknownEndpoints(t *testing.T) {
	l := &DockerLauncher{t: t, alias: map[string]string{"127.0.0.1:55432": "src"}}
	got, err := l.MapEndpoint(runner.Endpoint{Host: "127.0.0.1", Port: 55432})
	if err != nil || got.Host != "src" || got.Port != 5432 {
		t.Fatalf("a registered test container maps to its alias: %v %v", got, err)
	}
	for _, e := range []runner.Endpoint{
		{Host: "db.example.com", Port: 5432}, {Host: "10.0.0.5", Port: 5432}, {Host: "127.0.0.1", Port: 5432}, {Host: "127.0.0.1", Port: 1},
	} {
		if _, err := l.MapEndpoint(e); err == nil {
			t.Errorf("the tool launcher must refuse %s:%d", e.Host, e.Port)
		}
	}
}
