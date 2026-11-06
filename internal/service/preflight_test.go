package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/dbconn"
	"github.com/wisnuvb/lockkeeper/internal/secret"
)

const preflightYAML = `
version: 1
databases:
  src:
    engine: postgres
    host: 127.0.0.1
    port: 15432
    user: mon
    password: { env: DB_PW }
    tls: { mode: disable }
  tgt:
    engine: postgres
    host: 127.0.0.1
    port: 15433
    user: mon
    password: { env: DB_PW }
    tls: { mode: disable }
  alias-of-src:
    engine: postgres
    host: 127.0.0.1
    port: 15432
    user: other
    password: { env: DB_PW }
    tls: { mode: disable }
alerts:
  rules:
    pg.slot.retained_wal_bytes:
      warning: 1GiB
      critical: 3GiB
`

// newPreflightService builds a service whose connections always fail, and counts
// how often a connection was attempted: the argument checks must come first.
func newPreflightService(t *testing.T) (*Service, *int) {
	t.Helper()
	cfg, _, err := config.Parse([]byte(preflightYAML))
	if err != nil {
		t.Fatal(err)
	}
	attempts := 0
	svc, err := New(cfg, Deps{
		Secrets: secret.Resolver{Getenv: func(string) (string, bool) { return "pw", true }},
		OpenPG: func(context.Context, dbconn.PGSpec) (*pgx.Conn, error) {
			attempts++
			return nil, errors.New("no database in this test")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, &attempts
}

func TestPreflightRefusesBadArgumentsBeforeConnecting(t *testing.T) {
	svc, attempts := newPreflightService(t)
	cases := []struct {
		name, src, tgt, want string
	}{
		{"source equals target", "src", "src", "must be different"},
		{"unknown source", "nope", "tgt", `unknown database "nope"`},
		{"unknown target", "src", "nope", `unknown database "nope"`},
		{"two names for the same server", "src", "alias-of-src", "same server"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep, err := svc.PreflightPG(context.Background(), c.src, c.tgt, DiscoveryOptions{})
			if err == nil || rep != nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error containing %q, got report=%v err=%v", c.want, rep, err)
			}
		})
	}
	if *attempts != 0 {
		t.Errorf("argument errors must be raised before any connection attempt, got %d", *attempts)
	}
}

func TestPreflightReportsUnreachableServersAsBlockers(t *testing.T) {
	svc, attempts := newPreflightService(t)
	rep, err := svc.PreflightPG(context.Background(), "src", "tgt", DiscoveryOptions{})
	if err != nil {
		t.Fatalf("an unreachable server is a finding, not an operational error: %v", err)
	}
	if rep.ExitCode() != 3 || *attempts != 2 {
		t.Errorf("exit %d after %d attempts", rep.ExitCode(), *attempts)
	}
	var ids []string
	for _, f := range rep.Findings {
		ids = append(ids, f.ID)
	}
	if !strings.Contains(strings.Join(ids, " "), "connect.source") || !strings.Contains(strings.Join(ids, " "), "connect.target") {
		t.Errorf("findings %v", ids)
	}
}

func TestInventoryValidatesTheSourceName(t *testing.T) {
	svc, attempts := newPreflightService(t)
	if _, err := svc.Inventory(context.Background(), "nope", DiscoveryOptions{}); err == nil || !strings.Contains(err.Error(), `unknown database "nope"`) {
		t.Errorf("err = %v", err)
	}
	if *attempts != 0 {
		t.Error("must not connect for an unknown name")
	}
}

func TestSlotThresholdsFollowTheEffectiveMonitorRules(t *testing.T) {
	svc, _ := newPreflightService(t)
	th := svc.slotThresholds()
	if th.SlotWarnBytes != 1<<30 || th.SlotBlockerBytes != 3<<30 {
		t.Errorf("config overrides must reach the pre-flight, got %+v", th)
	}
}

func TestPreflightErrorsAreRedacted(t *testing.T) {
	cfg, _, err := config.Parse([]byte(preflightYAML))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(cfg, Deps{
		Secrets: secret.Resolver{Getenv: func(string) (string, bool) { return "SECRET-canary-77", true }},
		OpenPG: func(_ context.Context, spec dbconn.PGSpec) (*pgx.Conn, error) {
			return nil, errors.New("auth failed for password " + spec.Password.Reveal())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := svc.PreflightPG(context.Background(), "src", "tgt", DiscoveryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if strings.Contains(f.Message+f.Remediation, "SECRET-canary-77") {
			t.Errorf("secret leaked into finding %s: %s", f.ID, f.Message)
		}
	}
}
