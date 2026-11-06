package service

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/collector"
	mysqlcollector "github.com/wisnuvb/lockkeeper/internal/collector/mysql"
	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/dbconn"
	"github.com/wisnuvb/lockkeeper/internal/model"
	"github.com/wisnuvb/lockkeeper/internal/redact"
)

const mixedYAML = `
version: 1
databases:
  pgdb:
    engine: postgres
    host: 127.0.0.1
    user: mon
    password: { env: DB_PW }
    tls: { mode: disable }
  mydb:
    engine: mysql
    host: 127.0.0.1
    port: 3307
    user: lk
    password: { env: DB_PW }
    tls: { mode: disable }
alerts:
  channels:
    telegram:
      bot_token: { env: TG_TOKEN }
      chat_id: "42"
`

func mixedConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, _, err := config.Parse([]byte(mixedYAML))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Store.Path = t.TempDir() + "/state/lockkeeper.db"
	return cfg
}

func mySample(metric string, v float64) model.Sample {
	s := sampleOf(metric, v)
	s.Target = "mydb"
	return s
}

func TestEngineSwitchBuildsTheRightCollector(t *testing.T) {
	ts := newTelegram(t)
	deps := testDeps(ts, nil, nil, io.Discard)
	deps.NewCollector = nil
	svc, err := New(mixedConfig(t), deps)
	if err != nil {
		t.Fatal(err)
	}
	my := svc.newCollector("mydb")
	defer my.Close()
	if _, ok := my.(*mysqlcollector.Collector); !ok {
		t.Errorf("mysql target must use the MySQL collector, got %T", my)
	}
	pgc := svc.newCollector("pgdb")
	defer pgc.Close()
	if _, ok := pgc.(*mysqlcollector.Collector); ok {
		t.Error("postgres target must not use the MySQL collector")
	}
	if my.Target() != "mydb" {
		t.Errorf("target = %q", my.Target())
	}
}

func TestMySQLOpenGetsResolvedPasswordAndPolicyAndRedactsErrors(t *testing.T) {
	ts := newTelegram(t)
	red := redact.New()
	var got dbconn.MySQLSpec
	deps := testDeps(ts, nil, red, io.Discard)
	deps.NewCollector = nil
	deps.OpenMySQL = func(_ context.Context, spec dbconn.MySQLSpec) (*sql.DB, error) {
		got = spec
		return nil, fmt.Errorf("handshake failed for %s using password %s", spec.User, spec.Password.Reveal())
	}
	svc, err := New(mixedConfig(t), deps)
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.Check(context.Background(), []string{"mydb"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "127.0.0.1" || got.Port != 3307 || got.User != "lk" || got.Database != "" || got.TLSMode != "disable" ||
		got.Password.Reveal() != dbPassword || got.QueryTimeout != svc.cfg.Monitor.QueryTimeout.D() {
		t.Errorf("spec not built from the config: %+v", got)
	}
	tr := res.Targets[0]
	if tr.Up || res.ExitCode() != 3 {
		t.Errorf("an unreachable MySQL target must be critical: up=%v exit=%d", tr.Up, res.ExitCode())
	}
	if strings.Contains(tr.Error, dbPassword) || !strings.Contains(tr.Error, "***") {
		t.Errorf("the error must be redacted, got %q", tr.Error)
	}
}

func TestCheckRecognisesMySQLUp(t *testing.T) {
	ts := newTelegram(t)
	cases := []struct {
		name     string
		samples  []model.Sample
		wantCode int
		wantUp   bool
	}{
		{"healthy", []model.Sample{mySample(rules.MetricMySQLUp, 1), mySample(rules.MetricMySQLConnectionsRatio, 0.1)}, 0, true},
		{"connections high", []model.Sample{mySample(rules.MetricMySQLUp, 1), mySample(rules.MetricMySQLConnectionsRatio, 0.97)}, 3, true},
		{"down", []model.Sample{mySample(rules.MetricMySQLUp, 0)}, 3, false},
		// A broken replica must be critical even in a one-shot check.
		{"replica stopped", []model.Sample{mySample(rules.MetricMySQLUp, 1), mySample(rules.MetricMySQLReplSQLRunning, 0), mySample(rules.MetricMySQLReplIORunning, 1)}, 3, true},
	}
	for _, c := range cases {
		col := &fakeCollector{target: "mydb"}
		col.set(func() ([]model.Sample, bool, error) { return c.samples, true, nil })
		deps := testDeps(ts, col, nil, io.Discard)
		svc, err := New(mixedConfig(t), deps)
		if err != nil {
			t.Fatal(err)
		}
		res, err := svc.Check(context.Background(), []string{"mydb"}, false)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if res.ExitCode() != c.wantCode || res.Targets[0].Up != c.wantUp {
			t.Errorf("%s: exit=%d up=%v, want exit=%d up=%v: %+v", c.name, res.ExitCode(), res.Targets[0].Up, c.wantCode, c.wantUp, res.Targets[0])
		}
	}
}

func TestSlotsListIsNotApplicableToMySQL(t *testing.T) {
	ts := newTelegram(t)
	deps := testDeps(ts, nil, nil, io.Discard)
	deps.NewCollector = nil
	opened := false
	deps.OpenMySQL = func(context.Context, dbconn.MySQLSpec) (*sql.DB, error) { opened = true; return nil, nil }
	svc, err := New(mixedConfig(t), deps)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.SlotsList(context.Background(), "mydb")
	if err == nil || !strings.Contains(err.Error(), "do not apply to mysql") {
		t.Fatalf("expected a clear 'not applicable' error, got %v", err)
	}
	if opened {
		t.Error("no connection may be opened for a target the command does not apply to")
	}
}

func TestMySQLCollectorOutageIsData(t *testing.T) {
	ts := newTelegram(t)
	deps := testDeps(ts, nil, nil, io.Discard)
	deps.NewCollector = nil
	deps.OpenMySQL = func(context.Context, dbconn.MySQLSpec) (*sql.DB, error) { return nil, fmt.Errorf("connection refused") }
	svc, err := New(mixedConfig(t), deps)
	if err != nil {
		t.Fatal(err)
	}
	var col collector.Collector = svc.newCollector("mydb")
	defer col.Close()
	samples, complete, err := col.Collect(context.Background())
	if err == nil || complete {
		t.Fatalf("outage must be an incomplete batch with an error: %v %v", complete, err)
	}
	if len(samples) != 1 || samples[0].Metric != rules.MetricMySQLUp || samples[0].Value != 0 {
		t.Errorf("expected my.up=0, got %+v", samples)
	}
}
