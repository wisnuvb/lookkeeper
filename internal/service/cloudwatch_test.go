package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cw "github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/jackc/pgx/v5"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/cloudwatch"
	"github.com/wisnuvb/lockkeeper/internal/collector"
	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/dbconn"
	"github.com/wisnuvb/lockkeeper/internal/model"
	"github.com/wisnuvb/lockkeeper/internal/redact"
	"github.com/wisnuvb/lockkeeper/internal/secret"
)

// cwConfig is testYAML with a CloudWatch reader on the database.
func cwConfig(t *testing.T, extra string) *config.Config {
	t.Helper()
	y := `
version: 1
databases:
  db:
    engine: postgres
    host: 127.0.0.1
    user: mon
    password: { env: DB_PW }
    tls: { mode: disable }
    cloudwatch: { region: eu-west-1, db_instance_id: example-db }
` + extra
	cfg, _, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Store.Path = filepath.Join(t.TempDir(), "state", "lockkeeper.db")
	return cfg
}

type fakeCW struct {
	region string
	out    *cw.GetMetricDataOutput
	err    error
}

func (f *fakeCW) GetMetricData(context.Context, *cw.GetMetricDataInput, ...func(*cw.Options)) (*cw.GetMetricDataOutput, error) {
	return f.out, f.err
}

func freeStorage(now time.Time, bytes float64) *cw.GetMetricDataOutput {
	return &cw.GetMetricDataOutput{MetricDataResults: []types.MetricDataResult{{
		Id: aws.String("free_storage"), Timestamps: []time.Time{now.Add(-time.Minute)}, Values: []float64{bytes},
	}}}
}

func cwService(t *testing.T, cfg *config.Config, api *fakeCW, now time.Time) *Service {
	t.Helper()
	svc, err := New(cfg, Deps{
		Secrets: secret.Resolver{Getenv: func(string) (string, bool) { return "pw", true }},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		// The database is unreachable: the Postgres collector reports pg.up = 0,
		// while the CloudWatch member still delivers its samples.
		OpenPG: func(context.Context, dbconn.PGSpec) (*pgx.Conn, error) { return nil, errors.New("unreachable") },
		Now:    func() time.Time { return now },
		NewCloudWatch: func(region string) cloudwatch.API {
			api.region = region
			return api
		},
		Redactor: redact.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestCloudWatchIsWiredOnlyWhenConfigured(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	api := &fakeCW{out: freeStorage(now, 100<<30)}

	svc := cwService(t, cwConfig(t, ""), api, now)
	db := svc.cfg.Databases["db"]
	if got := svc.extraCollectors("db", db); len(got) != 1 || api.region != "eu-west-1" {
		t.Fatalf("extra collectors = %d, region = %q", len(got), api.region)
	}
	if svc.derivedSamples(db) == nil {
		t.Error("the derive hook must be installed with CloudWatch")
	}

	plain := testConfig(t) // no cloudwatch block
	svc2, err := New(plain, Deps{Secrets: secret.Resolver{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if got := svc2.extraCollectors("db", plain.Databases["db"]); len(got) != 0 {
		t.Errorf("no cloudwatch block must mean no reader, got %d", len(got))
	}
	if svc2.derivedSamples(plain.Databases["db"]) != nil {
		t.Error("no derive hook without CloudWatch")
	}
}

func TestNewCollectorMergesCloudWatchSamples(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	cfg := cwConfig(t, "")
	d := cfg.Databases["db"]
	d.DiskTotalGB = 200
	cfg.Databases["db"] = d
	svc := cwService(t, cfg, &fakeCW{out: freeStorage(now, 30<<30)}, now)

	col := svc.newCollector("db")
	defer col.Close()
	samples, complete, err := col.Collect(context.Background())
	if complete || err == nil {
		t.Fatalf("an unreachable database makes the batch incomplete: complete=%v err=%v", complete, err)
	}
	got := map[string]float64{}
	for _, s := range samples {
		got[s.Metric] = s.Value
	}
	if got[rules.MetricPGUp] != 0 || got[cloudwatch.MetricFreeStorageBytes] != 30<<30 {
		t.Errorf("samples = %v", got)
	}
	if want := 30.0 / 200.0; math.Abs(got[cloudwatch.MetricFreeStorageRatio]-want) > 1e-9 {
		t.Errorf("free ratio = %v, want %v", got[cloudwatch.MetricFreeStorageRatio], want)
	}
	if _, ok := got[rules.MetricPGSlotRetainedWALFreeRatio]; ok {
		t.Error("no slots were collected, so no per-slot ratio can exist")
	}
}

func TestUnavailableCloudWatchEmitsNoFreeStorage(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	svc := cwService(t, cwConfig(t, ""), &fakeCW{out: &cw.GetMetricDataOutput{}}, now)
	col := svc.newCollector("db")
	defer col.Close()
	samples, complete, err := col.Collect(context.Background())
	if complete || err == nil {
		t.Fatalf("complete=%v err=%v", complete, err)
	}
	for _, s := range samples {
		if s.Metric == cloudwatch.MetricFreeStorageBytes || s.Metric == cloudwatch.MetricFreeStorageRatio {
			t.Errorf("missing CloudWatch data must never produce %s (value %v)", s.Metric, s.Value)
		}
	}
}

func TestDeriveWALFreeRatio(t *testing.T) {
	at := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	slot := func(name string, v float64) model.Sample {
		return model.Sample{Target: "db", Metric: rules.MetricPGSlotRetainedWAL, Labels: map[string]string{"slot": name}, Value: v, At: at}
	}
	free := func(v float64) model.Sample {
		return model.Sample{Target: "db", Metric: cloudwatch.MetricFreeStorageBytes, Value: v, At: at}
	}

	got := deriveWALFreeRatio([]model.Sample{slot("a", 10<<30), free(40 << 30), slot("b", 0), {Metric: "other", Value: 1}})
	if len(got) != 2 {
		t.Fatalf("derived = %+v", got)
	}
	if got[0].Metric != rules.MetricPGSlotRetainedWALFreeRatio || got[0].Labels["slot"] != "a" || got[0].Value != 0.25 || got[0].Target != "db" || !got[0].At.Equal(at) {
		t.Errorf("slot a = %+v", got[0])
	}
	if got[1].Labels["slot"] != "b" || got[1].Value != 0 {
		t.Errorf("slot b = %+v", got[1])
	}
	got[0].Labels["slot"] = "mutated"
	if in := slot("a", 1); in.Labels["slot"] != "a" {
		t.Error("labels must be copied, not shared")
	}

	if got := deriveWALFreeRatio([]model.Sample{slot("a", 10<<30)}); len(got) != 0 {
		t.Errorf("without free storage nothing may be derived: %+v", got)
	}
	if got := deriveWALFreeRatio([]model.Sample{free(40 << 30)}); len(got) != 0 {
		t.Errorf("without slots nothing may be derived: %+v", got)
	}
	// A full disk is a finite, huge ratio rather than +Inf (which JSON cannot hold).
	got = deriveWALFreeRatio([]model.Sample{slot("a", 1<<30), free(0)})
	if len(got) != 1 || got[0].Value != maxWALFreeRatio || math.IsInf(got[0].Value, 0) {
		t.Errorf("zero free storage = %+v", got)
	}
}

// The derived metric must reach the alert engine through the default rules.
func TestDerivedRatioFiresTheGuardrailRule(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	svc := cwService(t, cwConfig(t, ""), &fakeCW{}, now)
	instant, _ := instantRules(svc.Rules())
	engine, err := rules.New(instant, rules.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var col collector.Collector = &fakeCollector{target: "db"}
	col.(*fakeCollector).set(func() ([]model.Sample, bool, error) {
		return []model.Sample{
			{Target: "db", Metric: rules.MetricPGSlotRetainedWAL, Labels: map[string]string{"slot": "lk"}, Value: 12 << 30, At: now},
			{Target: "db", Metric: cloudwatch.MetricFreeStorageBytes, Value: 20 << 30, At: now},
		}, true, nil
	})
	group := collector.NewGroupWithDerive("db", svc.derivedSamples(svc.cfg.Databases["db"]), col)
	samples, complete, _ := group.Collect(context.Background())
	events := engine.Eval(now, "db", samples, complete)
	var found bool
	for _, ev := range events {
		if ev.Rule == rules.MetricPGSlotRetainedWALFreeRatio && ev.Severity == model.SeverityCritical {
			found = true // 12 GiB retained of 20 GiB free = 60% > 50%
		}
	}
	if !found {
		t.Errorf("expected a critical guardrail event, got %+v", events)
	}
}
