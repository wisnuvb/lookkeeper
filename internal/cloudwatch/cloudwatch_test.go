package cloudwatch

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cw "github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/smithy-go"

	"github.com/wisnuvb/lockkeeper/internal/collector"
	"github.com/wisnuvb/lockkeeper/internal/model"
)

var t0 = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

const gib = 1 << 30

// fakeAPI answers GetMetricData from a script and records every request.
type fakeAPI struct {
	calls []*cw.GetMetricDataInput
	reply func(call int, in *cw.GetMetricDataInput) (*cw.GetMetricDataOutput, error)
}

func (f *fakeAPI) GetMetricData(_ context.Context, in *cw.GetMetricDataInput, _ ...func(*cw.Options)) (*cw.GetMetricDataOutput, error) {
	f.calls = append(f.calls, in)
	return f.reply(len(f.calls), in)
}

// points builds a result with the given (age, value) datapoints, oldest first or any order.
func points(now time.Time, pts ...[2]float64) *cw.GetMetricDataOutput {
	r := types.MetricDataResult{Id: aws.String(queryID), StatusCode: types.StatusCodeComplete}
	for _, p := range pts {
		r.Timestamps = append(r.Timestamps, now.Add(-time.Duration(p[0])*time.Second))
		r.Values = append(r.Values, p[1])
	}
	return &cw.GetMetricDataOutput{MetricDataResults: []types.MetricDataResult{r}}
}

func serve(out *cw.GetMetricDataOutput, err error) *fakeAPI {
	return &fakeAPI{reply: func(int, *cw.GetMetricDataInput) (*cw.GetMetricDataOutput, error) { return out, err }}
}

func newCollector(api API, now *time.Time, diskGB float64) *Collector {
	return New("rds-main", "example-db", api, Options{DiskTotalGB: diskGB, Now: func() time.Time { return *now }})
}

func TestCollectorSatisfiesCollector(t *testing.T) {
	var _ collector.Collector = (*Collector)(nil)
}

func TestRequestShape(t *testing.T) {
	now := t0
	api := serve(points(now, [2]float64{60, 100 * gib}), nil)
	if _, _, err := newCollector(api, &now, 0).Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	in := api.calls[0]
	if len(in.MetricDataQueries) != 1 {
		t.Fatalf("queries = %d", len(in.MetricDataQueries))
	}
	q := in.MetricDataQueries[0]
	m := q.MetricStat.Metric
	if aws.ToString(m.Namespace) != "AWS/RDS" || aws.ToString(m.MetricName) != "FreeStorageSpace" {
		t.Errorf("metric = %s/%s", aws.ToString(m.Namespace), aws.ToString(m.MetricName))
	}
	if len(m.Dimensions) != 1 || aws.ToString(m.Dimensions[0].Name) != "DBInstanceIdentifier" || aws.ToString(m.Dimensions[0].Value) != "example-db" {
		t.Errorf("dimensions = %+v", m.Dimensions)
	}
	if aws.ToInt32(q.MetricStat.Period) != 60 || aws.ToString(q.MetricStat.Stat) != "Minimum" {
		t.Errorf("period/stat = %d/%s", aws.ToInt32(q.MetricStat.Period), aws.ToString(q.MetricStat.Stat))
	}
	if !in.EndTime.Equal(now) || !in.StartTime.Equal(now.Add(-15*time.Minute)) {
		t.Errorf("window = %v .. %v", in.StartTime, in.EndTime)
	}
	if in.ScanBy != types.ScanByTimestampDescending {
		t.Errorf("scan by = %v", in.ScanBy)
	}
}

func TestCollectEmitsBytesAndOptionalRatio(t *testing.T) {
	now := t0
	api := serve(points(now, [2]float64{180, 50 * gib}, [2]float64{60, 40 * gib}, [2]float64{120, 45 * gib}), nil)

	// Without disk_total_gb only the byte metric exists.
	samples, complete, err := newCollector(api, &now, 0).Collect(context.Background())
	if err != nil || !complete {
		t.Fatalf("complete=%v err=%v", complete, err)
	}
	if len(samples) != 1 || samples[0].Metric != MetricFreeStorageBytes || samples[0].Value != 40*gib || samples[0].Target != "rds-main" || !samples[0].At.Equal(now) {
		t.Fatalf("samples = %+v (the newest datapoint must win, whatever the order)", samples)
	}

	// With it, the ratio is free / (disk_total_gb GiB).
	samples, complete, err = newCollector(api, &now, 200).Collect(context.Background())
	if err != nil || !complete || len(samples) != 2 {
		t.Fatalf("samples=%+v complete=%v err=%v", samples, complete, err)
	}
	if samples[1].Metric != MetricFreeStorageRatio || math.Abs(samples[1].Value-0.2) > 1e-9 {
		t.Errorf("ratio sample = %+v", samples[1])
	}
}

func TestUnavailableDataNeverBecomesZero(t *testing.T) {
	now := t0
	boom := &smithy.GenericAPIError{Code: "AccessDenied", Message: "User: arn:aws:iam::123456789012:user/lk is not authorized\nto perform: cloudwatch:GetMetricData"}
	cases := []struct {
		name string
		api  *fakeAPI
		want string
	}{
		{"no results", serve(&cw.GetMetricDataOutput{}, nil), "no FreeStorageSpace datapoints"},
		{"empty values", serve(points(now), nil), "no FreeStorageSpace datapoints"},
		{"wrong query id", serve(&cw.GetMetricDataOutput{MetricDataResults: []types.MetricDataResult{{Id: aws.String("other"), Timestamps: []time.Time{now}, Values: []float64{1}}}}, nil), "no FreeStorageSpace datapoints"},
		{"stale", serve(points(now, [2]float64{601, 50 * gib}), nil), "treating free storage as unavailable"},
		{"API error", serve(nil, boom), "AccessDenied"},
		{"NaN", serve(points(now, [2]float64{60, math.NaN()}), nil), "invalid value"},
		{"negative", serve(points(now, [2]float64{60, -1}), nil), "invalid value"},
	}
	for _, tc := range cases {
		samples, complete, err := newCollector(tc.api, &now, 200).Collect(context.Background())
		if len(samples) != 0 || complete || err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: samples=%v complete=%v err=%v", tc.name, samples, complete, err)
		}
		if strings.ContainsAny(fmt.Sprint(err), "\r\n") {
			t.Errorf("%s: error spans several lines: %q", tc.name, err)
		}
	}
}

func TestDatapointAgeBoundary(t *testing.T) {
	now := t0
	// Exactly ten minutes old is still accepted; one second more is not.
	if _, complete, err := newCollector(serve(points(now, [2]float64{600, gib}), nil), &now, 0).Collect(context.Background()); !complete || err != nil {
		t.Errorf("10m old: complete=%v err=%v", complete, err)
	}
	if _, complete, _ := newCollector(serve(points(now, [2]float64{601, gib}), nil), &now, 0).Collect(context.Background()); complete {
		t.Error("a datapoint older than 10m must be unavailable")
	}
}

func TestFreeExceedingConfiguredTotalWithholdsTheRatio(t *testing.T) {
	now := t0
	api := serve(points(now, [2]float64{60, 120 * gib}), nil)
	samples, complete, err := newCollector(api, &now, 100).Collect(context.Background())
	if complete || err == nil || !strings.Contains(err.Error(), "disk_total_gb") {
		t.Fatalf("complete=%v err=%v", complete, err)
	}
	if len(samples) != 1 || samples[0].Metric != MetricFreeStorageBytes {
		t.Errorf("samples = %+v: bytes may be reported, the ratio must not", samples)
	}
}

func TestFetchesAtMostOncePerMinuteAndStaysFresh(t *testing.T) {
	now := t0
	api := &fakeAPI{reply: func(_ int, _ *cw.GetMetricDataInput) (*cw.GetMetricDataOutput, error) {
		return points(now, [2]float64{60, 10 * gib}), nil
	}}
	c := newCollector(api, &now, 0)
	collect := func() ([]model.Sample, bool) {
		s, ok, err := c.Collect(context.Background())
		if ok && err != nil {
			t.Fatal(err)
		}
		return s, ok
	}
	collect()
	now = now.Add(30 * time.Second)
	collect() // served from cache: the monitor interval is shorter than the publication interval
	if len(api.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(api.calls))
	}
	now = now.Add(31 * time.Second)
	collect()
	if len(api.calls) != 2 {
		t.Fatalf("calls = %d, want 2 after a minute", len(api.calls))
	}

	// A cached point still ages: if CloudWatch stops publishing and fetches keep
	// failing, the stale value must not be reported forever.
	api.reply = func(int, *cw.GetMetricDataInput) (*cw.GetMetricDataOutput, error) { return nil, errors.New("down") }
	now = now.Add(11 * time.Minute)
	if s, ok := collect(); ok || len(s) != 0 {
		t.Errorf("stale cache served: %v %v", s, ok)
	}
}

func TestFailedFetchIsNotCached(t *testing.T) {
	now := t0
	fail := true
	api := &fakeAPI{reply: func(int, *cw.GetMetricDataInput) (*cw.GetMetricDataOutput, error) {
		if fail {
			return nil, errors.New("throttled")
		}
		return points(now, [2]float64{60, gib}), nil
	}}
	c := newCollector(api, &now, 0)
	if _, ok, _ := c.Collect(context.Background()); ok {
		t.Fatal("expected failure")
	}
	fail = false
	now = now.Add(time.Second)
	if _, ok, err := c.Collect(context.Background()); !ok || err != nil {
		t.Fatalf("recovery must not wait for the cache gap: ok=%v err=%v", ok, err)
	}
}

func TestCallIsBounded(t *testing.T) {
	now := t0
	api := &fakeAPI{reply: func(int, *cw.GetMetricDataInput) (*cw.GetMetricDataOutput, error) { return nil, nil }}
	var gotDeadline bool
	slow := &deadlineAPI{inner: api, seen: &gotDeadline}
	c := New("rds-main", "example-db", slow, Options{Now: func() time.Time { return now }, CallTimeout: 50 * time.Millisecond})
	start := time.Now()
	_, ok, err := c.Collect(context.Background())
	if ok || err == nil || !errors.Is(err, context.DeadlineExceeded) || !gotDeadline {
		t.Fatalf("ok=%v err=%v deadline=%v", ok, err, gotDeadline)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
}

// deadlineAPI blocks until its context ends, as a hung connection would.
type deadlineAPI struct {
	inner *fakeAPI
	seen  *bool
}

func (d *deadlineAPI) GetMetricData(ctx context.Context, _ *cw.GetMetricDataInput, _ ...func(*cw.Options)) (*cw.GetMetricDataOutput, error) {
	_, *d.seen = ctx.Deadline()
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestErrorsAreShortAndBounded(t *testing.T) {
	now := t0
	long := strings.Repeat("x", 5000)
	api := serve(nil, &smithy.GenericAPIError{Code: "Boom", Message: long})
	_, _, err := newCollector(api, &now, 0).Collect(context.Background())
	if err == nil || len(err.Error()) > 500 {
		t.Fatalf("error length = %d", len(fmt.Sprint(err)))
	}
}
