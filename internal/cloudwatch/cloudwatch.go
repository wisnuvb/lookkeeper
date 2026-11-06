// Package cloudwatch is the optional reader for RDS infrastructure metrics.
//
// RDS exposes no disk-free figure over SQL, so a Postgres target can opt in to
// reading FreeStorageSpace from CloudWatch. The package is deliberately small:
//
//   - The AWS SDK is only linked behind the API interface (see sdk.go); the
//     collector itself and every test work against a fake.
//   - Credentials come only from the standard AWS credential chain (environment,
//     shared config, SSO, instance or container role). Lockkeeper never stores
//     them and nothing here ever formats them.
//   - Missing or stale data is never reported as zero: the batch is marked
//     incomplete and carries a clear error instead.
package cloudwatch

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cw "github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/smithy-go"

	"github.com/wisnuvb/lockkeeper/internal/model"
)

// Metric names emitted by the collector.
const (
	MetricFreeStorageBytes = "rds.free_storage_bytes"
	MetricFreeStorageRatio = "rds.free_storage_ratio"
)

// Defaults for Options.
const (
	DefaultPeriod      = 60 * time.Second
	DefaultLookback    = 15 * time.Minute
	DefaultMaxAge      = 10 * time.Minute
	DefaultCallTimeout = 10 * time.Second
	// DefaultMinFetchGap avoids asking CloudWatch more often than it publishes: RDS
	// metrics arrive once a minute, so polling every 30s only costs money.
	DefaultMinFetchGap = 60 * time.Second

	// GiB is the unit of disk_total_gb: RDS allocated storage is in gibibytes.
	GiB = float64(1 << 30)
)

// API is the one SDK call the collector needs. *cloudwatch.Client satisfies it.
type API interface {
	GetMetricData(ctx context.Context, in *cw.GetMetricDataInput, optFns ...func(*cw.Options)) (*cw.GetMetricDataOutput, error)
}

// Options tune a Collector. Zero values select the defaults above.
type Options struct {
	// DiskTotalGB (GiB) enables rds.free_storage_ratio when positive.
	DiskTotalGB float64
	Period      time.Duration
	Lookback    time.Duration
	// MaxAge is how old the newest datapoint may be before it counts as missing.
	MaxAge      time.Duration
	CallTimeout time.Duration
	MinFetchGap time.Duration
	Now         func() time.Time
}

// Collector reads FreeStorageSpace for one RDS instance. It implements
// collector.Collector and is used from a single goroutine per target.
type Collector struct {
	target     string
	instanceID string
	api        API
	opts       Options

	// Newest datapoint from the last successful fetch, reused for MinFetchGap.
	cached    *point
	fetchedAt time.Time
}

type point struct {
	at    time.Time
	value float64
}

// New returns a collector for the RDS instance instanceID, reported under target.
func New(target, instanceID string, api API, opts Options) *Collector {
	if opts.Period <= 0 {
		opts.Period = DefaultPeriod
	}
	if opts.Lookback <= 0 {
		opts.Lookback = DefaultLookback
	}
	if opts.MaxAge <= 0 {
		opts.MaxAge = DefaultMaxAge
	}
	if opts.CallTimeout <= 0 {
		opts.CallTimeout = DefaultCallTimeout
	}
	if opts.MinFetchGap <= 0 {
		opts.MinFetchGap = DefaultMinFetchGap
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Collector{target: target, instanceID: instanceID, api: api, opts: opts}
}

// Target implements collector.Collector.
func (c *Collector) Target() string { return c.target }

// Close implements collector.Collector. The SDK client holds no resource that
// needs releasing.
func (c *Collector) Close() error { return nil }

// Collect implements collector.Collector. When CloudWatch has no fresh datapoint
// it returns no samples, complete=false and an error: an alert on free storage
// must never be driven by a made-up zero, and an unreadable metric must not
// clear an alert that is already firing.
func (c *Collector) Collect(ctx context.Context) ([]model.Sample, bool, error) {
	now := c.opts.Now()
	p, err := c.newest(ctx, now)
	if err != nil {
		return nil, false, err
	}
	if math.IsNaN(p.value) || math.IsInf(p.value, 0) || p.value < 0 {
		return nil, false, fmt.Errorf("cloudwatch: FreeStorageSpace for %s returned an invalid value; treating free storage as unavailable", c.instanceID)
	}
	if age := now.Sub(p.at); age > c.opts.MaxAge {
		return nil, false, fmt.Errorf("cloudwatch: newest FreeStorageSpace datapoint for %s is %s old (limit %s); treating free storage as unavailable",
			c.instanceID, age.Round(time.Second), c.opts.MaxAge)
	}
	samples := []model.Sample{{Target: c.target, Metric: MetricFreeStorageBytes, Value: p.value, At: now}}
	if total := c.opts.DiskTotalGB * GiB; c.opts.DiskTotalGB > 0 {
		if p.value > total {
			// Storage autoscaling or a wrong disk_total_gb. A ratio above 1 would
			// look healthy while meaning nothing, so withhold it.
			return samples, false, fmt.Errorf("cloudwatch: free storage (%.0f GiB) exceeds disk_total_gb (%.0f); "+
				"raise disk_total_gb (storage autoscaling may have grown the volume), so no free-storage ratio is reported",
				p.value/GiB, c.opts.DiskTotalGB)
		}
		samples = append(samples, model.Sample{Target: c.target, Metric: MetricFreeStorageRatio, Value: p.value / total, At: now})
	}
	return samples, true, nil
}

// newest returns the newest datapoint, from cache when it is recent enough.
func (c *Collector) newest(ctx context.Context, now time.Time) (point, error) {
	if c.cached != nil && now.Sub(c.fetchedAt) < c.opts.MinFetchGap && !now.Before(c.fetchedAt) {
		return *c.cached, nil
	}
	c.cached = nil
	ctx, cancel := context.WithTimeout(ctx, c.opts.CallTimeout)
	defer cancel()
	out, err := c.api.GetMetricData(ctx, c.request(now))
	if err != nil {
		return point{}, c.callError(ctx, err)
	}
	var best *point
	for _, r := range out.MetricDataResults {
		if aws.ToString(r.Id) != queryID {
			continue
		}
		for i := 0; i < len(r.Timestamps) && i < len(r.Values); i++ {
			if best == nil || r.Timestamps[i].After(best.at) {
				best = &point{at: r.Timestamps[i], value: r.Values[i]}
			}
		}
	}
	if best == nil {
		return point{}, fmt.Errorf("cloudwatch: no FreeStorageSpace datapoints for DB instance %q in the last %s; "+
			"check db_instance_id and region, that the instance exists, and that the credentials may call cloudwatch:GetMetricData",
			c.instanceID, c.opts.Lookback)
	}
	c.cached, c.fetchedAt = best, now
	return *best, nil
}

const queryID = "free_storage"

// request builds the GetMetricData call: FreeStorageSpace of one instance, newest
// first. Minimum is the conservative statistic: if a longer period were ever
// configured, the lowest free space in it is what matters.
func (c *Collector) request(now time.Time) *cw.GetMetricDataInput {
	period := int32(c.opts.Period / time.Second)
	return &cw.GetMetricDataInput{
		StartTime: aws.Time(now.Add(-c.opts.Lookback)),
		EndTime:   aws.Time(now),
		ScanBy:    types.ScanByTimestampDescending,
		MetricDataQueries: []types.MetricDataQuery{{
			Id:         aws.String(queryID),
			ReturnData: aws.Bool(true),
			MetricStat: &types.MetricStat{
				Period: aws.Int32(period),
				Stat:   aws.String("Minimum"),
				Unit:   types.StandardUnitBytes,
				Metric: &types.Metric{
					Namespace:  aws.String("AWS/RDS"),
					MetricName: aws.String("FreeStorageSpace"),
					Dimensions: []types.Dimension{{Name: aws.String("DBInstanceIdentifier"), Value: aws.String(c.instanceID)}},
				},
			},
		}},
	}
}

// callError turns an SDK error into a short message. SDK errors can be long and
// carry request IDs and, for credential failures, details of the provider chain;
// none of it is needed to act on, and none of it may include a secret.
func (c *Collector) callError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil:
		return fmt.Errorf("cloudwatch: GetMetricData for %s did not finish within %s: %w", c.instanceID, c.opts.CallTimeout, context.DeadlineExceeded)
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		return fmt.Errorf("cloudwatch: GetMetricData failed: %s: %s", api.ErrorCode(), clip(api.ErrorMessage()))
	}
	return fmt.Errorf("cloudwatch: GetMetricData failed: %s", clip(err.Error()))
}

// clip flattens whitespace and bounds the length of text taken from a remote error.
func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	const max = 300
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
