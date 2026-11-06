package service

import (
	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/cloudwatch"
	"github.com/wisnuvb/lockkeeper/internal/model"
)

// maxWALFreeRatio caps the derived ratio. With no free storage at all the true
// value is infinite, which JSON and SQLite cannot hold; anything this large is
// far past the critical threshold anyway.
const maxWALFreeRatio = 10.0

// deriveWALFreeRatio computes pg.slot.retained_wal_free_ratio, per slot, as
// retained WAL divided by current free storage (SPEC 10.3: "retained WAL as a
// share of free storage"). It needs both inputs in the same collection: when
// CloudWatch data is unavailable no free-storage sample exists, so nothing is
// derived and the absolute byte thresholds remain the only guard.
func deriveWALFreeRatio(samples []model.Sample) []model.Sample {
	var free *model.Sample
	for i := range samples {
		if samples[i].Metric == cloudwatch.MetricFreeStorageBytes {
			free = &samples[i]
			break
		}
	}
	if free == nil {
		return nil
	}
	var out []model.Sample
	for _, s := range samples {
		if s.Metric != rules.MetricPGSlotRetainedWAL {
			continue
		}
		ratio := maxWALFreeRatio
		if free.Value > 0 {
			ratio = min(s.Value/free.Value, maxWALFreeRatio)
		}
		labels := make(map[string]string, len(s.Labels))
		for k, v := range s.Labels {
			labels[k] = v
		}
		out = append(out, model.Sample{
			Target: s.Target, Metric: rules.MetricPGSlotRetainedWALFreeRatio, Labels: labels, Value: ratio, At: s.At,
		})
	}
	return out
}
