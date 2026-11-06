package service

import (
	"github.com/wisnuvb/lockkeeper/internal/cloudwatch"
	"github.com/wisnuvb/lockkeeper/internal/collector"
	"github.com/wisnuvb/lockkeeper/internal/config"
)

// extraCollectors returns additional collectors for a target, such as a cloud
// metrics reader configured next to the database.
func (s *Service) extraCollectors(target string, db config.Database) []collector.Collector {
	var out []collector.Collector
	if cwCfg := db.CloudWatch; cwCfg != nil {
		api := s.deps.NewCloudWatch(cwCfg.Region)
		out = append(out, cloudwatch.New(target, cwCfg.DBInstanceID, api, cloudwatch.Options{
			DiskTotalGB: db.DiskTotalGB,
			Now:         s.deps.Now,
		}))
	}
	return out
}

// derivedSamples returns the hook that computes metrics combining the outputs of
// several collectors of one target, or nil when the target has none to derive.
func (s *Service) derivedSamples(db config.Database) collector.DeriveFunc {
	if db.CloudWatch == nil {
		return nil
	}
	return deriveWALFreeRatio
}
