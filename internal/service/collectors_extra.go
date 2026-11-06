package service

import (
	"github.com/wisnuvb/lockkeeper/internal/collector"
	"github.com/wisnuvb/lockkeeper/internal/config"
)

// extraCollectors returns additional collectors for a target, such as a cloud
// metrics reader configured next to the database. None exist yet.
func (s *Service) extraCollectors(target string, db config.Database) []collector.Collector {
	_, _ = target, db
	return nil
}
