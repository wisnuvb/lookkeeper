package service

import (
	"github.com/wisnuvb/lockkeeper/internal/collector"
	"github.com/wisnuvb/lockkeeper/internal/collector/pg"
	"github.com/wisnuvb/lockkeeper/internal/config"
)

// newEngineCollector builds the collector for the database engine of db.
// Add a case per supported engine.
func (s *Service) newEngineCollector(target string, db config.Database) collector.Collector {
	_ = db // engine switch arrives with the MySQL collector
	return pg.New(target, s.openFunc(target), pg.Options{QueryTimeout: s.cfg.Monitor.QueryTimeout.D(), Now: s.deps.Now})
}
