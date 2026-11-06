package service

import (
	"github.com/wisnuvb/lockkeeper/internal/collector"
	mysqlcollector "github.com/wisnuvb/lockkeeper/internal/collector/mysql"
	"github.com/wisnuvb/lockkeeper/internal/collector/pg"
	"github.com/wisnuvb/lockkeeper/internal/config"
)

// newEngineCollector builds the collector for the database engine of db.
// Add a case per supported engine.
func (s *Service) newEngineCollector(target string, db config.Database) collector.Collector {
	qt := s.cfg.Monitor.QueryTimeout.D()
	switch db.Engine {
	case config.EngineMySQL:
		return mysqlcollector.New(target, s.openMySQLFunc(target), mysqlcollector.Options{QueryTimeout: qt, Now: s.deps.Now})
	default: // config.EnginePostgres; config validation rejects anything else
		return pg.New(target, s.openFunc(target), pg.Options{QueryTimeout: qt, Now: s.deps.Now})
	}
}
