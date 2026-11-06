package service

import (
	"context"
	"database/sql"
	"fmt"

	mysqlcollector "github.com/wisnuvb/lockkeeper/internal/collector/mysql"
	"github.com/wisnuvb/lockkeeper/internal/dbconn"
)

// openMySQLFunc returns a mysql.OpenFunc for a configured database. The password
// is resolved on every (re)connect, so a rotated secret is picked up, and errors
// are redacted before they leave this function.
func (s *Service) openMySQLFunc(name string) mysqlcollector.OpenFunc {
	return func(ctx context.Context) (*sql.DB, error) {
		db, ok := s.cfg.Databases[name]
		if !ok {
			return nil, fmt.Errorf("unknown database %q", name)
		}
		pw, err := s.resolveSecret(ctx, db.Password, "password for "+name)
		if err != nil {
			return nil, err
		}
		spec := dbconn.MySQLSpecFromConfig(db, pw, s.cfg.Monitor.QueryTimeout.D())
		conn, err := s.deps.OpenMySQL(ctx, spec)
		if err != nil {
			return nil, s.deps.Redactor.Error(err)
		}
		return conn, nil
	}
}
