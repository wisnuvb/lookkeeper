package mysql

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// Grant lines recorded from real MySQL 8.0.46 and 8.4.13 servers.
var (
	rootGrants80 = []string{
		"GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, RELOAD, SHUTDOWN, PROCESS, FILE, REFERENCES, INDEX, ALTER, SHOW DATABASES, SUPER, CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE, REPLICATION SLAVE, REPLICATION CLIENT, CREATE VIEW, SHOW VIEW, CREATE ROUTINE, ALTER ROUTINE, CREATE USER, EVENT, TRIGGER, CREATE TABLESPACE, CREATE ROLE, DROP ROLE ON *.* TO `root`@`localhost` WITH GRANT OPTION",
		"GRANT APPLICATION_PASSWORD_ADMIN,AUDIT_ABORT_EXEMPT,BACKUP_ADMIN,BINLOG_ADMIN,CONNECTION_ADMIN,SYSTEM_VARIABLES_ADMIN ON *.* TO `root`@`localhost` WITH GRANT OPTION",
		"GRANT PROXY ON ``@`` TO `root`@`localhost` WITH GRANT OPTION",
	}
	rootGrants84 = []string{
		"GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, RELOAD, SHUTDOWN, PROCESS, FILE, REFERENCES, INDEX, ALTER, SHOW DATABASES, SUPER, CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE, REPLICATION SLAVE, REPLICATION CLIENT, CREATE VIEW, SHOW VIEW, CREATE ROUTINE, ALTER ROUTINE, CREATE USER, EVENT, TRIGGER, CREATE TABLESPACE, CREATE ROLE, DROP ROLE ON *.* TO `root`@`localhost` WITH GRANT OPTION",
		"GRANT ALLOW_NONEXISTENT_DEFINER,BINLOG_ADMIN,SET_ANY_DEFINER,TRANSACTION_GTID_TAG ON *.* TO `root`@`localhost` WITH GRANT OPTION",
		"GRANT PROXY ON ``@`` TO `root`@`localhost` WITH GRANT OPTION",
	}
	allPrivileges = []string{
		"GRANT ALL PRIVILEGES ON *.* TO `admin`@`%` WITH GRANT OPTION",
	}
)

func hasWarning(w []string, parts ...string) bool {
	for _, m := range w {
		ok := true
		for _, p := range parts {
			if !strings.Contains(m, p) {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestAuditLeastPrivilegeAccountIsClean(t *testing.T) {
	for _, lines := range [][]string{
		{"GRANT PROCESS, REPLICATION CLIENT ON *.* TO `lockkeeper`@`%`"},
		{"GRANT PROCESS, REPLICATION CLIENT ON *.* TO `lockkeeper`@`%`", "GRANT SELECT ON `performance_schema`.* TO `lockkeeper`@`%`"},
		{"GRANT PROCESS ON *.* TO `lockkeeper`@`%`", "GRANT REPLICATION CLIENT ON *.* TO `lockkeeper`@`%`", "GRANT SELECT (`Host`, `User`) ON `mysql`.`user` TO `lockkeeper`@`%`"},
	} {
		if w := AuditGrants("lockkeeper@%", lines); len(w) != 0 {
			t.Errorf("expected no warnings for %v, got %v", lines, w)
		}
	}
}

func TestAuditFlagsRootAndAllPrivileges(t *testing.T) {
	// root lists every static privilege one by one instead of ALL PRIVILEGES: it
	// still counts as a full administrator and gets a single message.
	for name, lines := range map[string][]string{"8.0 root": rootGrants80, "8.4 root": rootGrants84} {
		w := AuditGrants("root@localhost", lines)
		if len(w) != 1 || !hasWarning(w, "ALL PRIVILEGES on *.*", "REQUIRE SSL", "grant privileges to others") {
			t.Errorf("%s must be flagged once as a full administrator: %v", name, w)
		}
	}

	w := AuditGrants("admin@%", allPrivileges)
	if len(w) != 1 || !hasWarning(w, "ALL PRIVILEGES on *.*", "REQUIRE SSL", "GRANT PROCESS, REPLICATION CLIENT", "grant privileges to others") {
		t.Errorf("ALL PRIVILEGES warning wrong: %v", w)
	}
}

func TestAuditFlagsIndividualPrivileges(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		want  string
	}{
		{"write", []string{"GRANT PROCESS, REPLICATION CLIENT, INSERT ON *.* TO `u`@`%`"}, "INSERT on *.*"},
		{"ddl on a schema", []string{"GRANT PROCESS, REPLICATION CLIENT ON *.* TO `u`@`%`", "GRANT CREATE, DROP, ALTER ON `app`.* TO `u`@`%`"}, "CREATE on `app`.*"},
		{"all on a schema", []string{"GRANT PROCESS, REPLICATION CLIENT ON *.* TO `u`@`%`", "GRANT ALL PRIVILEGES ON `app`.* TO `u`@`%`"}, "ALL PRIVILEGES on `app`.*"},
		{"grant option", []string{"GRANT PROCESS, REPLICATION CLIENT ON *.* TO `u`@`%` WITH GRANT OPTION"}, "WITH GRANT OPTION"},
		{"replication slave", []string{"GRANT PROCESS, REPLICATION CLIENT, REPLICATION SLAVE ON *.* TO `u`@`%`"}, "REPLICATION SLAVE"},
		{"super", []string{"GRANT PROCESS, REPLICATION CLIENT, SUPER ON *.* TO `u`@`%`"}, "has SUPER"},
		{"dynamic admin privilege", []string{"GRANT PROCESS, REPLICATION CLIENT ON *.* TO `u`@`%`", "GRANT CONNECTION_ADMIN,BINLOG_ADMIN ON *.* TO `u`@`%`"}, "BINLOG_ADMIN on *.*"},
		{"global select", []string{"GRANT SELECT, PROCESS, REPLICATION CLIENT ON *.* TO `u`@`%`"}, "SELECT on *.*"},
		{"unknown future privilege", []string{"GRANT PROCESS, REPLICATION CLIENT, FANCY_NEW_PRIV ON *.* TO `u`@`%`"}, "FANCY_NEW_PRIV"},
		{"identifier containing keywords", []string{"GRANT PROCESS, REPLICATION CLIENT ON *.* TO `u`@`%`", "GRANT DELETE ON `a ON b TO c`.* TO `u`@`%`"}, "DELETE on `a ON b TO c`.*"},
	}
	for _, c := range cases {
		if w := AuditGrants("u@%", c.lines); !hasWarning(w, c.want) {
			t.Errorf("%s: expected a warning containing %q, got %v", c.name, c.want, w)
		}
	}
}

func TestAuditReportsMissingPrivilegesAndTheirEffect(t *testing.T) {
	w := AuditGrants("lk@10.0.0.%", []string{"GRANT USAGE ON *.* TO `lk`@`10.0.0.%`"})
	if !hasWarning(w, "lacks the PROCESS", "my.trx.oldest_s", "my.innodb.history_list_length", "GRANT PROCESS ON *.* TO 'lk'@'10.0.0.%'") {
		t.Errorf("missing PROCESS not explained: %v", w)
	}
	if !hasWarning(w, "lacks the REPLICATION CLIENT", "my.repl.*", "my.binlog.disk_bytes", "would NOT alert", "GRANT REPLICATION CLIENT ON *.* TO 'lk'@'10.0.0.%'") {
		t.Errorf("missing REPLICATION CLIENT not explained: %v", w)
	}
	if len(w) != 2 {
		t.Errorf("expected exactly the two missing-privilege warnings: %v", w)
	}

	// Privileges only on a schema do not count: PROCESS and REPLICATION CLIENT are global.
	w = AuditGrants("u@%", []string{"GRANT PROCESS ON `app`.* TO `u`@`%`"})
	if !hasWarning(w, "lacks the PROCESS") {
		t.Errorf("a non-global PROCESS must not satisfy the requirement: %v", w)
	}

	w = AuditGrants("u@%", []string{"GRANT PROCESS ON *.* TO `u`@`%`"})
	if len(w) != 1 || !hasWarning(w, "lacks the REPLICATION CLIENT") {
		t.Errorf("only REPLICATION CLIENT should be missing: %v", w)
	}
}

func TestParseGrant(t *testing.T) {
	g, ok := parseGrant("GRANT SELECT (`a`, `b`), INSERT (`c`) ON `d`.`t` TO `u`@`%` WITH GRANT OPTION")
	if !ok || g.level != "`d`.`t`" || !g.grantOption || len(g.privs) != 2 || g.privs[0] != "SELECT" || g.privs[1] != "INSERT" {
		t.Errorf("column privileges: %+v %v", g, ok)
	}
	g, ok = parseGrant("GRANT EXECUTE ON FUNCTION `app`.`f` TO `u`@`%`")
	if !ok || g.level != "FUNCTION `app`.`f`" {
		t.Errorf("routine level: %+v %v", g, ok)
	}
	for _, not := range []string{
		"GRANT `reader`@`%` TO `u`@`%`",
		"REVOKE SELECT ON `mysql`.* FROM `u`@`%`",
		"",
		"GRANT",
	} {
		if _, ok := parseGrant(not); ok {
			t.Errorf("%q is not a privilege grant", not)
		}
	}
}

func TestParseRoleGrant(t *testing.T) {
	got := parseRoleGrant("GRANT `reader`@`%`,`app ro`@`10.%` TO `u`@`%`")
	if len(got) != 2 || got[0] != "`reader`@`%`" || got[1] != "`app ro`@`10.%`" {
		t.Errorf("roles = %v", got)
	}
	if r := parseRoleGrant("GRANT SELECT ON *.* TO `u`@`%`"); r != nil {
		t.Errorf("a privilege grant has no roles: %v", r)
	}
}

func TestAuditExpandsRoles(t *testing.T) {
	f := healthyServer()
	f.onRows("SELECT CURRENT_USER()", []string{"u"}, []any{"lk@%"})
	// Exact statements are matched by substring; the longer USING form first.
	f.onRows("USING", []string{"g"},
		[]any{"GRANT PROCESS, REPLICATION CLIENT ON *.* TO `lk`@`%`"},
		[]any{"GRANT INSERT ON *.* TO `lk`@`%`"},
		[]any{"GRANT `writer`@`%` TO `lk`@`%`"})
	f.onRows("SHOW GRANTS", []string{"g"},
		[]any{"GRANT PROCESS, REPLICATION CLIENT ON *.* TO `lk`@`%`"},
		[]any{"GRANT `writer`@`%` TO `lk`@`%`"})
	c := newTestCollector(t, f, &clock{t0})
	w, err := c.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(w, "INSERT on *.*") {
		t.Errorf("privileges that come through a role must be audited: %v", w)
	}
	var sawUsing bool
	for _, q := range f.executed() {
		if strings.Contains(q, "USING `writer`@`%`") {
			sawUsing = true
		}
	}
	if !sawUsing {
		t.Errorf("roles must be expanded with SHOW GRANTS ... USING: %v", f.executed())
	}
}

func TestAuditRoleExpansionFailureIsReported(t *testing.T) {
	f := healthyServer()
	f.onRows("SELECT CURRENT_USER()", []string{"u"}, []any{"lk@%"})
	f.onErr("USING", serverErr(3530, "`writer`@`%` is not granted to `lk`@`%`"))
	f.onRows("SHOW GRANTS", []string{"g"},
		[]any{"GRANT PROCESS, REPLICATION CLIENT ON *.* TO `lk`@`%`"},
		[]any{"GRANT `writer`@`%` TO `lk`@`%`"})
	w, err := newTestCollector(t, f, &clock{t0}).Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(w, "not audited") {
		t.Errorf("an unreadable role must be called out: %v", w)
	}
}

func TestAuditConnectionFailure(t *testing.T) {
	c := New("t", func(context.Context) (*sql.DB, error) { return nil, context.DeadlineExceeded }, Options{})
	if _, err := c.Audit(context.Background()); err == nil {
		t.Error("expected a connect error")
	}
}
