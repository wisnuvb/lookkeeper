package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

// recommendedGrants is the account Lockkeeper needs. Verified on MySQL 8.0 and
// 8.4: with only these two global privileges every metric is collected, and
// SELECT on performance_schema is NOT needed (SHOW GLOBAL STATUS needs no
// privilege; INNODB_TRX and INNODB_METRICS need PROCESS; SHOW REPLICA STATUS and
// SHOW BINARY LOGS need REPLICATION CLIENT).
const recommendedGrants = "CREATE USER 'lockkeeper'@'<allowed host>' IDENTIFIED BY '<password>' REQUIRE SSL; " +
	"GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'lockkeeper'@'<allowed host>';"

// harmlessPrivileges are the privileges an account may hold without a warning:
// the two Lockkeeper uses, plus ones that cannot change or leak table data.
// Anything else, including privileges added by future MySQL versions, is
// reported (the safe default for an allow-list).
var harmlessPrivileges = map[string]bool{
	"USAGE":                   true,
	"PROCESS":                 true,
	"REPLICATION CLIENT":      true,
	"SELECT":                  true, // data access is judged separately, see below
	"SHOW DATABASES":          true,
	"SHOW VIEW":               true,
	"REFERENCES":              true,
	"CREATE TEMPORARY TABLES": true, // writes only to the session's own temporary tables
	"SHOW_ROUTINE":            true,
}

// grant is one parsed "GRANT ... ON ... TO ..." line of SHOW GRANTS.
type grant struct {
	privs       []string // upper-cased, column lists removed
	level       string   // e.g. "*.*", "`app`.*"
	grantOption bool
}

// AuditGrants inspects the lines of SHOW GRANTS FOR CURRENT_USER() and returns
// human-readable warnings. account is only used in the messages.
//
// Why this matters: the session is forced read-only (transaction_read_only), but
// that is defence in depth, not a security boundary. Verified on 8.0 and 8.4: a
// read-only session still accepts SET GLOBAL, FLUSH, PURGE BINARY LOGS and KILL if
// the account may run them. The real boundary is a least-privilege account:
// PROCESS and REPLICATION CLIENT, nothing else.
func AuditGrants(account string, lines []string) []string {
	var grants []grant
	for _, l := range lines {
		if g, ok := parseGrant(l); ok {
			grants = append(grants, g)
		}
	}

	global := map[string]bool{}
	allGlobal := false
	for _, g := range grants {
		if g.level != "*.*" {
			continue
		}
		for _, p := range g.privs {
			global[p] = true
			if p == "ALL PRIVILEGES" || p == "ALL" {
				allGlobal = true
			}
		}
	}
	// SHOW GRANTS prints "ALL PRIVILEGES" only in some cases; a full administrator
	// is often listed privilege by privilege (verified on 8.4). Recognise that
	// too, so such an account gets one clear message instead of a wall of text.
	for _, p := range []string{"SUPER", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "SHUTDOWN", "FILE", "CREATE USER"} {
		if !global[p] {
			break
		}
		if p == "CREATE USER" {
			allGlobal = true
		}
	}
	has := func(p string) bool { return allGlobal || global[p] }

	var w []string
	switch {
	case allGlobal:
		msg := fmt.Sprintf("account %s has ALL PRIVILEGES on *.* (or every privilege listed one by one); Lockkeeper only needs PROCESS and REPLICATION CLIENT. A read-only session is not a safety boundary, so use a dedicated account: %s", account, recommendedGrants)
		if hasGrantOption(grants, true) {
			msg += " (the account can also grant privileges to others)"
		}
		w = append(w, msg)
	case global["SUPER"]:
		w = append(w, fmt.Sprintf("account %s has SUPER; it can change server settings and kill sessions even from a read-only session. Lockkeeper only needs PROCESS and REPLICATION CLIENT. Use a dedicated account: %s", account, recommendedGrants))
	}

	if !allGlobal {
		var risky []string
		seen := map[string]bool{}
		var replSlave, selectAll bool
		for _, g := range grants {
			for _, p := range g.privs {
				switch {
				case p == "SUPER" && g.level == "*.*": // reported above
				case p == "REPLICATION SLAVE":
					replSlave = true
				case p == "SELECT":
					if g.level == "*.*" {
						selectAll = true
					}
				case p == "ALL PRIVILEGES" || p == "ALL":
					addUnique(&risky, seen, "ALL PRIVILEGES on "+g.level)
				case !harmlessPrivileges[p]:
					addUnique(&risky, seen, p+" on "+g.level)
				}
			}
		}
		if len(risky) > 0 {
			w = append(w, fmt.Sprintf("account %s has privileges Lockkeeper never uses (write, DDL or administration): %s. Revoke them; Lockkeeper only needs PROCESS and REPLICATION CLIENT", account, summarize(risky, 40)))
		}
		if replSlave {
			w = append(w, fmt.Sprintf("account %s has REPLICATION SLAVE: it can stream the whole binary log, which contains every change to every table. Only a replication account needs it; revoke it from the monitoring account", account))
		}
		if selectAll {
			w = append(w, fmt.Sprintf("account %s has SELECT on *.*: it can read every table. Lockkeeper does not read table data; revoke it", account))
		}
		if hasGrantOption(grants, false) {
			w = append(w, fmt.Sprintf("account %s has WITH GRANT OPTION: it can hand out its privileges to other accounts. Revoke it", account))
		}
	}

	if !has("PROCESS") {
		w = append(w, fmt.Sprintf("account %s lacks the PROCESS privilege: transactions and InnoDB counters cannot be read, so my.trx.oldest_s and my.innodb.history_list_length are missing and collection is reported incomplete. Run: GRANT PROCESS ON *.* TO %s;", account, quoteAccountForGrant(account)))
	}
	if !has("REPLICATION CLIENT") && !has("SUPER") {
		w = append(w, fmt.Sprintf("account %s lacks the REPLICATION CLIENT privilege: replica status and binary log size cannot be read, so my.repl.* and my.binlog.disk_bytes are missing and a broken replica would NOT alert. Run: GRANT REPLICATION CLIENT ON *.* TO %s;", account, quoteAccountForGrant(account)))
	}
	return w
}

func addUnique(list *[]string, seen map[string]bool, s string) {
	if !seen[s] {
		seen[s] = true
		*list = append(*list, s)
	}
}

// summarize joins at most limit items.
func summarize(items []string, limit int) string {
	if len(items) <= limit {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:limit], ", ") + fmt.Sprintf(" and %d more", len(items)-limit)
}

// hasGrantOption reports whether any grant carries WITH GRANT OPTION. With
// globalOnly it only looks at *.*.
func hasGrantOption(grants []grant, globalOnly bool) bool {
	for _, g := range grants {
		if g.grantOption && (!globalOnly || g.level == "*.*") {
			return true
		}
	}
	return false
}

// quoteAccountForGrant turns "user@host" (CURRENT_USER() output) into
// 'user'@'host' for a ready-to-run statement.
func quoteAccountForGrant(account string) string {
	i := strings.LastIndex(account, "@")
	if i < 0 {
		return "'" + strings.ReplaceAll(account, "'", "''") + "'"
	}
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	return q(account[:i]) + "@" + q(account[i+1:])
}

// parseGrant parses "GRANT <privs> ON <level> TO <account> [WITH GRANT OPTION]".
// Role grants ("GRANT `r`@`%` TO ...") and REVOKE lines are not privilege grants
// and return ok=false.
func parseGrant(line string) (grant, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(strings.ToUpper(line), "GRANT ") {
		return grant{}, false
	}
	rest := line[len("GRANT "):]
	on := indexTopLevel(rest, " ON ")
	if on < 0 {
		return grant{}, false // role grant
	}
	privStr := rest[:on]
	after := rest[on+len(" ON "):]
	to := indexTopLevel(after, " TO ")
	if to < 0 {
		return grant{}, false
	}
	g := grant{level: strings.TrimSpace(after[:to])}
	g.grantOption = strings.HasSuffix(strings.ToUpper(strings.TrimSpace(after[to+len(" TO "):])), " WITH GRANT OPTION")
	for _, p := range splitTopLevel(privStr, ',') {
		p = strings.TrimSpace(p)
		if i := strings.Index(p, "("); i > 0 { // column privilege: SELECT (a, b)
			p = strings.TrimSpace(p[:i])
		}
		if p != "" {
			g.privs = append(g.privs, strings.ToUpper(p))
		}
	}
	return g, len(g.privs) > 0
}

// indexTopLevel returns the index of sep in s outside quoted identifiers,
// quoted strings and parentheses, or -1. Identifiers may contain " ON " or " TO ".
func indexTopLevel(s, sep string) int {
	depth := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if quote != 0 {
			if ch == quote {
				if i+1 < len(s) && s[i+1] == quote { // doubled quote is an escape
					i++
					continue
				}
				quote = 0
			}
			continue
		}
		switch ch {
		case '`', '\'', '"':
			quote = ch
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && strings.HasPrefix(s[i:], sep) {
				return i
			}
		}
	}
	return -1
}

// splitTopLevel splits s at sep outside quotes and parentheses.
func splitTopLevel(s string, sep byte) []string {
	var parts []string
	depth := 0
	var quote byte
	start := 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '`', '\'', '"':
			quote = ch
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case sep:
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, s[start:])
}

// parseRoleGrant returns the roles of a "GRANT `r1`@`%`,`r2`@`%` TO `u`@`%`" line,
// each re-quoted so it can be used in SHOW GRANTS ... USING.
func parseRoleGrant(line string) []string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(strings.ToUpper(line), "GRANT ") {
		return nil
	}
	rest := line[len("GRANT "):]
	if indexTopLevel(rest, " ON ") >= 0 {
		return nil
	}
	to := indexTopLevel(rest, " TO ")
	if to < 0 {
		return nil
	}
	var roles []string
	for _, acct := range splitTopLevel(rest[:to], ',') {
		acct = strings.TrimSpace(acct)
		if acct != "" {
			roles = append(roles, acct)
		}
	}
	return roles
}

// Audit runs AuditGrants on the collector's connection, connecting if necessary.
// Privileges that come through roles are included by re-reading the grants with
// SHOW GRANTS ... USING.
func (c *Collector) Audit(ctx context.Context) ([]string, error) {
	if err := c.ensureConn(ctx); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	gctx, cancel := context.WithTimeout(ctx, c.opts.QueryTimeout)
	defer cancel()

	var account string
	if err := c.db.QueryRowContext(gctx, "SELECT CURRENT_USER()").Scan(&account); err != nil {
		return nil, fmt.Errorf("audit account privileges: %w", err)
	}
	lines, err := c.showGrants(gctx, "SHOW GRANTS FOR CURRENT_USER()")
	if err != nil {
		return nil, fmt.Errorf("audit account privileges: %w", err)
	}
	var roles []string
	for _, l := range lines {
		roles = append(roles, parseRoleGrant(l)...)
	}
	var note []string
	if len(roles) > 0 {
		sort.Strings(roles)
		expanded, err := c.showGrants(gctx, "SHOW GRANTS FOR CURRENT_USER() USING "+strings.Join(roles, ","))
		if err != nil {
			note = append(note, fmt.Sprintf("account %s holds roles whose privileges could not be read (%v); privileges granted through roles were not audited", account, err))
		} else {
			lines = expanded
		}
	}
	return append(AuditGrants(account, lines), note...), nil
}

func (c *Collector) showGrants(ctx context.Context, stmt string) ([]string, error) {
	rows, err := c.db.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s sql.NullString
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s.String)
	}
	return out, rows.Err()
}
