package pg

import (
	"fmt"
	"sort"
	"strings"

	"github.com/wisnuvb/lockkeeper/internal/inventory"
	"github.com/wisnuvb/lockkeeper/internal/preflight"
)

// extUse is one extension and the databases it is installed in on the source.
type extUse struct {
	name      string
	version   string
	databases []string
}

func sourceExtensions(src *inventory.Server) []extUse {
	byName := map[string]*extUse{}
	for _, d := range src.Databases {
		for _, e := range d.Extensions {
			u := byName[e.Name+"\x00"+e.Version]
			if u == nil {
				u = &extUse{name: e.Name, version: e.Version}
				byName[e.Name+"\x00"+e.Version] = u
			}
			u.databases = append(u.databases, d.Name)
		}
	}
	out := make([]extUse, 0, len(byName))
	for _, u := range byName {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].name != out[j].name {
			return out[i].name < out[j].name
		}
		return out[i].version < out[j].version
	})
	return out
}

// checkExtensions requires every extension installed on the source to be
// installable on the target (BLOCKER) and notes version differences (WARN).
func checkExtensions(in Input) []preflight.Finding {
	src, tgt := in.Source.Server, in.Target.Server
	if src == nil || tgt == nil {
		return nil
	}
	uses := sourceExtensions(src)
	if len(uses) == 0 {
		return nil
	}
	avail := in.Target.Facts.AvailableExtensions
	if avail == nil {
		return []preflight.Finding{finding("extensions.unverified", areaExtensions, preflight.Warn,
			"could not read pg_available_extensions on the target, so it is unknown whether the source's extensions can be installed there",
			"On the target run `SELECT name, default_version FROM pg_available_extensions ORDER BY name;` and compare with the source's `SELECT extname, extversion FROM pg_extension;` in each database.")}
	}
	var out []preflight.Finding
	for _, u := range uses {
		id := "extensions." + u.name
		where := strings.Join(u.databases, ", ")
		def, ok := avail[u.name]
		if !ok {
			rem := fmt.Sprintf("Install the package that provides %q on the target server (for example the contrib or a vendor package matching PostgreSQL %d), then re-run the pre-flight. If the extension is not needed, remove it from the source schema before migrating.", u.name, tgt.Major)
			if src.IsRDS && (strings.HasPrefix(u.name, "aws_") || strings.HasPrefix(u.name, "rds_")) {
				rem = fmt.Sprintf("%q is probably an RDS-specific extension that exists only on AWS (name-based guess, not verified); code that uses it must be changed before leaving RDS, then drop it on the source. ", u.name) + rem
			}
			out = append(out, finding(id, areaExtensions, preflight.Blocker,
				fmt.Sprintf("extension %s %s (installed in %s on the source) is not available on the target", u.name, u.version, where), rem))
			continue
		}
		// Compare with what is installed on the target when the database exists
		// there, otherwise with the version CREATE EXTENSION would install.
		targetVer, from := def, "available"
		for _, dbn := range u.databases {
			if td, ok := tgt.Database(dbn); ok {
				for _, te := range td.Extensions {
					if te.Name == u.name {
						targetVer, from = te.Version, "installed in "+dbn
					}
				}
			}
		}
		if targetVer != u.version {
			out = append(out, finding(id, areaExtensions, preflight.Warn,
				fmt.Sprintf("extension %s is version %s on the source (%s) but version %s is %s on the target", u.name, u.version, where, targetVer, from),
				"Different extension versions can change behaviour or data formats. Compare the extension's release notes; after the migration, check `SELECT extname, extversion FROM pg_extension;` on the target and `ALTER EXTENSION "+inventory.QuoteIdent(u.name)+" UPDATE;` if appropriate (a TARGET change)."))
		}
	}
	if len(out) == 0 {
		out = append(out, finding("extensions.available", areaExtensions, preflight.OK,
			fmt.Sprintf("all %d extension(s) installed on the source are available on the target at the same version", len(uses)), ""))
	}
	return out
}

// checkPreload warns about shared libraries the source loads and the target does
// not: extensions such as pg_cron or timescaledb are listed as available even
// when CREATE EXTENSION would fail without preloading.
func checkPreload(in Input) []preflight.Finding {
	src, tgt := in.Source.Server, in.Target.Server
	if src == nil || tgt == nil {
		return nil
	}
	sv, _ := src.SettingString("shared_preload_libraries")
	tv, _ := tgt.SettingString("shared_preload_libraries")
	have := map[string]bool{}
	for _, l := range splitList(tv) {
		have[l] = true
	}
	var missing []string
	for _, l := range splitList(sv) {
		// RDS adds its own modules, which never exist elsewhere.
		if !have[l] && !strings.HasPrefix(l, "rds") {
			missing = append(missing, l)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return []preflight.Finding{finding("extensions.preload", areaExtensions, preflight.Warn,
		fmt.Sprintf("the source preloads %s through shared_preload_libraries but the target does not; extensions that need preloading fail to install or work without it", strings.Join(missing, ", ")),
		"If the source's extensions need these libraries, add them to shared_preload_libraries on the target (`ALTER SYSTEM SET shared_preload_libraries = '...';` including the existing entries) and restart. Libraries that only collect statistics (for example pg_stat_statements) are optional.")}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.Trim(strings.TrimSpace(p), `"`); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// checkLocale compares encoding and collation per database. For a database that
// already exists on the target, a different encoding is a BLOCKER (it cannot be
// changed) and a different collation a WARN (index order and comparisons would
// differ). For one that does not exist yet, the target's template1 is the
// reference: the database will have to be created explicitly from template0.
func checkLocale(in Input) []preflight.Finding {
	src, tgt := in.Source.Server, in.Target.Server
	if src == nil || tgt == nil {
		return nil
	}
	var out []preflight.Finding
	for _, sd := range src.Databases {
		id := "locale." + sd.Name
		ref, exists := tgt.Database(sd.Name)
		var tl inventory.Locale
		where := "the target's template1 (the default for a new database)"
		if exists {
			tl, where = ref.Locale, "the existing database on the target"
		} else {
			tl = tgt.DefaultLocale
		}
		var encDiff, locDiff []string
		if sd.Encoding != tl.Encoding {
			encDiff = append(encDiff, fmt.Sprintf("encoding %s vs %s", sd.Encoding, tl.Encoding))
		}
		if sd.Collate != tl.Collate {
			locDiff = append(locDiff, fmt.Sprintf("LC_COLLATE %s vs %s", sd.Collate, tl.Collate))
		}
		if sd.Ctype != tl.Ctype {
			locDiff = append(locDiff, fmt.Sprintf("LC_CTYPE %s vs %s", sd.Ctype, tl.Ctype))
		}
		if sd.Provider != tl.Provider || sd.ICULocale != tl.ICULocale {
			locDiff = append(locDiff, fmt.Sprintf("locale provider %s%s vs %s%s", sd.Provider, withSpace(sd.ICULocale), tl.Provider, withSpace(tl.ICULocale)))
		}
		create := fmt.Sprintf("CREATE DATABASE %s TEMPLATE template0 ENCODING '%s' LC_COLLATE '%s' LC_CTYPE '%s';",
			inventory.QuoteIdent(sd.Name), sd.Encoding, sd.Collate, sd.Ctype)
		switch {
		case len(encDiff) == 0 && len(locDiff) == 0:
			out = append(out, finding(id, areaLocale, preflight.OK,
				fmt.Sprintf("database %s: encoding %s and collation %s/%s match %s", sd.Name, sd.Encoding, sd.Collate, sd.Ctype, where), ""))
		case exists && len(encDiff) > 0:
			out = append(out, finding(id, areaLocale, preflight.Blocker,
				fmt.Sprintf("database %s: %s differ from %s; the encoding of a database cannot be changed and converting data on the way can fail or alter text", sd.Name, strings.Join(append(encDiff, locDiff...), ", "), where),
				"Create an empty database on the target with the source's encoding and locale, and migrate into that one: "+create+" (the OS locale must exist on the target: `locale -a`). Lockkeeper does not drop or recreate target databases."))
		case exists:
			out = append(out, finding(id, areaLocale, preflight.Warn,
				fmt.Sprintf("database %s: %s differ from %s; sort order and string comparison differ, which can reorder results and make unique constraints and indexes behave differently", sd.Name, strings.Join(locDiff, ", "), where),
				"Prefer a target database with the source's collation: "+create+" (the OS locale must exist on the target: `locale -a`). If you keep the difference, test the application's ordering-dependent queries."))
		default:
			out = append(out, finding(id, areaLocale, preflight.Warn,
				fmt.Sprintf("database %s does not exist on the target yet and the target's defaults differ from the source (%s); the target database must be created explicitly to match", sd.Name, strings.Join(append(encDiff, locDiff...), ", ")),
				"Create it with the source's settings before migrating (it needs template0 because the settings differ): "+create+" The OS locale must exist on the target (`locale -a`); that cannot be verified read-only."))
		}
	}
	return out
}

func withSpace(s string) string {
	if s == "" {
		return ""
	}
	return " " + s
}

// checkRoles warns about roles that own source objects but do not exist on the
// target: restoring the schema would fail on ALTER ... OWNER TO.
func checkRoles(in Input) []preflight.Finding {
	src, tgt := in.Source.Server, in.Target.Server
	if src == nil || tgt == nil {
		return nil
	}
	owners := map[string][]string{}
	for _, d := range src.Databases {
		for _, o := range d.Owners {
			owners[o] = append(owners[o], d.Name)
		}
		if d.Owner != "" && !strings.HasPrefix(d.Owner, "pg_") {
			owners[d.Owner] = append(owners[d.Owner], d.Name+" (database owner)")
		}
	}
	var missing []string
	for o := range owners {
		if !tgt.HasRole(o) {
			missing = append(missing, o)
		}
	}
	sort.Strings(missing)
	if len(missing) == 0 {
		return []preflight.Finding{finding("roles.owners", areaRoles, preflight.OK,
			"every role that owns objects in the migrated databases exists on the target", "")}
	}
	var stmts []string
	for i, m := range missing {
		if i == 3 {
			break
		}
		stmts = append(stmts, fmt.Sprintf("CREATE ROLE %s NOLOGIN;", inventory.QuoteIdent(m)))
	}
	detail := make([]string, 0, len(missing))
	for _, m := range missing {
		detail = append(detail, fmt.Sprintf("%s (owns objects in %s)", m, strings.Join(dedupe(owners[m]), ", ")))
	}
	note := ""
	if tgt.RolesTotal > len(tgt.Roles) {
		note = " The target has more roles than were listed, so some of these may exist after all."
	}
	return []preflight.Finding{finding("roles.owners", areaRoles, preflight.Warn,
		fmt.Sprintf("%s that own source objects do not exist on the target: %s.%s", plural(len(missing), "role"), nameList(detail, maxNamesPerMessage), note),
		"Create the roles on the target before the schema is restored, for example: "+strings.Join(stmts, " ")+
			" (use LOGIN and a password only if applications connect as them; passwords of source roles cannot be read from RDS, so set new ones). The bulk copy tool can also copy role definitions (ADR 0002); whether that works against RDS has not been verified.")}
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
