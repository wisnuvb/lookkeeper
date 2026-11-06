package pg

import (
	"fmt"
	"strings"

	"github.com/wisnuvb/lockkeeper/internal/alert/rules"
	"github.com/wisnuvb/lockkeeper/internal/inventory"
	"github.com/wisnuvb/lockkeeper/internal/preflight"
)

// Areas group findings in the report.
const (
	areaConnectivity   = "connectivity"
	areaVersions       = "versions"
	areaSourceParams   = "source-params"
	areaSourcePrivs    = "source-privileges"
	areaSlots          = "slots"
	areaTables         = "tables"
	areaExtensions     = "extensions"
	areaLocale         = "locale"
	areaRoles          = "roles"
	areaData           = "data"
	areaSchemaFreeze   = "schema-freeze"
	areaTargetParams   = "target-params"
	areaTargetPrivs    = "target-privileges"
	areaTargetLogging  = "target-logging"
	areaTargetState    = "target-state"
	areaNetwork        = "network"
	areaInspection     = "inspection"
	maxNamesPerMessage = 8
)

func finding(id, area string, sev preflight.Severity, msg, remediation string) preflight.Finding {
	return preflight.Finding{ID: id, Area: area, Severity: sev, Message: msg, Remediation: remediation}
}

func bytesStr(n int64) string { return rules.FormatBytes(float64(n)) }

// nameList joins names, showing at most max and counting the rest.
func nameList(names []string, max int) string {
	if len(names) <= max {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:max], ", "), len(names)-max)
}

// tableList renders tables with their sizes. total is the real count, which may
// exceed len(items) because the inventory caps its lists.
func tableList(items []inventory.Table, total int) string {
	parts := make([]string, 0, maxNamesPerMessage)
	for i, t := range items {
		if i == maxNamesPerMessage {
			break
		}
		if t.TotalBytes > 0 {
			parts = append(parts, fmt.Sprintf("%s.%s (%s)", t.Schema, t.Name, bytesStr(t.TotalBytes)))
		} else {
			parts = append(parts, t.Schema+"."+t.Name)
		}
	}
	s := strings.Join(parts, ", ")
	if rest := total - len(parts); rest > 0 {
		s += fmt.Sprintf(" and %d more", rest)
	}
	return s
}

// plural returns "1 table" or "2 tables".
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// pluralIs returns "1 table is" or "2 tables are".
func pluralIs(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s is", noun)
	}
	return fmt.Sprintf("%d %ss are", n, noun)
}

// capacity reports how many of a limited resource are still free and whether
// need more can be taken. A limit below used (for example after the limit was
// lowered) leaves nothing free.
func capacity(limit, used, need int64) (free int64, ok bool) {
	free = limit - used
	if free < 0 {
		free = 0
	}
	return free, free >= need
}

// sourceChangeNote ends remediation text that changes the source.
const sourceChangeNote = "This changes the SOURCE database. Lockkeeper's pre-flight never does it; the migration will ask for explicit confirmation (plan hash) before any source change."
