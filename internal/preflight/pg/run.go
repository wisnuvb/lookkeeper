package pg

import (
	"fmt"

	"github.com/wisnuvb/lockkeeper/internal/preflight"
)

// Engine is the value of Report.Engine for these checks.
const Engine = "postgres"

// Run executes every check on in and returns the report. It is pure: it performs
// no I/O, so every decision can be tested with canned inventories. Checks that
// need a server that could not be reached are skipped, and the report says so.
func Run(in Input) *preflight.Report {
	var fs []preflight.Finding
	add := func(f []preflight.Finding) { fs = append(fs, f...) }

	add(checkConnectivity("source", in.Source))
	add(checkConnectivity("target", in.Target))
	add(checkVersions(in))

	add(checkInspection("source", in.Source))
	add(checkInspection("target", in.Target))

	add(checkWALLevel(in))
	add(checkRDSNote(in))
	add(checkSlotHeadroom(in))
	add(checkSenderHeadroom(in))
	add(checkWALSenderTimeout(in))
	add(checkSlotWALKeep(in))
	add(checkSourcePrivileges(in))
	add(checkSlots(in))
	add(checkSourceTables(in))
	add(checkSchemaFreeze(in))

	add(checkExtensions(in))
	add(checkPreload(in))
	add(checkLocale(in))
	add(checkRoles(in))

	add(checkTargetSubscribe(in))
	add(checkTargetWorkers(in))
	add(checkTargetLogging(in))
	add(checkTargetEmpty(in))
	add(checkSizes(in))
	add(checkTargetToSource(in))

	if !in.Source.Reachable() || !in.Target.Reachable() {
		var down []string
		if !in.Source.Reachable() {
			down = append(down, "the source")
		}
		if !in.Target.Reachable() {
			down = append(down, "the target")
		}
		fs = append(fs, finding("run.incomplete", areaConnectivity, preflight.Info,
			fmt.Sprintf("checks that need %s were skipped because it could not be reached; the report is incomplete", joinAnd(down)),
			"Fix the connection problem above and run the pre-flight again."))
	}
	return preflight.NewReport(Engine, in.Source.Name, in.Target.Name, in.databases(), fs)
}

func joinAnd(parts []string) string {
	if len(parts) == 2 {
		return parts[0] + " and " + parts[1]
	}
	return parts[0]
}
