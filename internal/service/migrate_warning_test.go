package service

import (
	"strings"
	"testing"
)

func TestSlotWarningIsLoudAndNamesTheCommands(t *testing.T) {
	msg := formatSlotWarning("m1a2b3c4d", []slotRow{
		{Database: "app", Slot: "lk_m1a2b3c4d_d1_a1", Retained: 3 << 20, Known: true},
		{Database: "billing", Slot: "lk_m1a2b3c4d_d2_a1"},
	}, false)
	for _, want := range []string{
		"WARNING", "KEEP RETAINING WAL", "also while nothing is running", "2 replication slot(s)",
		"lk_m1a2b3c4d_d1_a1 (database app) retains 3.0 MiB", "lk_m1a2b3c4d_d2_a1 (database billing)",
		"Nothing drops them automatically",
		"lockkeeper migrate status --migration m1a2b3c4d",
		"lockkeeper migrate abort --migration m1a2b3c4d", "lockkeeper migrate cleanup --migration m1a2b3c4d",
		"wal-slot-full.md",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("warning lacks %q:\n%s", want, msg)
		}
	}
	if got := formatSlotWarning("m1", nil, false); got != "" {
		t.Fatalf("no slot, no warning: %q", got)
	}
	if got := formatSlotWarning("m1", nil, true); !strings.Contains(got, "could not check") || !strings.Contains(got, "migrate status --migration m1") {
		t.Fatalf("an unreadable source must be said, not hidden: %q", got)
	}
}
