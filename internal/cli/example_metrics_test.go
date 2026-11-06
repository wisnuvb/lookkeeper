package cli

import (
	"strings"
	"testing"

	"github.com/wisnuvb/lockkeeper/internal/config"
)

// The commented Prometheus block in the example must be valid once uncommented,
// and must be off in the example as shipped.
func TestExampleMetricsBlockIsValidWhenUncommented(t *testing.T) {
	cfg, _, err := config.Parse([]byte(ExampleConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Monitor.Metrics != nil {
		t.Fatal("the example config must ship with the Prometheus endpoint off")
	}

	lines := strings.Split(ExampleConfig, "\n")
	for i, l := range lines {
		switch strings.TrimSpace(l) {
		case "# metrics:", "#   listen: 127.0.0.1:9187", "#   allow_non_loopback: false":
			lines[i] = strings.Replace(l, "# ", "", 1)
		}
	}
	cfg, warnings, err := config.Parse([]byte(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatalf("uncommented metrics block is invalid: %v", err)
	}
	if cfg.Monitor.Metrics == nil || cfg.Monitor.Metrics.Listen != "127.0.0.1:9187" || cfg.Monitor.Metrics.AllowNonLoopback {
		t.Errorf("metrics block not parsed as documented: %+v", cfg.Monitor.Metrics)
	}
	for _, w := range warnings {
		if strings.Contains(w, "metrics") {
			t.Errorf("the documented loopback default must not warn: %s", w)
		}
	}
}
