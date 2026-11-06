package config

import (
	"strings"
	"testing"
)

func withMetrics(block string) string {
	return strings.Replace(validYAML, "monitor:\n  interval: 30s", "monitor:\n  interval: 30s\n"+block, 1)
}

func TestMetricsIsOffByDefault(t *testing.T) {
	cfg, _, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Monitor.Metrics != nil {
		t.Fatalf("the Prometheus endpoint must be off unless configured: %+v", cfg.Monitor.Metrics)
	}
}

func TestMetricsBlockDefaultsToLoopback(t *testing.T) {
	for _, block := range []string{"  metrics: {}", "  metrics: { allow_non_loopback: false }"} {
		cfg, warnings, err := Parse([]byte(withMetrics(block)))
		if err != nil {
			t.Fatalf("%s: %v", block, err)
		}
		if cfg.Monitor.Metrics == nil || cfg.Monitor.Metrics.Listen != "127.0.0.1:9187" {
			t.Errorf("%s: listen default = %+v", block, cfg.Monitor.Metrics)
		}
		if len(warnings) != 0 {
			t.Errorf("%s: loopback must not warn: %v", block, warnings)
		}
	}
}

func TestMetricsListenValidation(t *testing.T) {
	cases := []struct {
		name        string
		block       string
		wantErr     string
		wantWarning bool
	}{
		{"ipv4 loopback", `  metrics: { listen: "127.0.0.1:9187" }`, "", false},
		{"other loopback address", `  metrics: { listen: "127.0.0.2:9100" }`, "", false},
		{"ipv6 loopback", `  metrics: { listen: "[::1]:9187" }`, "", false},
		{"localhost", `  metrics: { listen: "localhost:9187" }`, "", false},
		{"all interfaces refused", `  metrics: { listen: "0.0.0.0:9187" }`, "not a loopback address", false},
		{"empty host refused", `  metrics: { listen: ":9187" }`, "not a loopback address", false},
		{"lan address refused", `  metrics: { listen: "10.0.0.5:9187" }`, "allow_non_loopback", false},
		{"hostname refused (never resolved)", `  metrics: { listen: "metrics.example.com:9187" }`, "not a loopback address", false},
		{"non-loopback allowed with a warning", `  metrics: { listen: "0.0.0.0:9187", allow_non_loopback: true }`, "", true},
		{"missing port", `  metrics: { listen: "127.0.0.1" }`, "host:port", false},
		{"port zero", `  metrics: { listen: "127.0.0.1:0" }`, "port must be 1-65535", false},
		{"port too big", `  metrics: { listen: "127.0.0.1:70000" }`, "port must be 1-65535", false},
		{"port not numeric", `  metrics: { listen: "127.0.0.1:http" }`, "port must be 1-65535", false},
		{"unix path is not a listen address", `  metrics: { listen: "/run/lk.sock:1" }`, "not a loopback address", false},
		{"unknown key", `  metrics: { listen: "127.0.0.1:9187", token: abc }`, "token", false},
	}
	for _, c := range cases {
		_, warnings, err := Parse([]byte(withMetrics(c.block)))
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%s: want error containing %q, got %v", c.name, c.wantErr, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
			continue
		}
		warned := false
		for _, w := range warnings {
			if strings.Contains(w, "monitor.metrics") && strings.Contains(w, "no authentication") {
				warned = true
			}
		}
		if warned != c.wantWarning {
			t.Errorf("%s: warning present = %v, want %v (%v)", c.name, warned, c.wantWarning, warnings)
		}
	}
}
