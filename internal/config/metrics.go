package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// DefaultMetricsListen is used when `monitor.metrics` is present without `listen`.
const DefaultMetricsListen = "127.0.0.1:9187"

// Metrics configures the optional Prometheus endpoint. The endpoint is OFF unless
// the `monitor.metrics` block is present. It has no authentication and its labels
// can contain table names, so it listens on loopback unless the operator opts in.
type Metrics struct {
	// Listen is the host:port to serve /metrics on. Default 127.0.0.1:9187.
	Listen string `yaml:"listen"`
	// AllowNonLoopback must be true to listen on anything but a loopback address.
	AllowNonLoopback bool `yaml:"allow_non_loopback"`
}

// CheckMetricsListen validates a listen address. It returns a warning when the
// address is not loopback but the operator allowed it, and an error when the
// address is malformed or non-loopback without allowNonLoopback.
//
// Host names other than "localhost" are never resolved (resolving would contact a
// DNS server and the answer can change), so they count as non-loopback. An empty
// host (":9187") means all interfaces and is therefore non-loopback too.
func CheckMetricsListen(listen string, allowNonLoopback bool) (warning string, err error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("must be host:port, such as %s (%v)", DefaultMetricsListen, err)
	}
	if n, perr := strconv.Atoi(port); perr != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("port must be 1-65535 (got %q)", port)
	}
	if isLoopbackListenHost(host) {
		return "", nil
	}
	if !allowNonLoopback {
		return "", fmt.Errorf("%q is not a loopback address; the endpoint has no authentication and its labels can contain table names, so it is refused unless allow_non_loopback: true", listen)
	}
	return fmt.Sprintf("the Prometheus endpoint listens on %q, which is not loopback: it has no authentication and its labels can contain table names; restrict access with a firewall or a reverse proxy", listen), nil
}

func isLoopbackListenHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
