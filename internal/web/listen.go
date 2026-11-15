// Package web is the HTTP server of `lockkeeper serve` (ADR 0005 item 3, ADR 0006).
//
// It holds production database credentials and can change source servers, so the defaults are the
// strict ones: loopback only, a Host allow-list against DNS rebinding, a strict CSP with no inline
// script and no third-party origin, bounded request bodies and timeouts, and a panic never reaches the
// client with a stack trace. Business logic does not live here: handlers are thin and call the service
// layer; authentication and authorisation are enforced by middleware that the API routes sit behind.
package web

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// CheckListen validates the address the server binds to.
//
// Loopback (127.0.0.0/8, ::1, "localhost") is always allowed. Anything else, including a wildcard
// (":8443", "0.0.0.0", "[::]") and any host name other than localhost (never resolved: DNS can change
// under us), is refused unless ALL of these hold: the operator opted in (allowNonLoopback), TLS is
// configured, and authentication is enabled. Exposing the server directly to the internet remains
// unsupported (use an SSH tunnel, a VPN or a TLS reverse proxy).
func CheckListen(listen string, tlsConfigured, authEnabled, allowNonLoopback bool) (warning string, err error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("listen address must be host:port, such as 127.0.0.1:8443 (%v)", err)
	}
	if n, perr := strconv.Atoi(port); perr != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("listen port must be 1-65535 (got %q)", port)
	}
	if IsLoopbackHost(host) {
		return "", nil
	}
	switch {
	case !allowNonLoopback:
		return "", fmt.Errorf("%q is not a loopback address: refused unless web.allow_non_loopback is true, TLS is configured and authentication is enabled", listen)
	case !tlsConfigured:
		return "", fmt.Errorf("%q is not a loopback address: TLS (certificate and key) is required before the server may listen there", listen)
	case !authEnabled:
		return "", fmt.Errorf("%q is not a loopback address: authentication must be enabled before the server may listen there", listen)
	}
	return fmt.Sprintf("the web server listens on %q, which is not loopback. It holds database credentials: do not expose it directly to the internet; prefer an SSH tunnel, a VPN or a TLS reverse proxy with its own access control", listen), nil
}

// IsLoopbackHost reports whether a bind host is loopback. Host names are not resolved.
func IsLoopbackHost(host string) bool {
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}
