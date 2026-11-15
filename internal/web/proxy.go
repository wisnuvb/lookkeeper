package web

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ProxyPolicy says which peers are trusted reverse proxies, and therefore whose X-Forwarded-* headers
// may be believed.
//
// Why it exists (independent review, finding 8): behind a TLS-terminating proxy the server sees plain
// HTTP from 127.0.0.1. Without this policy it would (1) hand out the non-Secure session cookie on an
// HTTPS site, (2) send no HSTS, and (3) see every client as 127.0.0.1, so one attacker could lock out
// every user through the per-address limiter. Believing X-Forwarded-For from anyone would instead let
// any client choose its own address. The rule: the headers count ONLY when the TCP peer is in
// TrustedProxies, and then the client is the rightmost address that is not itself a trusted proxy.
type ProxyPolicy struct {
	// TrustedProxies are the peer addresses allowed to set X-Forwarded-For / X-Forwarded-Proto,
	// for example 127.0.0.1/32 for a proxy on the same host.
	TrustedProxies []netip.Prefix
	// AssumeHTTPS declares that a TLS-terminating proxy is in front: a request from a trusted proxy is
	// treated as HTTPS even without X-Forwarded-Proto. It has no effect for any other peer.
	AssumeHTTPS bool
}

// ParseProxyList turns configuration strings ("127.0.0.1", "10.0.0.0/8", "::1") into prefixes.
func ParseProxyList(items []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(items))
	for _, it := range items {
		it = strings.TrimSpace(it)
		if p, err := netip.ParsePrefix(it); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(it)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q is not an address or a CIDR range", it)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

func (p ProxyPolicy) trusted(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	for _, pre := range p.TrustedProxies {
		if pre.Contains(a) {
			return true
		}
	}
	return false
}

func peerAddr(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

// ClientIP is the address the request really came from. It returns the zero Addr only if even the TCP
// peer address cannot be parsed.
func (p ProxyPolicy) ClientIP(r *http.Request) netip.Addr {
	peer, ok := peerAddr(r)
	if !ok {
		return netip.Addr{}
	}
	if !p.trusted(peer) {
		return peer // X-Forwarded-For from anyone else is attacker-controlled: ignore it
	}
	xff := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	if xff == "" {
		return peer
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			return peer // a malformed entry: do not guess, fall back to the proxy's own address
		}
		a = a.Unmap().WithZone("")
		if !p.trusted(a) {
			return a
		}
	}
	return peer
}

// IsHTTPS reports whether the client's connection is HTTPS: TLS terminates here, or a trusted proxy
// says it terminated TLS. It decides the cookie's Secure flag and name, and the Origin scheme check.
func (p ProxyPolicy) IsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	peer, ok := peerAddr(r)
	if !ok || !p.trusted(peer) {
		return false
	}
	if p.AssumeHTTPS {
		return true
	}
	vals := r.Header.Values("X-Forwarded-Proto")
	if len(vals) == 0 {
		return false
	}
	last := vals[len(vals)-1]
	if i := strings.LastIndex(last, ","); i >= 0 {
		last = last[i+1:]
	}
	return strings.EqualFold(strings.TrimSpace(last), "https")
}
