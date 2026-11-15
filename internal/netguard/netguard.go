// Package netguard stops the server from being used as a proxy into networks it should not reach.
//
// Threat T21 (SPEC section 12): whoever can create or test a connection in the web UI makes the
// Lockkeeper process open a TCP connection to a host and port of their choosing. Without a guard that
// is a port scanner for the internal network and a way to read cloud instance-metadata credentials.
//
// The rules, from strictest to loosest:
//
//  1. Some addresses are NEVER allowed, whatever the policy says: link-local (169.254.0.0/16,
//     fe80::/10, which includes the cloud metadata address 169.254.169.254), the IPv6 metadata range
//     fd00:ec2::/32, the unspecified address, multicast and broadcast.
//  2. Loopback and private (RFC 1918, unique-local, carrier-grade NAT) addresses are refused unless
//     the operator opted in, either with AllowLoopback / AllowPrivate or with an explicit Allowlist
//     prefix. A self-hosted deployment that monitors databases on its own LAN opts in on purpose.
//  3. An IPv4 address hidden inside an IPv6 one (IPv4-mapped ::ffff:a.b.c.d, NAT64 64:ff9b::/96,
//     6to4 2002::/16) is judged by the IPv4 address it carries, so 169.254.169.254 cannot be smuggled
//     in as ::ffff:169.254.169.254.
//  4. The check is made twice: on every address a host name resolves to (any bad answer rejects the
//     whole name), AND again on the address the socket is really connecting to (Control hook). The
//     second check defeats DNS rebinding, where a name resolves to a harmless address at check time
//     and to an internal one at connect time.
//
// This package decides; it does not know about databases. dbconn wires Policy.Dialer into every
// connection the web layer opens.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// ErrRefused is wrapped by every refusal so callers can map it to one API error code
// ("refused-address") without parsing messages.
var ErrRefused = errors.New("address not allowed")

// Policy is the operator's decision about which targets the server may connect to.
// The zero value is the safest: public addresses only.
type Policy struct {
	// AllowLoopback permits 127.0.0.0/8 and ::1.
	AllowLoopback bool
	// AllowPrivate permits RFC 1918, 100.64.0.0/10 and fc00::/7.
	AllowPrivate bool
	// Allowlist permits specific prefixes even when they are loopback or private. It never overrides
	// the always-refused ranges.
	Allowlist []netip.Prefix
}

// Resolver is the subset of net.Resolver that is needed; tests inject a fake.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

var neverAllowed = mustPrefixes(
	"0.0.0.0/8",      // "this network", includes 0.0.0.0
	"169.254.0.0/16", // IPv4 link-local, includes the cloud metadata address
	"224.0.0.0/4",    // multicast
	"240.0.0.0/4",    // reserved, includes 255.255.255.255
	"fe80::/10",      // IPv6 link-local
	"fd00:ec2::/32",  // AWS IPv6 metadata range
	"ff00::/8",       // IPv6 multicast
	"::/128",         // unspecified
)

var privateRanges = mustPrefixes(
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC 1918
	"100.64.0.0/10", // carrier-grade NAT, also used by some clouds internally
	"fc00::/7",      // IPv6 unique local
)

var (
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour = netip.MustParsePrefix("2002::/16")
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func inAny(ip netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// embeddedV4 returns the IPv4 address carried inside an IPv6 address, if any.
func embeddedV4(ip netip.Addr) (netip.Addr, bool) {
	if !ip.Is6() {
		return netip.Addr{}, false
	}
	b := ip.As16()
	switch {
	case nat64.Contains(ip):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(ip):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}

// CheckIP reports whether the policy lets the server connect to ip.
func (p Policy) CheckIP(ip netip.Addr) error {
	if !ip.IsValid() {
		return fmt.Errorf("%w: invalid address", ErrRefused)
	}
	ip = ip.WithZone("") // a zone ("fe80::1%eth0") must not change the verdict
	if ip.Is4In6() {
		ip = ip.Unmap() // ::ffff:a.b.c.d is judged as a.b.c.d
	}
	if inner, ok := embeddedV4(ip); ok {
		if err := p.CheckIP(inner); err != nil {
			return fmt.Errorf("%w: %s carries %s", ErrRefused, ip, inner)
		}
	}
	if inAny(ip, neverAllowed) {
		return fmt.Errorf("%w: %s is link-local, multicast, reserved or a cloud metadata address and is never allowed", ErrRefused, ip)
	}
	if inAny(ip, p.Allowlist) {
		return nil
	}
	if ip.IsLoopback() && !p.AllowLoopback {
		return fmt.Errorf("%w: %s is a loopback address; allow it explicitly if this is intended", ErrRefused, ip)
	}
	if !ip.IsLoopback() && (ip.IsPrivate() || inAny(ip, privateRanges)) && !p.AllowPrivate {
		return fmt.Errorf("%w: %s is a private address; allow it explicitly if this is intended", ErrRefused, ip)
	}
	return nil
}

// CheckPort rejects ports that cannot be a database listener.
func CheckPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%w: port %d is out of range", ErrRefused, port)
	}
	return nil
}

// Resolve checks port and host and returns every address the host resolves to. A literal address is
// not resolved. If ANY answer is refused the whole name is refused, because an attacker who controls
// DNS can return one harmless and one internal address and hope the dialer picks the second.
func (p Policy) Resolve(ctx context.Context, r Resolver, host string, port int) ([]netip.Addr, error) {
	if err := CheckPort(port); err != nil {
		return nil, err
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return nil, fmt.Errorf("%w: empty host", ErrRefused)
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		if r == nil {
			r = net.DefaultResolver
		}
		var rerr error
		addrs, rerr = r.LookupNetIP(ctx, "ip", host)
		if rerr != nil {
			// The resolver error can name internal DNS servers; keep the message generic.
			return nil, fmt.Errorf("could not resolve host %q", host)
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("could not resolve host %q", host)
		}
	}
	for _, a := range addrs {
		if err := p.CheckIP(a); err != nil {
			return nil, err
		}
	}
	return addrs, nil
}

// control is a net.Dialer.Control hook: it runs after name resolution, with the real destination
// address, immediately before connect(2). This is the DNS-rebinding defence.
func (p Policy) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: cannot parse destination %q", ErrRefused, address)
	}
	if err := CheckPort(int(ap.Port())); err != nil {
		return err
	}
	return p.CheckIP(ap.Addr())
}

// Dialer returns a dialer that enforces the policy on the address it actually connects to.
func (p Policy) Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second, Control: p.control}
}

// DialContext is Dialer(timeout).DialContext, for drivers that take a dial function.
func (p Policy) DialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := p.Dialer(timeout)
	return d.DialContext
}
