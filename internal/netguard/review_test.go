package netguard

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// Regression tests for the independent security review of 2026-11-15 (finding 5 and 13).

// Metadata endpoints and IPv6 transition ranges outside 169.254.0.0/16. Each is refused even when
// the operator opens loopback and private space AND allowlists the whole range.
func TestMetadataAndTransitionRangesAreNeverAllowed(t *testing.T) {
	everything := Policy{AllowLoopback: true, AllowPrivate: true, Allowlist: []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
	}}
	for _, a := range []string{
		"168.63.129.16",                            // Azure WireServer
		"100.100.100.200",                          // Alibaba metadata, inside CGNAT
		"192.0.0.192",                              // legacy Oracle metadata
		"192.0.0.1",                                // 192.0.0.0/24
		"::127.0.0.1",                              // IPv4-compatible loopback
		"::169.254.169.254",                        // IPv4-compatible metadata
		"::ffff:0:169.254.169.254",                 // SIIT metadata
		"2001:0:4136:e378:8000:63bf:3fff:fdd2",     // Teredo
		"64:ff9b:1::a9fe:a9fe",                     // local-use NAT64 metadata
		"fec0::1",                                  // site-local
		"192.0.2.1", "198.51.100.7", "203.0.113.9", // documentation
		"198.18.0.1", "198.19.255.255", // benchmarking
	} {
		for name, p := range map[string]Policy{"strict": {}, "everything opened": everything} {
			if err := p.CheckIP(netip.MustParseAddr(a)); !errors.Is(err, ErrRefused) {
				t.Errorf("%s must be refused under the %s policy, got %v", a, name, err)
			}
		}
	}
	// ::1 lives inside the deprecated ::/96 block; it must still behave as loopback.
	if err := (Policy{AllowLoopback: true}).CheckIP(netip.MustParseAddr("::1")); err != nil {
		t.Errorf("::1 must be allowed when loopback is opted in: %v", err)
	}
	if err := (Policy{}).CheckIP(netip.MustParseAddr("::1")); !errors.Is(err, ErrRefused) {
		t.Errorf("::1 must be refused by default: %v", err)
	}
	// Only the Alibaba metadata address is carved out of CGNAT: its neighbours stay governed by AllowPrivate.
	if err := (Policy{AllowPrivate: true}).CheckIP(netip.MustParseAddr("100.100.100.199")); err != nil {
		t.Errorf("100.100.100.199 is CGNAT and must be allowed once private space is opened: %v", err)
	}
	if err := (Policy{}).CheckIP(netip.MustParseAddr("100.100.100.199")); !errors.Is(err, ErrRefused) {
		t.Errorf("100.100.100.199 is CGNAT and must be refused by default: %v", err)
	}
	// Ordinary public addresses next to the new ranges are unaffected.
	for _, a := range []string{"168.63.129.15", "168.63.129.17", "198.20.0.1", "192.0.1.1", "93.184.216.34", "2606:2800:220:1::1"} {
		if err := (Policy{}).CheckIP(netip.MustParseAddr(a)); err != nil {
			t.Errorf("%s is an ordinary public address and must stay allowed: %v", a, err)
		}
	}
}

// A refusal must not teach the caller anything about the internal network: no address in the text, and
// the same shape whether the target was a literal or a name. The detail is for the server log.
func TestRefusalsAreGenericButLoggable(t *testing.T) {
	r := fakeResolver{"internal.corp": {netip.MustParseAddr("10.1.2.3")}}
	cases := []struct {
		name string
		err  error
		ip   string
	}{
		{"literal private", mustErr(Policy{}.Resolve(context.Background(), nil, "10.1.2.3", 5432)), "10.1.2.3"},
		{"name resolving to private", mustErr(Policy{}.Resolve(context.Background(), r, "internal.corp", 5432)), "10.1.2.3"},
		{"metadata", mustErr(Policy{}.Resolve(context.Background(), nil, "169.254.169.254", 5432)), "169.254.169.254"},
		{"wrapped metadata", mustErr(Policy{}.Resolve(context.Background(), nil, "::ffff:169.254.169.254", 5432)), ""},
		{"loopback", mustErr(Policy{}.Resolve(context.Background(), nil, "127.0.0.1", 5432)), "127.0.0.1"},
	}
	for _, c := range cases {
		if !errors.Is(c.err, ErrRefused) {
			t.Fatalf("%s: want ErrRefused, got %v", c.name, c.err)
		}
		msg := c.err.Error()
		for _, leak := range []string{"10.1.2.3", "169.254", "127.0.0.1", "internal.corp", "::ffff"} {
			if strings.Contains(msg, leak) {
				t.Errorf("%s: message %q leaks %q", c.name, msg, leak)
			}
		}
		var re *RefusedError
		if !errors.As(c.err, &re) || re.Reason == "" {
			t.Fatalf("%s: the detail must be reachable for logging: %v", c.name, c.err)
		}
		if c.ip != "" && re.Addr.String() != c.ip {
			t.Errorf("%s: the log detail should carry the address %s, got %s", c.name, c.ip, re.Addr)
		}
	}
}

func mustErr(_ []netip.Addr, err error) error { return err }
