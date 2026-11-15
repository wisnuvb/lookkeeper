package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestCheckIP(t *testing.T) {
	loop := Policy{AllowLoopback: true}
	priv := Policy{AllowPrivate: true}
	both := Policy{AllowLoopback: true, AllowPrivate: true}
	allowNet := Policy{Allowlist: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}}
	everything := Policy{AllowLoopback: true, AllowPrivate: true, Allowlist: []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("0.0.0.0/0")}}

	cases := []struct {
		name string
		p    Policy
		addr string
		ok   bool
	}{
		// Public addresses are fine under the zero policy.
		{"public v4", Policy{}, "93.184.216.34", true},
		{"public v6", Policy{}, "2606:2800:220:1:248:1893:25c8:1946", true},

		// Loopback and private need an opt-in.
		{"loopback default", Policy{}, "127.0.0.1", false},
		{"loopback v6 default", Policy{}, "::1", false},
		{"loopback opted in", loop, "127.0.0.1", true},
		{"loopback opt-in does not open private", loop, "10.0.0.5", false},
		{"rfc1918 10/8 default", Policy{}, "10.0.0.5", false},
		{"rfc1918 172.16/12 default", Policy{}, "172.31.255.254", false},
		{"rfc1918 192.168/16 default", Policy{}, "192.168.1.10", false},
		{"cgnat default", Policy{}, "100.64.0.1", false},
		{"ula default", Policy{}, "fd12:3456::1", false},
		{"private opted in", priv, "10.0.0.5", true},
		{"cgnat opted in", priv, "100.100.1.1", true},
		{"ula opted in", priv, "fd12:3456::1", true},
		{"private opt-in does not open loopback", priv, "127.0.0.1", false},
		{"allowlist prefix", allowNet, "10.20.30.40", true},
		{"allowlist does not open the rest of 10/8", allowNet, "10.21.0.1", false},
		{"172.15 is public, not rfc1918", Policy{}, "172.15.0.1", true},
		{"172.32 is public, not rfc1918", Policy{}, "172.32.0.1", true},

		// Never allowed, whatever the policy and even if explicitly allowlisted.
		{"metadata v4", Policy{}, "169.254.169.254", false},
		{"metadata v4 with everything opted in", everything, "169.254.169.254", false},
		{"link-local v4", both, "169.254.1.1", false},
		{"link-local v6", both, "fe80::1", false},
		{"aws v6 metadata", both, "fd00:ec2::254", false},
		{"unspecified v4", both, "0.0.0.0", false},
		{"0/8", both, "0.1.2.3", false},
		{"unspecified v6", both, "::", false},
		{"multicast v4", both, "224.0.0.1", false},
		{"multicast v6", both, "ff02::1", false},
		{"broadcast", both, "255.255.255.255", false},
		{"reserved 240/4", both, "240.0.0.1", false},

		// Smuggling an IPv4 address inside an IPv6 one.
		{"v4-mapped metadata", Policy{}, "::ffff:169.254.169.254", false},
		{"v4-mapped metadata with opt-ins", both, "::ffff:169.254.169.254", false},
		{"v4-mapped loopback judged as loopback", Policy{}, "::ffff:127.0.0.1", false},
		{"v4-mapped loopback opted in", loop, "::ffff:127.0.0.1", true},
		{"v4-mapped private judged as private", Policy{}, "::ffff:10.0.0.1", false},
		{"v4-mapped public ok", Policy{}, "::ffff:93.184.216.34", true},
		{"nat64 metadata", both, "64:ff9b::a9fe:a9fe", false},
		{"nat64 public ok", Policy{}, "64:ff9b::5db8:d822", true},
		{"nat64 private refused by default", Policy{}, "64:ff9b::a00:1", false},
		{"6to4 metadata", both, "2002:a9fe:a9fe::1", false},
		{"6to4 loopback refused by default", Policy{}, "2002:7f00:1::1", false},

		// A zone id must not change the verdict.
		{"zoned link-local", both, "fe80::1%eth0", false},
		{"zoned loopback default", Policy{}, "::1%lo", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.p.CheckIP(ip(c.addr))
			if c.ok && err != nil {
				t.Fatalf("want allowed, got %v", err)
			}
			if !c.ok {
				if err == nil {
					t.Fatalf("want refused, got allowed")
				}
				if !errors.Is(err, ErrRefused) {
					t.Fatalf("refusal must wrap ErrRefused, got %v", err)
				}
			}
		})
	}
	if err := (Policy{}).CheckIP(netip.Addr{}); !errors.Is(err, ErrRefused) {
		t.Fatalf("zero Addr must be refused, got %v", err)
	}
}

func TestCheckPort(t *testing.T) {
	for _, p := range []int{0, -1, 65536, 100000} {
		if err := CheckPort(p); !errors.Is(err, ErrRefused) {
			t.Errorf("port %d must be refused", p)
		}
	}
	for _, p := range []int{1, 5432, 3306, 65535} {
		if err := CheckPort(p); err != nil {
			t.Errorf("port %d must be allowed: %v", p, err)
		}
	}
}

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	a, ok := f[host]
	if !ok {
		return nil, errors.New("lookup failed for secret-internal-dns.corp:53")
	}
	return a, nil
}

func TestResolve(t *testing.T) {
	r := fakeResolver{
		"db.example.com":   {ip("93.184.216.34")},
		"mixed.evil.test":  {ip("93.184.216.34"), ip("169.254.169.254")},
		"internal.corp":    {ip("10.1.2.3")},
		"empty.test":       {},
		"v6.example.com":   {ip("2606:2800:220:1::1")},
		"mapped.evil.test": {ip("::ffff:169.254.169.254")},
	}
	ctx := context.Background()

	if _, err := (Policy{}).Resolve(ctx, r, "db.example.com", 5432); err != nil {
		t.Fatalf("public name: %v", err)
	}
	if _, err := (Policy{}).Resolve(ctx, r, "v6.example.com", 5432); err != nil {
		t.Fatalf("public v6 name: %v", err)
	}
	// ANY refused answer rejects the name.
	if _, err := (Policy{AllowPrivate: true, AllowLoopback: true}).Resolve(ctx, r, "mixed.evil.test", 5432); !errors.Is(err, ErrRefused) {
		t.Fatalf("mixed answers must be refused, got %v", err)
	}
	if _, err := (Policy{AllowPrivate: true}).Resolve(ctx, r, "mapped.evil.test", 5432); !errors.Is(err, ErrRefused) {
		t.Fatalf("v4-mapped metadata via DNS must be refused, got %v", err)
	}
	if _, err := (Policy{}).Resolve(ctx, r, "internal.corp", 5432); !errors.Is(err, ErrRefused) {
		t.Fatalf("private name by default: %v", err)
	}
	if _, err := (Policy{AllowPrivate: true}).Resolve(ctx, r, "internal.corp", 5432); err != nil {
		t.Fatalf("private name when allowed: %v", err)
	}
	// Literals are checked without DNS; brackets are tolerated.
	if _, err := (Policy{}).Resolve(ctx, nil, "169.254.169.254", 5432); !errors.Is(err, ErrRefused) {
		t.Fatalf("literal metadata: %v", err)
	}
	if _, err := (Policy{}).Resolve(ctx, nil, "[::1]", 5432); !errors.Is(err, ErrRefused) {
		t.Fatalf("bracketed literal loopback: %v", err)
	}
	// Bad port, empty host, unresolvable and empty answers.
	if _, err := (Policy{}).Resolve(ctx, r, "db.example.com", 0); !errors.Is(err, ErrRefused) {
		t.Fatalf("port 0: %v", err)
	}
	if _, err := (Policy{}).Resolve(ctx, r, "  ", 5432); !errors.Is(err, ErrRefused) {
		t.Fatalf("empty host: %v", err)
	}
	for _, h := range []string{"nope.test", "empty.test"} {
		_, err := (Policy{}).Resolve(ctx, r, h, 5432)
		if err == nil {
			t.Fatalf("%s must fail", h)
		}
		// The resolver's own error text (it can name internal DNS servers) must not leak.
		if got := err.Error(); strings.Contains(got, "secret-internal-dns") {
			t.Fatalf("resolver detail leaked: %q", got)
		}
	}
}

// The Control hook is what defeats DNS rebinding: it sees the address actually being connected to.
func TestDialerEnforcesPolicyOnTheRealAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	addr := ln.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Default policy: connecting to loopback is refused before any packet is sent.
	_, err = (Policy{}).Dialer(time.Second).DialContext(ctx, "tcp", addr)
	if err == nil {
		t.Fatal("default policy must refuse loopback at connect time")
	}
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("want ErrRefused through the dialer, got %v", err)
	}

	// Opted in: it connects.
	c, err := (Policy{AllowLoopback: true}).Dialer(time.Second).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("opted-in loopback must connect: %v", err)
	}
	_ = c.Close()

	// Even a fully opted-in policy never reaches the metadata address.
	p := Policy{AllowLoopback: true, AllowPrivate: true, Allowlist: []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")}}
	_, err = p.Dialer(500*time.Millisecond).DialContext(ctx, "tcp", "169.254.169.254:80")
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("metadata address must be refused by the dialer, got %v", err)
	}
}

// A hostname that resolves to a refused address is stopped by the dialer too (rebinding case: the
// pre-check saw a public address, the dial-time lookup returns loopback).
func TestDialerRefusesHostnameResolvingToLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := (Policy{}).Dialer(time.Second).DialContext(ctx, "tcp", "localhost:9")
	if err == nil {
		t.Fatal("localhost must be refused under the default policy")
	}
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("want ErrRefused, got %v", err)
	}
}
