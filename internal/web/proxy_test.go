package web

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func proxyReq(remote string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func policy(t *testing.T, proxies ...string) ProxyPolicy {
	t.Helper()
	p, err := ParseProxyList(proxies)
	if err != nil {
		t.Fatal(err)
	}
	return ProxyPolicy{TrustedProxies: p}
}

// Review finding 8: behind a proxy every client looked like 127.0.0.1, and trusting X-Forwarded-For from
// anyone lets a client pick its own address.
func TestClientIP(t *testing.T) {
	p := policy(t, "127.0.0.1", "10.0.0.0/8")
	cases := []struct {
		name   string
		remote string
		xff    string
		want   string
	}{
		{"direct client, no proxy", "203.0.113.9:5000", "", "203.0.113.9"},
		{"direct client forging X-Forwarded-For is ignored", "203.0.113.9:5000", "1.2.3.4", "203.0.113.9"},
		{"trusted proxy passes the client through", "127.0.0.1:41000", "198.51.100.7", "198.51.100.7"},
		{"trusted proxy, no header: the proxy itself", "127.0.0.1:41000", "", "127.0.0.1"},
		{"client forged a leftmost entry; the proxy appended the real one", "127.0.0.1:41000", "1.2.3.4, 198.51.100.7", "198.51.100.7"},
		{"chain through two trusted proxies", "10.0.0.2:1", "198.51.100.7, 10.0.0.9", "198.51.100.7"},
		{"every entry is a trusted proxy", "10.0.0.2:1", "10.0.0.5, 10.0.0.9", "10.0.0.2"},
		{"malformed entry: do not guess", "127.0.0.1:1", "198.51.100.7, not-an-ip", "127.0.0.1"},
		{"ipv6 client", "127.0.0.1:1", "2001:db8::5", "2001:db8::5"},
		{"ipv4-mapped client is unmapped", "127.0.0.1:1", "::ffff:198.51.100.7", "198.51.100.7"},
		{"ipv6 peer in brackets", "[::1]:9000", "", "::1"},
	}
	for _, c := range cases {
		r := proxyReq(c.remote, nil)
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := p.ClientIP(r); got.String() != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
	// Several X-Forwarded-For header lines are read as one list.
	r := proxyReq("127.0.0.1:1", nil)
	r.Header.Add("X-Forwarded-For", "1.2.3.4")
	r.Header.Add("X-Forwarded-For", "198.51.100.7")
	if got := p.ClientIP(r); got.String() != "198.51.100.7" {
		t.Errorf("multiple header lines: got %s", got)
	}
	// With no trusted proxies configured the headers are never believed.
	none := ProxyPolicy{}
	r = proxyReq("127.0.0.1:1", map[string]string{"X-Forwarded-For": "198.51.100.7"})
	if got := none.ClientIP(r); got.String() != "127.0.0.1" {
		t.Errorf("no trusted proxies: got %s", got)
	}
	if got := p.ClientIP(proxyReq("garbage", nil)); got.IsValid() {
		t.Errorf("an unparseable peer must give the zero address, got %s", got)
	}
}

func TestIsHTTPS(t *testing.T) {
	p := policy(t, "127.0.0.1")
	assume := ProxyPolicy{TrustedProxies: p.TrustedProxies, AssumeHTTPS: true}

	tlsReq := proxyReq("203.0.113.9:1", nil)
	tlsReq.TLS = &tls.ConnectionState{}
	if !none().IsHTTPS(tlsReq) {
		t.Error("a TLS connection is HTTPS")
	}
	if p.IsHTTPS(proxyReq("127.0.0.1:1", nil)) {
		t.Error("plain HTTP from a proxy that did not say otherwise is not HTTPS")
	}
	if !p.IsHTTPS(proxyReq("127.0.0.1:1", map[string]string{"X-Forwarded-Proto": "https"})) {
		t.Error("a trusted proxy saying https means https")
	}
	if !p.IsHTTPS(proxyReq("127.0.0.1:1", map[string]string{"X-Forwarded-Proto": "HTTPS"})) {
		t.Error("the value is case-insensitive")
	}
	if p.IsHTTPS(proxyReq("127.0.0.1:1", map[string]string{"X-Forwarded-Proto": "http"})) {
		t.Error("http is not https")
	}
	// Last value wins (it is the one the nearest proxy added).
	if !p.IsHTTPS(proxyReq("127.0.0.1:1", map[string]string{"X-Forwarded-Proto": "http, https"})) {
		t.Error("the last element is the proxy's")
	}
	if p.IsHTTPS(proxyReq("127.0.0.1:1", map[string]string{"X-Forwarded-Proto": "https, http"})) {
		t.Error("the last element is the proxy's")
	}
	// An untrusted peer cannot claim HTTPS.
	if p.IsHTTPS(proxyReq("203.0.113.9:1", map[string]string{"X-Forwarded-Proto": "https"})) {
		t.Error("an untrusted peer must not be able to claim HTTPS")
	}
	if assume.IsHTTPS(proxyReq("203.0.113.9:1", nil)) {
		t.Error("AssumeHTTPS must not apply to an untrusted peer")
	}
	if !assume.IsHTTPS(proxyReq("127.0.0.1:1", nil)) {
		t.Error("AssumeHTTPS applies to a trusted proxy")
	}
	if none().IsHTTPS(proxyReq("127.0.0.1:1", map[string]string{"X-Forwarded-Proto": "https"})) {
		t.Error("with no trusted proxies the header is never believed")
	}
}

func none() ProxyPolicy { return ProxyPolicy{} }

func TestParseProxyList(t *testing.T) {
	ps, err := ParseProxyList([]string{"127.0.0.1", "10.1.2.3/8", "::1", "2001:db8::/32", " 192.168.0.1 "})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.1/32", "10.0.0.0/8", "::1/128", "2001:db8::/32", "192.168.0.1/32"}
	for i, w := range want {
		if ps[i].String() != w {
			t.Errorf("entry %d = %s, want %s", i, ps[i], w)
		}
	}
	for _, bad := range []string{"", "not-an-ip", "10.0.0.0/33", "example.com", "1.2.3"} {
		if _, err := ParseProxyList([]string{bad}); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	// A name must never be accepted as a trusted proxy: it would be resolved by DNS.
	if _, err := ParseProxyList([]string{"proxy.example.net"}); err == nil || !strings.Contains(err.Error(), "not an address") {
		t.Errorf("a host name must be refused: %v", err)
	}
}

// Review finding 11: "localhost" is approved by CheckListen as a string and resolved only by net.Listen.
type fakeAddr struct{ ip net.IP }

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return a.ip.String() }

func TestCheckBound(t *testing.T) {
	tcp := func(ip string) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: 8443} }
	for _, ip := range []string{"127.0.0.1", "127.9.9.9", "::1", "::ffff:127.0.0.1"} {
		if err := checkBound(tcp(ip), false); err != nil {
			t.Errorf("%s is loopback and must be accepted: %v", ip, err)
		}
	}
	for _, ip := range []string{"0.0.0.0", "::", "192.168.1.5", "203.0.113.7", "2001:db8::1", "10.0.0.1"} {
		if err := checkBound(tcp(ip), false); err == nil {
			t.Errorf("%s is not loopback and must be refused", ip)
		}
	}
	if err := checkBound(tcp("203.0.113.7"), true); err != nil {
		t.Errorf("the explicit opt-in allows a non-loopback bind: %v", err)
	}
	if err := checkBound(fakeAddr{net.ParseIP("127.0.0.1")}, false); err == nil {
		t.Error("an unexpected address type must be refused, not assumed safe")
	}
	if err := checkBound(&net.TCPAddr{}, false); err == nil {
		t.Error("an empty address must be refused")
	}
}

func TestServeRefusesANonLoopbackListener(t *testing.T) {
	h := newHarness(t)
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skipf("cannot bind a wildcard listener here: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- h.s.Serve(ctx, ln) }()
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "not loopback") {
			t.Fatalf("a listener on 0.0.0.0 must be refused when the opt-in is off, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve accepted a non-loopback listener: it kept serving instead of refusing")
	}
	// The refused listener is closed, not left accepting.
	if c, err := net.Dial("tcp", ln.Addr().String()); err == nil {
		c.Close()
		t.Fatal("the refused listener must be closed")
	}
}
