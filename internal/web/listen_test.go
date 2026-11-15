package web

import (
	"strings"
	"testing"
)

func TestCheckListen(t *testing.T) {
	cases := []struct {
		name                 string
		listen               string
		tls, auth, allow     bool
		wantErr, wantWarning string // substring; "" means none
	}{
		{name: "default loopback", listen: "127.0.0.1:8443"},
		{name: "other loopback address", listen: "127.5.5.5:8443"},
		{name: "ipv6 loopback", listen: "[::1]:8443"},
		{name: "localhost", listen: "localhost:8443"},
		{name: "LOCALHOST", listen: "LOCALHOST:8443"},
		{name: "loopback needs no tls or auth flag", listen: "127.0.0.1:1"},

		{name: "wildcard refused", listen: ":8443", wantErr: "not a loopback"},
		{name: "0.0.0.0 refused", listen: "0.0.0.0:8443", wantErr: "not a loopback"},
		{name: "ipv6 wildcard refused", listen: "[::]:8443", wantErr: "not a loopback"},
		{name: "lan address refused", listen: "192.168.1.5:8443", wantErr: "not a loopback"},
		{name: "public address refused", listen: "203.0.113.7:8443", wantErr: "not a loopback"},
		{name: "host name is not resolved, so refused", listen: "lockkeeper.example.net:8443", wantErr: "not a loopback"},
		{name: "a name that merely contains localhost", listen: "localhost.evil.example:8443", wantErr: "not a loopback"},

		{name: "opt-in alone is not enough", listen: "0.0.0.0:8443", allow: true, wantErr: "TLS"},
		{name: "opt-in plus tls still needs auth", listen: "0.0.0.0:8443", allow: true, tls: true, wantErr: "authentication"},
		{name: "auth and tls without opt-in", listen: "0.0.0.0:8443", tls: true, auth: true, wantErr: "not a loopback"},
		{name: "all three", listen: "0.0.0.0:8443", allow: true, tls: true, auth: true, wantWarning: "not loopback"},

		{name: "no port", listen: "127.0.0.1", wantErr: "host:port"},
		{name: "empty", listen: "", wantErr: "host:port"},
		{name: "port zero", listen: "127.0.0.1:0", wantErr: "port"},
		{name: "port too large", listen: "127.0.0.1:70000", wantErr: "port"},
		{name: "port not a number", listen: "127.0.0.1:http", wantErr: "port"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			warn, err := CheckListen(c.listen, c.tls, c.auth, c.allow)
			if c.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("want error containing %q, got %v", c.wantErr, err)
				}
			}
			if c.wantWarning != "" && !strings.Contains(warn, c.wantWarning) {
				t.Fatalf("want a warning containing %q, got %q", c.wantWarning, warn)
			}
			if c.wantWarning == "" && warn != "" {
				t.Fatalf("unexpected warning %q", warn)
			}
		})
	}
}
