package service

import (
	"strings"
	"testing"

	"github.com/wisnuvb/lockkeeper/internal/config"
)

// The subscription connection carries the migration role's password to the
// source: a mode that does not authenticate the server must be refused for a
// remote peer unless the operator opted in, and unknown modes always.
func TestPeerSSLModeWhitelist(t *testing.T) {
	remote := config.Database{Host: "db.example.com", Port: 5432}
	remoteInsecure := config.Database{Host: "db.example.com", Port: 5432, TLS: config.TLS{AllowInsecure: true}}
	local := config.Database{Host: "127.0.0.1", Port: 5432}
	for _, tc := range []struct {
		name    string
		db      config.Database
		peer    string // --source-peer-addr
		mode    string
		wantErr string // "" = allowed
	}{
		{"verify-full remote", remote, "", "verify-full", ""},
		{"verify-ca remote", remote, "", "verify-ca", ""},
		{"require remote", remote, "", "require", "does not authenticate"},
		{"disable remote", remote, "", "disable", "does not authenticate"},
		{"allow remote", remote, "", "allow", "not supported"},
		{"prefer remote", remote, "", "prefer", "not supported"},
		{"unknown remote", remote, "", "verify_full", "not supported"},
		{"empty-ish unknown", remote, "", "VERIFY-FULL", "not supported"},
		{"require remote opted in", remoteInsecure, "", "require", ""},
		{"disable remote opted in", remoteInsecure, "", "disable", ""},
		{"allow remote opted in is still refused", remoteInsecure, "", "allow", "not supported"},
		{"prefer remote opted in is still refused", remoteInsecure, "", "prefer", "not supported"},
		{"unknown stays refused when opted in", remoteInsecure, "", "bogus", "not supported"},
		{"disable loopback", local, "", "disable", ""},
		{"require loopback", local, "", "require", ""},
		{"prefer loopback is not on the list", local, "", "prefer", "not supported"},
		{"unknown loopback", local, "", "nope", "not supported"},
		{"peer override to a remote host", local, "other.example.com:5432", "disable", "does not authenticate"},
		{"peer override to loopback", remote, "127.0.0.1:5432", "disable", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := peerFor(MigrateOptions{PeerAddr: tc.peer, PeerSSLMode: tc.mode}, tc.db)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("want allowed, got %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// When no mode is given the source connection's own mode is used and judged the same way.
func TestPeerDefaultsToTheConfiguredMode(t *testing.T) {
	p, err := peerFor(MigrateOptions{}, config.Database{Host: "db.example.com", Port: 5432})
	if err != nil || p.SSLMode != config.TLSVerifyFull {
		t.Fatalf("default mode must be verify-full: %v %q", err, p.SSLMode)
	}
	if _, err := peerFor(MigrateOptions{}, config.Database{Host: "db.example.com", TLS: config.TLS{Mode: config.TLSRequire}}); err == nil {
		t.Fatal("a configured require mode on a remote source must not be inherited silently")
	}
}
