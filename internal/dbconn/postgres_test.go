package dbconn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/secret"
)

func TestConnConfigSecurityDefaults(t *testing.T) {
	cfg, err := ConnConfig(PGSpec{
		Host: "127.0.0.1", Port: 5432, User: "mon", Database: "app",
		Password: secret.New("pw-xyz-123"), TLSMode: "disable",
		StatementTimeout: 7 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Password != "pw-xyz-123" {
		t.Error("password must be set on the config, not in the URL")
	}
	if len(cfg.Fallbacks) != 0 {
		t.Error("there must be no fallback configs (no silent plaintext retry)")
	}
	rp := cfg.RuntimeParams
	if rp["default_transaction_read_only"] != "on" {
		t.Errorf("sessions must be read-only, got %q", rp["default_transaction_read_only"])
	}
	if rp["statement_timeout"] != "7000" || rp["lock_timeout"] != "7000" {
		t.Errorf("timeouts not applied: %v", rp)
	}
	if rp["application_name"] != "lockkeeper" {
		t.Errorf("application_name = %q", rp["application_name"])
	}
}

func TestConnConfigIgnoresAmbientEnvironment(t *testing.T) {
	t.Setenv("PGOPTIONS", "-c default_transaction_read_only=off")
	t.Setenv("PGSSLMODE", "disable")
	t.Setenv("PGPASSWORD", "ambient-password")
	cfg, err := ConnConfig(PGSpec{
		Host: "db.example.com", User: "mon", Password: secret.New("explicit-pw"),
		TLSMode: "verify-full",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Password != "explicit-pw" {
		t.Error("ambient PGPASSWORD leaked into the config")
	}
	if cfg.TLSConfig == nil || cfg.TLSConfig.InsecureSkipVerify {
		t.Error("PGSSLMODE must not weaken TLS")
	}
	if cfg.RuntimeParams["default_transaction_read_only"] != "on" {
		t.Error("PGOPTIONS must not turn off read-only")
	}
	if _, ok := cfg.RuntimeParams["options"]; ok {
		t.Error("ambient options must be dropped")
	}
}

func TestConnConfigEscapesNames(t *testing.T) {
	cfg, err := ConnConfig(PGSpec{
		Host: "127.0.0.1", User: "we ird@user:name", Database: "db/with space", TLSMode: "disable",
		Password: secret.New("p"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.User != "we ird@user:name" || cfg.Database != "db/with space" {
		t.Errorf("round trip failed: user=%q db=%q", cfg.User, cfg.Database)
	}
}

func TestConnConfigUnixSocket(t *testing.T) {
	cfg, err := ConnConfig(PGSpec{Host: "/var/run/postgresql", User: "mon", TLSMode: "disable", Password: secret.New("p")})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "/var/run/postgresql" {
		t.Errorf("host = %q", cfg.Host)
	}
}

func TestTLSConfigPolicy(t *testing.T) {
	if _, err := TLSConfig("require", "db.example.com", "", false); err == nil {
		t.Error("require must be refused for remote hosts without allow_insecure")
	}
	if _, err := TLSConfig("disable", "10.1.2.3", "", false); err == nil {
		t.Error("disable must be refused for remote hosts without allow_insecure")
	}
	if c, err := TLSConfig("disable", "localhost", "", false); err != nil || c != nil {
		t.Errorf("disable on loopback must be allowed and yield nil, got %v %v", c, err)
	}
	if c, err := TLSConfig("require", "db.example.com", "", true); err != nil || !c.InsecureSkipVerify {
		t.Errorf("explicit opt-in must work: %v %v", c, err)
	}
	if _, err := TLSConfig("bogus", "localhost", "", false); err == nil {
		t.Error("unknown mode must fail")
	}

	c, err := TLSConfig("", "db.example.com", "", false) // default is verify-full
	if err != nil {
		t.Fatal(err)
	}
	if c.InsecureSkipVerify || c.ServerName != "db.example.com" || c.MinVersion < tls.VersionTLS12 {
		t.Errorf("default must be verify-full with TLS>=1.2: %+v", c)
	}
}

func TestTLSConfigCAFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := TLSConfig("verify-full", "db.example.com", bad, false); err == nil || !strings.Contains(err.Error(), "no valid PEM") {
		t.Errorf("invalid CA file must fail, got %v", err)
	}
	if _, err := TLSConfig("verify-full", "db.example.com", filepath.Join(dir, "missing.pem"), false); err == nil {
		t.Error("missing CA file must fail")
	}

	caPEM, leafDER := makeCAAndLeaf(t, "db.example.com")
	good := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(good, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := TLSConfig("verify-ca", "wrong-name.example.com", good, false)
	if err != nil {
		t.Fatal(err)
	}
	// verify-ca accepts a certificate issued by the CA even if the name differs...
	if err := c.VerifyPeerCertificate([][]byte{leafDER}, nil); err != nil {
		t.Errorf("verify-ca should accept a valid chain: %v", err)
	}
	// ...but must reject a certificate from an unknown CA.
	_, otherLeaf := makeCAAndLeaf(t, "db.example.com")
	if err := c.VerifyPeerCertificate([][]byte{otherLeaf}, nil); err == nil {
		t.Error("verify-ca must reject a certificate from an untrusted CA")
	}
	if err := c.VerifyPeerCertificate(nil, nil); err == nil {
		t.Error("verify-ca must reject an empty chain")
	}
}

func makeCAAndLeaf(t *testing.T, dnsName string) (caPEM, leafDER []byte) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err = x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), leafDER
}
