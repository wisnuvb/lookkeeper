// Package fakesmtp is a tiny in-process SMTP server for tests. It listens on
// loopback only, generates a throwaway self-signed certificate, and records what
// a client sent, so tests can assert on the wire behaviour (for example that no
// credentials were sent before TLS) without any real mail server.
package fakesmtp

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Mode selects how the server protects the connection.
type Mode int

const (
	// Plain accepts cleartext only and does not advertise STARTTLS.
	Plain Mode = iota
	// StartTLS advertises STARTTLS and upgrades on request.
	StartTLS
	// ImplicitTLS wraps the whole connection in TLS from the first byte.
	ImplicitTLS
)

// Options configure a Server. The zero value is a cleartext server with no AUTH.
type Options struct {
	Mode Mode
	// User and Password enable AUTH PLAIN when User is set.
	User, Password string
	// AdvertiseAuthBeforeTLS makes a STARTTLS server offer AUTH even before the
	// upgrade, which a careful client must still not use.
	AdvertiseAuthBeforeTLS bool
	// EchoAuthPayload makes a failed AUTH reply include the decoded credentials,
	// simulating a misbehaving server, to prove clients do not surface them.
	EchoAuthPayload bool
	// RejectRcpt lists recipient addresses answered with 550.
	RejectRcpt []string
	// Hang makes the server accept connections and then never answer.
	Hang bool
}

// Message is one accepted mail.
type Message struct {
	From string
	To   []string
	Data string // as received, dot-unstuffed, CRLF line endings
}

// Server is a running fake SMTP server.
type Server struct {
	Host string
	Port int

	opts Options
	ln   net.Listener
	cert tls.Certificate
	caPE []byte

	mu            sync.Mutex
	messages      []Message
	commands      []string
	authCleartext bool
	authAfter     int
	connections   int
	wg            sync.WaitGroup
}

// Start launches a server on 127.0.0.1 and stops it when the test ends.
func Start(t testing.TB, opts Options) *Server {
	t.Helper()
	cert, caPEM := selfSigned(t)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fakesmtp: listen: %v", err)
	}
	s := &Server{Host: "127.0.0.1", opts: opts, ln: raw, cert: cert, caPE: caPEM}
	s.Port = raw.Addr().(*net.TCPAddr).Port
	if opts.Mode == ImplicitTLS {
		s.ln = tls.NewListener(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	}
	s.wg.Add(1)
	go s.accept()
	t.Cleanup(func() {
		_ = s.ln.Close()
		s.wg.Wait()
	})
	return s
}

// CAPEM returns the PEM certificate clients must trust to verify this server.
func (s *Server) CAPEM() []byte { return s.caPE }

// WriteCA writes CAPEM to a file in the test's temp directory and returns its path.
func (s *Server) WriteCA(t testing.TB) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, s.caPE, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Messages returns the mails accepted so far.
func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.messages...)
}

// Commands returns every command line received, with AUTH payloads masked.
func (s *Server) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}

// AuthOverCleartext reports whether any client sent AUTH on a connection that
// was not (yet) encrypted.
func (s *Server) AuthOverCleartext() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authCleartext
}

// Connections is the number of TCP connections accepted.
func (s *Server) Connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connections
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.connections++
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer c.Close()
			s.serve(c)
		}()
	}
}

func (s *Server) record(cmd string) {
	s.mu.Lock()
	s.commands = append(s.commands, cmd)
	s.mu.Unlock()
}

func (s *Server) serve(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	if s.opts.Hang {
		_, _ = io.Copy(io.Discard, c) // until the client gives up and closes
		return
	}
	var conn net.Conn = c
	_, isTLS := conn.(*tls.Conn)
	br := bufio.NewReader(conn)
	say := func(format string, a ...any) { fmt.Fprintf(conn, format+"\r\n", a...) }
	say("220 fakesmtp ready")

	var from string
	var to []string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb, arg, _ := strings.Cut(line, " ")
		upper := strings.ToUpper(verb)
		if upper == "AUTH" {
			s.record("AUTH " + strings.Fields(arg + " ")[0] + " <masked>")
		} else {
			s.record(line)
		}
		switch upper {
		case "EHLO", "HELO":
			lines := []string{"fakesmtp"}
			if s.opts.Mode == StartTLS && !isTLS {
				lines = append(lines, "STARTTLS")
			}
			if s.opts.User != "" && (isTLS || s.opts.Mode == Plain || s.opts.AdvertiseAuthBeforeTLS) {
				lines = append(lines, "AUTH PLAIN")
			}
			for i, l := range lines {
				sep := "-"
				if i == len(lines)-1 {
					sep = " "
				}
				say("250%s%s", sep, l)
			}
		case "STARTTLS":
			if s.opts.Mode != StartTLS || isTLS {
				say("503 5.5.1 unexpected STARTTLS")
				continue
			}
			say("220 ready to start TLS")
			tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12})
			if err := tc.Handshake(); err != nil {
				return
			}
			conn, isTLS = tc, true
			br = bufio.NewReader(conn)
			from, to = "", nil
		case "AUTH":
			if !isTLS {
				s.mu.Lock()
				s.authCleartext = true
				s.mu.Unlock()
			}
			mech, ir, _ := strings.Cut(arg, " ")
			if !strings.EqualFold(mech, "PLAIN") || s.opts.User == "" {
				say("504 5.5.4 unsupported mechanism")
				continue
			}
			if ir == "" {
				say("334 ")
				l, err := br.ReadString('\n')
				if err != nil {
					return
				}
				ir = strings.TrimSpace(l)
			}
			raw, err := base64.StdEncoding.DecodeString(ir)
			parts := strings.Split(string(raw), "\x00")
			if err != nil || len(parts) != 3 || parts[1] != s.opts.User || parts[2] != s.opts.Password {
				if s.opts.EchoAuthPayload {
					say("535 5.7.8 bad credentials %s (%s)", ir, strings.ReplaceAll(string(raw), "\x00", "|"))
				} else {
					say("535 5.7.8 authentication failed")
				}
				continue
			}
			s.mu.Lock()
			s.authAfter++
			s.mu.Unlock()
			say("235 2.7.0 ok")
		case "MAIL":
			if s.opts.User != "" && !s.authenticated() {
				say("530 5.7.0 authentication required")
				continue
			}
			from = addrOf(arg)
			to = nil
			say("250 ok")
		case "RCPT":
			a := addrOf(arg)
			rejected := false
			for _, r := range s.opts.RejectRcpt {
				if strings.EqualFold(r, a) {
					rejected = true
				}
			}
			if rejected {
				say("550 5.1.1 no such user")
				continue
			}
			to = append(to, a)
			say("250 ok")
		case "DATA":
			say("354 go ahead")
			var b strings.Builder
			for {
				l, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(strings.TrimPrefix(l, ".")) // dot-unstuffing
			}
			s.mu.Lock()
			s.messages = append(s.messages, Message{From: from, To: append([]string(nil), to...), Data: b.String()})
			s.mu.Unlock()
			say("250 2.0.0 queued")
		case "RSET", "NOOP":
			say("250 ok")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("502 5.5.2 command not recognised")
		}
	}
}

func (s *Server) authenticated() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authAfter > 0
}

// addrOf extracts the address from "FROM:<a@b>" or "TO:<a@b> PARAM".
func addrOf(arg string) string {
	i := strings.Index(arg, "<")
	j := strings.Index(arg, ">")
	if i < 0 || j < i {
		return arg
	}
	return arg[i+1 : j]
}

func selfSigned(t testing.TB) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "fakesmtp-" + strconv.FormatInt(serial.Int64(), 16)},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert, certPEM
}
