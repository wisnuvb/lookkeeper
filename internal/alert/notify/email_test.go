package notify

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/model"
	"github.com/wisnuvb/lockkeeper/internal/secret"
	"github.com/wisnuvb/lockkeeper/internal/testutil/fakesmtp"
)

const (
	smtpUser     = "alerts@example.test"
	smtpPassword = "CANARY-smtp-pw-7f3a9c"
)

var fixedNow = time.Date(2026, 11, 6, 12, 30, 0, 0, time.FixedZone("WIB", 7*3600))

func pool(t *testing.T, pem []byte) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(pem) {
		t.Fatal("bad PEM")
	}
	return p
}

// emailFor returns a notifier pointed at srv that trusts its certificate.
func emailFor(t *testing.T, srv *fakesmtp.Server, mode string) *Email {
	t.Helper()
	return &Email{
		Host: srv.Host, Port: srv.Port, TLS: mode,
		From: "Lockkeeper <lockkeeper@example.test>", To: []string{"ops@example.test"},
		RootCAs: pool(t, srv.CAPEM()), Now: func() time.Time { return fixedNow },
		Timeout: 5 * time.Second,
	}
}

func withAuth(e *Email) *Email {
	e.Username, e.Password = smtpUser, secret.New(smtpPassword)
	return e
}

func decodeBody(t *testing.T, m *mail.Message) string {
	t.Helper()
	if enc := m.Header.Get("Content-Transfer-Encoding"); enc != "quoted-printable" {
		t.Fatalf("encoding = %q", enc)
	}
	b, err := io.ReadAll(quotedprintable.NewReader(m.Body))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEmailImplicitTLSDelivers(t *testing.T) {
	srv := fakesmtp.Start(t, fakesmtp.Options{Mode: fakesmtp.ImplicitTLS, User: smtpUser, Password: smtpPassword})
	e := withAuth(emailFor(t, srv, EmailTLS))
	e.To = []string{"ops@example.test", "Second Person <second@example.test>"}
	if err := e.Send(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	msgs := srv.Messages()
	if len(msgs) != 1 {
		t.Fatalf("messages = %d", len(msgs))
	}
	if msgs[0].From != "lockkeeper@example.test" || strings.Join(msgs[0].To, ",") != "ops@example.test,second@example.test" {
		t.Errorf("envelope = %q -> %v", msgs[0].From, msgs[0].To)
	}
	m, err := mail.ReadMessage(strings.NewReader(msgs[0].Data))
	if err != nil {
		t.Fatal(err)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject"))
	if err != nil || !strings.HasPrefix(subject, "[CRITICAL] ") || !strings.Contains(subject, "WAL retained") {
		t.Errorf("subject = %q (%v)", subject, err)
	}
	if d, err := m.Header.Date(); err != nil || !d.Equal(fixedNow) {
		t.Errorf("Date = %q (%v)", m.Header.Get("Date"), err)
	}
	if id := m.Header.Get("Message-ID"); !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, "@example.test>") {
		t.Errorf("Message-ID = %q", id)
	}
	if ct := m.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q", ct)
	}
	if body := decodeBody(t, m); !strings.Contains(strings.ReplaceAll(body, "\r\n", "\n"), FormatEvent(event)) {
		t.Errorf("body = %q", body)
	}
	if srv.AuthOverCleartext() {
		t.Error("AUTH was sent before TLS")
	}
}

func TestEmailMessageIDsAreUnique(t *testing.T) {
	a, b := messageID("x@example.test"), messageID("x@example.test")
	if a == b {
		t.Errorf("duplicate Message-ID %q", a)
	}
	if got := messageID("x@bad domain>\r\nBcc: z"); !strings.HasSuffix(got, "@lockkeeper.invalid>") {
		t.Errorf("unsafe domain must fall back: %q", got)
	}
}

func TestEmailStartTLSAuthsOnlyAfterUpgrade(t *testing.T) {
	// The server offers AUTH even before TLS: a careful client must still wait.
	srv := fakesmtp.Start(t, fakesmtp.Options{Mode: fakesmtp.StartTLS, User: smtpUser, Password: smtpPassword, AdvertiseAuthBeforeTLS: true})
	if err := withAuth(emailFor(t, srv, EmailStartTLS)).Send(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if srv.AuthOverCleartext() {
		t.Fatal("AUTH was sent over the cleartext channel")
	}
	var starttls, auth = -1, -1
	for i, c := range srv.Commands() {
		switch {
		case c == "STARTTLS":
			starttls = i
		case strings.HasPrefix(c, "AUTH "):
			auth = i
		}
	}
	if starttls < 0 || auth < starttls {
		t.Errorf("STARTTLS at %d, AUTH at %d; commands: %v", starttls, auth, srv.Commands())
	}
	if len(srv.Messages()) != 1 {
		t.Errorf("messages = %d", len(srv.Messages()))
	}
}

func TestEmailStartTLSWithoutServerSupportIsRefused(t *testing.T) {
	// A plaintext server that offers AUTH: the client must not downgrade.
	srv := fakesmtp.Start(t, fakesmtp.Options{Mode: fakesmtp.Plain, User: smtpUser, Password: smtpPassword})
	err := withAuth(emailFor(t, srv, EmailStartTLS)).Send(context.Background(), event)
	if err == nil || !strings.Contains(err.Error(), "does not offer STARTTLS") {
		t.Fatalf("err = %v", err)
	}
	if srv.AuthOverCleartext() || len(srv.Messages()) != 0 {
		t.Error("credentials or mail were sent without encryption")
	}
	for _, c := range srv.Commands() {
		if strings.HasPrefix(c, "AUTH") || strings.HasPrefix(c, "MAIL") {
			t.Errorf("unexpected command %q", c)
		}
	}
	var perm permanentError
	if !errors.As(err, &perm) {
		t.Error("a downgrade refusal must not be retried")
	}
}

func TestEmailPlaintextToLoopbackIsAllowed(t *testing.T) {
	srv := fakesmtp.Start(t, fakesmtp.Options{Mode: fakesmtp.Plain})
	if err := emailFor(t, srv, EmailNone).Send(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if len(srv.Messages()) != 1 {
		t.Fatalf("messages = %d", len(srv.Messages()))
	}
	// Credentials to a loopback relay follow net/smtp's localhost exception.
	authSrv := fakesmtp.Start(t, fakesmtp.Options{Mode: fakesmtp.Plain, User: smtpUser, Password: smtpPassword})
	if err := withAuth(emailFor(t, authSrv, EmailNone)).Send(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if len(authSrv.Messages()) != 1 {
		t.Fatalf("messages = %d", len(authSrv.Messages()))
	}
}

// countingDial records whether a connection was attempted and never touches the network.
func countingDial(n *atomic.Int32) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		n.Add(1)
		return nil, errors.New("dial blocked by test")
	}
}

func TestEmailRefusesPlaintextToNonLoopback(t *testing.T) {
	var dials atomic.Int32
	e := &Email{Host: "mail.example.com", TLS: EmailNone, From: "a@example.test", To: []string{"b@example.test"}, Dial: countingDial(&dials)}
	err := e.Send(context.Background(), event)
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("err = %v", err)
	}
	if dials.Load() != 0 {
		t.Fatal("the connection must be refused before dialling")
	}

	// allow_insecure lifts the refusal for an unauthenticated relay only.
	e.AllowInsecure = true
	if err := e.Send(context.Background(), event); err == nil || !strings.Contains(err.Error(), "dial blocked") {
		t.Fatalf("allow_insecure without credentials must proceed to dial: %v", err)
	}
	if dials.Load() != 1 {
		t.Fatalf("dials = %d", dials.Load())
	}

	// ...but credentials are never sent in the clear to a remote host.
	withAuth(e)
	err = e.Send(context.Background(), event)
	if err == nil || !strings.Contains(err.Error(), "credentials") || dials.Load() != 1 {
		t.Fatalf("err = %v, dials = %d", err, dials.Load())
	}
	if strings.Contains(err.Error(), smtpPassword) {
		t.Error("password in error")
	}
}

// spoofRemote reports a non-loopback peer address while talking to the loopback
// fake, to exercise the checks made after connecting.
type spoofRemote struct{ net.Conn }

func (spoofRemote) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 25}
}

func spoofDial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return spoofRemote{c}, nil
}

func TestEmailChecksThePeerAddressAfterConnecting(t *testing.T) {
	// "localhost" passes the name check but resolves to a remote address.
	srv := fakesmtp.Start(t, fakesmtp.Options{Mode: fakesmtp.Plain, User: smtpUser, Password: smtpPassword})
	e := emailFor(t, srv, EmailNone)
	e.Host, e.Dial = "localhost", spoofDial
	if err := e.Send(context.Background(), event); err == nil || !strings.Contains(err.Error(), "not loopback") {
		t.Fatalf("err = %v", err)
	}

	// With allow_insecure the connection is permitted, but credentials still are not sent.
	withAuth(e).AllowInsecure = true
	err := e.Send(context.Background(), event)
	if err == nil || !strings.Contains(err.Error(), "refusing to send credentials") {
		t.Fatalf("err = %v", err)
	}
	if srv.AuthOverCleartext() || len(srv.Messages()) != 0 {
		t.Error("credentials or mail crossed an unencrypted non-loopback connection")
	}
}

func TestEmailVerifiesServerCertificate(t *testing.T) {
	other := fakesmtp.Start(t, fakesmtp.Options{Mode: fakesmtp.Plain}) // only used for its (wrong) CA
	for _, tc := range []struct {
		name string
		mode fakesmtp.Mode
		tls  string
		pool func(*testing.T, *fakesmtp.Server) *x509.CertPool
	}{
		{"implicit tls, wrong CA", fakesmtp.ImplicitTLS, EmailTLS, func(t *testing.T, _ *fakesmtp.Server) *x509.CertPool { return pool(t, other.CAPEM()) }},
		{"starttls, wrong CA", fakesmtp.StartTLS, EmailStartTLS, func(t *testing.T, _ *fakesmtp.Server) *x509.CertPool { return pool(t, other.CAPEM()) }},
		{"implicit tls, system roots", fakesmtp.ImplicitTLS, EmailTLS, func(*testing.T, *fakesmtp.Server) *x509.CertPool { return nil }},
		{"starttls, system roots", fakesmtp.StartTLS, EmailStartTLS, func(*testing.T, *fakesmtp.Server) *x509.CertPool { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakesmtp.Start(t, fakesmtp.Options{Mode: tc.mode, User: smtpUser, Password: smtpPassword})
			e := withAuth(emailFor(t, srv, tc.tls))
			e.RootCAs = tc.pool(t, srv)
			err := e.Send(context.Background(), event)
			if err == nil || !strings.Contains(err.Error(), "certificate") {
				t.Fatalf("err = %v", err)
			}
			if len(srv.Messages()) != 0 || srv.AuthOverCleartext() {
				t.Error("nothing may be sent after a failed verification")
			}
			for _, c := range srv.Commands() {
				if strings.HasPrefix(c, "AUTH") || strings.HasPrefix(c, "MAIL") {
					t.Errorf("command %q sent over an unverified channel", c)
				}
			}
			var perm permanentError
			if !errors.As(err, &perm) {
				t.Error("a certificate failure must not be retried")
			}
		})
	}
}

func TestEmailRejectsWrongServerName(t *testing.T) {
	srv := fakesmtp.Start(t, fakesmtp.Options{Mode: fakesmtp.ImplicitTLS})
	e := emailFor(t, srv, EmailTLS)
	e.Host = "mail.example.com" // the certificate is for localhost / 127.0.0.1
	e.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port)))
	}
	err := e.Send(context.Background(), event)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("err = %v", err)
	}
}

func TestEmailRetryDoesNotRepeatPermanentFailures(t *testing.T) {
	srv := fakesmtp.Start(t, fakesmtp.Options{Mode: fakesmtp.ImplicitTLS})
	e := emailFor(t, srv, EmailTLS)
	e.RootCAs = nil // untrusted self-signed certificate
	r := Retrying{Notifier: e, Attempts: 3, Sleep: func(context.Context, time.Duration) error { return nil }}
	if err := r.Send(context.Background(), event); err == nil {
		t.Fatal("expected a failure")
	}
	if n := srv.Connections(); n != 1 {
		t.Errorf("connections = %d, want 1", n)
	}
}

func TestEmailErrorsNeverContainThePassword(t *testing.T) {
	// A hostile server that echoes the credentials in its rejection.
	srv := fakesmtp.Start(t, fakesmtp.Options{Mode: fakesmtp.ImplicitTLS, User: smtpUser, Password: "different", EchoAuthPayload: true})
	e := withAuth(emailFor(t, srv, EmailTLS))
	err := e.Send(context.Background(), event)
	if err == nil || !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("err = %v", err)
	}
	blob := base64.StdEncoding.EncodeToString([]byte("\x00" + smtpUser + "\x00" + smtpPassword))
	for _, leak := range []string{smtpPassword, blob} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error leaks %q: %v", leak, err)
		}
	}
	if !strings.Contains(err.Error(), "***") {
		t.Errorf("expected a masked placeholder in %v", err)
	}
	var perm permanentError
	if !errors.As(err, &perm) {
		t.Error("an authentication failure must not be retried")
	}
	// The password must not be reachable through the secret type's formatting either.
	if got := (&Email{Password: secret.New(smtpPassword)}).Password.String(); strings.Contains(got, smtpPassword) {
		t.Error("secret.Value formats its plaintext")
	}
}

func TestEmailHeaderInjectionInAddressesIsRejected(t *testing.T) {
	srv := fakesmtp.Start(t, fakesmtp.Options{Mode: fakesmtp.Plain})
	for name, mutate := range map[string]func(*Email){
		"from CRLF":       func(e *Email) { e.From = "a@example.test\r\nBcc: evil@example.test" },
		"from LF":         func(e *Email) { e.From = "a@example.test\nBcc: evil@example.test" },
		"from name CRLF":  func(e *Email) { e.From = "Evil\r\nBcc: evil@example.test <a@example.test>" },
		"to CRLF":         func(e *Email) { e.To = []string{"b@example.test\r\nBcc: evil@example.test"} },
		"to second entry": func(e *Email) { e.To = []string{"b@example.test", "c@example.test\nX-Evil: 1"} },
		"to NUL":          func(e *Email) { e.To = []string{"b@example.test\x00"} },
		"to not an address": func(e *Email) {
			e.To = []string{"not an address"}
		},
		"to empty list": func(e *Email) { e.To = nil },
	} {
		t.Run(name, func(t *testing.T) {
			e := emailFor(t, srv, EmailNone)
			mutate(e)
			if err := e.Send(context.Background(), event); err == nil {
				t.Fatal("expected a rejection")
			}
		})
	}
	if srv.Connections() != 0 {
		t.Error("an invalid address must be rejected before connecting")
	}
	if err := ParseEmailAddress("ops@example.test\r\nBcc: x@example.test"); err == nil {
		t.Error("ParseEmailAddress must reject CRLF")
	}
	if err := ParseEmailAddress("Ops <ops@example.test>"); err != nil {
		t.Errorf("a display name is fine: %v", err)
	}
}

func TestEmailHeaderInjectionInSubjectIsNeutralised(t *testing.T) {
	srv := fakesmtp.Start(t, fakesmtp.Options{Mode: fakesmtp.Plain})
	ev := event
	ev.Summary = "disk low\r\nBcc: evil@example.test\nX-Injected: yes Subject: pwned\u0085more"
	if err := emailFor(t, srv, EmailNone).Send(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	msgs := srv.Messages()
	if len(msgs) != 1 {
		t.Fatalf("messages = %d", len(msgs))
	}
	if got := msgs[0].To; len(got) != 1 {
		t.Errorf("recipients = %v", got)
	}
	head, _, _ := strings.Cut(msgs[0].Data, "\r\n\r\n")
	for _, line := range strings.Split(head, "\r\n") {
		name, _, _ := strings.Cut(line, ":")
		switch name {
		case "From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type", "Content-Transfer-Encoding", "Auto-Submitted":
		default:
			if !strings.HasPrefix(line, " ") { // a folded continuation of an encoded Subject
				t.Errorf("unexpected header line %q", line)
			}
		}
	}
	m, err := mail.ReadMessage(strings.NewReader(msgs[0].Data))
	if err != nil {
		t.Fatal(err)
	}
	if m.Header.Get("Bcc") != "" || m.Header.Get("X-Injected") != "" {
		t.Error("an injected header was parsed")
	}
	subject, _ := new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject"))
	if strings.ContainsAny(subject, "\r\n \u0085") || !strings.HasPrefix(subject, "[CRITICAL] disk low Bcc: evil@example.test") {
		t.Errorf("subject = %q", subject)
	}
}

func TestEmailSubjectFormat(t *testing.T) {
	long := strings.Repeat("é", 300)
	ev := event
	ev.Summary = long
	s := subjectFor(ev)
	if n := len([]rune(s)); n > len("[CRITICAL] ")+maxSubjectSummary {
		t.Errorf("subject has %d runes", n)
	}
	if !strings.HasSuffix(s, "…") || !strings.HasPrefix(s, "[CRITICAL] ") {
		t.Errorf("subject = %q", s)
	}
	enc := encodeSubject(s)
	if strings.ContainsAny(strings.ReplaceAll(enc, "\r\n ", ""), "\r\n") {
		t.Errorf("encoded subject has a bare line break: %q", enc)
	}
	if dec, err := new(mime.WordDecoder).DecodeHeader(enc); err != nil || dec != s {
		t.Errorf("round trip failed: %q %v", dec, err)
	}
	warn := event
	warn.Severity = model.SeverityWarning
	res := event
	res.State = model.StateResolved
	rem := warn
	rem.State = model.StateReminder
	for ev, want := range map[*model.Event]string{&warn: "[WARNING] ", &res: "[RESOLVED] ", &rem: "[WARNING reminder] "} {
		if got := subjectFor(*ev); !strings.HasPrefix(got, want) {
			t.Errorf("subject %q does not start with %q", got, want)
		}
	}
}

func TestEmailBodyEncodesNonASCII(t *testing.T) {
	var buf bytes.Buffer
	e := &Email{Now: func() time.Time { return fixedNow }}
	from, _ := mail.ParseAddress("a@example.test")
	to, _ := mail.ParseAddress("b@example.test")
	buf.Write(e.buildMessage(event, from, []*mail.Address{to}))
	m, err := mail.ReadMessage(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if body := decodeBody(t, m); !strings.Contains(body, "🔴 CRITICAL") {
		t.Errorf("body = %q", body)
	}
}

func TestEmailPartialRecipientRejection(t *testing.T) {
	srv := fakesmtp.Start(t, fakesmtp.Options{Mode: fakesmtp.Plain, RejectRcpt: []string{"gone@example.test"}})
	e := emailFor(t, srv, EmailNone)
	e.To = []string{"gone@example.test", "ops@example.test"}
	err := e.Send(context.Background(), event)
	var perm permanentError
	if err == nil || !errors.As(err, &perm) || !strings.Contains(err.Error(), "gone@example.test") {
		t.Fatalf("err = %v", err)
	}
	if msgs := srv.Messages(); len(msgs) != 1 || strings.Join(msgs[0].To, ",") != "ops@example.test" {
		t.Errorf("messages = %+v", msgs)
	}

	e.To = []string{"gone@example.test"}
	if err := e.Send(context.Background(), event); err == nil || !strings.Contains(err.Error(), "every recipient") {
		t.Errorf("err = %v", err)
	}
}

func TestEmailTimeoutAndCancellation(t *testing.T) {
	srv := fakesmtp.Start(t, fakesmtp.Options{Mode: fakesmtp.Plain, Hang: true})
	e := emailFor(t, srv, EmailNone)
	e.Timeout = 300 * time.Millisecond
	start := time.Now()
	err := e.Send(context.Background(), event)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("timeout took %v", time.Since(start))
	}

	e.Timeout = 10 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start = time.Now()
	if err := e.Send(ctx, event); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("cancellation took %v", time.Since(start))
	}
}

func TestEmailDefaultsAndName(t *testing.T) {
	if mode, port := (&Email{}).effective(); mode != EmailStartTLS || port != 587 {
		t.Errorf("default = %s/%d", mode, port)
	}
	if mode, port := (&Email{TLS: EmailTLS}).effective(); mode != EmailTLS || port != 465 {
		t.Errorf("tls default = %s/%d", mode, port)
	}
	if mode, port := (&Email{TLS: EmailNone, Port: 25}).effective(); mode != EmailNone || port != 25 {
		t.Errorf("explicit = %s/%d", mode, port)
	}
	if (&Email{}).Name() != "email" {
		t.Error("name")
	}
	e := &Email{Host: "bad host", From: "a@example.test", To: []string{"b@example.test"}}
	if err := e.Send(context.Background(), event); err == nil {
		t.Error("an invalid host must be refused")
	}
}
