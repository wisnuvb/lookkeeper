package notify

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wisnuvb/lockkeeper/internal/model"
	"github.com/wisnuvb/lockkeeper/internal/secret"
)

// Transport security modes for Email.TLS.
const (
	EmailStartTLS = "starttls" // plaintext greeting, then upgrade; refuses to continue without STARTTLS
	EmailTLS      = "tls"      // implicit TLS from the first byte (usually port 465)
	EmailNone     = "none"     // no encryption: loopback, or a relay the operator explicitly accepted
)

const (
	defaultEmailTimeout = 30 * time.Second
	dialTimeout         = 10 * time.Second
	maxSubjectSummary   = 120 // runes of the event summary kept in the subject
	maxServerReply      = 200 // bytes of an SMTP server reply kept in an error
)

// Email sends alerts through an SMTP server.
//
// Security properties, all covered by tests:
//   - STARTTLS and implicit TLS verify the server certificate and name; a server
//     that does not offer STARTTLS is an error, never a silent downgrade.
//   - Credentials are only sent over an encrypted connection (or to a loopback
//     address), and never before the TLS upgrade.
//   - "none" is refused for non-loopback hosts unless AllowInsecure is set, and
//     even then credentials are not sent.
//   - Header and address values cannot inject extra headers or recipients.
//   - Errors never contain the password, even if the server echoes it.
type Email struct {
	Host     string
	Port     int
	TLS      string // EmailStartTLS (default), EmailTLS or EmailNone
	Username string
	Password secret.Value
	From     string
	To       []string
	// RootCAs verifies the server certificate; nil selects the system roots.
	RootCAs *x509.CertPool
	// AllowInsecure permits TLS "none" towards a non-loopback host.
	AllowInsecure bool
	// Timeout bounds a whole delivery (connect, TLS, SMTP exchange). Default 30s.
	Timeout time.Duration

	// Now supplies the Date header (tests). Default time.Now.
	Now func() time.Time
	// Dial opens the TCP connection (tests). Default net.Dialer with a timeout.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Name implements Notifier.
func (e *Email) Name() string { return "email" }

// Send implements Notifier. The returned error never contains the password.
func (e *Email) Send(ctx context.Context, ev model.Event) error {
	err := e.send(ctx, ev)
	if err == nil {
		return nil
	}
	return e.scrub(err)
}

func (e *Email) send(ctx context.Context, ev model.Event) error {
	mode, port := e.effective()
	if err := validateHost(e.Host); err != nil {
		return permanentError{err: fmt.Errorf("email: %w", err)}
	}
	from, rcpts, err := e.addresses()
	if err != nil {
		return permanentError{err: fmt.Errorf("email: %w", err)}
	}
	if err := e.checkPolicy(mode); err != nil {
		return permanentError{err: err}
	}
	msg := e.buildMessage(ev, from, rcpts)

	timeout := e.Timeout
	if timeout <= 0 {
		timeout = defaultEmailTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := e.connect(ctx, mode, net.JoinHostPort(e.Host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	// One deadline covers every read and write of the exchange; cancelling ctx
	// closes the socket, which unblocks anything still waiting on it.
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	c, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		_ = conn.Close()
		return e.smtpError(ctx, "greeting", err)
	}
	defer c.Close()

	if mode == EmailStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return permanentError{err: errors.New("email: server does not offer STARTTLS; refusing to send without encryption (use tls: none only for a trusted local relay)")}
		}
		if err := c.StartTLS(e.tlsConfig()); err != nil {
			return e.smtpError(ctx, "STARTTLS", err)
		}
	}

	if e.Username != "" {
		// Re-check at the moment of use: credentials need an encrypted channel or a
		// loopback peer, whatever the configuration said.
		_, encrypted := c.TLSConnectionState()
		if !encrypted && !isLoopbackAddr(conn.RemoteAddr()) {
			return permanentError{err: errors.New("email: refusing to send credentials over an unencrypted connection")}
		}
		auth := smtp.PlainAuth("", e.Username, e.Password.Reveal(), e.Host)
		if err := c.Auth(auth); err != nil {
			return e.smtpError(ctx, "authentication", err)
		}
	}

	if err := c.Mail(from.Address); err != nil {
		return e.smtpError(ctx, "MAIL FROM", err)
	}
	var accepted int
	var rejected []string
	for _, r := range rcpts {
		if err := c.Rcpt(r.Address); err != nil {
			if isPermanentSMTP(err) {
				rejected = append(rejected, r.Address)
				continue
			}
			return e.smtpError(ctx, "RCPT TO", err)
		}
		accepted++
	}
	if accepted == 0 {
		return permanentError{err: fmt.Errorf("email: every recipient was rejected by the server (%s)", strings.Join(rejected, ", "))}
	}
	w, err := c.Data()
	if err != nil {
		return e.smtpError(ctx, "DATA", err)
	}
	if _, err := w.Write(msg); err != nil {
		return e.smtpError(ctx, "write message", err)
	}
	if err := w.Close(); err != nil {
		return e.smtpError(ctx, "end of message", err)
	}
	_ = c.Quit()
	if len(rejected) > 0 {
		// Permanent: the mail already went to the accepted recipients, so a retry
		// would duplicate it.
		return permanentError{err: fmt.Errorf("email: delivered to %d of %d recipients; rejected: %s", accepted, len(rcpts), strings.Join(rejected, ", "))}
	}
	return nil
}

// effective returns the TLS mode and port with defaults applied: starttls on 587,
// or 465 when implicit TLS is selected.
func (e *Email) effective() (mode string, port int) {
	mode, port = e.TLS, e.Port
	if mode == "" {
		mode = EmailStartTLS
	}
	if port == 0 {
		port = 587
		if mode == EmailTLS {
			port = 465
		}
	}
	return mode, port
}

// checkPolicy refuses configurations that would send mail or credentials in the clear.
func (e *Email) checkPolicy(mode string) error {
	switch mode {
	case EmailStartTLS, EmailTLS:
		return nil
	case EmailNone:
		if isLoopbackHost(e.Host) {
			return nil
		}
		if !e.AllowInsecure {
			return fmt.Errorf("email: tls \"none\" is refused for non-loopback host %q; use starttls or tls, or set allow_insecure", e.Host)
		}
		if e.Username != "" {
			return errors.New("email: credentials are never sent over an unencrypted connection to a non-loopback host; remove the username or enable TLS")
		}
		return nil
	default:
		return fmt.Errorf("email: unknown tls mode %q", mode)
	}
}

func (e *Email) tlsConfig() *tls.Config {
	return &tls.Config{ServerName: e.Host, RootCAs: e.RootCAs, MinVersion: tls.VersionTLS12}
}

// connect opens the TCP (and for implicit TLS, TLS) connection.
func (e *Email) connect(ctx context.Context, mode, addr string) (net.Conn, error) {
	dial := e.Dial
	if dial == nil {
		d := net.Dialer{Timeout: dialTimeout}
		dial = d.DialContext
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, e.smtpError(ctx, "connect", err)
	}
	if mode == EmailNone && !isLoopbackAddr(conn.RemoteAddr()) && !e.AllowInsecure {
		_ = conn.Close()
		return nil, permanentError{err: errors.New("email: tls \"none\" is refused: the server address is not loopback")}
	}
	if mode != EmailTLS {
		return conn, nil
	}
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))
	tc := tls.Client(conn, e.tlsConfig())
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, e.smtpError(ctx, "TLS handshake", err)
	}
	return tc, nil
}

// addresses validates From and every recipient.
func (e *Email) addresses() (*mail.Address, []*mail.Address, error) {
	from, err := parseAddress(e.From)
	if err != nil {
		return nil, nil, fmt.Errorf("from address: %w", err)
	}
	if len(e.To) == 0 {
		return nil, nil, errors.New("no recipients configured")
	}
	rcpts := make([]*mail.Address, 0, len(e.To))
	for _, t := range e.To {
		a, err := parseAddress(t)
		if err != nil {
			return nil, nil, fmt.Errorf("recipient address: %w", err)
		}
		rcpts = append(rcpts, a)
	}
	return from, rcpts, nil
}

// ParseEmailAddress validates one address the way the notifier does. It rejects
// control characters (CR and LF would allow header injection) before parsing.
func ParseEmailAddress(s string) error {
	_, err := parseAddress(s)
	return err
}

func parseAddress(s string) (*mail.Address, error) {
	if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return nil, errors.New("address contains control characters")
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return nil, errors.New("invalid address")
	}
	return a, nil
}

func validateHost(h string) error {
	if h == "" {
		return errors.New("host is empty")
	}
	if strings.ContainsFunc(h, func(r rune) bool { return r <= 0x20 || r == 0x7f || r == '/' || r == '@' }) {
		return errors.New("host contains invalid characters")
	}
	return nil
}

// isLoopbackHost reports whether host names the local machine.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func isLoopbackAddr(a net.Addr) bool {
	if a == nil {
		return false
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// buildMessage renders the RFC 5322 message with CRLF-safe headers. Every
// header value is single-line by construction.
func (e *Email) buildMessage(ev model.Event, from *mail.Address, rcpts []*mail.Address) []byte {
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	to := make([]string, len(rcpts))
	for i, r := range rcpts {
		to[i] = r.String()
	}
	var b strings.Builder
	header := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	header("From", from.String())
	header("To", strings.Join(to, ", "))
	header("Subject", encodeSubject(subjectFor(ev)))
	header("Date", now().Format(time.RFC1123Z))
	header("Message-ID", messageID(from.Address))
	header("MIME-Version", "1.0")
	header("Content-Type", `text/plain; charset="utf-8"`)
	header("Content-Transfer-Encoding", "quoted-printable")
	header("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")

	qp := quotedprintable.NewWriter(&stringWriter{&b})
	_, _ = io.WriteString(qp, strings.ReplaceAll(FormatEvent(ev), "\n", "\r\n")+"\r\n")
	_ = qp.Close()
	return []byte(b.String())
}

type stringWriter struct{ b *strings.Builder }

func (w *stringWriter) Write(p []byte) (int, error) { return w.b.Write(p) }

// subjectFor builds "[CRITICAL] <summary>" with the summary flattened to one
// line and trimmed.
func subjectFor(ev model.Event) string {
	tag := "WARNING"
	switch {
	case ev.State == model.StateResolved:
		tag = "RESOLVED"
	case ev.Severity == model.SeverityCritical:
		tag = "CRITICAL"
	}
	if ev.State == model.StateReminder {
		tag += " reminder"
	}
	return "[" + tag + "] " + trimRunes(oneLine(ev.Summary), maxSubjectSummary)
}

// oneLine replaces every control character (CR and LF included) with a space.
func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

func trimRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return strings.TrimSpace(string(r[:n-1])) + "…"
}

// encodeSubject applies RFC 2047 encoding when the subject is not plain ASCII.
func encodeSubject(s string) string { return mime.QEncoding.Encode("utf-8", s) }

func messageID(fromAddr string) string {
	domain := "lockkeeper.invalid"
	if i := strings.LastIndexByte(fromAddr, '@'); i >= 0 {
		if d := fromAddr[i+1:]; isPlainDomain(d) {
			domain = d
		}
	}
	var r [12]byte
	_, _ = rand.Read(r[:])
	return fmt.Sprintf("<%s.%d@%s>", hex.EncodeToString(r[:]), time.Now().UnixNano(), domain)
}

func isPlainDomain(d string) bool {
	if d == "" {
		return false
	}
	for _, r := range d {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

// smtpError converts a protocol or network error into a short, scrubbed one.
// Context expiry is reported as such, because the socket close that follows it
// would otherwise surface as an opaque "use of closed connection".
func (e *Email) smtpError(ctx context.Context, step string, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("email: %s: %w", step, cerr)
	}
	var ne *net.OpError
	if errors.As(err, &ne) && ne.Err != nil {
		err = ne.Err // drops addresses; keeps the cause
	}
	out := fmt.Errorf("email: %s: %s", step, sanitizeBody(truncate(err.Error(), maxServerReply)))
	switch {
	case isPermanentSMTP(err), isCertError(err):
		return permanentError{err: out}
	}
	return out
}

func isPermanentSMTP(err error) bool {
	var te *textproto.Error
	return errors.As(err, &te) && te.Code >= 500
}

func isCertError(err error) bool {
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	var cv *tls.CertificateVerificationError
	return errors.As(err, &ua) || errors.As(err, &hn) || errors.As(err, &ci) || errors.As(err, &cv)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// scrub removes the password, and the base64 form that appears in AUTH PLAIN,
// from an error. Servers should never echo either, but the cost of checking is
// nil and the cost of a leak is not.
func (e *Email) scrub(err error) error {
	pw := e.Password.Reveal()
	if pw == "" {
		return err
	}
	blob := base64.StdEncoding.EncodeToString([]byte("\x00" + e.Username + "\x00" + pw))
	msg := err.Error()
	clean := strings.ReplaceAll(strings.ReplaceAll(msg, blob, "***"), pw, "***")
	if clean == msg {
		return err
	}
	if errors.As(err, new(permanentError)) {
		return permanentError{err: errors.New(clean)}
	}
	return errors.New(clean)
}
