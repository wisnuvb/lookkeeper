// Package redact scrubs secrets from text before it reaches a log, an error
// message or a child-process capture file.
//
// It is a defence in depth: the primary protection is that secrets are held in
// secret.Value and never formatted. Redaction catches what slips through (for
// example a driver error that echoes a connection string).
package redact

import (
	"bytes"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Mask replaces every redacted value.
const Mask = "***"

// MinSecretLen is the shortest secret that is registered for literal scrubbing.
// Scrubbing one- or two-character strings would mangle ordinary text; such
// secrets are still protected by the secret.Value type.
const MinSecretLen = 4

var (
	// scheme://user:password@host — scrub the password part.
	uriPassword = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://[^:/?#\s@]+:)[^@/?#\s]+(@)`)
	// password=... / pwd=... / token=... style key-value pairs (libpq, DSNs, URLs).
	kvPassword = regexp.MustCompile(`(?i)\b(password|passwd|pwd|token|secret|api[_-]?key)(\s*[=:]\s*)('[^']*'|"[^"]*"|[^\s&;,]+)`)
	// Telegram bot tokens inside URLs: /bot<id>:<token>/
	botToken = regexp.MustCompile(`/bot[0-9]+:[A-Za-z0-9_\-]+`)
)

// Redactor holds the set of literal secrets to scrub. It is safe for concurrent use.
type Redactor struct {
	mu      sync.RWMutex
	secrets []string // longest first so that a secret containing another is scrubbed whole
}

// New returns an empty Redactor. Pattern-based scrubbing is always active.
func New() *Redactor { return &Redactor{} }

// Add registers literal secrets. Values shorter than MinSecretLen are ignored.
func (r *Redactor) Add(secrets ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range secrets {
		if len(s) < MinSecretLen || r.hasLocked(s) {
			continue
		}
		r.secrets = append(r.secrets, s)
	}
	sort.Slice(r.secrets, func(i, j int) bool { return len(r.secrets[i]) > len(r.secrets[j]) })
}

func (r *Redactor) hasLocked(s string) bool {
	for _, x := range r.secrets {
		if x == s {
			return true
		}
	}
	return false
}

// String returns s with all known secrets and credential patterns masked.
func (r *Redactor) String(s string) string {
	r.mu.RLock()
	secrets := r.secrets
	r.mu.RUnlock()
	for _, sec := range secrets {
		s = strings.ReplaceAll(s, sec, Mask)
	}
	s = uriPassword.ReplaceAllString(s, "${1}"+Mask+"${2}")
	s = kvPassword.ReplaceAllString(s, "${1}${2}"+Mask)
	s = botToken.ReplaceAllString(s, "/bot"+Mask)
	return s
}

// Error returns a copy of err's text with secrets masked, or nil.
func (r *Redactor) Error(err error) error {
	if err == nil {
		return nil
	}
	return redactedError{msg: r.String(err.Error()), cause: err}
}

type redactedError struct {
	msg   string
	cause error
}

func (e redactedError) Error() string { return e.msg }

// Unwrap keeps errors.Is / errors.As working on the original error.
func (e redactedError) Unwrap() error { return e.cause }

// Writer wraps w so that everything written through it is scrubbed. Output is
// buffered per line so that a secret split across two Write calls (typical for
// child-process pipes) is still caught. Call Close to flush a trailing partial line.
func (r *Redactor) Writer(w io.Writer) io.WriteCloser {
	return &lineWriter{r: r, w: w}
}

type lineWriter struct {
	r   *Redactor
	w   io.Writer
	mu  sync.Mutex
	buf []byte
}

// maxLine bounds memory if a producer never emits a newline.
const maxLine = 64 * 1024

func (lw *lineWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	lw.buf = append(lw.buf, p...)
	for {
		i := bytes.IndexByte(lw.buf, '\n')
		if i < 0 {
			break
		}
		if err := lw.emit(lw.buf[:i+1]); err != nil {
			return 0, err
		}
		lw.buf = lw.buf[i+1:]
	}
	if len(lw.buf) > maxLine {
		if err := lw.emit(lw.buf); err != nil {
			return 0, err
		}
		lw.buf = lw.buf[:0]
	}
	return len(p), nil
}

func (lw *lineWriter) emit(line []byte) error {
	_, err := io.WriteString(lw.w, lw.r.String(string(line)))
	return err
}

// Close flushes any partial trailing line. It does not close the underlying writer.
func (lw *lineWriter) Close() error {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if len(lw.buf) == 0 {
		return nil
	}
	err := lw.emit(lw.buf)
	lw.buf = nil
	return err
}
