// Package notify delivers alert events to external channels.
//
// Notifiers receive only model.Event values, which carry identifiers, numbers and
// short summaries: never query text or credentials. Errors are written so that
// they cannot contain webhook URLs or bot tokens.
package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/model"
)

// Notifier sends one event to one channel.
type Notifier interface {
	Name() string
	Send(ctx context.Context, e model.Event) error
}

// HTTPDoer is the part of *http.Client that notifiers use.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// NewHTTPClient returns a client with sane timeouts and no redirect following
// (a redirect could carry a secret URL to another host).
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// FormatEvent renders an event as plain text shared by all channels.
func FormatEvent(e model.Event) string {
	var head string
	switch {
	case e.State == model.StateResolved:
		head = "✅ RESOLVED"
	case e.Severity == model.SeverityCritical:
		head = "🔴 CRITICAL"
	default:
		head = "🟠 WARNING"
	}
	if e.State == model.StateReminder {
		head += " (reminder)"
	}
	var b strings.Builder
	b.WriteString(head)
	b.WriteString("\n")
	b.WriteString(e.Summary)
	if !e.Since.IsZero() && e.State != model.StateResolved {
		fmt.Fprintf(&b, "\nsince %s", e.Since.UTC().Format("2006-01-02 15:04 UTC"))
	}
	return b.String()
}

// permanentError marks failures that retrying cannot fix (bad token, bad chat id).
type permanentError struct{ err error }

func (p permanentError) Error() string { return p.err.Error() }
func (p permanentError) Unwrap() error { return p.err }

// retryAfterError asks the retry loop to wait at least d.
type retryAfterError struct {
	err error
	d   time.Duration
}

func (r retryAfterError) Error() string { return r.err.Error() }
func (r retryAfterError) Unwrap() error { return r.err }

// transportError strips the request URL (which contains secrets) from a client
// error, keeping only the underlying cause.
func transportError(channel string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return fmt.Errorf("%s: request failed: %w", channel, err)
}

// statusError converts a non-2xx response into an error without echoing
// anything that could contain a secret. Only a short slice of the body is kept.
func statusError(channel string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	err := fmt.Errorf("%s: HTTP %d: %s", channel, resp.StatusCode, sanitizeBody(string(body)))
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return retryAfterError{err: err, d: parseRetryAfter(resp.Header.Get("Retry-After"))}
	case resp.StatusCode >= 500:
		return err
	default:
		return permanentError{err: err}
	}
}

func sanitizeBody(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

func parseRetryAfter(v string) time.Duration {
	var secs int
	if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &secs); err == nil && secs > 0 {
		if secs > 60 {
			secs = 60
		}
		return time.Duration(secs) * time.Second
	}
	return 0
}

// Retrying wraps a Notifier with bounded retries and exponential backoff.
type Retrying struct {
	Notifier
	Attempts  int           // total attempts, default 3
	BaseDelay time.Duration // default 1s
	Sleep     func(context.Context, time.Duration) error
}

// Send implements Notifier.
func (r Retrying) Send(ctx context.Context, e model.Event) error {
	attempts := r.Attempts
	if attempts <= 0 {
		attempts = 3
	}
	delay := r.BaseDelay
	if delay == 0 {
		delay = time.Second
	}
	sleep := r.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	var err error
	for i := 0; i < attempts; i++ {
		if err = r.Notifier.Send(ctx, e); err == nil {
			return nil
		}
		var perm permanentError
		if errors.As(err, &perm) || ctx.Err() != nil || i == attempts-1 {
			break
		}
		wait := delay << i
		var ra retryAfterError
		if errors.As(err, &ra) && ra.d > wait {
			wait = ra.d
		}
		if serr := sleep(ctx, wait); serr != nil {
			break
		}
	}
	return err
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
