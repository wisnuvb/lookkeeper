package service

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/alert/notify"
	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/model"
)

// buildChannels resolves secrets and constructs the configured notifiers,
// wrapped with retries, keyed by channel name.
func (s *Service) buildChannels(ctx context.Context) (map[string]notify.Notifier, error) {
	out := map[string]notify.Notifier{}
	wrap := func(n notify.Notifier) notify.Notifier {
		return notify.Retrying{Notifier: n, Attempts: 3, BaseDelay: time.Second, Sleep: s.deps.RetrySleep}
	}
	if t := s.cfg.Alerts.Channels.Telegram; t != nil {
		token, err := s.resolveSecret(ctx, t.BotToken, "telegram bot token")
		if err != nil {
			return nil, err
		}
		out["telegram"] = wrap(&notify.Telegram{Token: token, ChatID: t.ChatID, Client: s.httpClient(), BaseURL: s.deps.TelegramBaseURL})
	}
	if sl := s.cfg.Alerts.Channels.Slack; sl != nil {
		hook, err := s.resolveSecret(ctx, sl.WebhookURL, "slack webhook URL")
		if err != nil {
			return nil, err
		}
		out["slack"] = wrap(&notify.Slack{Webhook: hook, Client: s.httpClient()})
	}
	if em := s.cfg.Alerts.Channels.Email; em != nil {
		n, err := s.newEmail(ctx, em)
		if err != nil {
			return nil, err
		}
		out["email"] = wrap(n)
	}
	return out, nil
}

// newEmail builds the SMTP notifier. The password is resolved here, registered
// with the redactor, and held only in a secret.Value.
func (s *Service) newEmail(ctx context.Context, em *config.Email) (*notify.Email, error) {
	n := &notify.Email{
		Host: em.Host, Port: em.Port, TLS: em.TLS, Username: em.Username,
		From: em.From, To: em.To, AllowInsecure: em.AllowInsecure, Now: s.deps.Now,
	}
	if !em.Password.IsZero() {
		pw, err := s.resolveSecret(ctx, em.Password, "email password")
		if err != nil {
			return nil, err
		}
		n.Password = pw
	}
	if em.CAFile != "" {
		pem, err := os.ReadFile(em.CAFile)
		if err != nil {
			var pe *fs.PathError
			if errors.As(err, &pe) {
				err = pe.Err
			}
			return nil, fmt.Errorf("alerts.channels.email.ca_file %s: %w", em.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("alerts.channels.email.ca_file %s: no PEM certificates found", em.CAFile)
		}
		n.RootCAs = pool
	}
	return n, nil
}

// buildRoutes turns the configured routes into dispatcher routes. With no routes
// configured, every event goes to every channel.
func (s *Service) buildRoutes(channels map[string]notify.Notifier) []notify.Route {
	if len(s.cfg.Alerts.Routes) == 0 {
		var all []notify.Notifier
		for _, name := range s.cfg.ChannelNames() {
			all = append(all, channels[name])
		}
		if len(all) == 0 {
			return nil
		}
		return []notify.Route{{Notifiers: all}}
	}
	var out []notify.Route
	for _, r := range s.cfg.Alerts.Routes {
		route := notify.Route{}
		for _, sev := range r.Match.Severity {
			route.Severities = append(route.Severities, model.Severity(sev))
		}
		for _, name := range r.To {
			route.Notifiers = append(route.Notifiers, channels[name])
		}
		out = append(out, route)
	}
	return out
}

// ChannelResult is the outcome of sending a test alert to one channel.
type ChannelResult struct {
	Channel string
	Err     error
}

// AlertsTest sends a synthetic alert to the named channel, or to all configured
// channels when channel is empty. Delivery is synchronous so that problems with
// tokens or chat IDs surface immediately.
func (s *Service) AlertsTest(ctx context.Context, channel string) ([]ChannelResult, error) {
	channels, err := s.buildChannels(ctx)
	if err != nil {
		return nil, s.redactErr(err)
	}
	if len(channels) == 0 {
		return nil, fmt.Errorf("no notification channel is configured")
	}
	var names []string
	if channel != "" {
		if _, ok := channels[channel]; !ok {
			return nil, fmt.Errorf("channel %q is not configured (configured: %s)", channel, strings.Join(s.cfg.ChannelNames(), ", "))
		}
		names = []string{channel}
	} else {
		names = s.cfg.ChannelNames()
	}
	now := s.deps.Now()
	ev := model.Event{
		Rule: "lockkeeper.test", Target: "lockkeeper", State: model.StateFiring, Severity: model.SeverityWarning,
		Since: now, At: now,
		Summary: "Test alert from Lockkeeper: if you can read this, notifications work.",
	}
	var results []ChannelResult
	for _, name := range names {
		err := channels[name].Send(ctx, ev)
		results = append(results, ChannelResult{Channel: name, Err: s.redactErr(err)})
	}
	return results, nil
}
