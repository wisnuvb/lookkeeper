package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/wisnuvb/lockkeeper/internal/model"
	"github.com/wisnuvb/lockkeeper/internal/secret"
)

// DefaultTelegramBaseURL is the public Telegram Bot API endpoint.
const DefaultTelegramBaseURL = "https://api.telegram.org"

// Telegram sends messages through a bot.
type Telegram struct {
	Token   secret.Value
	ChatID  string
	Client  HTTPDoer
	BaseURL string // override for tests
}

// Name implements Notifier.
func (t *Telegram) Name() string { return "telegram" }

// Send implements Notifier.
func (t *Telegram) Send(ctx context.Context, e model.Event) error {
	base := t.BaseURL
	if base == "" {
		base = DefaultTelegramBaseURL
	}
	payload, _ := json.Marshal(map[string]any{
		"chat_id":                  t.ChatID,
		"text":                     FormatEvent(e),
		"disable_web_page_preview": true,
	})
	// The token is part of the URL by Telegram's design; it must never reach a log.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/bot"+t.Token.Reveal()+"/sendMessage", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("telegram: build request: %w", permanentError{err: fmt.Errorf("invalid bot token or base URL")})
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.Client.Do(req)
	if err != nil {
		return transportError("telegram", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return statusError("telegram", resp)
	}
	return nil
}

// Slack posts to an incoming webhook.
type Slack struct {
	Webhook secret.Value
	Client  HTTPDoer
}

// Name implements Notifier.
func (s *Slack) Name() string { return "slack" }

// escapeSlack escapes the three characters Slack treats specially in text.
func escapeSlack(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// Send implements Notifier.
func (s *Slack) Send(ctx context.Context, e model.Event) error {
	payload, _ := json.Marshal(map[string]any{"text": escapeSlack(FormatEvent(e))})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Webhook.Reveal(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("slack: %w", permanentError{err: fmt.Errorf("invalid webhook URL")})
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.Do(req)
	if err != nil {
		return transportError("slack", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return statusError("slack", resp)
	}
	return nil
}

// Heartbeat pings a URL to prove Lockkeeper itself is alive (dead-man switch).
type Heartbeat struct {
	URL    secret.Value
	Client HTTPDoer
}

// Ping sends one GET request.
func (h *Heartbeat) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.URL.Reveal(), nil)
	if err != nil {
		return fmt.Errorf("heartbeat: invalid URL")
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return transportError("heartbeat", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return statusError("heartbeat", resp)
	}
	return nil
}
