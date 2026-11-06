package service

import (
	"context"
	"fmt"
	"sort"

	"github.com/wisnuvb/lockkeeper/internal/secret"
)

// SecretCheck is the result of verifying that every referenced secret can be resolved.
type SecretCheck struct {
	// Problems are references that could not be resolved (missing env var,
	// missing or too-open file).
	Problems []string
	// Prompts are references that will ask interactively at run time and were
	// therefore not tried.
	Prompts []string
}

// VerifySecrets resolves every secret reference in the configuration (except
// interactive prompts) to catch mistakes before the daemon needs them. Values
// are never returned or printed.
func (s *Service) VerifySecrets(ctx context.Context) SecretCheck {
	type item struct {
		label string
		ref   secret.Ref
	}
	var items []item
	for _, name := range s.databaseNames() {
		items = append(items, item{"databases." + name + ".password", s.cfg.Databases[name].Password})
	}
	if t := s.cfg.Alerts.Channels.Telegram; t != nil {
		items = append(items, item{"alerts.channels.telegram.bot_token", t.BotToken})
	}
	if sl := s.cfg.Alerts.Channels.Slack; sl != nil {
		items = append(items, item{"alerts.channels.slack.webhook_url", sl.WebhookURL})
	}
	if em := s.cfg.Alerts.Channels.Email; em != nil && !em.Password.IsZero() {
		items = append(items, item{"alerts.channels.email.password", em.Password})
	}
	if hb := s.cfg.Monitor.Heartbeat; hb != nil {
		items = append(items, item{"monitor.heartbeat.url", hb.URL})
	}

	var res SecretCheck
	for _, it := range items {
		if it.ref.Prompt {
			res.Prompts = append(res.Prompts, it.label)
			continue
		}
		if _, err := s.deps.Secrets.Resolve(ctx, it.ref, it.label); err != nil {
			res.Problems = append(res.Problems, fmt.Sprintf("%s (%s): %v", it.label, it.ref, err))
		}
	}
	sort.Strings(res.Problems)
	sort.Strings(res.Prompts)
	return res
}
