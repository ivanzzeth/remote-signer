package server

import (
	"github.com/ivanzzeth/remote-signer/internal/notify"
	"github.com/ivanzzeth/remote-signer/internal/settings"
)

// notifyYAMLToSnapshot lifts cfg.Notify (provider service config) and
// cfg.NotifyChannel (per-provider recipient lists) into the composite
// NotifySnapshot used by the runtime settings store.
func notifyYAMLToSnapshot(cfg *notify.Config, channels *notify.Channel) *settings.NotifySnapshot {
	snap := &settings.NotifySnapshot{}
	if cfg != nil {
		if cfg.Slack != nil {
			snap.Providers.Slack = &settings.NotifySlackProvider{
				Enabled:  cfg.Slack.Enabled,
				BotToken: cfg.Slack.BotToken,
			}
		}
		if cfg.Pushover != nil {
			snap.Providers.Pushover = &settings.NotifyPushoverProvider{
				Enabled:    cfg.Pushover.Enabled,
				AppToken:   cfg.Pushover.AppToken,
				Retry:      cfg.Pushover.Retry,
				Expire:     cfg.Pushover.Expire,
				MaxRetries: cfg.Pushover.MaxRetries,
				RetryDelay: cfg.Pushover.RetryDelay,
			}
		}
		if cfg.Webhook != nil {
			snap.Providers.Webhook = &settings.NotifyWebhookProvider{
				Enabled: cfg.Webhook.Enabled,
				Headers: copyStringMap(cfg.Webhook.Headers),
				Timeout: cfg.Webhook.Timeout,
			}
		}
		if cfg.Telegram != nil {
			snap.Providers.Telegram = &settings.NotifyTelegramProvider{
				Enabled:  cfg.Telegram.Enabled,
				BotToken: cfg.Telegram.BotToken,
			}
		}
	}
	if channels != nil {
		snap.Channels = settings.NotifyChannels{
			Slack:    append([]string(nil), channels.Slack...),
			Pushover: append([]string(nil), channels.Pushover...),
			Webhook:  append([]string(nil), channels.Webhook...),
			Telegram: append([]string(nil), channels.Telegram...),
		}
	}
	return snap
}

// applyNotifySnapshot overlays the DB-backed notify snapshot back onto the
// cfg.Notify / cfg.NotifyChannel structs so the existing downstream wiring
// (NewNotifyService, audit monitor, budget alerter) picks up DB values
// without each consumer needing to read the Manager directly.
func applyNotifySnapshot(cfg *notify.Config, channels *notify.Channel, s *settings.NotifySnapshot) {
	if s == nil {
		return
	}
	// Providers
	cfg.Slack = nil
	if p := s.Providers.Slack; p != nil {
		cfg.Slack = &notify.SlackConfig{Enabled: p.Enabled, BotToken: p.BotToken}
	}
	cfg.Pushover = nil
	if p := s.Providers.Pushover; p != nil {
		cfg.Pushover = &notify.PushoverConfig{
			Enabled:    p.Enabled,
			AppToken:   p.AppToken,
			Retry:      p.Retry,
			Expire:     p.Expire,
			MaxRetries: p.MaxRetries,
			RetryDelay: p.RetryDelay,
		}
	}
	cfg.Webhook = nil
	if p := s.Providers.Webhook; p != nil {
		cfg.Webhook = &notify.WebhookConfig{
			Enabled: p.Enabled,
			Headers: copyStringMap(p.Headers),
			Timeout: p.Timeout,
		}
	}
	cfg.Telegram = nil
	if p := s.Providers.Telegram; p != nil {
		cfg.Telegram = &notify.TelegramConfig{Enabled: p.Enabled, BotToken: p.BotToken}
	}
	// Channels
	channels.Slack = append([]string(nil), s.Channels.Slack...)
	channels.Pushover = append([]string(nil), s.Channels.Pushover...)
	channels.Webhook = append([]string(nil), s.Channels.Webhook...)
	channels.Telegram = append([]string(nil), s.Channels.Telegram...)
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
