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
		// ⛔ Providers 现在是 *NotifyProviders,必须先建出来再往里写 ——
		// 指针化之后 `snap.Providers.Slack = …` 是在解引用 nil。
		// ⚠️ 这一类错误**编译器看不见**(Go 对指针字段自动解引用),只有真跑到
		// 才炸;2026-09-16 就是被这一行的 panic 逮住的。
		//
		// ⚠️ cfg 非 nil 时无条件建出 providers 块,哪怕里面一个 provider 都没有:
		// 这是**启动播种**路径,它给出的是 YAML 的完整状态 ——「配置里有 notify 这
		// 一块,只是没启用任何 provider」与「根本没提到它」是两件事,后者才是 nil。
		providers := &settings.NotifyProviders{}
		if cfg.Slack != nil {
			providers.Slack = &settings.NotifySlackProvider{
				Enabled:  cfg.Slack.Enabled,
				BotToken: cfg.Slack.BotToken,
			}
		}
		if cfg.Pushover != nil {
			providers.Pushover = &settings.NotifyPushoverProvider{
				Enabled:    cfg.Pushover.Enabled,
				AppToken:   cfg.Pushover.AppToken,
				Retry:      cfg.Pushover.Retry,
				Expire:     cfg.Pushover.Expire,
				MaxRetries: cfg.Pushover.MaxRetries,
				RetryDelay: cfg.Pushover.RetryDelay,
			}
		}
		if cfg.Webhook != nil {
			providers.Webhook = &settings.NotifyWebhookProvider{
				Enabled: cfg.Webhook.Enabled,
				Headers: copyStringMap(cfg.Webhook.Headers),
				Timeout: cfg.Webhook.Timeout,
			}
		}
		if cfg.Telegram != nil {
			providers.Telegram = &settings.NotifyTelegramProvider{
				Enabled:  cfg.Telegram.Enabled,
				BotToken: cfg.Telegram.BotToken,
			}
		}
		snap.Providers = providers
	}
	if channels != nil {
		snap.Channels = &settings.NotifyChannels{
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
	// ⛔ 两块都可能是 nil(「这次没提到它」),先取成值再读 —— 直接写
	// `s.Providers.Slack` 是在解引用 nil,而 Go 的自动解引用让**编译器看不见**
	// 这件事。⚠️ nil 读成零值块的效果与指针化之前一致:没有 provider、没有收件人。
	var provs settings.NotifyProviders
	if s.Providers != nil {
		provs = *s.Providers
	}
	var chans settings.NotifyChannels
	if s.Channels != nil {
		chans = *s.Channels
	}
	// Providers
	cfg.Slack = nil
	if p := provs.Slack; p != nil {
		cfg.Slack = &notify.SlackConfig{Enabled: p.Enabled, BotToken: p.BotToken}
	}
	cfg.Pushover = nil
	if p := provs.Pushover; p != nil {
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
	if p := provs.Webhook; p != nil {
		cfg.Webhook = &notify.WebhookConfig{
			Enabled: p.Enabled,
			Headers: copyStringMap(p.Headers),
			Timeout: p.Timeout,
		}
	}
	cfg.Telegram = nil
	if p := provs.Telegram; p != nil {
		cfg.Telegram = &notify.TelegramConfig{Enabled: p.Enabled, BotToken: p.BotToken}
	}
	// Channels
	channels.Slack = append([]string(nil), chans.Slack...)
	channels.Pushover = append([]string(nil), chans.Pushover...)
	channels.Webhook = append([]string(nil), chans.Webhook...)
	channels.Telegram = append([]string(nil), chans.Telegram...)
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
