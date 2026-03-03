package notify

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/logger"
	"github.com/rs/zerolog"
)

// Channel specifies which concrete channels to deliver to.
type Channel struct {
	Slack    []string `yaml:"slack,omitempty"`    // Slack channel IDs
	Pushover []string `yaml:"pushover,omitempty"` // Pushover user keys
	Webhook  []string `yaml:"webhook,omitempty"`   // Webhook URLs
	Telegram []string `yaml:"telegram,omitempty"` // Telegram chat IDs or @channel
}

// SlackConfig Slack配置
type SlackConfig struct {
	Enabled  bool   `yaml:"enabled"`
	BotToken string `yaml:"bot_token"`
}

// PushoverConfig Pushover配置
type PushoverConfig struct {
	Enabled    bool `yaml:"enabled"`
	AppToken   string `yaml:"app_token"`
	Retry      int  `yaml:"retry"`
	Expire     int  `yaml:"expire"`
	MaxRetries int  `yaml:"max_retries"`
	RetryDelay int  `yaml:"retry_delay"`
}

// WebhookConfig configures the generic webhook notification channel.
type WebhookConfig struct {
	Enabled bool              `yaml:"enabled"`
	Headers map[string]string `yaml:"headers,omitempty"` // e.g. Authorization: Bearer ...
	Timeout time.Duration     `yaml:"timeout,omitempty"` // HTTP client timeout
}

// TelegramConfig configures the Telegram Bot notification channel.
type TelegramConfig struct {
	Enabled  bool   `yaml:"enabled"`
	BotToken string `yaml:"bot_token"` // Bot token from @BotFather
}

// Config is the root notification service configuration.
type Config struct {
	Slack    *SlackConfig    `yaml:"slack,omitempty"`
	Pushover *PushoverConfig `yaml:"pushover,omitempty"`
	Webhook  *WebhookConfig  `yaml:"webhook,omitempty"`
	Telegram *TelegramConfig `yaml:"telegram,omitempty"`
}

// notifyMessage 内部消息结构
type notifyMessage struct {
	channel  *Channel
	message  string
	priority int
	sound    string
}

// NotifyService 统一通知服务
// 使用异步发送模式，Send方法将消息放入channel，由消费goroutine实际发送
type NotifyService struct {
	slackClient    *SlackClient
	pushoverClient *PushoverClient
	webhookClient  *WebhookClient
	telegramClient *TelegramClient
	logger         zerolog.Logger

	// 异步发送相关
	msgChan chan notifyMessage
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewNotifyService 创建通知服务
// 创建后需要调用Start()启动消费goroutine
func NewNotifyService(cfg *Config) (*NotifyService, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	log := logger.GetGlobal()
	service := &NotifyService{
		logger:  log,
		msgChan: make(chan notifyMessage, 1000), // 缓冲1000条消息
	}

	// 初始化 Slack 客户端
	if cfg.Slack != nil && cfg.Slack.Enabled {
		if cfg.Slack.BotToken == "" {
			return nil, fmt.Errorf("slack bot token is required when enabled")
		}
		slackClient, err := NewSlackClient(cfg.Slack.BotToken)
		if err != nil {
			return nil, fmt.Errorf("failed to create slack client: %w", err)
		}
		service.slackClient = slackClient
		log.Debug().Msg("Slack client initialized")
	}

	// 初始化 Pushover 客户端
	if cfg.Pushover != nil && cfg.Pushover.Enabled {
		if cfg.Pushover.AppToken == "" {
			return nil, fmt.Errorf("pushover app token is required when enabled")
		}
		// 设置默认值
		retry := cfg.Pushover.Retry
		if retry == 0 {
			retry = 30 // 默认30秒
		}
		expire := cfg.Pushover.Expire
		if expire == 0 {
			expire = 300 // 默认300秒
		}
		maxRetries := cfg.Pushover.MaxRetries
		if maxRetries == 0 {
			maxRetries = 3 // 默认3次
		}
		retryDelay := cfg.Pushover.RetryDelay
		if retryDelay == 0 {
			retryDelay = 1 // 默认1秒
		}

		pushoverClient, err := NewPushoverClient(cfg.Pushover.AppToken, retry, expire, maxRetries, retryDelay)
		if err != nil {
			return nil, fmt.Errorf("failed to create pushover client: %w", err)
		}
		service.pushoverClient = pushoverClient
		log.Debug().Msg("Pushover client initialized")
	}

	// Initialize Webhook client
	if cfg.Webhook != nil && cfg.Webhook.Enabled {
		timeout := cfg.Webhook.Timeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		webhookClient, err := NewWebhookClient(timeout, cfg.Webhook.Headers)
		if err != nil {
			return nil, fmt.Errorf("failed to create webhook client: %w", err)
		}
		service.webhookClient = webhookClient
		log.Debug().Msg("Webhook client initialized")
	}

	// Initialize Telegram client
	if cfg.Telegram != nil && cfg.Telegram.Enabled {
		if cfg.Telegram.BotToken == "" {
			return nil, fmt.Errorf("telegram bot token is required when enabled")
		}
		telegramClient, err := NewTelegramClient(cfg.Telegram.BotToken)
		if err != nil {
			return nil, fmt.Errorf("failed to create telegram client: %w", err)
		}
		service.telegramClient = telegramClient
		log.Debug().Msg("Telegram client initialized")
	}

	return service, nil
}

// Start 启动消费goroutine
func (n *NotifyService) Start(ctx context.Context) {
	n.ctx, n.cancel = context.WithCancel(ctx)
	n.wg.Add(1)
	go n.consumeLoop()
	n.logger.Info().Msg("NotifyService started")
}

// Stop 停止服务，等待所有消息发送完成
func (n *NotifyService) Stop() {
	if n.cancel != nil {
		n.cancel()
	}
	n.wg.Wait()
	n.logger.Info().Msg("NotifyService stopped")
}

// consumeLoop 消费goroutine，持续从channel读取消息并发送
func (n *NotifyService) consumeLoop() {
	defer n.wg.Done()
	for {
		select {
		case <-n.ctx.Done():
			// 消费完剩余消息后退出
			for {
				select {
				case msg := <-n.msgChan:
					n.sendSync(msg.channel, msg.message, msg.priority, msg.sound)
				default:
					return
				}
			}
		case msg := <-n.msgChan:
			n.sendSync(msg.channel, msg.message, msg.priority, msg.sound)
		}
	}
}

// Send 异步发送消息到指定渠道
// 将消息放入channel，由消费goroutine实际发送，不阻塞调用方
func (n *NotifyService) Send(channel *Channel, message string) error {
	if channel == nil {
		return fmt.Errorf("channel is required")
	}
	if message == "" {
		return fmt.Errorf("message is required")
	}

	// 非阻塞放入channel
	select {
	case n.msgChan <- notifyMessage{channel: channel, message: message}:
		return nil
	default:
		n.logger.Warn().Msg("Notification channel full, message dropped")
		return fmt.Errorf("notification channel full")
	}
}

// sendSync 同步发送消息（内部方法，由消费goroutine调用）
func (n *NotifyService) sendSync(channel *Channel, message string, priority int, sound string) {
	if channel == nil || message == "" {
		return
	}

	// 发送到 Slack channels
	if len(channel.Slack) > 0 {
		if n.slackClient == nil {
			n.logger.Warn().Msg("Slack client not initialized, skipping Slack channels")
		} else {
			n.logger.Debug().
				Int("channel_count", len(channel.Slack)).
				Strs("channels", channel.Slack).
				Msg("Sending notification to Slack channels")
			if err := n.slackClient.SendToChannels(channel.Slack, message); err != nil {
				n.logger.Warn().
					Err(err).
					Int("channel_count", len(channel.Slack)).
					Msg("Failed to send to Slack channels")
			} else {
				n.logger.Info().
					Int("channel_count", len(channel.Slack)).
					Msg("Successfully sent notification to Slack channels")
			}
		}
	}

	// 发送到 Pushover users
	if len(channel.Pushover) > 0 {
		if n.pushoverClient == nil {
			n.logger.Warn().Msg("Pushover client not initialized, skipping Pushover users")
		} else {
			if err := n.pushoverClient.SendToUsers(channel.Pushover, message, priority, sound); err != nil {
				n.logger.Warn().
					Err(err).
					Msg("Failed to send to Pushover users")
			}
		}
	}

	// Send to Webhook URLs
	if len(channel.Webhook) > 0 {
		if n.webhookClient == nil {
			n.logger.Warn().Msg("Webhook client not initialized, skipping webhook URLs")
		} else {
			if err := n.webhookClient.SendToURLs(channel.Webhook, message); err != nil {
				n.logger.Warn().
					Err(err).
					Int("url_count", len(channel.Webhook)).
					Msg("Failed to send to webhook URLs")
			} else {
				n.logger.Info().
					Int("url_count", len(channel.Webhook)).
					Msg("Successfully sent notification to webhook URLs")
			}
		}
	}

	// Send to Telegram chats
	if len(channel.Telegram) > 0 {
		if n.telegramClient == nil {
			n.logger.Warn().Msg("Telegram client not initialized, skipping Telegram chats")
		} else {
			n.logger.Debug().
				Int("chat_count", len(channel.Telegram)).
				Strs("chats", channel.Telegram).
				Msg("Sending notification to Telegram chats")
			if err := n.telegramClient.SendToChats(channel.Telegram, message); err != nil {
				n.logger.Warn().
					Err(err).
					Int("chat_count", len(channel.Telegram)).
					Msg("Failed to send to Telegram chats")
			}
		}
	}
}

// SendWithPriority 异步发送消息到指定渠道，支持 Pushover 的优先级和声音配置
func (n *NotifyService) SendWithPriority(channel *Channel, message string, priority int, sound string) error {
	if channel == nil {
		return fmt.Errorf("channel is required")
	}
	if message == "" {
		return fmt.Errorf("message is required")
	}

	// 非阻塞放入channel
	select {
	case n.msgChan <- notifyMessage{channel: channel, message: message, priority: priority, sound: sound}:
		return nil
	default:
		n.logger.Warn().Msg("Notification channel full, message dropped")
		return fmt.Errorf("notification channel full")
	}
}
