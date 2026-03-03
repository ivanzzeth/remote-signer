package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/logger"
)

// PushoverClient Pushover API客户端
type PushoverClient struct {
	appToken   string
	retry      int
	expire     int
	maxRetries int
	retryDelay time.Duration
	httpClient *http.Client
}

// NewPushoverClient 创建Pushover客户端
func NewPushoverClient(appToken string, retry, expire, maxRetries, retryDelay int) (*PushoverClient, error) {
	if appToken == "" {
		return nil, fmt.Errorf("app token is required")
	}
	if maxRetries <= 0 {
		return nil, fmt.Errorf("max retries must be greater than 0")
	}
	if retryDelay < 0 {
		return nil, fmt.Errorf("retry delay must be non-negative")
	}

	return &PushoverClient{
		appToken:   appToken,
		retry:      retry,
		expire:     expire,
		maxRetries: maxRetries,
		retryDelay: time.Duration(retryDelay) * time.Second,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// PushoverRequest Pushover API请求
type PushoverRequest struct {
	Token    string `json:"token"`
	User     string `json:"user"`
	Message  string `json:"message"`
	Priority int    `json:"priority"`
	Sound    string `json:"sound"`
	Retry    int    `json:"retry"`
	Expire   int    `json:"expire"`
}

// PushoverResponse Pushover API响应
type PushoverResponse struct {
	Status  int      `json:"status"`
	Request string   `json:"request"`
	Errors  []string `json:"errors,omitempty"`
}

// SendNotification 发送通知（支持自定义优先级和声音），带指数退避重试
func (p *PushoverClient) SendNotification(userKey, message string, priority int, sound string) error {
	payload := PushoverRequest{
		Token:    p.appToken,
		User:     userKey,
		Message:  message,
		Priority: priority,
		Sound:    sound,
	}

	// 只有 priority=2 (emergency) 才需要 retry 和 expire
	if priority == 2 {
		payload.Retry = p.retry
		payload.Expire = p.expire
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	log := logger.GetGlobal()
	var lastErr error
	for attempt := 1; attempt <= p.maxRetries; attempt++ {
		if attempt > 1 {
			// 指数退避: retryDelay * 2^(attempt-2)
			delay := p.retryDelay * time.Duration(1<<uint(attempt-2))
			log.Debug().
				Int("attempt", attempt).
				Int("max_retries", p.maxRetries).
				Dur("delay", delay).
				Str("user_key", maskUserKey(userKey)).
				Msg("Retry attempt")
			time.Sleep(delay)
		}

		log.Debug().
			Int("priority", priority).
			Str("sound", sound).
			Str("user_key", maskUserKey(userKey)).
			Int("attempt", attempt).
			Int("max_retries", p.maxRetries).
			Msg("Sending Pushover notification")

		resp, err := p.httpClient.Post(
			"https://api.pushover.net/1/messages.json",
			"application/json",
			bytes.NewBuffer(body),
		)
		if err != nil {
			lastErr = fmt.Errorf("failed to send request: %w", err)
			log.Warn().
				Err(err).
				Int("attempt", attempt).
				Int("max_retries", p.maxRetries).
				Msg("Attempt failed")
			continue
		}

		var result PushoverResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			if closeErr := resp.Body.Close(); closeErr != nil {
				log.Warn().Err(closeErr).Msg("failed to close response body")
			}
			lastErr = fmt.Errorf("failed to decode response: %w", err)
			log.Warn().
				Err(err).
				Int("attempt", attempt).
				Int("max_retries", p.maxRetries).
				Msg("Attempt failed to decode response")
			continue
		}
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("failed to close response body")
		}

		if result.Status != 1 {
			errMsg := "unknown error"
			if len(result.Errors) > 0 {
				errMsg = result.Errors[0]
			}
			lastErr = fmt.Errorf("Pushover API error: %s", errMsg)
			log.Warn().
				Err(lastErr).
				Int("attempt", attempt).
				Int("max_retries", p.maxRetries).
				Msg("Attempt failed")
			continue
		}

		// 成功
		log.Debug().
			Str("request_id", result.Request).
			Int("attempt", attempt).
			Msg("Pushover notification sent successfully")
		return nil
	}

	// 所有重试都失败
	return fmt.Errorf("failed after %d attempts: %w", p.maxRetries, lastErr)
}

// SendEmergencyNotification 发送紧急通知（保持向后兼容）
func (p *PushoverClient) SendEmergencyNotification(userKey, message string) error {
	return p.SendNotification(userKey, message, 2, "persistent")
}

// maskUserKey 遮蔽用户key的部分内容（用于日志）
func maskUserKey(key string) string {
	if len(key) <= 8 {
		return "***"
	}
	return key[:4] + "***" + key[len(key)-4:]
}

// SendToUsers 向多个Pushover用户发送通知
func (p *PushoverClient) SendToUsers(userKeys []string, message string, priority int, sound string) error {
	if len(userKeys) == 0 {
		return fmt.Errorf("user keys are required")
	}
	if message == "" {
		return fmt.Errorf("message is required")
	}

	log := logger.GetGlobal()
	var lastErr error
	successCount := 0

	for _, userKey := range userKeys {
		if err := p.SendNotification(userKey, message, priority, sound); err != nil {
			lastErr = err
			log.Warn().
				Err(err).
				Str("user_key", maskUserKey(userKey)).
				Msg("Failed to send notification to user")
			continue
		}
		successCount++
	}

	if successCount == 0 {
		return fmt.Errorf("failed to send to any user: %w", lastErr)
	}

	if lastErr != nil {
		log.Warn().
			Int("success_count", successCount).
			Int("total_count", len(userKeys)).
			Msg("Some users failed to receive notification")
	}

	return nil
}
