package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/logger"
)

// PushoverClient is the Pushover API client for sending notifications.
type PushoverClient struct {
	appToken   string
	retry      int
	expire     int
	maxRetries int
	retryDelay time.Duration
	httpClient *http.Client
}

// NewPushoverClient creates a Pushover client.
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

// PushoverRequest is the request body for the Pushover API.
type PushoverRequest struct {
	Token    string `json:"token"`
	User     string `json:"user"`
	Message  string `json:"message"`
	Priority int    `json:"priority"`
	Sound    string `json:"sound"`
	Retry    int    `json:"retry"`
	Expire   int    `json:"expire"`
}

// PushoverResponse is the response from the Pushover API.
type PushoverResponse struct {
	Status  int      `json:"status"`
	Request string   `json:"request"`
	Errors  []string `json:"errors,omitempty"`
}

// SendNotification sends a notification with optional priority and sound; uses exponential backoff retry.
func (p *PushoverClient) SendNotification(userKey, message string, priority int, sound string) error {
	payload := PushoverRequest{
		Token:    p.appToken,
		User:     userKey,
		Message:  message,
		Priority: priority,
		Sound:    sound,
	}

	// Only priority=2 (emergency) uses retry and expire
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
			// Exponential backoff: retryDelay * 2^(attempt-2)
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
			//lint:ignore ST1005 专有名词(Slack/Pushover)开头 —— Go 风格指南允许
			lastErr = fmt.Errorf("Pushover API error: %s", errMsg)
			log.Warn().
				Err(lastErr).
				Int("attempt", attempt).
				Int("max_retries", p.maxRetries).
				Msg("Attempt failed")
			continue
		}

		log.Debug().
			Str("request_id", result.Request).
			Int("attempt", attempt).
			Msg("Pushover notification sent successfully")
		return nil
	}

	return fmt.Errorf("failed after %d attempts: %w", p.maxRetries, lastErr)
}

// SendEmergencyNotification sends an emergency notification (backward compatible).
func (p *PushoverClient) SendEmergencyNotification(userKey, message string) error {
	return p.SendNotification(userKey, message, 2, "persistent")
}

// maskUserKey masks part of the user key for logging.
func maskUserKey(key string) string {
	if len(key) <= 8 {
		return "***"
	}
	return key[:4] + "***" + key[len(key)-4:]
}

// pushoverUsers is the Pushover fan-out's half of the strings — see fanout.go.
// It is the only target that masks the recipient: a Pushover user key is a
// credential, and the log is not the place for it.
var pushoverUsers = fanOutTarget{
	emptyErr:   "user keys are required",
	allFailed:  "failed to send to any user",
	logField:   "user_key",
	sendFailed: "Failed to send notification to user",
	partial:    "Some users failed to receive notification",
	sent:       "Sent Pushover notification to user",
	allSent:    "Successfully sent notification to Pushover users",
	mask:       maskUserKey,
}

// SendToUsers sends the notification to multiple Pushover users. Partial
// failures are logged and tolerated; an error means nothing was delivered.
func (p *PushoverClient) SendToUsers(userKeys []string, message string, priority int, sound string) error {
	return fanOut(userKeys, message, pushoverUsers, func(userKey string) error {
		return p.SendNotification(userKey, message, priority, sound)
	})
}
