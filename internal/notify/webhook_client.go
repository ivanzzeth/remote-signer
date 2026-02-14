package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/logger"
)

// WebhookClient sends notifications to generic HTTP webhook endpoints.
type WebhookClient struct {
	httpClient *http.Client
	headers    map[string]string
}

// WebhookPayload is the JSON body posted to each webhook URL.
type WebhookPayload struct {
	Text      string `json:"text"`
	Timestamp string `json:"timestamp"`
}

// NewWebhookClient creates a WebhookClient with the given timeout and optional
// custom headers (e.g. Authorization tokens).
func NewWebhookClient(timeout time.Duration, headers map[string]string) (*WebhookClient, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	return &WebhookClient{
		httpClient: &http.Client{Timeout: timeout},
		headers:    headers,
	}, nil
}

// SendToURLs posts the message to every URL. It returns an error only when
// all URLs fail; partial failures are logged but do not block the rest.
func (w *WebhookClient) SendToURLs(urls []string, message string) error {
	if len(urls) == 0 {
		return fmt.Errorf("webhook URLs are required")
	}
	if message == "" {
		return fmt.Errorf("message is required")
	}

	log := logger.GetGlobal()

	payload := WebhookPayload{
		Text:      message,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	var lastErr error
	successCount := 0

	for _, url := range urls {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			lastErr = fmt.Errorf("failed to create request for %s: %w", url, err)
			log.Warn().Err(lastErr).Str("url", url).Msg("Failed to create webhook request")
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range w.headers {
			req.Header.Set(k, v)
		}

		resp, err := w.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to post to %s: %w", url, err)
			log.Warn().Err(lastErr).Str("url", url).Msg("Webhook request failed")
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("webhook %s returned status %d", url, resp.StatusCode)
			log.Warn().Err(lastErr).Str("url", url).Int("status", resp.StatusCode).Msg("Webhook returned non-2xx")
			continue
		}

		successCount++
		log.Debug().Str("url", url).Msg("Webhook notification sent")
	}

	if successCount == 0 {
		return fmt.Errorf("failed to send to any webhook: %w", lastErr)
	}

	if lastErr != nil {
		log.Warn().
			Int("success_count", successCount).
			Int("total_count", len(urls)).
			Msg("Some webhooks failed to receive notification")
	}

	return nil
}
