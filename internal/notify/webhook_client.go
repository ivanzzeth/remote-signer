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
//
// Security note (SSRF): Webhook URLs are currently sourced from the config file
// and controlled by the server administrator, so SSRF risk is low.
// If webhook URLs are ever exposed via API (user-configurable), the following
// protections MUST be added:
//   - Validate URL scheme (allow only http/https, reject file://, gopher://, etc.)
//   - Resolve hostname and block private/reserved IP ranges:
//     127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (ip.IsPrivate)
//     169.254.169.254 (cloud metadata endpoint, ip.IsLinkLocalUnicast)
//     ::1, fc00::/7 (IPv6 loopback/private)
//   - Disable HTTP redirects (attacker can redirect to internal IPs)
//   - Consider DNS rebinding protection (re-resolve after redirect)
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
