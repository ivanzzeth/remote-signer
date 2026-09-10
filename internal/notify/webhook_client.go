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
	payload := WebhookPayload{
		Text:      message,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	return fanOut(urls, message, webhookURLs, func(url string) error {
		return w.postOne(url, body)
	})
}

// webhookURLs is the webhook fan-out's half of the strings — see fanout.go.
var webhookURLs = fanOutTarget{
	emptyErr:   "webhook URLs are required",
	allFailed:  "failed to send to any webhook",
	logField:   "url",
	sendFailed: "Webhook delivery failed",
	partial:    "Some webhooks failed to receive notification",
	sent:       "Webhook notification sent",
	allSent:    "Successfully sent notification to webhooks",
}

// postOne delivers the already-marshalled body to one URL. Each failure names
// the URL in the error itself, because the fan-out logs one line per failed
// recipient and that line is all the operator gets.
func (w *WebhookClient) postOne(url string, body []byte) error {
	log := logger.GetGlobal()

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request for %s: %w", url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to post to %s: %w", url, err)
	}
	if closeErr := resp.Body.Close(); closeErr != nil {
		log.Warn().Err(closeErr).Msg("failed to close response body")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook %s returned status %d", url, resp.StatusCode)
	}
	return nil
}
