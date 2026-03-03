package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Transport handles HTTP communication with the remote-signer service.
type Transport struct {
	baseURL    string
	apiKeyID   string
	auth       *Auth
	httpClient *http.Client
}

// Config holds configuration for creating a new Transport.
type Config struct {
	BaseURL    string
	APIKeyID   string
	HTTPClient *http.Client
	TLS        *TLSConfig
}

// TLSConfig holds TLS configuration.
type TLSConfig struct {
	CAFile     string
	CertFile   string
	KeyFile    string
	SkipVerify bool
}

// NewTransport creates a new Transport with the given configuration.
func NewTransport(cfg Config, auth *Auth) (*Transport, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("BaseURL is required")
	}
	if cfg.APIKeyID == "" {
		return nil, fmt.Errorf("APIKeyID is required")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	if cfg.TLS != nil {
		tlsHTTPClient, err := configureTLS(httpClient, cfg.TLS)
		if err != nil {
			return nil, err
		}
		httpClient = tlsHTTPClient
	}

	return &Transport{
		baseURL:    strings.TrimSuffix(cfg.BaseURL, "/"),
		apiKeyID:   cfg.APIKeyID,
		auth:       auth,
		httpClient: httpClient,
	}, nil
}

// Request performs an authenticated JSON request and decodes the response into result.
func (t *Transport) Request(ctx context.Context, method, path string, body interface{}, result interface{}, acceptedStatuses ...int) error {
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
	}

	resp, err := t.doSignedRequest(ctx, method, path, bodyBytes)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if !isAcceptedStatus(resp.StatusCode, acceptedStatuses) {
		return ParseErrorResponse(resp)
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// RequestRaw performs an authenticated request and returns the raw response body as bytes.
func (t *Transport) RequestRaw(ctx context.Context, method, path string, body []byte, acceptedStatuses ...int) ([]byte, error) {
	resp, err := t.doSignedRequest(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if !isAcceptedStatus(resp.StatusCode, acceptedStatuses) {
		return nil, ParseErrorResponse(resp)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return data, nil
}

// RequestNoAuth performs an unauthenticated request (for /health, /metrics).
func (t *Transport) RequestNoAuth(ctx context.Context, method, path string) (*http.Response, error) {
	url := t.baseURL + path

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

// BaseURL returns the base URL.
func (t *Transport) BaseURL() string {
	return t.baseURL
}

func (t *Transport) doSignedRequest(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	url := t.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	timestamp := time.Now().UnixMilli()
	nonce := GenerateNonce()
	signature := t.auth.SignRequest(timestamp, nonce, method, path, body)

	req.Header.Set("X-API-Key-ID", t.apiKeyID)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", signature)

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

func isAcceptedStatus(status int, accepted []int) bool {
	if len(accepted) == 0 {
		return status >= 200 && status < 300
	}
	for _, s := range accepted {
		if status == s {
			return true
		}
	}
	return false
}

// ParseErrorResponse parses an error response from the API.
func ParseErrorResponse(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)

	var errResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &errResp); err != nil {
		return &APIError{
			StatusCode: resp.StatusCode,
			Code:       "unknown",
			Message:    string(body),
		}
	}

	return &APIError{
		StatusCode: resp.StatusCode,
		Code:       errResp.Error,
		Message:    errResp.Message,
	}
}

// APIError represents an error returned by the remote-signer API.
// Defined here so transport can construct it; re-exported from the root client package.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("API error %d (%s): %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("API error %d: %s", e.StatusCode, e.Code)
}

// IsStatusCode checks if the error has the given HTTP status code.
func (e *APIError) IsStatusCode(code int) bool {
	return e.StatusCode == code
}

// IsCode checks if the error has the given error code string.
func (e *APIError) IsCode(code string) bool {
	return e.Code == code
}

// ErrorResponse represents an error response from the API.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
