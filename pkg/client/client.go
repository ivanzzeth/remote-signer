package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Client is a client for the remote-signer service.
type Client struct {
	baseURL    string
	apiKeyID   string
	privateKey ed25519.PrivateKey
	httpClient *http.Client

	// PollInterval is the interval between status checks when waiting for approval.
	PollInterval time.Duration

	// PollTimeout is the maximum time to wait for approval.
	PollTimeout time.Duration

	// UseNonce enables nonce-based replay protection (recommended for production).
	// When enabled, a random nonce is included in each request signature.
	UseNonce bool
}

// Config holds configuration for creating a new Client.
type Config struct {
	// BaseURL is the base URL of the remote-signer service.
	// Example: "http://localhost:8080"
	BaseURL string

	// APIKeyID is the API key identifier.
	APIKeyID string

	// PrivateKey is the Ed25519 private key for signing requests.
	// Must be 64 bytes (seed + public key).
	PrivateKey ed25519.PrivateKey

	// PrivateKeyHex is an alternative way to provide the private key as hex string.
	// Either PrivateKey, PrivateKeyHex, or PrivateKeyBase64 must be provided.
	PrivateKeyHex string

	// PrivateKeyBase64 is an alternative way to provide the private key in base64 DER format.
	// This is the format output by: openssl pkey -in private.pem -outform DER | base64
	PrivateKeyBase64 string

	// HTTPClient is an optional custom HTTP client.
	// If nil, a default client with 30s timeout is used.
	HTTPClient *http.Client

	// PollInterval is the interval between status checks when waiting for approval.
	// Default: 2 seconds.
	PollInterval time.Duration

	// PollTimeout is the maximum time to wait for approval.
	// Default: 5 minutes.
	PollTimeout time.Duration

	// UseNonce enables nonce-based replay protection (recommended for production).
	// When enabled, a random nonce is included in each request signature.
	// Default: true (enabled for security)
	UseNonce *bool

	// TLS configuration

	// TLSCertFile is the path to the client TLS certificate (for mTLS).
	TLSCertFile string

	// TLSKeyFile is the path to the client TLS private key (for mTLS).
	TLSKeyFile string

	// TLSCAFile is the path to the CA certificate to verify the server.
	// Required when connecting to a server with a self-signed certificate.
	TLSCAFile string

	// TLSSkipVerify skips server certificate verification.
	// WARNING: This is insecure and should only be used for testing.
	TLSSkipVerify bool
}

// NewClient creates a new Client with the given configuration.
func NewClient(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("BaseURL is required")
	}
	if cfg.APIKeyID == "" {
		return nil, fmt.Errorf("APIKeyID is required")
	}

	var privateKey ed25519.PrivateKey
	if cfg.PrivateKey != nil {
		privateKey = cfg.PrivateKey
	} else if cfg.PrivateKeyHex != "" {
		keyBytes, err := hex.DecodeString(strings.TrimPrefix(cfg.PrivateKeyHex, "0x"))
		if err != nil {
			return nil, fmt.Errorf("invalid PrivateKeyHex: %w", err)
		}
		if len(keyBytes) == ed25519.SeedSize {
			privateKey = ed25519.NewKeyFromSeed(keyBytes)
		} else if len(keyBytes) == ed25519.PrivateKeySize {
			privateKey = ed25519.PrivateKey(keyBytes)
		} else {
			return nil, fmt.Errorf("invalid private key length: expected %d or %d bytes, got %d",
				ed25519.SeedSize, ed25519.PrivateKeySize, len(keyBytes))
		}
	} else if cfg.PrivateKeyBase64 != "" {
		derBytes, err := base64.StdEncoding.DecodeString(cfg.PrivateKeyBase64)
		if err != nil {
			return nil, fmt.Errorf("invalid PrivateKeyBase64: %w", err)
		}
		// Ed25519 private key DER format: header + 32-byte seed
		// Extract the last 32 bytes as seed
		if len(derBytes) < ed25519.SeedSize {
			return nil, fmt.Errorf("invalid base64 private key length: got %d bytes, need at least %d",
				len(derBytes), ed25519.SeedSize)
		}
		seed := derBytes[len(derBytes)-ed25519.SeedSize:]
		privateKey = ed25519.NewKeyFromSeed(seed)
	} else {
		return nil, fmt.Errorf("either PrivateKey, PrivateKeyHex, or PrivateKeyBase64 is required")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	// Configure TLS if any TLS option is set
	if cfg.TLSCAFile != "" || cfg.TLSCertFile != "" || cfg.TLSSkipVerify {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS13,
		}

		// Load CA certificate to verify server
		if cfg.TLSCAFile != "" {
			caCert, err := os.ReadFile(cfg.TLSCAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read TLS CA file: %w", err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse TLS CA certificate")
			}
			tlsConfig.RootCAs = caCertPool
		}

		// Load client certificate for mTLS
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			clientCert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load TLS client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{clientCert}
		}

		// Skip server verification (insecure, testing only)
		if cfg.TLSSkipVerify {
			tlsConfig.InsecureSkipVerify = true //nolint:gosec // Intentionally configurable for testing
		}

		// Apply TLS config to HTTP client
		// If user provided a custom HTTPClient, we create a new one with TLS transport
		// to avoid modifying the original
		httpClient = &http.Client{
			Timeout: httpClient.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	}

	pollInterval := cfg.PollInterval
	if pollInterval == 0 {
		pollInterval = 2 * time.Second
	}

	pollTimeout := cfg.PollTimeout
	if pollTimeout == 0 {
		pollTimeout = 5 * time.Minute
	}

	// Default to using nonce for security
	useNonce := true
	if cfg.UseNonce != nil {
		useNonce = *cfg.UseNonce
	}

	return &Client{
		baseURL:      strings.TrimSuffix(cfg.BaseURL, "/"),
		apiKeyID:     cfg.APIKeyID,
		privateKey:   privateKey,
		httpClient:   httpClient,
		PollInterval: pollInterval,
		PollTimeout:  pollTimeout,
		UseNonce:     useNonce,
	}, nil
}

// Health checks the health of the remote-signer service.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp)
	}

	var health HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &health, nil
}

// Sign submits a signing request and returns the result.
// If the request requires manual approval, this method will poll for the result
// until it's completed or the timeout is reached.
func (c *Client) Sign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	return c.SignWithOptions(ctx, req, true)
}

// SignWithOptions submits a signing request with options.
// If waitForApproval is false, returns immediately even if approval is pending.
func (c *Client) SignWithOptions(ctx context.Context, req *SignRequest, waitForApproval bool) (*SignResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := c.newSignedRequest(ctx, http.MethodPost, "/api/v1/evm/sign", body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		return nil, c.parseErrorResponse(resp)
	}

	var signResp SignResponse
	if err := json.NewDecoder(resp.Body).Decode(&signResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// If completed, return immediately
	if signResp.Status == StatusCompleted {
		return &signResp, nil
	}

	// If rejected or failed, return error
	if signResp.Status == StatusRejected || signResp.Status == StatusFailed {
		return nil, &SignError{
			RequestID: signResp.RequestID,
			Status:    signResp.Status,
			Message:   signResp.Message,
		}
	}

	// If pending approval and we should wait
	if waitForApproval && (signResp.Status == StatusPending || signResp.Status == StatusAuthorizing) {
		return c.pollForResult(ctx, signResp.RequestID)
	}

	// Return pending status
	return &signResp, &SignError{
		RequestID: signResp.RequestID,
		Status:    signResp.Status,
		Message:   signResp.Message,
	}
}

// GetRequest gets the status of a signing request.
func (c *Client) GetRequest(ctx context.Context, requestID string) (*RequestStatus, error) {
	path := fmt.Sprintf("/api/v1/evm/requests/%s", requestID)
	httpReq, err := c.newSignedRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp)
	}

	var status RequestStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &status, nil
}

// ListRequests lists signing requests with optional filters using cursor-based pagination.
func (c *Client) ListRequests(ctx context.Context, filter *ListRequestsFilter) (*ListRequestsResponse, error) {
	path := "/api/v1/evm/requests"
	params := make([]string, 0)

	if filter != nil {
		if filter.Status != "" {
			params = append(params, fmt.Sprintf("status=%s", filter.Status))
		}
		if filter.SignerAddress != "" {
			params = append(params, fmt.Sprintf("signer_address=%s", filter.SignerAddress))
		}
		if filter.ChainID != "" {
			params = append(params, fmt.Sprintf("chain_id=%s", filter.ChainID))
		}
		if filter.Limit > 0 {
			params = append(params, fmt.Sprintf("limit=%d", filter.Limit))
		}
		if filter.Cursor != nil {
			params = append(params, fmt.Sprintf("cursor=%s", url.QueryEscape(*filter.Cursor)))
		}
		if filter.CursorID != nil {
			params = append(params, fmt.Sprintf("cursor_id=%s", url.QueryEscape(*filter.CursorID)))
		}
	}

	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}

	httpReq, err := c.newSignedRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp)
	}

	var listResp ListRequestsResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &listResp, nil
}

// pollForResult polls for the result of a pending request.
func (c *Client) pollForResult(ctx context.Context, requestID string) (*SignResponse, error) {
	deadline := time.Now().Add(c.PollTimeout)
	ticker := time.NewTicker(c.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return nil, ErrTimeout
			}

			status, err := c.GetRequest(ctx, requestID)
			if err != nil {
				return nil, err
			}

			switch status.Status {
			case StatusCompleted:
				return &SignResponse{
					RequestID:   status.ID,
					Status:      status.Status,
					Signature:   status.Signature,
					SignedData:  status.SignedData,
					RuleMatched: ptrToString(status.RuleMatchedID),
				}, nil
			case StatusRejected, StatusFailed:
				return nil, &SignError{
					RequestID: status.ID,
					Status:    status.Status,
					Message:   status.ErrorMessage,
				}
			}
			// Continue polling for pending/authorizing/signing
		}
	}
}

// newSignedRequest creates a new HTTP request with Ed25519 signature.
// Supports three modes:
// - Legacy: timestamp|method|path|sha256(body)
// - Nonce: timestamp|nonce|method|path|sha256(body)
// - Full (nonce+sequence): timestamp|nonce|sequence|method|path|sha256(body)
func (c *Client) newSignedRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	url := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Sign the request
	timestamp := time.Now().UnixMilli()

	var signature string

	if c.UseNonce {
		// Nonce mode for replay protection
		nonce := generateNonce()
		signature = c.signRequestWithNonce(timestamp, nonce, method, path, body)
		req.Header.Set("X-Nonce", nonce)
	} else {
		// Legacy mode
		signature = c.signRequest(timestamp, method, path, body)
	}

	req.Header.Set("X-API-Key-ID", c.apiKeyID)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-Signature", signature)

	return req, nil
}

// signRequest creates the Ed25519 signature for a request (legacy format).
// Format: {timestamp}|{method}|{path}|{sha256(body)}
func (c *Client) signRequest(timestamp int64, method, path string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%d|%s|%s|%x", timestamp, method, path, bodyHash)
	signature := ed25519.Sign(c.privateKey, []byte(message))
	return base64.StdEncoding.EncodeToString(signature)
}

// signRequestWithNonce creates the Ed25519 signature for a request with nonce.
// Format: {timestamp}|{nonce}|{method}|{path}|{sha256(body)}
func (c *Client) signRequestWithNonce(timestamp int64, nonce, method, path string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%d|%s|%s|%s|%x", timestamp, nonce, method, path, bodyHash)
	signature := ed25519.Sign(c.privateKey, []byte(message))
	return base64.StdEncoding.EncodeToString(signature)
}

// generateNonce generates a random nonce for replay protection.
// Returns a 16-byte random value encoded as hex (32 characters).
func generateNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based if crypto/rand fails (unlikely)
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// parseErrorResponse parses an error response from the API.
func (c *Client) parseErrorResponse(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)

	var errResp ErrorResponse
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

func ptrToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
