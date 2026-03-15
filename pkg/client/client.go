// Package client provides a Go SDK for the remote-signer service.
//
// The client uses a resource-based API design (Stripe/Octokit style):
//
//	client.EVM.Sign.Execute(ctx, req)
//	client.EVM.Rules.List(ctx, filter)
//	client.Audit.List(ctx, filter)
//	client.Templates.Get(ctx, id)
package client

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/pkg/client/acls"
	"github.com/ivanzzeth/remote-signer/pkg/client/apikeys"
	"github.com/ivanzzeth/remote-signer/pkg/client/audit"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
	"github.com/ivanzzeth/remote-signer/pkg/client/presets"
	"github.com/ivanzzeth/remote-signer/pkg/client/templates"
)

// Client is a client for the remote-signer service.
type Client struct {
	// EVM provides EVM-specific operations (signing, rules, signers, HD wallets, etc.).
	EVM *evm.Service

	// Audit provides audit log operations.
	Audit *audit.Service

	// Templates provides rule template operations.
	Templates *templates.Service

	// APIKeys provides API key management operations.
	APIKeys *apikeys.Service

	// ACLs provides read-only ACL operations (admin only), e.g. IP whitelist config.
	ACLs *acls.Service

	// Presets provides preset list/vars/apply (admin only; requires server presets.dir).
	Presets *presets.Service

	transport *transport.Transport
}

// Config holds configuration for creating a new Client.
type Config struct {
	// BaseURL is the base URL of the remote-signer service.
	BaseURL string

	// APIKeyID is the API key identifier.
	APIKeyID string

	// PrivateKey is the Ed25519 private key for signing requests.
	PrivateKey ed25519.PrivateKey

	// PrivateKeyHex is an alternative way to provide the private key as hex string.
	PrivateKeyHex string

	// PrivateKeyBase64 is an alternative way to provide the private key in base64 DER format.
	PrivateKeyBase64 string

	// HTTPClient is an optional custom HTTP client.
	HTTPClient *http.Client

	// PollInterval is the interval between status checks when waiting for approval.
	// Default: 2 seconds.
	PollInterval time.Duration

	// PollTimeout is the maximum time to wait for approval.
	// Default: 5 minutes.
	PollTimeout time.Duration

	// TLS configuration

	// TLSCertFile is the path to the client TLS certificate (for mTLS).
	TLSCertFile string

	// TLSKeyFile is the path to the client TLS private key (for mTLS).
	TLSKeyFile string

	// TLSCAFile is the path to the CA certificate to verify the server.
	TLSCAFile string

	// TLSSkipVerify skips server certificate verification.
	TLSSkipVerify bool
}

// NewClient creates a new Client with the given configuration.
func NewClient(cfg Config) (*Client, error) {
	privateKey, err := transport.ParsePrivateKey(cfg.PrivateKey, cfg.PrivateKeyHex, cfg.PrivateKeyBase64)
	if err != nil {
		return nil, err
	}

	auth := transport.NewAuth(privateKey)

	var tlsCfg *transport.TLSConfig
	if cfg.TLSCAFile != "" || cfg.TLSCertFile != "" || cfg.TLSSkipVerify {
		tlsCfg = &transport.TLSConfig{
			CAFile:     cfg.TLSCAFile,
			CertFile:   cfg.TLSCertFile,
			KeyFile:    cfg.TLSKeyFile,
			SkipVerify: cfg.TLSSkipVerify,
		}
	}

	t, err := transport.NewTransport(transport.Config{
		BaseURL:    cfg.BaseURL,
		APIKeyID:   cfg.APIKeyID,
		HTTPClient: cfg.HTTPClient,
		TLS:        tlsCfg,
	}, auth)
	if err != nil {
		return nil, err
	}

	pollInterval := cfg.PollInterval
	if pollInterval == 0 {
		pollInterval = 2 * time.Second
	}

	pollTimeout := cfg.PollTimeout
	if pollTimeout == 0 {
		pollTimeout = 5 * time.Minute
	}

	evmSvc := evm.NewService(t)
	evmSvc.Sign.SetPolling(pollInterval, pollTimeout)

	return &Client{
		EVM:       evmSvc,
		Audit:     audit.NewService(t),
		Templates: templates.NewService(t),
		APIKeys:   apikeys.NewService(t),
		ACLs:      acls.NewService(t),
		Presets:   presets.NewService(t),
		transport: t,
	}, nil
}

// SecurityConfigInfo represents security configuration summary.
type SecurityConfigInfo struct {
	AutoLockTimeout       string `json:"auto_lock_timeout"`
	SignTimeout           string `json:"sign_timeout"`
	AuditRetentionDays    int    `json:"audit_retention_days"`
	ContentTypeValidation bool   `json:"content_type_validation"`
}

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status   string              `json:"status"`
	Version  string              `json:"version"`
	Security *SecurityConfigInfo `json:"security,omitempty"`
}

// Health checks the health of the remote-signer service.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	resp, err := c.transport.RequestNoAuth(ctx, http.MethodGet, "/health")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, transport.ParseErrorResponse(resp)
	}

	var health HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &health, nil
}

// Metrics fetches the Prometheus exposition format metrics from /metrics.
func (c *Client) Metrics(ctx context.Context) (string, error) {
	resp, err := c.transport.RequestNoAuth(ctx, http.MethodGet, "/metrics")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return "", fmt.Errorf("metrics request failed: status=%d message=%s", resp.StatusCode, msg)
	}

	return string(body), nil
}
