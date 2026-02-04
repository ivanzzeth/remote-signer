package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ErrNonceReplay indicates a nonce has been reused (replay attack detected)
var ErrNonceReplay = errors.New("nonce replay detected")

// ErrNonceRequired indicates nonce is required but not provided
var ErrNonceRequired = errors.New("nonce required for replay protection")

// Config for auth verifier
type Config struct {
	// MaxRequestAge is the maximum age of a request (to prevent replay attacks)
	// Recommended: 30-60 seconds to minimize replay window while tolerating network latency
	// Default: 60 seconds
	MaxRequestAge time.Duration `yaml:"max_request_age"`

	// NonceRequired enforces nonce for all requests when NonceStore is configured
	// If true, requests without nonce will be rejected (stronger security)
	// If false, legacy requests without nonce are allowed (backward compatible)
	// Default: true (recommended for production)
	NonceRequired bool `yaml:"nonce_required"`
}

// DefaultConfig returns the default auth config
func DefaultConfig() Config {
	return Config{
		MaxRequestAge: 60 * time.Second, // 60s window (reduced from 5min for security)
		NonceRequired: true,             // Require nonce by default for security
	}
}

// Verifier verifies API request signatures
type Verifier struct {
	apiKeyRepo storage.APIKeyRepository
	nonceStore storage.NonceStore
	config     Config
}

// NewVerifier creates a new auth verifier
func NewVerifier(apiKeyRepo storage.APIKeyRepository, config Config) (*Verifier, error) {
	if apiKeyRepo == nil {
		return nil, fmt.Errorf("API key repository is required")
	}
	if config.MaxRequestAge <= 0 {
		return nil, fmt.Errorf("max request age must be positive")
	}
	return &Verifier{
		apiKeyRepo: apiKeyRepo,
		config:     config,
	}, nil
}

// NewVerifierWithNonceStore creates a new auth verifier with nonce store for replay protection
func NewVerifierWithNonceStore(apiKeyRepo storage.APIKeyRepository, nonceStore storage.NonceStore, config Config) (*Verifier, error) {
	v, err := NewVerifier(apiKeyRepo, config)
	if err != nil {
		return nil, err
	}
	v.nonceStore = nonceStore
	return v, nil
}


// VerifyRequest verifies the signature of an API request (legacy format without nonce)
// The client signs: {timestamp}|{method}|{path}|{sha256(body)}
// Deprecated: Use VerifyRequestWithNonce for better replay protection
func (v *Verifier) VerifyRequest(
	ctx interface{ Value(key interface{}) interface{} },
	apiKeyID string,
	timestamp int64,
	signature string,
	method string,
	path string,
	body []byte,
) (*types.APIKey, error) {
	return v.verifyRequestInternal(ctx, apiKeyID, timestamp, "", signature, method, path, body)
}

// VerifyRequestWithNonce verifies the signature of an API request with nonce
// The client signs: {timestamp}|{nonce}|{method}|{path}|{sha256(body)}
// This provides stronger replay protection than timestamp-only verification.
func (v *Verifier) VerifyRequestWithNonce(
	ctx context.Context,
	apiKeyID string,
	timestamp int64,
	nonce string,
	signature string,
	method string,
	path string,
	body []byte,
) (*types.APIKey, error) {
	return v.verifyRequestInternal(ctx, apiKeyID, timestamp, nonce, signature, method, path, body)
}

// verifyRequestInternal is the internal implementation that handles all formats
func (v *Verifier) verifyRequestInternal(
	ctx interface{ Value(key interface{}) interface{} },
	apiKeyID string,
	timestamp int64,
	nonce string,
	signature string,
	method string,
	path string,
	body []byte,
) (*types.APIKey, error) {
	// Get API key
	apiKey, err := v.apiKeyRepo.Get(ctx.(interface {
		Value(key interface{}) interface{}
		Done() <-chan struct{}
		Err() error
		Deadline() (deadline time.Time, ok bool)
	}), apiKeyID)
	if err != nil {
		if types.IsNotFound(err) {
			return nil, fmt.Errorf("api_key_id '%s' not found: %w", apiKeyID, types.ErrUnauthorized)
		}
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}

	// Check if API key is enabled
	if !apiKey.Enabled {
		return nil, fmt.Errorf("api_key '%s' is disabled: %w", apiKeyID, types.ErrUnauthorized)
	}

	// Check if API key is expired
	if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("api_key '%s' expired at %s: %w", apiKeyID, apiKey.ExpiresAt.Format(time.RFC3339), types.ErrUnauthorized)
	}

	// Check timestamp (prevent replay attacks)
	requestTime := time.UnixMilli(timestamp)
	age := time.Since(requestTime)
	if age < 0 {
		age = -age // Handle future timestamps
	}
	if age > v.config.MaxRequestAge {
		return nil, fmt.Errorf("request timestamp too old (age: %s, max: %s): %w", age, v.config.MaxRequestAge, types.ErrUnauthorized)
	}

	// Decode public key
	publicKeyBytes, err := hex.DecodeString(apiKey.PublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid public key hex in config: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size in config: expected %d, got %d", ed25519.PublicKeySize, len(publicKeyBytes))
	}
	publicKey := ed25519.PublicKey(publicKeyBytes)

	// Decode signature
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding (not valid base64): %w", types.ErrUnauthorized)
	}

	// Build message to verify based on what fields are provided
	bodyHash := sha256.Sum256(body)
	var message string
	if nonce != "" {
		// Format with nonce: {timestamp}|{nonce}|{method}|{path}|{sha256(body)}
		message = fmt.Sprintf("%d|%s|%s|%s|%x", timestamp, nonce, method, path, bodyHash)
	} else {
		// Legacy format: {timestamp}|{method}|{path}|{sha256(body)}
		message = fmt.Sprintf("%d|%s|%s|%x", timestamp, method, path, bodyHash)
	}

	// Verify signature
	if !ed25519.Verify(publicKey, []byte(message), signatureBytes) {
		return nil, fmt.Errorf("signature verification failed (public key mismatch or message tampered): %w", types.ErrUnauthorized)
	}

	// Enforce nonce requirement if configured
	if v.config.NonceRequired && v.nonceStore != nil && nonce == "" {
		return nil, fmt.Errorf("%w: nonce header required", ErrNonceRequired)
	}

	stdCtx, ok := ctx.(context.Context)
	if !ok {
		stdCtx = context.Background()
	}

	// Check nonce for replay protection (if nonce provided and store configured)
	if nonce != "" && v.nonceStore != nil {
		isNew, err := v.nonceStore.CheckAndStore(stdCtx, apiKeyID, nonce, v.config.MaxRequestAge)
		if err != nil {
			return nil, fmt.Errorf("failed to check nonce: %w", err)
		}
		if !isNew {
			return nil, fmt.Errorf("%w: nonce %s already used", ErrNonceReplay, nonce)
		}
	}

	return apiKey, nil
}

// ParseTimestamp parses a timestamp string (milliseconds since epoch)
func ParseTimestamp(s string) (int64, error) {
	ts, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid timestamp: %w", err)
	}
	return ts, nil
}

// SignRequest signs a request (used by clients) - legacy format without nonce
// Returns the base64-encoded signature
// Deprecated: Use SignRequestWithNonce for better replay protection
func SignRequest(privateKey ed25519.PrivateKey, timestamp int64, method string, path string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%d|%s|%s|%x", timestamp, method, path, bodyHash)
	signature := ed25519.Sign(privateKey, []byte(message))
	return base64.StdEncoding.EncodeToString(signature)
}

// SignRequestWithNonce signs a request with nonce (used by clients)
// Format: {timestamp}|{nonce}|{method}|{path}|{sha256(body)}
// Returns the base64-encoded signature
func SignRequestWithNonce(privateKey ed25519.PrivateKey, timestamp int64, nonce string, method string, path string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%d|%s|%s|%s|%x", timestamp, nonce, method, path, bodyHash)
	signature := ed25519.Sign(privateKey, []byte(message))
	return base64.StdEncoding.EncodeToString(signature)
}

