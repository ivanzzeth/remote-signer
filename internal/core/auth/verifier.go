package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// Config for auth verifier
type Config struct {
	// MaxRequestAge is the maximum age of a request (to prevent replay attacks)
	MaxRequestAge time.Duration `yaml:"max_request_age"`
}

// DefaultConfig returns the default auth config
func DefaultConfig() Config {
	return Config{
		MaxRequestAge: 5 * time.Minute,
	}
}

// Verifier verifies API request signatures
type Verifier struct {
	apiKeyRepo storage.APIKeyRepository
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

// VerifyRequest verifies the signature of an API request
// The client signs: {timestamp}|{method}|{path}|{sha256(body)}
func (v *Verifier) VerifyRequest(
	ctx interface{ Value(key interface{}) interface{} },
	apiKeyID string,
	timestamp int64,
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
			return nil, types.ErrUnauthorized
		}
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}

	// Check if API key is enabled
	if !apiKey.Enabled {
		return nil, types.ErrUnauthorized
	}

	// Check if API key is expired
	if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
		return nil, types.ErrUnauthorized
	}

	// Check timestamp (prevent replay attacks)
	requestTime := time.UnixMilli(timestamp)
	age := time.Since(requestTime)
	if age < 0 {
		age = -age // Handle future timestamps
	}
	if age > v.config.MaxRequestAge {
		return nil, fmt.Errorf("request too old or from the future: %w", types.ErrUnauthorized)
	}

	// Decode public key
	publicKeyBytes, err := hex.DecodeString(apiKey.PublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid public key hex: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(publicKeyBytes))
	}
	publicKey := ed25519.PublicKey(publicKeyBytes)

	// Decode signature
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", types.ErrUnauthorized)
	}

	// Build message to verify: {timestamp}|{method}|{path}|{sha256(body)}
	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%d|%s|%s|%x", timestamp, method, path, bodyHash)

	// Verify signature
	if !ed25519.Verify(publicKey, []byte(message), signatureBytes) {
		return nil, types.ErrUnauthorized
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

// SignRequest signs a request (used by clients)
// Returns the base64-encoded signature
func SignRequest(privateKey ed25519.PrivateKey, timestamp int64, method string, path string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%d|%s|%s|%x", timestamp, method, path, bodyHash)
	signature := ed25519.Sign(privateKey, []byte(message))
	return base64.StdEncoding.EncodeToString(signature)
}
