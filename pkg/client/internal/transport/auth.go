package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Auth handles Ed25519 request signing.
type Auth struct {
	privateKey ed25519.PrivateKey
}

// NewAuth creates a new Auth from a private key.
func NewAuth(privateKey ed25519.PrivateKey) *Auth {
	return &Auth{privateKey: privateKey}
}

// SignRequest creates the Ed25519 signature for a request with nonce.
// Format: {timestamp}|{nonce}|{method}|{path}|{sha256(body)}
func (a *Auth) SignRequest(timestamp int64, nonce, method, path string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%d|%s|%s|%s|%x", timestamp, nonce, method, path, bodyHash)
	signature := ed25519.Sign(a.privateKey, []byte(message))
	return base64.StdEncoding.EncodeToString(signature)
}

// ParsePrivateKey parses a private key from various formats.
// Supports: raw ed25519.PrivateKey, hex string, base64 DER.
func ParsePrivateKey(raw ed25519.PrivateKey, hexKey, base64Key string) (ed25519.PrivateKey, error) {
	if raw != nil {
		return raw, nil
	}

	if hexKey != "" {
		keyBytes, err := hex.DecodeString(strings.TrimPrefix(hexKey, "0x"))
		if err != nil {
			return nil, fmt.Errorf("invalid PrivateKeyHex: %w", err)
		}
		if len(keyBytes) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(keyBytes), nil
		}
		if len(keyBytes) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(keyBytes), nil
		}
		return nil, fmt.Errorf("invalid private key length: expected %d or %d bytes, got %d",
			ed25519.SeedSize, ed25519.PrivateKeySize, len(keyBytes))
	}

	if base64Key != "" {
		derBytes, err := base64.StdEncoding.DecodeString(base64Key)
		if err != nil {
			return nil, fmt.Errorf("invalid PrivateKeyBase64: %w", err)
		}
		if len(derBytes) < ed25519.SeedSize {
			return nil, fmt.Errorf("invalid base64 private key length: got %d bytes, need at least %d",
				len(derBytes), ed25519.SeedSize)
		}
		seed := derBytes[len(derBytes)-ed25519.SeedSize:]
		return ed25519.NewKeyFromSeed(seed), nil
	}

	return nil, fmt.Errorf("either PrivateKey, PrivateKeyHex, or PrivateKeyBase64 is required")
}

// GenerateNonce generates a random nonce for replay protection.
// Returns a 16-byte random value encoded as hex (32 characters).
func GenerateNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
