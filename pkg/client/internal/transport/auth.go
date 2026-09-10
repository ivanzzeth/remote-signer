package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
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
		return parseBase64PrivateKey(base64Key)
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

// parseBase64PrivateKey decodes a base64 Ed25519 private key in any of the three
// forms an operator actually has on hand: the body of a PEM file (PKCS#8 DER),
// a raw 32-byte seed, or a raw 64-byte private key.
//
// ⛔ It refuses anything it cannot identify rather than guessing. The previous
// implementation took the *last* 32 bytes as the seed, which is right for
// PKCS#8 and for a bare seed, and silently wrong for a raw 64-byte key — those
// last 32 bytes are the public half, so it produced a completely different,
// valid-looking key. The symptom was authentication failing with an error that
// said nothing about the key having been misread.
func parseBase64PrivateKey(base64Key string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(base64Key))
	if err != nil {
		return nil, fmt.Errorf("invalid PrivateKeyBase64: not valid base64: %w", err)
	}

	switch len(raw) {
	case ed25519.SeedSize: // 32: raw seed
		return ed25519.NewKeyFromSeed(raw), nil

	case ed25519.PrivateKeySize: // 64: seed || public key
		// ⚠️ Derive the public half from the seed and compare. ⛔ Not
		// key.Public() — Go returns a copy of priv[32:] rather than
		// recomputing, so comparing that against priv[32:] is a tautology that
		// accepts any 64 bytes. (Caught by the test below, which feeds it 64
		// zero bytes.)
		derived := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
		if !ed25519.PublicKey(raw[ed25519.SeedSize:]).Equal(derived.Public()) {
			return nil, fmt.Errorf("invalid PrivateKeyBase64: 64-byte key whose public half does not match its seed")
		}
		return derived, nil
	}

	// Anything else: the body of a PEM file. Parse it as PKCS#8 rather than
	// slicing bytes off the end and hoping.
	parsed, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid PrivateKeyBase64: %d bytes is neither a %d-byte seed, a %d-byte key, nor PKCS#8 DER (%w)",
			len(raw), ed25519.SeedSize, ed25519.PrivateKeySize, err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid PrivateKeyBase64: PKCS#8 key is %T, want ed25519", parsed)
	}
	return key, nil
}
