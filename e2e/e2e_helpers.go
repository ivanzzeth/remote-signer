//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"crypto/ed25519"
)

// isHexKey determines if a key string is hex-encoded (vs base64)
func isHexKey(key string) bool {
	if len(key) == 128 {
		for _, c := range key {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
		return true
	}
	_, err := base64.StdEncoding.DecodeString(key)
	return err != nil
}

// convertPrivateKeyToHex converts a private key from hex or base64 to hex format
func convertPrivateKeyToHex(key string) (string, error) {
	if isHexKey(key) {
		return key, nil
	}
	derBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 key: %w", err)
	}
	if len(derBytes) < 32 {
		return "", fmt.Errorf("invalid key length: got %d bytes, need at least 32", len(derBytes))
	}
	var privateKey ed25519.PrivateKey
	if len(derBytes) >= 48 {
		seed := derBytes[len(derBytes)-32:]
		privateKey = ed25519.NewKeyFromSeed(seed)
	} else if len(derBytes) == 32 {
		privateKey = ed25519.NewKeyFromSeed(derBytes)
	} else {
		return "", fmt.Errorf("unexpected key format: %d bytes", len(derBytes))
	}
	return hex.EncodeToString(privateKey), nil
}
