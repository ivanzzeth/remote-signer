package simulation

import (
	"encoding/hex"
	"math/big"
	"strings"
)

// trimHexPrefix removes an optional "0x" or "0X" prefix from hex strings.
func trimHexPrefix(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

func hexDecode(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	if len(s)%2 != 0 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}

// normalizeRPCQuantity converts decimal or 0x-prefixed quantities to JSON-RPC hex.
// Empty and zero values become 0x0 (used for tx value).
func normalizeRPCQuantity(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return "0x0"
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		var b big.Int
		if _, ok := b.SetString(s, 0); ok {
			return "0x" + b.Text(16)
		}
		return s
	}
	var b big.Int
	if _, ok := b.SetString(s, 10); ok {
		return "0x" + b.Text(16)
	}
	// Legacy fallback: treat bare hex digits as hex (avoid breaking callers).
	return normalizeHex(s)
}

// normalizeRPCGasOptional converts optional gas limits to JSON-RPC hex.
// Returns "" when unset so the field can be omitted from the RPC call.
func normalizeRPCGasOptional(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if s == "0" {
		return "0x0"
	}
	return normalizeRPCQuantity(s)
}

func normalizeHex(s string) string {
	if s == "" || s == "0" || s == "0x" {
		return "0x0"
	}
	if !strings.HasPrefix(s, "0x") {
		return "0x" + s
	}
	return s
}
