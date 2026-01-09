package types

import (
	"time"

	"github.com/lib/pq"
)

// APIKey represents an API key for authentication
type APIKey struct {
	ID           string `json:"id" gorm:"primaryKey;type:varchar(64)"`
	Name         string `json:"name" gorm:"type:varchar(255)"`
	PublicKeyHex string `json:"public_key" gorm:"type:varchar(128)"` // Ed25519 public key, hex encoded

	// Permissions
	AllowedChainTypes pq.StringArray `json:"allowed_chain_types,omitempty" gorm:"type:text[]"` // empty = all
	AllowedSigners    pq.StringArray `json:"allowed_signers,omitempty" gorm:"type:text[]"`     // empty = all

	RateLimit int `json:"rate_limit" gorm:"default:100"` // requests per minute

	Enabled    bool       `json:"enabled" gorm:"index;default:true"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// TableName specifies the table name for GORM
func (APIKey) TableName() string {
	return "api_keys"
}

// IsAllowedChain checks if the API key allows the given chain type
func (k *APIKey) IsAllowedChain(chainType ChainType) bool {
	if len(k.AllowedChainTypes) == 0 {
		return true // empty = all allowed
	}
	for _, ct := range k.AllowedChainTypes {
		if ct == string(chainType) {
			return true
		}
	}
	return false
}

// IsAllowedSigner checks if the API key allows the given signer address
func (k *APIKey) IsAllowedSigner(address string) bool {
	if len(k.AllowedSigners) == 0 {
		return true // empty = all allowed
	}
	for _, a := range k.AllowedSigners {
		if a == address {
			return true
		}
	}
	return false
}

// SignedAPIRequest represents the authentication headers for a signed request
type SignedAPIRequest struct {
	APIKeyID  string `header:"X-API-Key-ID"`
	Timestamp int64  `header:"X-Timestamp"` // Unix timestamp in milliseconds
	Signature string `header:"X-Signature"` // Ed25519 signature, base64 encoded
}
