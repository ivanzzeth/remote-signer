package types

import (
	"strings"
	"time"

	"github.com/lib/pq"
)

// APIKey represents an API key for authentication
type APIKey struct {
	ID           string `json:"id" gorm:"primaryKey;type:varchar(64)"`
	Name         string `json:"name" gorm:"type:varchar(255)"`
	PublicKeyHex string `json:"public_key" gorm:"type:varchar(128)"` // Ed25519 public key, hex encoded

	// Permissions (empty list = no access; use allow_all_signers / allow_all_hd_wallets to grant all)
	AllowAllSigners   bool            `json:"allow_all_signers" gorm:"default:false"`         // when true: any signer (private_key, keystore)
	AllowAllHDWallets bool            `json:"allow_all_hd_wallets" gorm:"default:false"`      // when true: any HD wallet (derive, sign derived)
	AllowedChainTypes pq.StringArray  `json:"allowed_chain_types,omitempty" gorm:"type:text[]"` // empty = all chains
	AllowedSigners    pq.StringArray  `json:"allowed_signers,omitempty" gorm:"type:text[]"`    // signer addresses; empty = none
	AllowedHDWallets  pq.StringArray  `json:"allowed_hd_wallets,omitempty" gorm:"type:text[]"`  // HD wallet primary addresses; empty = none

	RateLimit int  `json:"rate_limit" gorm:"default:100"` // requests per minute
	Admin     bool `json:"admin" gorm:"default:false"`    // admin keys can approve requests and manage rules

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

// IsAllowedSigner checks if the API key allows the given signer address.
// Empty AllowedSigners = no access unless AllowAllSigners is true.
func (k *APIKey) IsAllowedSigner(address string) bool {
	if k.AllowAllSigners {
		return true
	}
	if len(k.AllowedSigners) == 0 {
		return false
	}
	for _, a := range k.AllowedSigners {
		if strings.EqualFold(a, address) {
			return true
		}
	}
	return false
}

// IsAllowedHDWallet checks if the API key grants access to the given HD wallet primary address.
// Empty AllowedHDWallets = no access unless AllowAllHDWallets is true.
func (k *APIKey) IsAllowedHDWallet(primaryAddress string) bool {
	if k.AllowAllHDWallets {
		return true
	}
	if len(k.AllowedHDWallets) == 0 {
		return false
	}
	for _, a := range k.AllowedHDWallets {
		if strings.EqualFold(a, primaryAddress) {
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
