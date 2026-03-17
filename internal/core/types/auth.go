package types

import (
	"strings"
	"time"

	"github.com/lib/pq"
)

const (
	APIKeySourceConfig = "config"
	APIKeySourceAPI    = "api"
)

// APIKeyRole represents the role of an API key (admin/dev/agent/strategy).
type APIKeyRole string

const (
	RoleAdmin    APIKeyRole = "admin"
	RoleDev      APIKeyRole = "dev"
	RoleAgent    APIKeyRole = "agent"
	RoleStrategy APIKeyRole = "strategy"
)

// ValidAPIKeyRoles contains all valid role values for validation.
var ValidAPIKeyRoles = []APIKeyRole{RoleAdmin, RoleDev, RoleAgent, RoleStrategy}

// IsValidAPIKeyRole checks if a string is a valid API key role.
func IsValidAPIKeyRole(role string) bool {
	switch APIKeyRole(role) {
	case RoleAdmin, RoleDev, RoleAgent, RoleStrategy:
		return true
	}
	return false
}

// APIKey represents an API key for authentication
type APIKey struct {
	ID           string `json:"id" gorm:"primaryKey;type:varchar(64)"`
	Name         string `json:"name" gorm:"type:varchar(255)"`
	PublicKeyHex string `json:"public_key" gorm:"type:varchar(128)"` // Ed25519 public key, hex encoded

	// Permissions (empty list = no access; use allow_all_signers / allow_all_hd_wallets to grant all)
	AllowAllSigners   bool           `json:"allow_all_signers" gorm:"default:false"`           // when true: any signer (private_key, keystore)
	AllowAllHDWallets bool           `json:"allow_all_hd_wallets" gorm:"default:false"`        // when true: any HD wallet (derive, sign derived)
	AllowedChainTypes pq.StringArray `json:"allowed_chain_types,omitempty" gorm:"type:text[]"` // empty = all chains
	AllowedSigners    pq.StringArray `json:"allowed_signers,omitempty" gorm:"type:text[]"`     // signer addresses; empty = none
	AllowedHDWallets  pq.StringArray `json:"allowed_hd_wallets,omitempty" gorm:"type:text[]"`  // HD wallet primary addresses; empty = none

	RateLimit int        `json:"rate_limit" gorm:"default:100"`                           // requests per minute
	Role      APIKeyRole `json:"role" gorm:"type:varchar(32);not null;default:'strategy'"` // admin/dev/agent/strategy

	Enabled bool `json:"enabled" gorm:"index;default:true"`
	// Source indicates where the API key was created: "config" (from config file) or "api" (created via API).
	// Default "config" for backward compatibility with existing keys.
	Source     string     `json:"source" gorm:"type:varchar(10);default:'config';not null"`
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
	return k.isExplicitlyAllowedSigner(address)
}

// IsAllowedSignerExplicit checks only the explicit AllowedSigners list,
// ignoring AllowAllSigners. Used for agent keys that must be restricted
// to their explicitly listed signers only.
func (k *APIKey) IsAllowedSignerExplicit(address string) bool {
	return k.isExplicitlyAllowedSigner(address)
}

func (k *APIKey) isExplicitlyAllowedSigner(address string) bool {
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
	return k.isExplicitlyAllowedHDWallet(primaryAddress)
}

// IsAllowedHDWalletExplicit checks only the explicit AllowedHDWallets list,
// ignoring AllowAllHDWallets. Used for agent keys.
func (k *APIKey) IsAllowedHDWalletExplicit(primaryAddress string) bool {
	return k.isExplicitlyAllowedHDWallet(primaryAddress)
}

func (k *APIKey) isExplicitlyAllowedHDWallet(primaryAddress string) bool {
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

// IsAdmin returns true if the API key has the admin role.
func (k *APIKey) IsAdmin() bool { return k.Role == RoleAdmin }

// IsDev returns true if the API key has the dev role.
func (k *APIKey) IsDev() bool { return k.Role == RoleDev }

// IsAgent returns true if the API key has the agent role.
func (k *APIKey) IsAgent() bool { return k.Role == RoleAgent }

// IsStrategy returns true if the API key has the strategy role.
func (k *APIKey) IsStrategy() bool { return k.Role == RoleStrategy }

// SignedAPIRequest represents the authentication headers for a signed request
type SignedAPIRequest struct {
	APIKeyID  string `header:"X-API-Key-ID"`
	Timestamp int64  `header:"X-Timestamp"` // Unix timestamp in milliseconds
	Signature string `header:"X-Signature"` // Ed25519 signature, base64 encoded
}
