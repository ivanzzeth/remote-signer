package types

import (
	"time"
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
