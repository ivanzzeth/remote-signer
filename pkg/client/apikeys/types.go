package apikeys

import "time"

// APIKey represents an API key in responses.
type APIKey struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	Source            string     `json:"source"`
	Admin             bool       `json:"admin"`
	Agent             bool       `json:"agent"`
	Enabled           bool       `json:"enabled"`
	RateLimit         int        `json:"rate_limit"`
	AllowAllSigners   bool       `json:"allow_all_signers"`
	AllowAllHDWallets bool       `json:"allow_all_hd_wallets"`
	AllowedSigners    []string   `json:"allowed_signers,omitempty"`
	AllowedHDWallets  []string   `json:"allowed_hd_wallets,omitempty"`
	AllowedChainTypes []string   `json:"allowed_chain_types,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	LastUsedAt        *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
}

// ListResponse represents the response from listing API keys.
type ListResponse struct {
	Keys  []APIKey `json:"keys"`
	Total int      `json:"total"`
}

// ListFilter contains filter options for listing API keys.
type ListFilter struct {
	Source  string
	Enabled *bool
	Limit   int
	Offset  int
}

// CreateRequest represents a request to create an API key.
type CreateRequest struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	PublicKey         string   `json:"public_key"`
	Admin             bool     `json:"admin"`
	Agent             bool     `json:"agent"`
	RateLimit         int      `json:"rate_limit,omitempty"`
	AllowAllSigners   bool     `json:"allow_all_signers"`
	AllowAllHDWallets bool     `json:"allow_all_hd_wallets"`
	AllowedSigners    []string `json:"allowed_signers,omitempty"`
	AllowedHDWallets  []string `json:"allowed_hd_wallets,omitempty"`
	AllowedChainTypes []string `json:"allowed_chain_types,omitempty"`
}

// UpdateRequest represents a request to update an API key.
type UpdateRequest struct {
	Name              *string  `json:"name,omitempty"`
	Enabled           *bool    `json:"enabled,omitempty"`
	Admin             *bool    `json:"admin,omitempty"`
	Agent             *bool    `json:"agent,omitempty"`
	RateLimit         *int     `json:"rate_limit,omitempty"`
	AllowAllSigners   *bool    `json:"allow_all_signers,omitempty"`
	AllowAllHDWallets *bool    `json:"allow_all_hd_wallets,omitempty"`
	AllowedSigners    []string `json:"allowed_signers,omitempty"`
	AllowedHDWallets  []string `json:"allowed_hd_wallets,omitempty"`
	AllowedChainTypes []string `json:"allowed_chain_types,omitempty"`
}
