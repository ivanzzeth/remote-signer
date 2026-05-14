package apikeys

import "time"

// APIKey represents an API key in responses.
type APIKey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Source     string     `json:"source"`
	Role       string     `json:"role"` // admin, dev, agent, strategy
	Enabled    bool       `json:"enabled"`
	RateLimit  int        `json:"rate_limit"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
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
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Role      string `json:"role"` // admin, dev, agent, strategy
	RateLimit int    `json:"rate_limit,omitempty"`
}

// UpdateRequest represents a request to update an API key.
type UpdateRequest struct {
	Name      *string `json:"name,omitempty"`
	Enabled   *bool   `json:"enabled,omitempty"`
	Role      *string `json:"role,omitempty"` // admin, dev, agent, strategy
	RateLimit *int    `json:"rate_limit,omitempty"`
}
