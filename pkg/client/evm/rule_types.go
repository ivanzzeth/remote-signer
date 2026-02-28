package evm

import (
	"encoding/json"
	"time"
)

// Rule represents an authorization rule.
type Rule struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Description   string     `json:"description,omitempty"`
	Type          string     `json:"type"`
	Mode          string     `json:"mode"`
	Source        string     `json:"source"`
	ChainType     *string    `json:"chain_type,omitempty"`
	ChainID       *string    `json:"chain_id,omitempty"`
	APIKeyID      *string    `json:"api_key_id,omitempty"`
	SignerAddress *string    `json:"signer_address,omitempty"`
	Config        RuleConfig `json:"config,omitempty"`
	Enabled       bool       `json:"enabled"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	MatchCount    uint64     `json:"match_count"`
	LastMatchedAt *time.Time `json:"last_matched_at,omitempty"`
}

// RuleConfig represents the configuration for a rule.
type RuleConfig json.RawMessage

// MarshalJSON implements json.Marshaler.
func (r RuleConfig) MarshalJSON() ([]byte, error) {
	return json.RawMessage(r).MarshalJSON()
}

// UnmarshalJSON implements json.Unmarshaler.
func (r *RuleConfig) UnmarshalJSON(data []byte) error {
	*r = RuleConfig(data)
	return nil
}

// ListRulesResponse represents the response from listing rules.
type ListRulesResponse struct {
	Rules []Rule `json:"rules"`
	Total int    `json:"total"`
}

// ListRulesFilter contains filter options for listing rules.
type ListRulesFilter struct {
	ChainType     string
	SignerAddress string
	APIKeyID      string
	Type          string
	Mode          string
	Enabled       *bool
	Limit         int
	Offset        int
}

// CreateRuleRequest represents a request to create a new rule.
type CreateRuleRequest struct {
	Name          string                 `json:"name"`
	Description   string                 `json:"description,omitempty"`
	Type          string                 `json:"type"`
	Mode          string                 `json:"mode"`
	ChainType     *string                `json:"chain_type,omitempty"`
	ChainID       *string                `json:"chain_id,omitempty"`
	APIKeyID      *string                `json:"api_key_id,omitempty"`
	SignerAddress *string                `json:"signer_address,omitempty"`
	Config        map[string]interface{} `json:"config"`
	Enabled       bool                   `json:"enabled"`
}

// UpdateRuleRequest represents a request to update an existing rule.
type UpdateRuleRequest struct {
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Enabled     bool                   `json:"enabled"`
}
