package templates

import (
	"encoding/json"
	"time"
)

// Template represents a rule template.
type Template struct {
	ID             string             `json:"id"`
	Name           string             `json:"name"`
	Description    string             `json:"description,omitempty"`
	Type           string             `json:"type"`
	Mode           string             `json:"mode"`
	Source         string             `json:"source"`
	Variables      []TemplateVariable `json:"variables,omitempty"`
	Config         json.RawMessage    `json:"config,omitempty"`
	BudgetMetering json.RawMessage    `json:"budget_metering,omitempty"`
	Enabled        bool               `json:"enabled"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
}

// TemplateVariable describes a variable in a rule template.
type TemplateVariable struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"`
}

// ListResponse represents the response from listing templates.
type ListResponse struct {
	Templates []Template `json:"templates"`
	Total     int        `json:"total"`
}

// ListFilter contains filter options for listing templates.
type ListFilter struct {
	Type    string
	Source  string
	Enabled *bool
	Limit   int
	Offset  int
}

// CreateRequest represents a request to create a new template.
type CreateRequest struct {
	Name           string                 `json:"name"`
	Description    string                 `json:"description,omitempty"`
	Type           string                 `json:"type"`
	Mode           string                 `json:"mode"`
	Variables      []TemplateVariable     `json:"variables,omitempty"`
	Config         map[string]interface{} `json:"config"`
	BudgetMetering map[string]interface{} `json:"budget_metering,omitempty"`
	TestVariables  map[string]string      `json:"test_variables,omitempty"`
	Enabled        bool                   `json:"enabled"`
}

// UpdateRequest represents a request to update a template.
type UpdateRequest struct {
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Enabled     *bool                  `json:"enabled,omitempty"`
}

// InstantiateRequest represents a request to create a rule instance from a template.
type InstantiateRequest struct {
	TemplateName  string            `json:"template_name,omitempty"`
	Name          string            `json:"name,omitempty"`
	Variables     map[string]string `json:"variables"`
	ChainType     *string           `json:"chain_type,omitempty"`
	ChainID       *string           `json:"chain_id,omitempty"`
	APIKeyID      *string           `json:"api_key_id,omitempty"`
	SignerAddress *string           `json:"signer_address,omitempty"`
	ExpiresAt     *time.Time        `json:"expires_at,omitempty"`
	ExpiresIn     *string           `json:"expires_in,omitempty"`
	Budget        *BudgetConfig     `json:"budget,omitempty"`
	Schedule      *ScheduleConfig   `json:"schedule,omitempty"`
}

// BudgetConfig defines budget limits for an instance.
type BudgetConfig struct {
	MaxTotal   string `json:"max_total"`
	MaxPerTx   string `json:"max_per_tx"`
	MaxTxCount int    `json:"max_tx_count,omitempty"`
	AlertPct   int    `json:"alert_pct,omitempty"`
}

// ScheduleConfig defines periodic budget renewal.
type ScheduleConfig struct {
	Period  string     `json:"period"`
	StartAt *time.Time `json:"start_at,omitempty"`
}

// InstantiateResponse represents the response from creating a rule instance.
type InstantiateResponse struct {
	Rule   json.RawMessage `json:"rule"`
	Budget json.RawMessage `json:"budget,omitempty"`
}

// RevokeInstanceResponse represents the response from revoking an instance.
type RevokeInstanceResponse struct {
	Status string `json:"status"`
	RuleID string `json:"rule_id"`
}
