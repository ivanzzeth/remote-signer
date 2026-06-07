package templates

import (
	"encoding/json"
	"time"
)

// VariableType is the canonical type tag for a template variable.
// Matches internal/core/types VarType* constants and the JS SDK's
// VariableType union. Widgets dispatch on this value.
type VariableType string

const (
	VarTypeAddress     VariableType = "address"
	VarTypeAddressList VariableType = "address_list"
	VarTypeBigInt      VariableType = "bigint"
	VarTypeBigIntList  VariableType = "bigint_list"
	VarTypeString      VariableType = "string"
	VarTypeBool        VariableType = "bool"
	VarTypeBytes       VariableType = "bytes"
	VarTypeBytes4      VariableType = "bytes4"
	VarTypeDuration    VariableType = "duration"
	VarTypeEnum        VariableType = "enum"
	VarTypeJSON        VariableType = "json"
)

// Template represents a rule template.
type Template struct {
	ID             string             `json:"id"`
	Name           string             `json:"name"`
	Description    string             `json:"description,omitempty"`
	Type           string             `json:"type"`
	Mode           string             `json:"mode"`
	Source         string             `json:"source"`
	// ChainType narrows the template to one chain family. Empty for
	// off-chain templates (sign_type_allowlist, future rate_limit, ...).
	ChainType      string             `json:"chain_type,omitempty"`
	// SourcePath is the relative path under the configured source root,
	// e.g. "evm/erc20.yaml" for file sources. Empty for source=api.
	SourcePath     string             `json:"source_path,omitempty"`
	Variables      []TemplateVariable `json:"variables,omitempty"`
	VariableGroups json.RawMessage    `json:"variable_groups,omitempty"`
	Config         json.RawMessage    `json:"config,omitempty"`
	BudgetMetering json.RawMessage    `json:"budget_metering,omitempty"`
	Enabled        bool               `json:"enabled"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
}

// TemplateVariable describes a variable in a rule template. v0.3
// carries every UI-relevant field so the typed-widget dispatch
// (bool→checkbox, enum→select, *_list→textarea, etc.) doesn't have to
// roundtrip again for option lists or placeholder hints.
type TemplateVariable struct {
	Name        string       `json:"name"`
	Type        VariableType `json:"type"`
	Label       string       `json:"label,omitempty"`
	Description string       `json:"description,omitempty"`
	Required    bool         `json:"required"`
	// Default is raw JSON so the natural shape (string / number / bool /
	// array) round-trips. Callers can json.Unmarshal into a concrete
	// type if they know the variable's Type, or pass through as-is.
	Default     json.RawMessage `json:"default,omitempty"`
	Placeholder string          `json:"placeholder,omitempty"`
	Hint        string          `json:"hint,omitempty"`
	// Options enumerates the legal values for Type=enum.
	Options   []string `json:"options,omitempty"`
	Sensitive bool     `json:"sensitive,omitempty"`
	Pattern   string   `json:"pattern,omitempty"`
	Min       *string  `json:"min,omitempty"`
	Max       *string  `json:"max,omitempty"`
}

// VariableGroup is an optional UI grouping hint for long forms.
type VariableGroup struct {
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Variables   []string `json:"variables"`
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
	TemplateName   string            `json:"template_name,omitempty"`
	Name           string            `json:"name,omitempty"`
	Variables      map[string]string `json:"variables"`
	ChainType      *string           `json:"chain_type,omitempty"`
	ChainID        *string           `json:"chain_id,omitempty"`
	APIKeyID       *string           `json:"api_key_id,omitempty"`
	SignerAddress  *string           `json:"signer_address,omitempty"`
	ExpiresAt      *time.Time        `json:"expires_at,omitempty"`
	ExpiresIn      *string           `json:"expires_in,omitempty"`
	Budget         *BudgetConfig     `json:"budget,omitempty"`
	Schedule       *ScheduleConfig   `json:"schedule,omitempty"`
	// FORCED VALIDATION — do not send skip_validation. Server rejects it (fund-loss risk).
	// SkipValidation bool `json:"skip_validation,omitempty"`
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

// ValidateRuleResultItem is a single rule result in template/preset validation.
type ValidateRuleResultItem struct {
	RuleID   string `json:"rule_id,omitempty"`
	RuleName string `json:"rule_name"`
	Type     string `json:"type"`
	Mode     string `json:"mode"`
	Valid    bool   `json:"valid"`
	Error    string `json:"error,omitempty"`
}

// ValidateTemplateResponse is the response for POST /api/v1/templates/{id}/validate.
type ValidateTemplateResponse struct {
	TemplateID   string                  `json:"template_id"`
	TemplateName string                  `json:"template_name"`
	Results      []*ValidateRuleResultItem `json:"results,omitempty"`
	Total        int                     `json:"total"`
	Passed       int                     `json:"passed"`
	Failed       int                     `json:"failed"`
}
