package evm

import (
	"encoding/json"
	"time"
)

// Rule represents an authorization rule.
type Rule struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	Description       string     `json:"description,omitempty"`
	Type              string     `json:"type"`
	Mode              string     `json:"mode"`
	Source            string     `json:"source"`
	ChainType         *string    `json:"chain_type,omitempty"`
	ChainID           *string    `json:"chain_id,omitempty"`
	Owner             *string    `json:"owner,omitempty"`
	AppliedTo         []string   `json:"applied_to,omitempty"`
	Status            string     `json:"status,omitempty"`
	ApprovedBy        *string    `json:"approved_by,omitempty"`
	Immutable         bool       `json:"immutable,omitempty"`
	SignerAddress     *string    `json:"signer_address,omitempty"`
	Config            RuleConfig `json:"config,omitempty"`
	Enabled           bool       `json:"enabled"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	MatchCount        uint64     `json:"match_count"`
	LastMatchedAt     *time.Time `json:"last_matched_at,omitempty"`
	BudgetPeriod      string     `json:"budget_period,omitempty"`      // e.g. "24h0m0s" when schedule.period is set
	BudgetPeriodStart *string    `json:"budget_period_start,omitempty"` // RFC3339
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

// JSRuleTestCase is a test case for evm_js rules submitted via API.
type JSRuleTestCase struct {
	Name         string                 `json:"name"`
	Input        map[string]interface{} `json:"input"`
	ExpectPass   bool                   `json:"expect_pass"`
	ExpectReason string                 `json:"expect_reason,omitempty"`
}

// CreateRuleRequest represents a request to create a new rule.
type CreateRuleRequest struct {
	Name          string                 `json:"name"`
	Description   string                 `json:"description,omitempty"`
	Type          string                 `json:"type"`
	Mode          string                 `json:"mode"`
	ChainType     *string                `json:"chain_type,omitempty"`
	ChainID       *string                `json:"chain_id,omitempty"`
	SignerAddress *string                `json:"signer_address,omitempty"`
	Config        map[string]interface{} `json:"config"`
	Enabled       bool                   `json:"enabled"`
	Immutable     bool                   `json:"immutable,omitempty"`
	AppliedTo     []string               `json:"applied_to,omitempty"`
	TestCases     []JSRuleTestCase       `json:"test_cases,omitempty"`
}

// UpdateRuleRequest represents a request to update an existing rule.
type UpdateRuleRequest struct {
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Type        string                 `json:"type,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Enabled     bool                   `json:"enabled"`
	AppliedTo   []string               `json:"applied_to,omitempty"`
	TestCases   []JSRuleTestCase       `json:"test_cases,omitempty"`
}

// RuleBudget represents a budget record for a rule instance (GET /api/v1/evm/rules/{id}/budgets).
type RuleBudget struct {
	ID         string    `json:"id"`
	RuleID     string    `json:"rule_id"`
	Unit       string    `json:"unit"`
	MaxTotal   string    `json:"max_total"`
	MaxPerTx   string    `json:"max_per_tx"`
	Spent      string    `json:"spent"`
	AlertPct   int       `json:"alert_pct"`
	AlertSent  bool      `json:"alert_sent"`
	TxCount    int       `json:"tx_count"`
	MaxTxCount int       `json:"max_tx_count"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}
