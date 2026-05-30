// Package evm provides HTTP handlers for EVM signer and rule management API.
// This file contains response/request types and helpers for the rule management endpoints.
package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// RuleResponse represents a rule in API responses
type RuleResponse struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	Description       string          `json:"description,omitempty"`
	Type              string          `json:"type"`
	Mode              string          `json:"mode"`
	Source            string          `json:"source"`
	ChainType         *string         `json:"chain_type,omitempty"`
	ChainID           *string         `json:"chain_id,omitempty"`
	Owner             *string         `json:"owner,omitempty"`
	AppliedTo         []string        `json:"applied_to,omitempty"`
	Status            string          `json:"status,omitempty"`
	ApprovedBy        *string         `json:"approved_by,omitempty"`
	Immutable         bool            `json:"immutable,omitempty"`
	SignerAddress     *string         `json:"signer_address,omitempty"`
	TemplateID        *string         `json:"template_id,omitempty"`
	Config            json.RawMessage `json:"config,omitempty"`
	Variables         json.RawMessage `json:"variables,omitempty"`
	VariableDefs      []VariableDef   `json:"variable_defs,omitempty"`
	Matrix            json.RawMessage `json:"matrix,omitempty"`
	Enabled           bool            `json:"enabled"`
	Priority          int             `json:"priority"`
	CreatedAt         string          `json:"created_at"`
	UpdatedAt         string          `json:"updated_at"`
	ExpiresAt         *string         `json:"expires_at,omitempty"`
	MatchCount        uint64          `json:"match_count"`
	LastMatchedAt     *string         `json:"last_matched_at,omitempty"`
	BudgetPeriod      string          `json:"budget_period,omitempty"`       // e.g. "24h0m0s"; set when schedule.period is configured
	BudgetPeriodStart *string         `json:"budget_period_start,omitempty"` // RFC3339; when first period began
}

// VariableDef exposes a template variable's metadata alongside its current
// bound value so the UI can render typed controls without a separate template
// fetch. Mirrors PresetVariableDetail but includes the current value.
type VariableDef struct {
	Name         string `json:"name"`
	Type         string `json:"type,omitempty"`
	Label        string `json:"label,omitempty"`
	Description  string `json:"description,omitempty"`
	Required     bool   `json:"required"`
	DefaultValue string `json:"default_value,omitempty"`
	Placeholder  string `json:"placeholder,omitempty"`
	Hint         string `json:"hint,omitempty"`
	Options      []string `json:"options,omitempty"`
	Sensitive    bool   `json:"sensitive,omitempty"`
	Value        string `json:"value,omitempty"`
}

// ListRulesResponse represents the response for listing rules
type ListRulesResponse struct {
	Rules []RuleResponse `json:"rules"`
	Total int            `json:"total"`
}

// JSRuleTestCase is a test case for evm_js rules submitted via API.
type JSRuleTestCase struct {
	Name         string                 `json:"name"`
	Input        map[string]interface{} `json:"input"`
	ExpectPass   bool                   `json:"expect_pass"`
	ExpectReason string                 `json:"expect_reason,omitempty"`
}

// CreateRuleRequest represents a request to create a new rule
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
	Priority      *int                   `json:"priority,omitempty"`
	TestCases     []JSRuleTestCase       `json:"test_cases,omitempty"` // required for evm_js rules
}

// UpdateRuleRequest represents a request to update an existing rule
type UpdateRuleRequest struct {
	Name          string                 `json:"name,omitempty"`
	Description   string                 `json:"description,omitempty"`
	Type          string                 `json:"type,omitempty"`
	Config        map[string]interface{} `json:"config,omitempty"`
	Variables     map[string]string      `json:"variables,omitempty"`
	Matrix        []map[string]any       `json:"matrix,omitempty"`
	ChainType     *string                `json:"chain_type,omitempty"`
	ChainID       *string                `json:"chain_id,omitempty"`
	SignerAddress *string                `json:"signer_address,omitempty"`
	Enabled       *bool                  `json:"enabled,omitempty"`
	AppliedTo     []string               `json:"applied_to,omitempty"`
	Priority      *int                   `json:"priority,omitempty"`
	TestCases     []JSRuleTestCase       `json:"test_cases,omitempty"` // required for evm_js when updating config
}

// RejectRuleRequest represents a request body for POST /evm/rules/:id/reject
type RejectRuleRequest struct {
	Reason string `json:"reason"`
}

// ValidateTestResult represents the result of a single test case validation
type ValidateTestResult struct {
	Name       string `json:"name"`
	Passed     bool   `json:"passed"`
	ActualPass bool   `json:"actual_pass"`
	Reason     string `json:"reason,omitempty"`
}

// ValidateRuleResponse represents the response for rule validation
type ValidateRuleResponse struct {
	RuleID  string               `json:"rule_id"`
	RuleName string              `json:"rule_name"`
	Type    string               `json:"type"`
	Valid   bool                 `json:"valid"`
	Results []ValidateTestResult `json:"results,omitempty"`
	Error   string               `json:"error,omitempty"`
}

// BatchValidateResponse represents the response for batch rule validation
type BatchValidateResponse struct {
	Results []ValidateRuleResponse `json:"results"`
	Total   int                    `json:"total"`
	Passed  int                    `json:"passed"`
	Failed  int                    `json:"failed"`
}

func (h *RuleHandler) toRuleResponse(rule *types.Rule) RuleResponse {
	resp := RuleResponse{
		ID:          string(rule.ID),
		Name:        rule.Name,
		Description: rule.Description,
		Type:        string(rule.Type),
		Mode:        string(rule.Mode),
		Source:      string(rule.Source),
		Config:      rule.Config,
		Enabled:     rule.Enabled,
		Priority:    rule.Priority,
		CreatedAt:   rule.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   rule.UpdatedAt.Format(time.RFC3339),
		MatchCount:  rule.MatchCount,
		Immutable:   rule.Immutable,
	}

	if rule.ChainType != nil {
		ct := string(*rule.ChainType)
		resp.ChainType = &ct
	}
	if rule.ChainID != nil {
		resp.ChainID = rule.ChainID
	}
	if rule.Owner != "" {
		owner := rule.Owner
		resp.Owner = &owner
	}
	if len(rule.AppliedTo) > 0 {
		resp.AppliedTo = []string(rule.AppliedTo)
	}
	if rule.Status != "" {
		resp.Status = string(rule.Status)
	}
	if rule.ApprovedBy != nil {
		resp.ApprovedBy = rule.ApprovedBy
	}
	if rule.SignerAddress != nil {
		resp.SignerAddress = rule.SignerAddress
	}
	if rule.ExpiresAt != nil {
		expiresAt := rule.ExpiresAt.Format(time.RFC3339)
		resp.ExpiresAt = &expiresAt
	}
	if rule.LastMatchedAt != nil {
		lastMatchedAt := rule.LastMatchedAt.Format(time.RFC3339)
		resp.LastMatchedAt = &lastMatchedAt
	}
	if rule.BudgetPeriod != nil && *rule.BudgetPeriod > 0 {
		resp.BudgetPeriod = rule.BudgetPeriod.String()
	}
	if rule.BudgetPeriodStart != nil {
		s := rule.BudgetPeriodStart.Format(time.RFC3339)
		resp.BudgetPeriodStart = &s
	}
	if rule.TemplateID != nil {
		tid := *rule.TemplateID
		resp.TemplateID = &tid
	}
	if rule.Variables != nil {
		resp.Variables = json.RawMessage(rule.Variables)
	}
	if rule.Matrix != nil {
		resp.Matrix = json.RawMessage(rule.Matrix)
	}

	return resp
}

// enrichVariableDefs attaches template-level variable metadata + current
// bound values when the rule has a template_id. If the template repo is
// unavailable or the template can't be found, the response simply omits
// variable_defs — the UI falls back to raw Variables display.
func (h *RuleHandler) enrichVariableDefs(resp *RuleResponse, rule *types.Rule) {
	if h.templateRepo == nil || rule.TemplateID == nil || *rule.TemplateID == "" {
		return
	}

	tmpl, err := h.templateRepo.Get(context.Background(), *rule.TemplateID)
	if err != nil || tmpl == nil || len(tmpl.Variables) == 0 {
		return
	}

	var defs []types.TemplateVariable
	if err := json.Unmarshal(tmpl.Variables, &defs); err != nil {
		h.logger.Warn("enrichVariableDefs: decode template variables", "template_id", *rule.TemplateID, "error", err)
		return
	}

	// Decode current bound values (map[string]string stored as JSONB)
	var bound map[string]string
	if rule.Variables != nil {
		if err := json.Unmarshal(rule.Variables, &bound); err != nil {
			h.logger.Debug("enrichVariableDefs: decode rule variables", "rule_id", string(rule.ID), "error", err)
			bound = nil
		}
	}

	out := make([]VariableDef, 0, len(defs))
	for _, def := range defs {
		entry := VariableDef{
			Name:        def.Name,
			Type:        string(def.Type),
			Label:       def.Label,
			Description: def.Description,
			Required:    def.Required,
			Placeholder: def.Placeholder,
			Hint:        def.Hint,
			Options:     def.Options,
			Sensitive:   def.Sensitive,
		}
		entry.DefaultValue = stringifyDefault(def.Default)
		if v, ok := bound[def.Name]; ok {
			entry.Value = v
		}
		out = append(out, entry)
	}
	resp.VariableDefs = out
}

// stringifyDefault converts a TemplateVariable.Default (any) to its JSON-safe
// string form for wire transport. nil → "".
func stringifyDefault(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}

func (h *RuleHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

func (h *RuleHandler) writeError(w http.ResponseWriter, message string, status int) {
	h.writeJSON(w, ErrorResponse{Error: message}, status)
}
