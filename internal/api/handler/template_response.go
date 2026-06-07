// Package handler provides HTTP handlers for template, MCP, broadcast, and config management.
// This file contains response/request types for the template management endpoints.
package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TemplateResponse represents a template in API responses
type TemplateResponse struct {
	ID             string                `json:"id"`
	Name           string                `json:"name"`
	Description    string                `json:"description,omitempty"`
	Type           string                `json:"type"`
	Mode           string                `json:"mode"`
	Source         string                `json:"source"`
	// ChainType surfaces the template's chain family — empty for off-chain
	// templates (sign_type_allowlist etc.). The UI uses this for the
	// "Chain" column and for filtering; before R10 the column showed
	// every row as off-chain because this field was missing from the wire.
	ChainType      string                `json:"chain_type,omitempty"`
	SourcePath     string                `json:"source_path,omitempty"`
	Variables      []TemplateVarResponse `json:"variables,omitempty"`
	VariableGroups json.RawMessage       `json:"variable_groups,omitempty"`
	Config         json.RawMessage       `json:"config,omitempty"`
	BudgetMetering json.RawMessage       `json:"budget_metering,omitempty"`
	Enabled        bool                  `json:"enabled"`
	CreatedAt      string                `json:"created_at"`
	UpdatedAt      string                `json:"updated_at"`
}

// TemplateVarResponse represents a template variable in API responses.
// Carries every UI-relevant field so the typed-widget dispatch on the
// frontend (R10) doesn't have to make a second roundtrip per variable.
type TemplateVarResponse struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Label       string   `json:"label,omitempty"`
	Description string   `json:"description,omitempty"`
	Required    bool     `json:"required"`
	// Default is `any` server-side; the SDK types it as `unknown` and
	// stringifies in the UI when needed. Round-trip via json.RawMessage
	// preserves the natural shape (string / number / bool / array).
	Default     json.RawMessage `json:"default,omitempty"`
	Placeholder string   `json:"placeholder,omitempty"`
	Hint        string   `json:"hint,omitempty"`
	Options     []string `json:"options,omitempty"`
	Sensitive   bool     `json:"sensitive,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	Min         *string  `json:"min,omitempty"`
	Max         *string  `json:"max,omitempty"`
}

// ListTemplatesResponse represents the response for listing templates
type ListTemplatesResponse struct {
	Templates []TemplateResponse `json:"templates"`
	Total     int                `json:"total"`
}

// CreateTemplateRequest represents a request to create a new template via API
type CreateTemplateRequest struct {
	Name           string                 `json:"name"`
	Description    string                 `json:"description,omitempty"`
	Type           string                 `json:"type"`
	Mode           string                 `json:"mode"`
	Variables      []TemplateVarRequest   `json:"variables,omitempty"`
	Config         map[string]interface{} `json:"config"`
	// BudgetMetering (optional) configures how a template instance measures "spend amount"
	// for budget enforcement.
	//
	// Expected keys:
	// - method: "none" | "count_only" | "tx_value" | "calldata_param" | "typed_data_field" | "js"
	// - unit:   budget identity string (recommended: include chain+asset identity, e.g. "${chain_id}:${token_address}")
	//
	// Notes:
	// - For method "js" (evm_js rules), the script may implement validateBudget(input) and return bigint/decimal-string.
	BudgetMetering map[string]interface{} `json:"budget_metering,omitempty"`
	TestVariables  map[string]string      `json:"test_variables,omitempty"`
	Enabled        bool                   `json:"enabled"`
}

// TemplateVarRequest represents a template variable in a create/update request
type TemplateVarRequest struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"`
}

// UpdateTemplateRequest represents a request to update an existing template
type UpdateTemplateRequest struct {
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Enabled     *bool                  `json:"enabled,omitempty"`
}

// InstantiateTemplateRequest represents a request to create a rule instance from a template
type InstantiateTemplateRequest struct {
	TemplateName  string            `json:"template_name,omitempty"`
	Name          string            `json:"name,omitempty"`
	Variables     map[string]string `json:"variables"`
	ChainType     *string           `json:"chain_type,omitempty"`
	ChainID       *string           `json:"chain_id,omitempty"`
	APIKeyID      *string           `json:"api_key_id,omitempty"`
	SignerAddress *string           `json:"signer_address,omitempty"`
	ExpiresAt     *time.Time        `json:"expires_at,omitempty"`
	ExpiresIn     *string           `json:"expires_in,omitempty"` // duration string e.g. "24h", "168h"
	Budget        *BudgetRequest    `json:"budget,omitempty"`
	Schedule      *ScheduleRequest  `json:"schedule,omitempty"`
	// Parsed only to reject — never honored. See validation_mandatory.go.
	SkipValidation bool `json:"skip_validation,omitempty"` //nolint:staticcheck // kept to detect forbidden client requests
}

// BudgetRequest represents budget config in an instantiate request
type BudgetRequest struct {
	MaxTotal   string `json:"max_total"`
	MaxPerTx   string `json:"max_per_tx"`
	MaxTxCount int    `json:"max_tx_count,omitempty"`
	AlertPct   int    `json:"alert_pct,omitempty"`
}

// ScheduleRequest represents schedule config in an instantiate request
type ScheduleRequest struct {
	Period  string     `json:"period"` // duration string e.g. "24h"
	StartAt *time.Time `json:"start_at,omitempty"`
}

// InstantiateTemplateResponse represents the response for creating a rule instance
type InstantiateTemplateResponse struct {
	Rule   json.RawMessage `json:"rule"`
	Budget json.RawMessage `json:"budget,omitempty"`
}

func (h *TemplateHandler) toTemplateResponse(tmpl *types.RuleTemplate) TemplateResponse {
	resp := TemplateResponse{
		ID:          tmpl.ID,
		Name:        tmpl.Name,
		Description: tmpl.Description,
		Type:        string(tmpl.Type),
		Mode:        string(tmpl.Mode),
		Source:      string(tmpl.Source),
		ChainType:   string(tmpl.ChainType),
		SourcePath:  tmpl.SourcePath,
		Config:      tmpl.Config,
		Enabled:     tmpl.Enabled,
		CreatedAt:   tmpl.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   tmpl.UpdatedAt.Format(time.RFC3339),
	}

	if len(tmpl.VariableGroups) > 0 {
		resp.VariableGroups = tmpl.VariableGroups
	}

	// Parse variables, preserving every UI-relevant field so R10's
	// typed widgets can render bool checkboxes, enum selects, list
	// textareas, etc. without a per-variable second roundtrip.
	if len(tmpl.Variables) > 0 {
		var vars []types.TemplateVariable
		if err := json.Unmarshal(tmpl.Variables, &vars); err == nil {
			resp.Variables = make([]TemplateVarResponse, len(vars))
			for i, v := range vars {
				// Marshal Default back to raw JSON so the natural shape
				// (string / number / bool / array) survives the round-
				// trip. Nil default → omit field entirely.
				var defaultRaw json.RawMessage
				if v.Default != nil {
					if b, err := json.Marshal(v.Default); err == nil {
						defaultRaw = b
					}
				}
				resp.Variables[i] = TemplateVarResponse{
					Name:        v.Name,
					Type:        string(v.Type),
					Label:       v.Label,
					Description: v.Description,
					Required:    v.Required,
					Default:     defaultRaw,
					Placeholder: v.Placeholder,
					Hint:        v.Hint,
					Options:     v.Options,
					Sensitive:   v.Sensitive,
					Pattern:     v.Pattern,
					Min:         v.Min,
					Max:         v.Max,
				}
			}
		}
	}

	if len(tmpl.BudgetMetering) > 0 {
		resp.BudgetMetering = tmpl.BudgetMetering
	}

	// Derive a display-friendly Mode when the template doesn't declare
	// one at the top level (v0.3 multi-rule templates leave it empty).
	// Aggregates the rules array: if every rule agrees, surface that
	// mode; if rules disagree, surface "mixed" so the list view can
	// still tell the operator something useful at a glance.
	if resp.Mode == "" {
		resp.Mode = aggregateRuleModes(tmpl.Config)
	}

	return resp
}

// aggregateRuleModes pulls each rule's `mode` out of the template
// config blob and returns:
//
//	""        — no rules / no modes set (shouldn't happen post-R6 but
//	            tolerated)
//	"whitelist" / "blocklist" — every rule agrees
//	"mixed"   — at least two distinct modes present
//
// Operates on the loosely-typed config JSON rather than a typed struct
// because the template body still carries ${var} placeholders that
// would fail a strict unmarshal.
func aggregateRuleModes(configJSON []byte) string {
	if len(configJSON) == 0 {
		return ""
	}
	var doc struct {
		Rules []struct {
			Mode string `json:"mode"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(configJSON, &doc); err != nil {
		return ""
	}
	seen := make(map[string]bool, 2)
	for _, r := range doc.Rules {
		if r.Mode != "" {
			seen[r.Mode] = true
		}
	}
	switch len(seen) {
	case 0:
		return ""
	case 1:
		for m := range seen {
			return m
		}
	}
	return "mixed"
}

func (h *TemplateHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

func (h *TemplateHandler) writeError(w http.ResponseWriter, message string, status int) {
	h.writeJSON(w, ErrorResponse{Error: message}, status)
}
