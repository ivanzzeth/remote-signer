// Package presets provides preset API client for the remote-signer (admin only).
package presets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// Service handles preset operations (list, vars, apply). All require admin API key.
type Service struct {
	transport *transport.Transport
}

// NewService creates a new presets service. Panics if transport is nil (programming error).
func NewService(t *transport.Transport) *Service {
	if t == nil {
		panic("presets.NewService: transport is required")
	}
	return &Service{transport: t}
}

// PresetEntry is a preset list item. v0.3 renames template_names →
// template_ids (file-stem IDs, stable across renames) and gains the
// description + chain scope + enabled fields the UI list view uses.
type PresetEntry struct {
	ID          string   `json:"id"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	ChainType   string   `json:"chain_type,omitempty"`
	ChainID     string   `json:"chain_id,omitempty"`
	TemplateIDs []string `json:"template_ids"`
	Enabled     bool     `json:"enabled"`
}

// ListResponse is the response for GET /api/v1/presets.
type ListResponse struct {
	Presets []PresetEntry `json:"presets"`
}

// List returns presets visible to the caller. Pass query for case-insensitive
// fuzzy filter on id, name, description, and template_ids (GET ?q=).
func (s *Service) List(ctx context.Context, query string) (*ListResponse, error) {
	path := "/api/v1/presets"
	if strings.TrimSpace(query) != "" {
		path += "?q=" + url.QueryEscape(strings.TrimSpace(query))
	}
	var out ListResponse
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &out, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// VariableDetail is the per-variable metadata on a preset detail response.
type VariableDetail struct {
	Name         string `json:"name"`
	Type         string `json:"type,omitempty"`
	Description  string `json:"description,omitempty"`
	DefaultValue string `json:"default_value,omitempty"`
	Required     bool   `json:"required"`
}

// DetailResponse is the response for GET /api/v1/presets/:id.
// Variables[] resolves each operator_override against the referenced
// template's variable definition (type, description, default). The
// older bare /vars endpoint that returned `override_hints []string`
// is gone in v0.3; template_names is now template_ids.
type DetailResponse struct {
	ID          string           `json:"id"`
	Name        string           `json:"name,omitempty"`
	Description string           `json:"description,omitempty"`
	ChainType   string           `json:"chain_type,omitempty"`
	ChainID     string           `json:"chain_id,omitempty"`
	Enabled     bool             `json:"enabled"`
	TemplateIDs []string         `json:"template_ids"`
	Variables   []VariableDetail `json:"variables"`
	Matrix      json.RawMessage   `json:"matrix,omitempty"`
}

// Get returns rich detail for a preset (admin only).
func (s *Service) Get(ctx context.Context, id string) (*DetailResponse, error) {
	path := "/api/v1/presets/" + url.PathEscape(id)
	var out DetailResponse
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &out, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ApplyRequest is the body for POST /api/v1/presets/:id/apply.
type ApplyRequest struct {
	Variables      map[string]string `json:"variables,omitempty"`
	AppliedTo      []string          `json:"applied_to,omitempty"`
	SkipValidation bool              `json:"skip_validation,omitempty"`
}

// ApplyResultItem is one entry in the apply response.
type ApplyResultItem struct {
	Rule   json.RawMessage `json:"rule"`
	Budget json.RawMessage `json:"budget,omitempty"`
}

// ApplyResponse is the response for POST /api/v1/presets/:id/apply (201).
type ApplyResponse struct {
	Results []ApplyResultItem `json:"results"`
}

// ValidatePresetResponse is the response for POST /api/v1/presets/{id}/validate.
type ValidatePresetResponse struct {
	PresetID   string      `json:"preset_id"`
	PresetName string      `json:"preset_name"`
	Results    []*PresetValidateResultItem `json:"results,omitempty"`
	Total      int         `json:"total"`
	Passed     int         `json:"passed"`
	Failed     int         `json:"failed"`
}

// PresetValidateResultItem is a single rule result in preset validation.
type PresetValidateResultItem struct {
	RuleName string `json:"rule_name"`
	Type     string `json:"type"`
	Mode     string `json:"mode"`
	Valid    bool   `json:"valid"`
	Error    string `json:"error,omitempty"`
}

// Apply applies a preset and creates template instances in one transaction (admin only).
// Returns 201 with results, or error (e.g. 403 when rules_api_readonly, 400 on parse/template failure).
func (s *Service) Apply(ctx context.Context, id string, req *ApplyRequest) (*ApplyResponse, error) {
	if req == nil {
		req = &ApplyRequest{}
	}
	path := "/api/v1/presets/" + url.PathEscape(id) + "/apply"
	var out ApplyResponse
	err := s.transport.Request(ctx, http.MethodPost, path, req, &out, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ApplyWithVariables is a convenience that calls Apply with the given variables.
func (s *Service) ApplyWithVariables(ctx context.Context, id string, variables map[string]string) (*ApplyResponse, error) {
	return s.Apply(ctx, id, &ApplyRequest{Variables: variables})
}

// Validate runs test case validation for a preset (POST /api/v1/presets/{id}/validate).
// Resolves preset-level variables, substitutes them into each referenced template's
// config and test inputs, then runs tests via the JS sandbox.
func (s *Service) Validate(ctx context.Context, id string, variables map[string]string) (*ValidatePresetResponse, error) {
	path := "/api/v1/presets/" + url.PathEscape(id) + "/validate"
	body := struct {
		Variables map[string]string `json:"variables,omitempty"`
	}{Variables: variables}
	var resp ValidatePresetResponse
	err := s.transport.Request(ctx, http.MethodPost, path, body, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
