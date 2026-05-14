// Package presets provides preset API client for the remote-signer (admin only).
package presets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

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

// List returns all presets (admin only).
func (s *Service) List(ctx context.Context) (*ListResponse, error) {
	var out ListResponse
	err := s.transport.Request(ctx, http.MethodGet, "/api/v1/presets", nil, &out, http.StatusOK)
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
	Variables map[string]string `json:"variables,omitempty"`
	AppliedTo []string          `json:"applied_to,omitempty"`
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
