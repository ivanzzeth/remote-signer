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

// NewService creates a new presets service.
func NewService(t *transport.Transport) *Service {
	return &Service{transport: t}
}

// PresetEntry is a preset list item.
type PresetEntry struct {
	ID            string   `json:"id"`
	TemplateNames []string `json:"template_names"`
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

// VarsResponse is the response for GET /api/v1/presets/:id/vars.
type VarsResponse struct {
	OverrideHints []string `json:"override_hints"`
}

// Vars returns variable override hints for a preset (admin only).
func (s *Service) Vars(ctx context.Context, id string) (*VarsResponse, error) {
	path := "/api/v1/presets/" + url.PathEscape(id) + "/vars"
	var out VarsResponse
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &out, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ApplyRequest is the body for POST /api/v1/presets/:id/apply.
type ApplyRequest struct {
	Variables map[string]string `json:"variables,omitempty"`
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
