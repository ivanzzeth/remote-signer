// Package templates provides template client services for the remote-signer.
package templates

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// Service handles template operations.
type Service struct {
	transport *transport.Transport
}

// NewService creates a new template service.
func NewService(t *transport.Transport) *Service {
	return &Service{transport: t}
}

// List lists rule templates with optional filters.
func (s *Service) List(ctx context.Context, filter *ListFilter) (*ListResponse, error) {
	path := "/api/v1/templates"
	params := make([]string, 0)

	if filter != nil {
		if filter.Type != "" {
			params = append(params, fmt.Sprintf("type=%s", filter.Type))
		}
		if filter.Source != "" {
			params = append(params, fmt.Sprintf("source=%s", filter.Source))
		}
		if filter.Enabled != nil {
			params = append(params, fmt.Sprintf("enabled=%t", *filter.Enabled))
		}
		if filter.Limit > 0 {
			params = append(params, fmt.Sprintf("limit=%d", filter.Limit))
		}
		if filter.Offset > 0 {
			params = append(params, fmt.Sprintf("offset=%d", filter.Offset))
		}
	}

	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}

	var listResp ListResponse
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &listResp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &listResp, nil
}

// Get retrieves a specific template by ID.
func (s *Service) Get(ctx context.Context, templateID string) (*Template, error) {
	path := fmt.Sprintf("/api/v1/templates/%s", templateID)
	var tmpl Template
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &tmpl, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &tmpl, nil
}

// Create creates a new rule template (admin only).
func (s *Service) Create(ctx context.Context, req *CreateRequest) (*Template, error) {
	var tmpl Template
	err := s.transport.Request(ctx, http.MethodPost, "/api/v1/templates", req, &tmpl,
		http.StatusOK, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	return &tmpl, nil
}

// Update updates an existing template (admin only).
func (s *Service) Update(ctx context.Context, templateID string, req *UpdateRequest) (*Template, error) {
	path := fmt.Sprintf("/api/v1/templates/%s", templateID)
	var tmpl Template
	err := s.transport.Request(ctx, http.MethodPatch, path, req, &tmpl, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &tmpl, nil
}

// Delete deletes a template by ID (admin only).
func (s *Service) Delete(ctx context.Context, templateID string) error {
	path := fmt.Sprintf("/api/v1/templates/%s", templateID)
	return s.transport.Request(ctx, http.MethodDelete, path, nil, nil,
		http.StatusOK, http.StatusNoContent)
}

// Instantiate creates a rule instance from a template (admin only).
func (s *Service) Instantiate(ctx context.Context, templateID string, req *InstantiateRequest) (*InstantiateResponse, error) {
	path := fmt.Sprintf("/api/v1/templates/%s/instantiate", templateID)
	var resp InstantiateResponse
	err := s.transport.Request(ctx, http.MethodPost, path, req, &resp,
		http.StatusOK, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// RevokeInstance revokes (disables) a rule instance created from a template (admin only).
func (s *Service) RevokeInstance(ctx context.Context, ruleID string) (*RevokeInstanceResponse, error) {
	path := fmt.Sprintf("/api/v1/templates/instances/%s/revoke", ruleID)
	var resp RevokeInstanceResponse
	err := s.transport.Request(ctx, http.MethodPost, path, nil, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// API defines the template service interface.
type API interface {
	List(ctx context.Context, filter *ListFilter) (*ListResponse, error)
	Get(ctx context.Context, templateID string) (*Template, error)
	Create(ctx context.Context, req *CreateRequest) (*Template, error)
	Update(ctx context.Context, templateID string, req *UpdateRequest) (*Template, error)
	Delete(ctx context.Context, templateID string) error
	Instantiate(ctx context.Context, templateID string, req *InstantiateRequest) (*InstantiateResponse, error)
	RevokeInstance(ctx context.Context, ruleID string) (*RevokeInstanceResponse, error)
}

// Compile-time interface check.
var _ API = (*Service)(nil)
