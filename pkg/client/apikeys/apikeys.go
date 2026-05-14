package apikeys

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// Service handles API key management operations.
type Service struct {
	transport *transport.Transport
}

// NewService creates a new API key service.
func NewService(t *transport.Transport) *Service {
	return &Service{transport: t}
}

// List lists API keys with optional filters.
func (s *Service) List(ctx context.Context, filter *ListFilter) (*ListResponse, error) {
	path := "/api/v1/api-keys"
	params := make([]string, 0)

	if filter != nil {
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

	var resp ListResponse
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Get retrieves an API key by ID.
func (s *Service) Get(ctx context.Context, id string) (*APIKey, error) {
	var key APIKey
	path := fmt.Sprintf("/api/v1/api-keys/%s", url.PathEscape(id))
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &key, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// Create creates a new API key (admin only).
func (s *Service) Create(ctx context.Context, req *CreateRequest) (*APIKey, error) {
	var key APIKey
	err := s.transport.Request(ctx, http.MethodPost, "/api/v1/api-keys", req, &key,
		http.StatusOK, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// Update updates an existing API key (admin only, API-sourced keys only).
func (s *Service) Update(ctx context.Context, id string, req *UpdateRequest) (*APIKey, error) {
	var key APIKey
	path := fmt.Sprintf("/api/v1/api-keys/%s", url.PathEscape(id))
	err := s.transport.Request(ctx, http.MethodPut, path, req, &key, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// Delete deletes an API key (admin only, API-sourced keys only).
func (s *Service) Delete(ctx context.Context, id string) error {
	path := fmt.Sprintf("/api/v1/api-keys/%s", url.PathEscape(id))
	return s.transport.Request(ctx, http.MethodDelete, path, nil, nil, http.StatusNoContent, http.StatusOK)
}

// API defines the API key service interface.
type API interface {
	List(ctx context.Context, filter *ListFilter) (*ListResponse, error)
	Get(ctx context.Context, id string) (*APIKey, error)
	Create(ctx context.Context, req *CreateRequest) (*APIKey, error)
	Update(ctx context.Context, id string, req *UpdateRequest) (*APIKey, error)
	Delete(ctx context.Context, id string) error
}

// Compile-time interface check.
var _ API = (*Service)(nil)
