// Package audit provides audit log client services for the remote-signer.
package audit

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// Service handles audit log operations.
type Service struct {
	transport *transport.Transport
}

// NewService creates a new audit service.
func NewService(t *transport.Transport) *Service {
	return &Service{transport: t}
}

// List lists audit records with optional filters.
func (s *Service) List(ctx context.Context, filter *ListFilter) (*ListResponse, error) {
	path := "/api/v1/audit"
	params := make([]string, 0)

	if filter != nil {
		if filter.EventType != "" {
			params = append(params, fmt.Sprintf("event_type=%s", filter.EventType))
		}
		if filter.Severity != "" {
			params = append(params, fmt.Sprintf("severity=%s", filter.Severity))
		}
		if filter.APIKeyID != "" {
			params = append(params, fmt.Sprintf("api_key_id=%s", filter.APIKeyID))
		}
		if filter.SignerAddress != "" {
			params = append(params, fmt.Sprintf("signer_address=%s", filter.SignerAddress))
		}
		if filter.ChainType != "" {
			params = append(params, fmt.Sprintf("chain_type=%s", filter.ChainType))
		}
		if filter.ChainID != "" {
			params = append(params, fmt.Sprintf("chain_id=%s", filter.ChainID))
		}
		if filter.StartTime != nil {
			params = append(params, fmt.Sprintf("start_time=%s", filter.StartTime.Format(time.RFC3339)))
		}
		if filter.EndTime != nil {
			params = append(params, fmt.Sprintf("end_time=%s", filter.EndTime.Format(time.RFC3339)))
		}
		if filter.Limit > 0 {
			params = append(params, fmt.Sprintf("limit=%d", filter.Limit))
		}
		if filter.Cursor != nil {
			params = append(params, fmt.Sprintf("cursor=%s", url.QueryEscape(*filter.Cursor)))
		}
		if filter.CursorID != nil {
			params = append(params, fmt.Sprintf("cursor_id=%s", url.QueryEscape(*filter.CursorID)))
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

// API defines the audit service interface.
type API interface {
	List(ctx context.Context, filter *ListFilter) (*ListResponse, error)
}

// Compile-time interface check.
var _ API = (*Service)(nil)
