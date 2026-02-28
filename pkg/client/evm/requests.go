package evm

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// RequestService handles signing request operations.
type RequestService struct {
	transport *transport.Transport
}

// Get gets the status of a signing request.
func (s *RequestService) Get(ctx context.Context, requestID string) (*RequestStatus, error) {
	path := fmt.Sprintf("/api/v1/evm/requests/%s", requestID)
	var status RequestStatus
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &status, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &status, nil
}

// List lists signing requests with optional filters using cursor-based pagination.
func (s *RequestService) List(ctx context.Context, filter *ListRequestsFilter) (*ListRequestsResponse, error) {
	path := "/api/v1/evm/requests"
	params := make([]string, 0)

	if filter != nil {
		if filter.Status != "" {
			params = append(params, fmt.Sprintf("status=%s", filter.Status))
		}
		if filter.SignerAddress != "" {
			params = append(params, fmt.Sprintf("signer_address=%s", filter.SignerAddress))
		}
		if filter.ChainID != "" {
			params = append(params, fmt.Sprintf("chain_id=%s", filter.ChainID))
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

	var listResp ListRequestsResponse
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &listResp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &listResp, nil
}

// Approve approves or rejects a pending signing request.
func (s *RequestService) Approve(ctx context.Context, requestID string, req *ApproveRequest) (*ApproveResponse, error) {
	path := fmt.Sprintf("/api/v1/evm/requests/%s/approve", requestID)
	var resp ApproveResponse
	err := s.transport.Request(ctx, http.MethodPost, path, req, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// PreviewRule previews the rule that would be generated for a pending request.
func (s *RequestService) PreviewRule(ctx context.Context, requestID string, req *PreviewRuleRequest) (*PreviewRuleResponse, error) {
	path := fmt.Sprintf("/api/v1/evm/requests/%s/preview-rule", requestID)
	var resp PreviewRuleResponse
	err := s.transport.Request(ctx, http.MethodPost, path, req, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
