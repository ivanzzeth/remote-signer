package evm

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// SignerService handles signer management operations.
type SignerService struct {
	transport *transport.Transport
}

// List lists available signers with optional filters.
func (s *SignerService) List(ctx context.Context, filter *ListSignersFilter) (*ListSignersResponse, error) {
	path := "/api/v1/evm/signers"
	params := make([]string, 0)

	if filter != nil {
		if filter.Type != "" {
			params = append(params, fmt.Sprintf("type=%s", filter.Type))
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

	var listResp ListSignersResponse
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &listResp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &listResp, nil
}

// Create creates a new signer (admin only).
func (s *SignerService) Create(ctx context.Context, req *CreateSignerRequest) (*Signer, error) {
	var signer Signer
	err := s.transport.Request(ctx, http.MethodPost, "/api/v1/evm/signers", req, &signer,
		http.StatusOK, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	return &signer, nil
}

// Unlock unlocks a locked signer (admin only).
func (s *SignerService) Unlock(ctx context.Context, address string, req *UnlockSignerRequest) (*UnlockSignerResponse, error) {
	var resp UnlockSignerResponse
	path := fmt.Sprintf("/api/v1/evm/signers/%s/unlock", address)
	err := s.transport.Request(ctx, http.MethodPost, path, req, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Lock locks an unlocked signer (admin only).
func (s *SignerService) Lock(ctx context.Context, address string) (*LockSignerResponse, error) {
	var resp LockSignerResponse
	path := fmt.Sprintf("/api/v1/evm/signers/%s/lock", address)
	err := s.transport.Request(ctx, http.MethodPost, path, nil, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
