package evm

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
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
		if filter.Tag != "" {
			params = append(params, fmt.Sprintf("tag=%s", url.QueryEscape(filter.Tag)))
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

// ApproveSigner approves a pending signer (admin only).
func (s *SignerService) ApproveSigner(ctx context.Context, address string) error {
	path := fmt.Sprintf("/api/v1/evm/signers/%s/approve", address)
	return s.transport.Request(ctx, http.MethodPost, path, nil, nil, http.StatusOK)
}

// GrantAccess grants access to a signer for another API key (owner only).
func (s *SignerService) GrantAccess(ctx context.Context, address string, req *GrantAccessRequest) error {
	path := fmt.Sprintf("/api/v1/evm/signers/%s/access", address)
	return s.transport.Request(ctx, http.MethodPost, path, req, nil, http.StatusOK)
}

// RevokeAccess revokes access from a signer for an API key (owner only).
func (s *SignerService) RevokeAccess(ctx context.Context, address, apiKeyID string) error {
	path := fmt.Sprintf("/api/v1/evm/signers/%s/access/%s", address, apiKeyID)
	return s.transport.Request(ctx, http.MethodDelete, path, nil, nil, http.StatusOK)
}

// ListAccess lists access grants for a signer (owner only).
func (s *SignerService) ListAccess(ctx context.Context, address string) ([]SignerAccessEntry, error) {
	var resp []SignerAccessEntry
	path := fmt.Sprintf("/api/v1/evm/signers/%s/access", address)
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// TransferOwnership transfers signer ownership to a new API key (owner only).
// Clears the entire access list; old owner loses ALL access.
func (s *SignerService) TransferOwnership(ctx context.Context, address string, req *TransferOwnershipRequest) error {
	path := fmt.Sprintf("/api/v1/evm/signers/%s/transfer", address)
	return s.transport.Request(ctx, http.MethodPost, path, req, nil, http.StatusOK)
}

// DeleteSigner deletes a signer's ownership and access records (owner only).
func (s *SignerService) DeleteSigner(ctx context.Context, address string) error {
	path := fmt.Sprintf("/api/v1/evm/signers/%s", address)
	return s.transport.Request(ctx, http.MethodDelete, path, nil, nil, http.StatusNoContent)
}

// PatchSignerLabels updates display name and/or tags (owner only).
func (s *SignerService) PatchSignerLabels(ctx context.Context, address string, req *PatchSignerLabelsRequest) (*Signer, error) {
	var out Signer
	path := fmt.Sprintf("/api/v1/evm/signers/%s", address)
	err := s.transport.Request(ctx, http.MethodPatch, path, req, &out, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListWallets lists wallets (grouped signers).
func (s *SignerService) ListWallets(ctx context.Context, filter *ListSignersFilter) (*ListWalletsResponse, error) {
	path := "/api/v1/evm/signers?group_by_wallet=true"
	params := make([]string, 0)

	if filter != nil {
		if filter.Tag != "" {
			params = append(params, fmt.Sprintf("tag=%s", url.QueryEscape(filter.Tag)))
		}
		if filter.Limit > 0 {
			params = append(params, fmt.Sprintf("limit=%d", filter.Limit))
		}
		if filter.Offset > 0 {
			params = append(params, fmt.Sprintf("offset=%d", filter.Offset))
		}
	}

	if len(params) > 0 {
		path += "&" + strings.Join(params, "&")
	}

	var listResp ListWalletsResponse
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &listResp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &listResp, nil
}

// ListWalletSigners lists signers for a specific wallet.
func (s *SignerService) ListWalletSigners(ctx context.Context, walletID string, filter *ListSignersFilter) (*WalletSignersResponse, error) {
	path := fmt.Sprintf("/api/v1/evm/wallets/%s/signers", walletID)
	params := make([]string, 0)

	if filter != nil {
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

	var resp WalletSignersResponse
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
