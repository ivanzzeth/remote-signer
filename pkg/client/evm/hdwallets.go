package evm

import (
	"context"
	"fmt"
	"net/http"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// HDWalletService handles HD wallet management operations.
type HDWalletService struct {
	transport *transport.Transport
}

// Create creates a new HD wallet.
func (s *HDWalletService) Create(ctx context.Context, req *CreateHDWalletRequest) (*HDWalletResponse, error) {
	if req.Action == "" {
		req.Action = "create"
	}
	var result HDWalletResponse
	err := s.transport.Request(ctx, http.MethodPost, "/api/v1/evm/hd-wallets", req, &result,
		http.StatusCreated)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// Import imports an HD wallet from a mnemonic.
func (s *HDWalletService) Import(ctx context.Context, req *CreateHDWalletRequest) (*HDWalletResponse, error) {
	req.Action = "import"
	return s.Create(ctx, req)
}

// List lists all HD wallets.
func (s *HDWalletService) List(ctx context.Context) (*ListHDWalletsResponse, error) {
	var result ListHDWalletsResponse
	err := s.transport.Request(ctx, http.MethodGet, "/api/v1/evm/hd-wallets", nil, &result,
		http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// DeriveAddress derives a single address from an HD wallet.
func (s *HDWalletService) DeriveAddress(ctx context.Context, primaryAddr string, req *DeriveAddressRequest) (*DeriveAddressResponse, error) {
	path := fmt.Sprintf("/api/v1/evm/hd-wallets/%s/derive", primaryAddr)
	var result DeriveAddressResponse
	err := s.transport.Request(ctx, http.MethodPost, path, req, &result, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// ListDerived lists all derived addresses for an HD wallet.
func (s *HDWalletService) ListDerived(ctx context.Context, primaryAddr string) (*ListDerivedAddressesResponse, error) {
	path := fmt.Sprintf("/api/v1/evm/hd-wallets/%s/derived", primaryAddr)
	var result ListDerivedAddressesResponse
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &result, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
