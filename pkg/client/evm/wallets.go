package evm

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// WalletService handles wallet operations.
type WalletService struct {
	transport *transport.Transport
}

// Create creates a new wallet.
func (s *WalletService) Create(ctx context.Context, req *CreateWalletRequest) (*Wallet, error) {
	var wallet Wallet
	err := s.transport.Request(ctx, http.MethodPost, "/api/v1/wallets", req, &wallet,
		http.StatusOK, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	return &wallet, nil
}

// Get retrieves a wallet by ID.
func (s *WalletService) Get(ctx context.Context, id string) (*Wallet, error) {
	var wallet Wallet
	path := fmt.Sprintf("/api/v1/wallets/%s", id)
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &wallet, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &wallet, nil
}

// List lists wallets with optional filters.
func (s *WalletService) List(ctx context.Context, filter *ListWalletsFilter) (*ListWalletsResponse, error) {
	path := "/api/v1/wallets"
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

	var resp ListWalletsResponse
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Delete deletes a wallet by ID (cascade deletes members).
func (s *WalletService) Delete(ctx context.Context, id string) error {
	path := fmt.Sprintf("/api/v1/wallets/%s", id)
	return s.transport.Request(ctx, http.MethodDelete, path, nil, nil, http.StatusOK, http.StatusNoContent)
}

// AddMember adds a signer member to a wallet.
func (s *WalletService) AddMember(ctx context.Context, walletID string, req *AddWalletMemberRequest) (*WalletMember, error) {
	var member WalletMember
	path := fmt.Sprintf("/api/v1/wallets/%s/members", walletID)
	err := s.transport.Request(ctx, http.MethodPost, path, req, &member,
		http.StatusOK, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	return &member, nil
}

// RemoveMember removes a signer from a wallet.
func (s *WalletService) RemoveMember(ctx context.Context, walletID, signerAddress string) error {
	path := fmt.Sprintf("/api/v1/wallets/%s/members/%s", walletID, signerAddress)
	return s.transport.Request(ctx, http.MethodDelete, path, nil, nil, http.StatusOK, http.StatusNoContent)
}

// ListMembers lists members of a wallet.
func (s *WalletService) ListMembers(ctx context.Context, walletID string) (*ListWalletMembersResponse, error) {
	var resp ListWalletMembersResponse
	path := fmt.Sprintf("/api/v1/wallets/%s/members", walletID)
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
