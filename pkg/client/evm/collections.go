package evm

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// CollectionService handles wallet collection operations.
type CollectionService struct {
	transport *transport.Transport
}

// Create creates a new wallet collection.
func (s *CollectionService) Create(ctx context.Context, req *CreateCollectionRequest) (*Collection, error) {
	var col Collection
	err := s.transport.Request(ctx, http.MethodPost, "/api/v1/collections", req, &col,
		http.StatusOK, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	return &col, nil
}

// Get retrieves a collection by ID.
func (s *CollectionService) Get(ctx context.Context, id string) (*Collection, error) {
	var col Collection
	path := fmt.Sprintf("/api/v1/collections/%s", id)
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &col, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &col, nil
}

// List lists collections with optional filters.
func (s *CollectionService) List(ctx context.Context, filter *ListCollectionsFilter) (*ListCollectionsResponse, error) {
	path := "/api/v1/collections"
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

	var resp ListCollectionsResponse
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Delete deletes a collection by ID (cascade deletes members).
func (s *CollectionService) Delete(ctx context.Context, id string) error {
	path := fmt.Sprintf("/api/v1/collections/%s", id)
	return s.transport.Request(ctx, http.MethodDelete, path, nil, nil, http.StatusOK, http.StatusNoContent)
}

// AddMember adds a wallet as a member of a collection.
func (s *CollectionService) AddMember(ctx context.Context, collectionID string, req *AddCollectionMemberRequest) (*CollectionMember, error) {
	var member CollectionMember
	path := fmt.Sprintf("/api/v1/collections/%s/members", collectionID)
	err := s.transport.Request(ctx, http.MethodPost, path, req, &member,
		http.StatusOK, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	return &member, nil
}

// RemoveMember removes a wallet from a collection.
func (s *CollectionService) RemoveMember(ctx context.Context, collectionID, walletID string) error {
	path := fmt.Sprintf("/api/v1/collections/%s/members/%s", collectionID, walletID)
	return s.transport.Request(ctx, http.MethodDelete, path, nil, nil, http.StatusOK, http.StatusNoContent)
}

// ListMembers lists members of a collection.
func (s *CollectionService) ListMembers(ctx context.Context, collectionID string) (*ListCollectionMembersResponse, error) {
	var resp ListCollectionMembersResponse
	path := fmt.Sprintf("/api/v1/collections/%s/members", collectionID)
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
