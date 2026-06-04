package evm

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// TransactionService handles on-chain transaction queries.
type TransactionService struct {
	transport *transport.Transport
}

// NewTransactionService creates a new transaction service.
func NewTransactionService(t *transport.Transport) *TransactionService {
	return &TransactionService{transport: t}
}

// List lists on-chain transactions with optional filters.
func (s *TransactionService) List(ctx context.Context, filter *ListTransactionsFilter) (*ListTransactionsResponse, error) {
	path := "/api/v1/evm/transactions"
	params := make([]string, 0)

	if filter != nil {
		if filter.Status != "" {
			params = append(params, fmt.Sprintf("status=%s", filter.Status))
		}
		if filter.SignerAddress != "" {
			params = append(params, fmt.Sprintf("from=%s", filter.SignerAddress))
		}
		if filter.ChainID != "" {
			params = append(params, fmt.Sprintf("chain_id=%s", filter.ChainID))
		}
		if filter.SignType != "" {
			params = append(params, fmt.Sprintf("sign_type=%s", filter.SignType))
		}
		if filter.SignRequestID != "" {
			params = append(params, fmt.Sprintf("sign_request_id=%s", filter.SignRequestID))
		}
		if filter.APIKeyID != "" {
			params = append(params, fmt.Sprintf("api_key_id=%s", filter.APIKeyID))
		}
		if filter.Role != "" {
			params = append(params, fmt.Sprintf("role=%s", filter.Role))
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

	var resp ListTransactionsResponse
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Get retrieves a transaction by ID.
func (s *TransactionService) Get(ctx context.Context, id string) (*TransactionRecord, error) {
	path := fmt.Sprintf("/api/v1/evm/transactions/%s", id)
	var tx TransactionRecord
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &tx, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &tx, nil
}
