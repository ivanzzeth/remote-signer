package evm

import (
	"context"
	"encoding/json"
	"net/http"
)

// BatchSignRequest is the request for signing multiple transactions atomically.
type BatchSignRequest struct {
	Requests []BatchSignItemRequest `json:"requests"`
}

// BatchSignItemRequest is a single transaction in a batch sign request.
type BatchSignItemRequest struct {
	ChainID       string          `json:"chain_id"`
	SignerAddress string          `json:"signer_address"`
	SignType      string          `json:"sign_type"`
	Transaction   json.RawMessage `json:"transaction"`
}

// BatchSignResponse is the response from a batch sign request.
type BatchSignResponse struct {
	Results           []BatchSignResultDTO `json:"results"`
	NetBalanceChanges []BalanceChangeDTO   `json:"net_balance_changes,omitempty"`
}

// BatchSignResultDTO is a per-tx result in a batch sign response.
type BatchSignResultDTO struct {
	Index      int                `json:"index"`
	RequestID  string             `json:"request_id,omitempty"`
	Signature  string             `json:"signature,omitempty"`
	SignedData string             `json:"signed_data,omitempty"`
	Simulation *SimulateResponse  `json:"simulation,omitempty"`
}

// ExecuteBatch submits a batch of signing requests atomically.
// If any transaction fails rules/budget/simulation, the entire batch is rejected.
func (s *SignService) ExecuteBatch(ctx context.Context, req *BatchSignRequest) (*BatchSignResponse, error) {
	var resp BatchSignResponse
	err := s.transport.Request(ctx, http.MethodPost, "/api/v1/evm/sign/batch", req, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
