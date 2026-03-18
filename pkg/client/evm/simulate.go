package evm

import (
	"context"
	"net/http"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// SimulateService handles transaction simulation operations.
type SimulateService struct {
	transport *transport.Transport
}

// SimulateRequest is the request for simulating a single transaction.
type SimulateRequest struct {
	ChainID string `json:"chain_id"`
	From    string `json:"from"`
	To      string `json:"to"`
	Value   string `json:"value,omitempty"`
	Data    string `json:"data,omitempty"`
	Gas     string `json:"gas,omitempty"`
}

// SimulateResponse is the response from simulating a single transaction.
type SimulateResponse struct {
	Success        bool              `json:"success"`
	GasUsed        uint64            `json:"gas_used"`
	BalanceChanges []BalanceChangeDTO `json:"balance_changes"`
	Events         []SimEventDTO     `json:"events"`
	HasApproval    bool              `json:"has_approval"`
	RevertReason   string            `json:"revert_reason,omitempty"`
}

// BalanceChangeDTO is a balance change in API responses.
type BalanceChangeDTO struct {
	Token     string `json:"token"`
	Standard  string `json:"standard"`
	Amount    string `json:"amount"`
	Direction string `json:"direction"`
	TokenID   string `json:"token_id,omitempty"`
}

// SimEventDTO is a parsed event in API responses.
type SimEventDTO struct {
	Address  string            `json:"address"`
	Event    string            `json:"event"`
	Standard string            `json:"standard"`
	Args     map[string]string `json:"args"`
}

// SimulateBatchRequest is the request for simulating multiple transactions.
type SimulateBatchRequest struct {
	ChainID      string         `json:"chain_id"`
	From         string         `json:"from"`
	Transactions []SimulateTxDTO `json:"transactions"`
}

// SimulateTxDTO is a single transaction in a batch request.
type SimulateTxDTO struct {
	To    string `json:"to"`
	Value string `json:"value,omitempty"`
	Data  string `json:"data,omitempty"`
	Gas   string `json:"gas,omitempty"`
}

// SimulateBatchResponse is the response from simulating a batch of transactions.
type SimulateBatchResponse struct {
	Results           []SimulateResultDTO `json:"results"`
	NetBalanceChanges []BalanceChangeDTO  `json:"net_balance_changes"`
}

// SimulateResultDTO is a per-tx result in a batch response.
type SimulateResultDTO struct {
	Index          int                `json:"index"`
	Success        bool               `json:"success"`
	GasUsed        uint64             `json:"gas_used"`
	BalanceChanges []BalanceChangeDTO `json:"balance_changes"`
	Events         []SimEventDTO      `json:"events"`
	HasApproval    bool               `json:"has_approval"`
	RevertReason   string             `json:"revert_reason,omitempty"`
}

// Simulate simulates a single transaction.
func (s *SimulateService) Simulate(ctx context.Context, req *SimulateRequest) (*SimulateResponse, error) {
	var resp SimulateResponse
	err := s.transport.Request(ctx, http.MethodPost, "/api/v1/evm/simulate", req, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// SimulateBatch simulates multiple transactions in sequence.
func (s *SimulateService) SimulateBatch(ctx context.Context, req *SimulateBatchRequest) (*SimulateBatchResponse, error) {
	var resp SimulateBatchResponse
	err := s.transport.Request(ctx, http.MethodPost, "/api/v1/evm/simulate/batch", req, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
