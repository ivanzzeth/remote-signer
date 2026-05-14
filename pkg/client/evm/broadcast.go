package evm

import (
	"context"
	"net/http"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// BroadcastService handles broadcasting signed transactions.
type BroadcastService struct {
	transport *transport.Transport
}

// BroadcastRequest is the request body for broadcasting a signed transaction.
type BroadcastRequest struct {
	ChainID     string `json:"chain_id"`
	SignedTxHex string `json:"signed_tx_hex"`
}

// BroadcastResponse is the response from broadcasting a transaction.
type BroadcastResponse struct {
	TxHash string `json:"tx_hash"`
}

// Broadcast broadcasts a signed transaction to the chain.
func (s *BroadcastService) Broadcast(ctx context.Context, req *BroadcastRequest) (*BroadcastResponse, error) {
	var resp BroadcastResponse
	err := s.transport.Request(ctx, http.MethodPost, "/api/v1/evm/broadcast", req, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
