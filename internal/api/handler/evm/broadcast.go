package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/validate"
)

// Broadcaster defines the interface for broadcasting signed transactions.
type Broadcaster interface {
	SendRawTransaction(ctx context.Context, chainID, signedTxHex string) (string, error)
}

// BroadcastHandler handles broadcasting signed transactions.
type BroadcastHandler struct {
	rpcProvider Broadcaster
	logger      *slog.Logger
}

// NewBroadcastHandler creates a new broadcast handler.
func NewBroadcastHandler(rpcProvider Broadcaster, logger *slog.Logger) (*BroadcastHandler, error) {
	if rpcProvider == nil {
		return nil, fmt.Errorf("rpc provider is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &BroadcastHandler{
		rpcProvider: rpcProvider,
		logger:      logger,
	}, nil
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

// ServeHTTP handles POST /api/v1/evm/broadcast.
func (h *BroadcastHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req BroadcastRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.ChainID == "" || !validate.IsValidChainID(req.ChainID) {
		h.writeError(w, "chain_id is required and must be a positive decimal integer", http.StatusBadRequest)
		return
	}
	if req.SignedTxHex == "" || !validate.IsValidHexData(req.SignedTxHex) {
		h.writeError(w, "signed_tx_hex is required and must be valid 0x-prefixed hex", http.StatusBadRequest)
		return
	}

	txHash, err := h.rpcProvider.SendRawTransaction(r.Context(), req.ChainID, req.SignedTxHex)
	if err != nil {
		h.logger.Error("broadcast failed", "error", err, "chain_id", req.ChainID)
		h.writeError(w, fmt.Sprintf("broadcast failed: %s", err.Error()), http.StatusBadGateway)
		return
	}

	h.logger.Info("transaction broadcast", "tx_hash", txHash, "chain_id", req.ChainID)
	h.writeJSON(w, BroadcastResponse{TxHash: txHash}, http.StatusOK)
}

func (h *BroadcastHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

func (h *BroadcastHandler) writeError(w http.ResponseWriter, message string, status int) {
	h.writeJSON(w, ErrorResponse{Error: message}, status)
}
