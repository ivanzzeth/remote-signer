package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/api/respond"

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
	// Rejected when empty or not a positive decimal integer — one combined 400.
	ChainID string `json:"chain_id" binding:"required"`
	// Rejected when empty or not 0x-prefixed hex — one combined 400.
	SignedTxHex string `json:"signed_tx_hex" binding:"required"`
}

// BroadcastResponse is the response from broadcasting a transaction.
type BroadcastResponse struct {
	TxHash string `json:"tx_hash"`
}

// ServeHTTP handles POST /api/v1/evm/broadcast.
//
//	@Summary	Broadcast a signed transaction
//	@Description	⛔ This endpoint does NOT sign and does NOT consult the rule engine: it forwards bytes the caller already holds to the chain's RPC. A transaction signed elsewhere goes out unexamined.
//	@Description	⚠️ An RPC rejection is 502, not 400 — including a rejection caused by the caller's own transaction (bad nonce, underpriced). The upstream message is passed through verbatim in `error`.
//	@Tags	sign
//	@Accept	json
//	@Produce	json
//	@Param	body	body	BroadcastRequest	true	"signed transaction to broadcast"
//	@Success	200	{object}	BroadcastResponse
//	@Failure	400	{object}	map[string]string
//	@Failure	401	{object}	map[string]string
//	@Failure	502	{object}	map[string]string	"the upstream RPC refused it"
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/broadcast [post]
func (h *BroadcastHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// ⛔ No method check: the route is method-scoped (see setupRoutes) and Go's
	// ServeMux answers 405 before this runs.

	var req BroadcastRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.Error(w, "invalid request body", http.StatusBadRequest, h.logger)
		return
	}

	if req.ChainID == "" || !validate.IsValidChainID(req.ChainID) {
		respond.Error(w, "chain_id is required and must be a positive decimal integer", http.StatusBadRequest, h.logger)
		return
	}
	if req.SignedTxHex == "" || !validate.IsValidHexData(req.SignedTxHex) {
		respond.Error(w, "signed_tx_hex is required and must be valid 0x-prefixed hex", http.StatusBadRequest, h.logger)
		return
	}

	txHash, err := h.rpcProvider.SendRawTransaction(r.Context(), req.ChainID, req.SignedTxHex)
	if err != nil {
		h.logger.Error("broadcast failed", "error", err, "chain_id", req.ChainID)
		respond.Error(w, fmt.Sprintf("broadcast failed: %s", err.Error()), http.StatusBadGateway, h.logger)
		return
	}

	h.logger.Info("transaction broadcast", "tx_hash", txHash, "chain_id", req.ChainID)
	respond.JSON(w, BroadcastResponse{TxHash: txHash}, http.StatusOK, h.logger)
}
