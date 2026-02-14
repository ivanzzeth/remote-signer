package evm

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// SignHandler handles EVM sign requests
type SignHandler struct {
	signService *service.SignService
	logger      *slog.Logger
}

// NewSignHandler creates a new sign handler
func NewSignHandler(signService *service.SignService, logger *slog.Logger) (*SignHandler, error) {
	if signService == nil {
		return nil, fmt.Errorf("sign service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &SignHandler{
		signService: signService,
		logger:      logger,
	}, nil
}

// SignRequest represents the request body for signing
type SignRequest struct {
	ChainID       string          `json:"chain_id"`
	SignerAddress string          `json:"signer_address"`
	SignType      string          `json:"sign_type"`
	Payload       json.RawMessage `json:"payload"`
}

// SignResponse represents the response for a sign request
type SignResponse struct {
	RequestID  string `json:"request_id"`
	Status     string `json:"status"`
	Signature  string `json:"signature,omitempty"`   // hex encoded
	SignedData string `json:"signed_data,omitempty"` // hex encoded
	Message    string `json:"message,omitempty"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// ServeHTTP handles the sign request
func (h *SignHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get API key from context
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Check chain permission
	if !middleware.CheckChainPermission(apiKey, types.ChainTypeEVM) {
		h.writeError(w, "not authorized for EVM chain", http.StatusForbidden)
		return
	}

	// Parse request
	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.ChainID == "" {
		h.writeError(w, "chain_id is required", http.StatusBadRequest)
		return
	}
	if req.SignerAddress == "" {
		h.writeError(w, "signer_address is required", http.StatusBadRequest)
		return
	}
	if req.SignType == "" {
		h.writeError(w, "sign_type is required", http.StatusBadRequest)
		return
	}
	if len(req.Payload) == 0 {
		h.writeError(w, "payload is required", http.StatusBadRequest)
		return
	}

	// Check signer permission
	if !middleware.CheckSignerPermission(apiKey, req.SignerAddress) {
		h.writeError(w, "not authorized for this signer", http.StatusForbidden)
		return
	}

	// Process sign request
	signReq := &service.SignRequest{
		APIKeyID:      apiKey.ID,
		ChainType:     types.ChainTypeEVM,
		ChainID:       req.ChainID,
		SignerAddress: req.SignerAddress,
		SignType:      req.SignType,
		Payload:       req.Payload,
	}

	resp, err := h.signService.Sign(r.Context(), signReq)
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "signer not found", http.StatusNotFound)
			return
		}
		h.logger.Error("sign request failed", "error", err)
		h.writeError(w, "sign request failed", http.StatusInternalServerError)
		return
	}

	// Build response
	signResp := SignResponse{
		RequestID: string(resp.RequestID),
		Status:    string(resp.Status),
		Message:   resp.Message,
	}
	if len(resp.Signature) > 0 {
		signResp.Signature = fmt.Sprintf("0x%x", resp.Signature)
	}
	if len(resp.SignedData) > 0 {
		signResp.SignedData = fmt.Sprintf("0x%x", resp.SignedData)
	}

	h.writeJSON(w, signResp, http.StatusOK)
}

func (h *SignHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

func (h *SignHandler) writeError(w http.ResponseWriter, message string, status int) {
	h.writeJSON(w, ErrorResponse{Error: message}, status)
}
