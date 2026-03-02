package evm

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/metrics"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

// SignHandler handles EVM sign requests
type SignHandler struct {
	signService   *service.SignService
	signerManager evm.SignerManager
	logger        *slog.Logger
}

// NewSignHandler creates a new sign handler
func NewSignHandler(signService *service.SignService, signerManager evm.SignerManager, logger *slog.Logger) (*SignHandler, error) {
	if signService == nil {
		return nil, fmt.Errorf("sign service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &SignHandler{
		signService:   signService,
		signerManager: signerManager,
		logger:        logger,
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

	// Parse request — log details internally, return generic error to client
	// to prevent leaking Go type names and package paths in error messages.
	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("failed to decode sign request", "error", err, "path", r.URL.Path)
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields and formats
	if req.ChainID == "" {
		h.writeError(w, "chain_id is required", http.StatusBadRequest)
		return
	}
	if _, err := strconv.ParseUint(req.ChainID, 10, 64); err != nil {
		h.writeError(w, "invalid chain_id: must be a positive decimal integer", http.StatusBadRequest)
		return
	}
	if req.SignerAddress == "" {
		h.writeError(w, "signer_address is required", http.StatusBadRequest)
		return
	}
	if !validate.IsValidEthereumAddress(req.SignerAddress) {
		h.writeError(w, "invalid signer_address: must be 0x followed by 40 hex characters", http.StatusBadRequest)
		return
	}
	if req.SignType == "" {
		h.writeError(w, "sign_type is required", http.StatusBadRequest)
		return
	}
	if !validate.ValidSignTypes[req.SignType] {
		h.writeError(w, "invalid sign_type: must be one of hash, raw_message, eip191, personal, typed_data, transaction", http.StatusBadRequest)
		return
	}
	if len(req.Payload) == 0 {
		h.writeError(w, "payload is required", http.StatusBadRequest)
		return
	}
	const maxPayloadSize = 2 * 1024 * 1024 // 2 MB
	if len(req.Payload) > maxPayloadSize {
		h.writeError(w, "payload exceeds maximum size", http.StatusBadRequest)
		return
	}

	// Check signer permission (includes HD wallet derived address check)
	var hdMgr middleware.HDWalletDerivedLister
	if h.signerManager != nil {
		var hdErr error
		hdMgr, hdErr = h.signerManager.HDWalletManager()
		if hdErr != nil {
			h.logger.Warn("failed to get HD wallet manager for permission check", "error", hdErr)
		}
	}
	if !middleware.CheckSignerPermissionWithHDWallets(apiKey, req.SignerAddress, hdMgr) {
		h.writeError(w, "not authorized for this signer", http.StatusForbidden)
		return
	}

	start := time.Now()
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
	duration := time.Since(start)
	chainType := string(types.ChainTypeEVM)

	if err != nil {
		if types.IsNotFound(err) || types.IsSignerNotFound(err) {
			h.logger.Warn("signer not found",
				"signer_address", req.SignerAddress,
				"sign_type", req.SignType,
				"chain_id", req.ChainID,
			)
			metrics.RecordSignRequestDuration(chainType, req.SignType, metrics.SignOutcomeNotFound, duration)
			h.writeError(w, fmt.Sprintf("signer not found: %s", req.SignerAddress), http.StatusNotFound)
			return
		}
		if errors.Is(err, types.ErrInvalidPayload) {
			h.logger.Warn("invalid payload",
				"error", err,
				"signer_address", req.SignerAddress,
				"sign_type", req.SignType,
				"chain_id", req.ChainID,
			)
			metrics.RecordSignRequestDuration(chainType, req.SignType, metrics.SignOutcomeError, duration)
			h.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if errors.Is(err, service.ErrManualApprovalDisabled) {
			h.logger.Warn("request rejected: no matching rule and manual approval disabled",
				"signer_address", req.SignerAddress,
				"sign_type", req.SignType,
				"chain_id", req.ChainID,
			)
			metrics.RecordSignRequestDuration(chainType, req.SignType, metrics.SignOutcomeRejected, duration)
			h.writeError(w, "no matching rule and manual approval is disabled", http.StatusForbidden)
			return
		}
		h.logger.Error("sign request failed",
			"error", err,
			"signer_address", req.SignerAddress,
			"sign_type", req.SignType,
			"chain_id", req.ChainID,
		)
		metrics.RecordSignRequestDuration(chainType, req.SignType, metrics.SignOutcomeError, duration)
		h.writeError(w, "sign request failed", http.StatusInternalServerError)
		return
	}

	metrics.RecordSignRequestDuration(chainType, req.SignType, metrics.SignOutcomeOK, duration)
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
