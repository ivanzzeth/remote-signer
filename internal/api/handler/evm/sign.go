package evm

import (
	"context"
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
	"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

// SignHandler handles EVM sign requests
type SignHandler struct {
	signService   service.SignServiceAPI
	signerManager evm.SignerManager
	accessService *service.SignerAccessService
	signerRepo    storage.SignerRepository
	logger        *slog.Logger
	alertService  *middleware.SecurityAlertService
	signTimeout   time.Duration // context timeout for sign operations (default: 30s)
}

// SetAlertService sets the security alert service for real-time notifications.
func (h *SignHandler) SetAlertService(alertService *middleware.SecurityAlertService) {
	h.alertService = alertService
}

// SetSignTimeout sets the context timeout for sign operations.
func (h *SignHandler) SetSignTimeout(d time.Duration) {
	h.signTimeout = d
}

// SetSignerRepo sets signer repository for material status guard checks.
func (h *SignHandler) SetSignerRepo(repo storage.SignerRepository) {
	h.signerRepo = repo
}

// NewSignHandler creates a new sign handler
func NewSignHandler(signService service.SignServiceAPI, signerManager evm.SignerManager, accessService *service.SignerAccessService, logger *slog.Logger) (*SignHandler, error) {
	if signService == nil {
		return nil, fmt.Errorf("sign service is required")
	}
	if accessService == nil {
		return nil, fmt.Errorf("access service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &SignHandler{
		signService:   signService,
		signerManager: signerManager,
		accessService: accessService,
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

	// Check signer access via ownership/access service
	allowed, err := h.accessService.CheckAccess(r.Context(), apiKey.ID, req.SignerAddress)
	if err != nil {
		h.logger.Error("signer access check failed",
			"api_key_id", apiKey.ID,
			"signer_address", req.SignerAddress,
			"error", err,
		)
		h.writeError(w, "failed to check signer access", http.StatusInternalServerError)
		return
	}
	if !allowed {
		h.logger.Warn("signer permission denied",
			"api_key_id", apiKey.ID,
			"signer_address", req.SignerAddress,
		)
		if h.alertService != nil {
			clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
			h.alertService.Alert(middleware.AlertSignerDenied, apiKey.ID,
				fmt.Sprintf("[Remote Signer] SIGNER ACCESS DENIED\n\nAPI Key: %s (%s)\nIP: %s\nSigner: %s\nTime: %s",
					apiKey.ID, apiKey.Name, clientIP, req.SignerAddress,
					time.Now().UTC().Format(time.RFC3339)))
		}
		h.writeError(w, "not authorized for this signer", http.StatusForbidden)
		return
	}
	if h.signerRepo != nil {
		rec, recErr := h.signerRepo.Get(r.Context(), req.SignerAddress)
		if recErr == nil && rec != nil {
			if rec.MaterialStatus != types.SignerMaterialStatusPresent {
				h.writeError(w, fmt.Sprintf("signer material unavailable: %s", rec.MaterialStatus), http.StatusConflict)
				return
			}
		}
	}

	start := time.Now()
	clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
	// Process sign request
	signReq := &service.SignRequest{
		APIKeyID:      apiKey.ID,
		APIKeyRole:    apiKey.Role,
		ChainType:     types.ChainTypeEVM,
		ChainID:       req.ChainID,
		SignerAddress: req.SignerAddress,
		SignType:      req.SignType,
		Payload:       req.Payload,
		ClientIP:      clientIP,
	}

	signTimeout := h.signTimeout
	if signTimeout == 0 {
		signTimeout = 30 * time.Second
	}
	signCtx, signCancel := context.WithTimeout(r.Context(), signTimeout)
	defer signCancel()

	resp, err := h.signService.Sign(signCtx, signReq)
	duration := time.Since(start)
	chainType := string(types.ChainTypeEVM)

	if err != nil {
		// SECURITY NOTE (V3-10): Different responses for locked vs not-found signers are intentional.
		// AI agents need to distinguish these states to guide human operators (e.g., "unlock signer"
		// vs "signer doesn't exist"). This endpoint is behind authentication + signer access control,
		// so only authorized users see this information. Accepted risk per security audit v3.
		errResult := categorizeSignError(err, req.SignerAddress)

		// Choose appropriate log level and metrics outcome based on error category
		outcome := metrics.SignOutcomeError
		switch errResult.StatusCode {
		case http.StatusNotFound:
			outcome = metrics.SignOutcomeNotFound
			h.logger.Warn("signer not found",
				"signer_address", req.SignerAddress,
				"sign_type", req.SignType,
				"chain_id", req.ChainID,
			)
		case http.StatusForbidden:
			if errors.Is(err, service.ErrManualApprovalDisabled) {
				outcome = metrics.SignOutcomeRejected
			}
			h.logger.Warn("sign request forbidden",
				"signer_address", req.SignerAddress,
				"sign_type", req.SignType,
				"chain_id", req.ChainID,
			)
		case http.StatusBadRequest:
			h.logger.Warn("invalid payload",
				"error", err,
				"signer_address", req.SignerAddress,
				"sign_type", req.SignType,
				"chain_id", req.ChainID,
			)
		default:
			h.logger.Error("sign request failed",
				"error", err,
				"signer_address", req.SignerAddress,
				"sign_type", req.SignType,
				"chain_id", req.ChainID,
			)
		}

		metrics.RecordSignRequestDuration(chainType, req.SignType, outcome, duration)
		h.writeError(w, errResult.Message, errResult.StatusCode)
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
