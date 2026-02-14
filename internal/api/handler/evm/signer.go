package evm

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// SignerHandler handles signer management endpoints
type SignerHandler struct {
	signerManager evm.SignerManager
	logger        *slog.Logger
}

// NewSignerHandler creates a new signer handler
func NewSignerHandler(signerManager evm.SignerManager, logger *slog.Logger) (*SignerHandler, error) {
	if signerManager == nil {
		return nil, fmt.Errorf("signer manager is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &SignerHandler{
		signerManager: signerManager,
		logger:        logger,
	}, nil
}

// SignerResponse represents a signer in API responses
type SignerResponse struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
}

// ListSignersResponse represents the response for listing signers
type ListSignersResponse struct {
	Signers []SignerResponse `json:"signers"`
	Total   int              `json:"total"`
	HasMore bool             `json:"has_more"`
}

// CreateSignerRequest represents the request to create a signer
type CreateSignerRequest struct {
	Type     string                  `json:"type"`
	Keystore *CreateKeystoreRequest  `json:"keystore,omitempty"`
}

// CreateKeystoreRequest contains keystore creation parameters
type CreateKeystoreRequest struct {
	Password string `json:"password"`
}

// CreateSignerResponse represents the response after creating a signer
type CreateSignerResponse struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
}

// ServeHTTP handles /api/v1/evm/signers
func (h *SignerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get API key from context
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.listSigners(w, r)
	case http.MethodPost:
		// Create requires admin
		if !apiKey.Admin {
			h.writeError(w, "admin access required", http.StatusForbidden)
			return
		}
		h.createSigner(w, r)
	default:
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// listSigners handles GET /api/v1/evm/signers
func (h *SignerHandler) listSigners(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// Parse filter parameters
	filter := types.SignerFilter{
		Offset: 0,
		Limit:  20, // Default limit
	}

	// Parse type filter
	if typeStr := query.Get("type"); typeStr != "" {
		signerType := types.SignerType(typeStr)
		filter.Type = &signerType
	}

	// Parse offset
	if offsetStr := query.Get("offset"); offsetStr != "" {
		offset, err := strconv.Atoi(offsetStr)
		if err != nil || offset < 0 {
			h.writeError(w, "invalid offset parameter", http.StatusBadRequest)
			return
		}
		filter.Offset = offset
	}

	// Parse limit
	if limitStr := query.Get("limit"); limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 0 {
			h.writeError(w, "invalid limit parameter", http.StatusBadRequest)
			return
		}
		if limit > 100 {
			limit = 100 // Max limit
		}
		filter.Limit = limit
	}

	result, err := h.signerManager.ListSigners(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list signers", slog.String("error", err.Error()))
		h.writeError(w, "failed to list signers", http.StatusInternalServerError)
		return
	}

	// Convert to response
	signers := make([]SignerResponse, len(result.Signers))
	for i, s := range result.Signers {
		signers[i] = SignerResponse{
			Address: s.Address,
			Type:    s.Type,
			Enabled: s.Enabled,
		}
	}

	resp := ListSignersResponse{
		Signers: signers,
		Total:   result.Total,
		HasMore: result.HasMore,
	}

	h.writeJSON(w, resp, http.StatusOK)
}

// createSigner handles POST /api/v1/evm/signers
func (h *SignerHandler) createSigner(w http.ResponseWriter, r *http.Request) {
	var req CreateSignerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Convert to types.CreateSignerRequest
	createReq := types.CreateSignerRequest{
		Type: types.SignerType(req.Type),
	}

	if req.Keystore != nil {
		createReq.Keystore = &types.CreateKeystoreParams{
			Password: req.Keystore.Password,
		}
	}

	// Validate request
	if err := createReq.Validate(); err != nil {
		h.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	signerInfo, err := h.signerManager.CreateSigner(r.Context(), createReq)
	if err != nil {
		h.logger.Error("failed to create signer",
			slog.String("type", req.Type),
			slog.String("error", err.Error()),
		)
		h.writeError(w, "failed to create signer", http.StatusInternalServerError)
		return
	}

	h.logger.Info("signer created",
		slog.String("address", signerInfo.Address),
		slog.String("type", signerInfo.Type),
	)

	resp := CreateSignerResponse{
		Address: signerInfo.Address,
		Type:    signerInfo.Type,
		Enabled: signerInfo.Enabled,
	}

	h.writeJSON(w, resp, http.StatusCreated)
}

// writeJSON writes a JSON response
func (h *SignerHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", slog.String("error", err.Error()))
	}
}

// writeError writes an error response
func (h *SignerHandler) writeError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
