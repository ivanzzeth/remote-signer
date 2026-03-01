package evm

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

// SignerHandler handles signer management endpoints
type SignerHandler struct {
	signerManager evm.SignerManager
	apiKeyRepo    storage.APIKeyRepository // nil = no filtering/enrichment
	logger        *slog.Logger
}

// NewSignerHandler creates a new signer handler
func NewSignerHandler(signerManager evm.SignerManager, apiKeyRepo storage.APIKeyRepository, logger *slog.Logger) (*SignerHandler, error) {
	if signerManager == nil {
		return nil, fmt.Errorf("signer manager is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &SignerHandler{
		signerManager: signerManager,
		apiKeyRepo:    apiKeyRepo,
		logger:        logger,
	}, nil
}

// AllowedKeyInfo represents an API key that has access to a signer
type AllowedKeyInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	AccessType string `json:"access_type"` // "unrestricted" or "explicit"
}

// SignerResponse represents a signer in API responses
type SignerResponse struct {
	Address     string           `json:"address"`
	Type        string           `json:"type"`
	Enabled     bool             `json:"enabled"`
	AllowedKeys []AllowedKeyInfo `json:"allowed_keys,omitempty"`
}

// ListSignersResponse represents the response for listing signers
type ListSignersResponse struct {
	Signers []SignerResponse `json:"signers"`
	Total   int              `json:"total"`
	HasMore bool             `json:"has_more"`
}

// CreateSignerRequest represents the request to create a signer
type CreateSignerRequest struct {
	Type     string                 `json:"type"`
	Keystore *CreateKeystoreRequest `json:"keystore,omitempty"`
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

// allowedKeysData holds precomputed access data for admin enrichment.
type allowedKeysData struct {
	unrestricted   []AllowedKeyInfo            // keys with empty AllowedSigners (access all)
	explicitAccess map[string][]AllowedKeyInfo // lowercase address -> keys with explicit access
}

// keysForSigner returns the combined AllowedKeyInfo for a given signer address.
func (d *allowedKeysData) keysForSigner(address string) []AllowedKeyInfo {
	lower := strings.ToLower(address)
	explicit := d.explicitAccess[lower]
	if len(d.unrestricted) == 0 && len(explicit) == 0 {
		return nil
	}
	result := make([]AllowedKeyInfo, 0, len(d.unrestricted)+len(explicit))
	result = append(result, d.unrestricted...)
	result = append(result, explicit...)
	return result
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

	apiKey := middleware.GetAPIKey(r.Context())

	// Parse filter parameters
	requestedOffset := 0
	requestedLimit := 20 // Default limit

	// Parse type filter (strict: unknown type returns 400)
	var signerType *types.SignerType
	if typeStr := query.Get("type"); typeStr != "" {
		if !validate.IsValidSignerType(typeStr) {
			h.writeError(w, "invalid type filter: must be private_key or keystore", http.StatusBadRequest)
			return
		}
		st := types.SignerType(typeStr)
		signerType = &st
	}

	// Parse offset
	if offsetStr := query.Get("offset"); offsetStr != "" {
		offset, err := strconv.Atoi(offsetStr)
		if err != nil || offset < 0 {
			h.writeError(w, "invalid offset parameter", http.StatusBadRequest)
			return
		}
		requestedOffset = offset
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
		requestedLimit = limit
	}

	// Determine if non-admin filtering is needed
	needsFiltering := apiKey != nil && !apiKey.Admin && len(apiKey.AllowedSigners) > 0

	filter := types.SignerFilter{
		Type: signerType,
	}

	if needsFiltering {
		// Fetch all signers (ignoring pagination) so we can filter client-side
		filter.Offset = 0
		filter.Limit = 10000
	} else {
		filter.Offset = requestedOffset
		filter.Limit = requestedLimit
	}

	result, err := h.signerManager.ListSigners(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list signers", slog.String("error", err.Error()))
		h.writeError(w, "failed to list signers", http.StatusInternalServerError)
		return
	}

	// Apply non-admin filtering
	var filteredSigners []types.SignerInfo
	if needsFiltering {
		for _, s := range result.Signers {
			if apiKey.IsAllowedSigner(s.Address) {
				filteredSigners = append(filteredSigners, s)
			}
		}
	} else {
		filteredSigners = result.Signers
	}

	// Calculate total and apply manual pagination for filtered results
	total := result.Total
	hasMore := result.HasMore
	if needsFiltering {
		total = len(filteredSigners)
		// Apply manual pagination
		if requestedOffset >= len(filteredSigners) {
			filteredSigners = nil
		} else {
			end := requestedOffset + requestedLimit
			if end > len(filteredSigners) {
				end = len(filteredSigners)
			}
			filteredSigners = filteredSigners[requestedOffset:end]
		}
		hasMore = requestedOffset+requestedLimit < total
	}

	// Build admin enrichment data
	var accessData *allowedKeysData
	if apiKey != nil && apiKey.Admin && h.apiKeyRepo != nil {
		accessData, err = h.buildAllowedKeysData(r)
		if err != nil {
			h.logger.Error("failed to build allowed keys data", slog.String("error", err.Error()))
			// Non-fatal: continue without enrichment
		}
	}

	// Convert to response
	signers := make([]SignerResponse, len(filteredSigners))
	for i, s := range filteredSigners {
		signers[i] = SignerResponse{
			Address: s.Address,
			Type:    s.Type,
			Enabled: s.Enabled,
		}
		if accessData != nil {
			signers[i].AllowedKeys = accessData.keysForSigner(s.Address)
		}
	}

	resp := ListSignersResponse{
		Signers: signers,
		Total:   total,
		HasMore: hasMore,
	}

	h.writeJSON(w, resp, http.StatusOK)
}

// buildAllowedKeysData fetches all enabled API keys and builds a lookup
// for which keys can access which signers.
func (h *SignerHandler) buildAllowedKeysData(r *http.Request) (*allowedKeysData, error) {
	apiKeys, err := h.apiKeyRepo.List(r.Context(), storage.APIKeyFilter{
		EnabledOnly: true,
		Limit:       1000,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list API keys: %w", err)
	}

	data := &allowedKeysData{
		explicitAccess: make(map[string][]AllowedKeyInfo),
	}

	for _, key := range apiKeys {
		info := AllowedKeyInfo{
			ID:   key.ID,
			Name: key.Name,
		}
		if len(key.AllowedSigners) == 0 {
			info.AccessType = "unrestricted"
			data.unrestricted = append(data.unrestricted, info)
		} else {
			info.AccessType = "explicit"
			for _, addr := range key.AllowedSigners {
				lower := strings.ToLower(addr)
				data.explicitAccess[lower] = append(data.explicitAccess[lower], info)
			}
		}
	}

	return data, nil
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
