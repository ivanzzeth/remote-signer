package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

var apiKeyIDPattern = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

// APIKeyResponse represents an API key in API responses.
type APIKeyResponse struct {
	ID                string             `json:"id"`
	Name              string             `json:"name"`
	Source            string             `json:"source"`
	Role              types.APIKeyRole   `json:"role"`
	Enabled           bool               `json:"enabled"`
	RateLimit         int                `json:"rate_limit"`
	AllowAllSigners   bool               `json:"allow_all_signers"`
	AllowAllHDWallets bool               `json:"allow_all_hd_wallets"`
	AllowedSigners    []string           `json:"allowed_signers,omitempty"`
	AllowedHDWallets  []string           `json:"allowed_hd_wallets,omitempty"`
	AllowedChainTypes []string           `json:"allowed_chain_types,omitempty"`
	CreatedAt         time.Time          `json:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at"`
	LastUsedAt        *time.Time         `json:"last_used_at,omitempty"`
	ExpiresAt         *time.Time         `json:"expires_at,omitempty"`
}

// CreateAPIKeyRequest represents the request to create an API key.
type CreateAPIKeyRequest struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	PublicKey         string   `json:"public_key"` // Ed25519 public key, hex or base64 DER
	Role              string   `json:"role"`       // admin, dev, agent, strategy
	RateLimit         int      `json:"rate_limit,omitempty"` // default 100
	AllowAllSigners   bool     `json:"allow_all_signers"`
	AllowAllHDWallets bool     `json:"allow_all_hd_wallets"`
	AllowedSigners    []string `json:"allowed_signers,omitempty"`
	AllowedHDWallets  []string `json:"allowed_hd_wallets,omitempty"`
	AllowedChainTypes []string `json:"allowed_chain_types,omitempty"`
}

// UpdateAPIKeyRequest represents the request to update an API key.
type UpdateAPIKeyRequest struct {
	Name              *string  `json:"name,omitempty"`
	Enabled           *bool    `json:"enabled,omitempty"`
	Role              *string  `json:"role,omitempty"` // admin, dev, agent, strategy
	RateLimit         *int     `json:"rate_limit,omitempty"`
	AllowAllSigners   *bool    `json:"allow_all_signers,omitempty"`
	AllowAllHDWallets *bool    `json:"allow_all_hd_wallets,omitempty"`
	AllowedSigners    []string `json:"allowed_signers,omitempty"`
	AllowedHDWallets  []string `json:"allowed_hd_wallets,omitempty"`
	AllowedChainTypes []string `json:"allowed_chain_types,omitempty"`
}

// ListAPIKeysResponse represents the response for listing API keys.
type ListAPIKeysResponse struct {
	Keys  []APIKeyResponse `json:"keys"`
	Total int              `json:"total"`
}

// APIKeyHandler handles API key management endpoints.
type APIKeyHandler struct {
	repo        storage.APIKeyRepository
	readOnly    bool
	logger      *slog.Logger
	auditLogger *audit.AuditLogger
}

// NewAPIKeyHandler creates a new API key handler.
func NewAPIKeyHandler(repo storage.APIKeyRepository, logger *slog.Logger, readOnly bool) (*APIKeyHandler, error) {
	if repo == nil {
		return nil, fmt.Errorf("API key repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &APIKeyHandler{
		repo:     repo,
		readOnly: readOnly,
		logger:   logger,
	}, nil
}

// SetAuditLogger sets the audit logger for API key management operations.
func (h *APIKeyHandler) SetAuditLogger(al *audit.AuditLogger) {
	h.auditLogger = al
}

// ServeHTTP handles /api/v1/api-keys (GET list, POST create).
func (h *APIKeyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listAPIKeys(w, r)
	case http.MethodPost:
		h.createAPIKey(w, r)
	default:
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ServeKeyHTTP handles /api/v1/api-keys/{id} (GET, PUT, DELETE).
func (h *APIKeyHandler) ServeKeyHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract key ID from path: /api/v1/api-keys/{id}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/api-keys/")
	if id == "" {
		h.writeError(w, "API key ID is required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getAPIKey(w, r, id)
	case http.MethodPut:
		h.updateAPIKey(w, r, id)
	case http.MethodDelete:
		h.deleteAPIKey(w, r, id)
	default:
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// listAPIKeys handles GET /api/v1/api-keys.
func (h *APIKeyHandler) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	filter := storage.APIKeyFilter{
		Limit: 100,
	}

	if source := query.Get("source"); source != "" {
		filter.Source = source
	}
	if enabledStr := query.Get("enabled"); enabledStr != "" {
		enabled, err := strconv.ParseBool(enabledStr)
		if err != nil {
			h.writeError(w, "invalid enabled parameter: must be true or false", http.StatusBadRequest)
			return
		}
		if enabled {
			filter.EnabledOnly = true
		}
	}
	if limitStr := query.Get("limit"); limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 0 {
			h.writeError(w, "invalid limit parameter", http.StatusBadRequest)
			return
		}
		if limit > 100 {
			limit = 100
		}
		filter.Limit = limit
	}
	if offsetStr := query.Get("offset"); offsetStr != "" {
		offset, err := strconv.Atoi(offsetStr)
		if err != nil || offset < 0 {
			h.writeError(w, "invalid offset parameter", http.StatusBadRequest)
			return
		}
		filter.Offset = offset
	}

	keys, err := h.repo.List(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list API keys", slog.String("error", err.Error()))
		h.writeError(w, "failed to list API keys", http.StatusInternalServerError)
		return
	}

	total, err := h.repo.Count(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to count API keys", slog.String("error", err.Error()))
		h.writeError(w, "failed to count API keys", http.StatusInternalServerError)
		return
	}

	resp := ListAPIKeysResponse{
		Keys:  make([]APIKeyResponse, 0, len(keys)),
		Total: total,
	}
	for _, key := range keys {
		resp.Keys = append(resp.Keys, toAPIKeyResponse(key))
	}

	h.writeJSON(w, resp, http.StatusOK)
}

// getAPIKey handles GET /api/v1/api-keys/{id}.
func (h *APIKeyHandler) getAPIKey(w http.ResponseWriter, r *http.Request, id string) {
	key, err := h.repo.Get(r.Context(), id)
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "API key not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to get API key", slog.String("id", id), slog.String("error", err.Error()))
		h.writeError(w, "failed to get API key", http.StatusInternalServerError)
		return
	}

	h.writeJSON(w, toAPIKeyResponse(key), http.StatusOK)
}

// createAPIKey handles POST /api/v1/api-keys.
func (h *APIKeyHandler) createAPIKey(w http.ResponseWriter, r *http.Request) {
	if h.readOnly {
		h.writeError(w, "API key management is disabled", http.StatusForbidden)
		return
	}

	var req CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validate ID
	if req.ID == "" {
		h.writeError(w, "id is required", http.StatusBadRequest)
		return
	}
	if len(req.ID) > 64 {
		h.writeError(w, "id must be at most 64 characters", http.StatusBadRequest)
		return
	}
	if !apiKeyIDPattern.MatchString(req.ID) {
		h.writeError(w, "id must contain only alphanumeric characters and hyphens", http.StatusBadRequest)
		return
	}

	// Validate Name
	if req.Name == "" {
		h.writeError(w, "name is required", http.StatusBadRequest)
		return
	}
	if len(req.Name) > 255 {
		h.writeError(w, "name must be at most 255 characters", http.StatusBadRequest)
		return
	}

	// Validate PublicKey
	if req.PublicKey == "" {
		h.writeError(w, "public_key is required", http.StatusBadRequest)
		return
	}
	if len(req.PublicKey) > 128 {
		h.writeError(w, "public_key exceeds maximum length", http.StatusBadRequest)
		return
	}

	// Validate RateLimit
	rateLimit := req.RateLimit
	if rateLimit == 0 {
		rateLimit = 100
	}
	if rateLimit < 1 || rateLimit > 10000 {
		h.writeError(w, "rate_limit must be between 1 and 10000", http.StatusBadRequest)
		return
	}

	// Validate role
	if req.Role == "" {
		h.writeError(w, "role is required (admin, dev, agent, strategy)", http.StatusBadRequest)
		return
	}
	if !types.IsValidAPIKeyRole(req.Role) {
		h.writeError(w, fmt.Sprintf("invalid role %q (must be admin, dev, agent, or strategy)", req.Role), http.StatusBadRequest)
		return
	}

	// Validate array sizes
	if len(req.AllowedSigners) > 100 {
		h.writeError(w, "allowed_signers exceeds maximum of 100 entries", http.StatusBadRequest)
		return
	}
	if len(req.AllowedHDWallets) > 100 {
		h.writeError(w, "allowed_hd_wallets exceeds maximum of 100 entries", http.StatusBadRequest)
		return
	}

	key := &types.APIKey{
		ID:                req.ID,
		Name:              req.Name,
		PublicKeyHex:      req.PublicKey,
		Role:              types.APIKeyRole(req.Role),
		RateLimit:         rateLimit,
		AllowAllSigners:   req.AllowAllSigners,
		AllowAllHDWallets: req.AllowAllHDWallets,
		AllowedSigners:    req.AllowedSigners,
		AllowedHDWallets:  req.AllowedHDWallets,
		AllowedChainTypes: req.AllowedChainTypes,
		Enabled:           true,
		Source:            types.APIKeySourceAPI,
	}

	if err := h.repo.Create(r.Context(), key); err != nil {
		h.logger.Error("failed to create API key",
			slog.String("id", req.ID),
			slog.String("error", err.Error()),
		)
		h.writeError(w, "failed to create API key", http.StatusInternalServerError)
		return
	}

	h.logger.Info("API key created",
		slog.String("id", key.ID),
		slog.String("name", key.Name),
	)

	if h.auditLogger != nil {
		apiKey := middleware.GetAPIKey(r.Context())
		keyID := ""
		if apiKey != nil {
			keyID = apiKey.ID
		}
		h.auditLogger.LogAPIKeySynced(r.Context(), "created_via_api:"+keyID, key.ID, key.Name)
	}

	// Re-fetch to get server-generated timestamps
	created, err := h.repo.Get(r.Context(), key.ID)
	if err != nil {
		// Key was created but we cannot fetch it; return what we have
		h.writeJSON(w, toAPIKeyResponse(key), http.StatusCreated)
		return
	}

	h.writeJSON(w, toAPIKeyResponse(created), http.StatusCreated)
}

// updateAPIKey handles PUT /api/v1/api-keys/{id}.
func (h *APIKeyHandler) updateAPIKey(w http.ResponseWriter, r *http.Request, id string) {
	if h.readOnly {
		h.writeError(w, "API key management is disabled", http.StatusForbidden)
		return
	}

	key, err := h.repo.Get(r.Context(), id)
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "API key not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to get API key for update", slog.String("id", id), slog.String("error", err.Error()))
		h.writeError(w, "failed to get API key", http.StatusInternalServerError)
		return
	}

	if key.Source == types.APIKeySourceConfig {
		h.writeError(w, "cannot modify config-sourced API key via API", http.StatusForbidden)
		return
	}

	var req UpdateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Apply partial updates
	if req.Name != nil {
		if *req.Name == "" {
			h.writeError(w, "name must not be empty", http.StatusBadRequest)
			return
		}
		if len(*req.Name) > 255 {
			h.writeError(w, "name must be at most 255 characters", http.StatusBadRequest)
			return
		}
		key.Name = *req.Name
	}
	if req.Enabled != nil {
		key.Enabled = *req.Enabled
	}
	if req.Role != nil {
		if !types.IsValidAPIKeyRole(*req.Role) {
			h.writeError(w, fmt.Sprintf("invalid role %q (must be admin, dev, agent, or strategy)", *req.Role), http.StatusBadRequest)
			return
		}
		key.Role = types.APIKeyRole(*req.Role)
	}
	if req.RateLimit != nil {
		if *req.RateLimit < 1 || *req.RateLimit > 10000 {
			h.writeError(w, "rate_limit must be between 1 and 10000", http.StatusBadRequest)
			return
		}
		key.RateLimit = *req.RateLimit
	}
	if req.AllowAllSigners != nil {
		key.AllowAllSigners = *req.AllowAllSigners
	}
	if req.AllowAllHDWallets != nil {
		key.AllowAllHDWallets = *req.AllowAllHDWallets
	}
	if req.AllowedSigners != nil {
		key.AllowedSigners = req.AllowedSigners
	}
	if req.AllowedHDWallets != nil {
		key.AllowedHDWallets = req.AllowedHDWallets
	}
	if req.AllowedChainTypes != nil {
		key.AllowedChainTypes = req.AllowedChainTypes
	}

	if err := h.repo.Update(r.Context(), key); err != nil {
		h.logger.Error("failed to update API key",
			slog.String("id", id),
			slog.String("error", err.Error()),
		)
		h.writeError(w, "failed to update API key", http.StatusInternalServerError)
		return
	}

	h.logger.Info("API key updated",
		slog.String("id", key.ID),
		slog.String("name", key.Name),
	)

	if h.auditLogger != nil {
		apiKey := middleware.GetAPIKey(r.Context())
		actorKeyID := ""
		if apiKey != nil {
			actorKeyID = apiKey.ID
		}
		h.auditLogger.LogAPIKeySynced(r.Context(), "updated_via_api:"+actorKeyID, key.ID, key.Name)
	}

	h.writeJSON(w, toAPIKeyResponse(key), http.StatusOK)
}

// deleteAPIKey handles DELETE /api/v1/api-keys/{id}.
func (h *APIKeyHandler) deleteAPIKey(w http.ResponseWriter, r *http.Request, id string) {
	if h.readOnly {
		h.writeError(w, "API key management is disabled", http.StatusForbidden)
		return
	}

	key, err := h.repo.Get(r.Context(), id)
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "API key not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to get API key for deletion", slog.String("id", id), slog.String("error", err.Error()))
		h.writeError(w, "failed to get API key", http.StatusInternalServerError)
		return
	}

	if key.Source == types.APIKeySourceConfig {
		h.writeError(w, "cannot delete config-sourced API key via API", http.StatusForbidden)
		return
	}

	// Prevent deleting the last admin key (lockout protection)
	if key.IsAdmin() {
		adminCount, err := h.repo.Count(r.Context(), storage.APIKeyFilter{EnabledOnly: true})
		if err != nil {
			h.logger.Error("failed to count admin keys", slog.String("error", err.Error()))
			h.writeError(w, "failed to verify admin key count", http.StatusInternalServerError)
			return
		}
		// Count admin keys by iterating — simpler than adding a Role filter to Count
		allKeys, err := h.repo.List(r.Context(), storage.APIKeyFilter{EnabledOnly: true, Limit: adminCount})
		if err != nil {
			h.logger.Error("failed to list keys for admin check", slog.String("error", err.Error()))
			h.writeError(w, "failed to verify admin key count", http.StatusInternalServerError)
			return
		}
		adminKeyCount := 0
		for _, k := range allKeys {
			if k.IsAdmin() && k.Enabled {
				adminKeyCount++
			}
		}
		if adminKeyCount <= 1 {
			h.writeError(w, "cannot delete the last admin API key", http.StatusForbidden)
			return
		}
	}

	if err := h.repo.Delete(r.Context(), id); err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "API key not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to delete API key",
			slog.String("id", id),
			slog.String("error", err.Error()),
		)
		h.writeError(w, "failed to delete API key", http.StatusInternalServerError)
		return
	}

	h.logger.Info("API key deleted",
		slog.String("id", id),
		slog.String("name", key.Name),
	)

	if h.auditLogger != nil {
		apiKey := middleware.GetAPIKey(r.Context())
		actorKeyID := ""
		if apiKey != nil {
			actorKeyID = apiKey.ID
		}
		h.auditLogger.LogAPIKeySynced(r.Context(), "deleted_via_api:"+actorKeyID, key.ID, key.Name)
	}

	w.WriteHeader(http.StatusNoContent)
}

// toAPIKeyResponse converts a types.APIKey to an APIKeyResponse.
// Never includes PublicKeyHex for security.
func toAPIKeyResponse(key *types.APIKey) APIKeyResponse {
	resp := APIKeyResponse{
		ID:                key.ID,
		Name:              key.Name,
		Source:            key.Source,
		Role:              key.Role,
		Enabled:           key.Enabled,
		RateLimit:         key.RateLimit,
		AllowAllSigners:   key.AllowAllSigners,
		AllowAllHDWallets: key.AllowAllHDWallets,
		CreatedAt:         key.CreatedAt,
		UpdatedAt:         key.UpdatedAt,
		LastUsedAt:        key.LastUsedAt,
		ExpiresAt:         key.ExpiresAt,
	}
	if len(key.AllowedSigners) > 0 {
		resp.AllowedSigners = key.AllowedSigners
	}
	if len(key.AllowedHDWallets) > 0 {
		resp.AllowedHDWallets = key.AllowedHDWallets
	}
	if len(key.AllowedChainTypes) > 0 {
		resp.AllowedChainTypes = key.AllowedChainTypes
	}
	return resp
}

// writeJSON writes a JSON response.
func (h *APIKeyHandler) writeJSON(w http.ResponseWriter, v any, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		h.logger.Error("failed to encode response", slog.String("error", err.Error()))
	}
}

// writeError writes an error response.
func (h *APIKeyHandler) writeError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	// #nosec G104 -- HTTP response write error cannot be meaningfully handled
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
