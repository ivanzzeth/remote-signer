package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/respond"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

var apiKeyIDPattern = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

// APIKeyResponse represents an API key in API responses.
type APIKeyResponse struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Source     string           `json:"source"`
	Role       types.APIKeyRole `json:"role"`
	Enabled    bool             `json:"enabled"`
	RateLimit  int              `json:"rate_limit"`
	CreatedAt  time.Time        `json:"created_at"`
	UpdatedAt  time.Time        `json:"updated_at"`
	LastUsedAt *time.Time       `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time       `json:"expires_at,omitempty"`
}

// CreateAPIKeyRequest represents the request to create an API key.
type CreateAPIKeyRequest struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`           // Ed25519 public key, hex or base64 DER
	Role      string `json:"role"`                 // admin, dev, agent, strategy
	RateLimit int    `json:"rate_limit,omitempty"` // default 100
}

// UpdateAPIKeyRequest represents the request to update an API key.
type UpdateAPIKeyRequest struct {
	Name      *string `json:"name,omitempty"`
	Enabled   *bool   `json:"enabled,omitempty"`
	Role      *string `json:"role,omitempty"` // admin, dev, agent, strategy
	RateLimit *int    `json:"rate_limit,omitempty"`
}

// ListAPIKeysResponse represents the response for listing API keys.
type ListAPIKeysResponse struct {
	Keys  []APIKeyResponse `json:"keys"`
	Total int              `json:"total"`
}

// APIKeyNameResponse is the projection returned by GET
// /api/v1/api-keys/names. Strips every audit-relevant timestamp +
// rate-limit knob so non-admin callers only see the fields a Grant /
// filter dropdown needs (id / name / role / enabled).
//
// Kept distinct from APIKeyResponse so future additions to the full
// admin response (e.g. usage stats) don't leak into the public-by-
// authentication name list.
type APIKeyNameResponse struct {
	ID      string           `json:"id"`
	Name    string           `json:"name"`
	Role    types.APIKeyRole `json:"role"`
	Enabled bool             `json:"enabled"`
}

// ListAPIKeyNamesResponse is the envelope for the /names endpoint.
// Sibling shape to ListAPIKeysResponse so a future paginated names
// listing can drop in without a breaking change.
type ListAPIKeyNamesResponse struct {
	Keys []APIKeyNameResponse `json:"keys"`
}

// APIKeyHandler handles API key management endpoints.
type APIKeyHandler struct {
	repo          storage.APIKeyRepository
	accessService AccessServiceForKeyDelete // optional: for signer ownership checks + cascade
	readOnly      func() bool
	logger        *slog.Logger
	auditLogger   *audit.AuditLogger
}

// AccessServiceForKeyDelete is the subset of SignerAccessService needed by the API key delete handler.
type AccessServiceForKeyDelete interface {
	CountOwnedSigners(ctx context.Context, ownerID string) (int64, error)
	CleanupForDeletedKey(ctx context.Context, apiKeyID string) error
}

// NewAPIKeyHandler creates a new API key handler.
func NewAPIKeyHandler(repo storage.APIKeyRepository, logger *slog.Logger, readOnly func() bool) (*APIKeyHandler, error) {
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

// SetAccessService sets the access service for signer ownership checks during key deletion.
func (h *APIKeyHandler) SetAccessService(svc AccessServiceForKeyDelete) {
	h.accessService = svc
}

// --- Handler entry points ---
//
// # One exported function per endpoint (proposal S4, copying S3's shape)
//
// These five replace two: ServeHTTP, which switched on r.Method for
// /api/v1/api-keys, and ServeKeyHTTP, which cut the id out of r.URL.Path with
// TrimPrefix and then switched on the method again. The registration that used
// to hide them behind two method-less prefix patterns is
// internal/api/module_apikeys.go, and it now names each one.
//
// ⭐ Why both halves had to move at once (proposal §1.3): registering
// `GET /api/v1/api-keys/{id}` while the handler still read r.URL.Path would
// leave the wildcard decorative — the handler would keep working when reached by
// some other pattern, and the handler-path-dispatch gate would not move. The id
// is read through r.PathValue here, which only a matching pattern can populate.
//
// ⛔ APIKeyHandler is deliberately no longer an http.Handler. It has no
// ServeHTTP, so there is no way to hand the whole API-key surface to one pattern
// again by accident.

// ListAPIKeys serves GET /api/v1/api-keys.
func (h *APIKeyHandler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	h.listAPIKeys(w, r)
}

// CreateAPIKey serves POST /api/v1/api-keys.
func (h *APIKeyHandler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	h.createAPIKey(w, r)
}

// GetAPIKey serves GET /api/v1/api-keys/{id}.
func (h *APIKeyHandler) GetAPIKey(w http.ResponseWriter, r *http.Request) {
	h.getAPIKey(w, r, r.PathValue("id"))
}

// UpdateAPIKey serves PUT /api/v1/api-keys/{id}.
func (h *APIKeyHandler) UpdateAPIKey(w http.ResponseWriter, r *http.Request) {
	h.updateAPIKey(w, r, r.PathValue("id"))
}

// DeleteAPIKey serves DELETE /api/v1/api-keys/{id}.
func (h *APIKeyHandler) DeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	h.deleteAPIKey(w, r, r.PathValue("id"))
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
			respond.Error(w, "invalid enabled parameter: must be true or false", http.StatusBadRequest, h.logger)
			return
		}
		if enabled {
			filter.EnabledOnly = true
		}
	}
	if limitStr := query.Get("limit"); limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 0 {
			respond.Error(w, "invalid limit parameter", http.StatusBadRequest, h.logger)
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
			respond.Error(w, "invalid offset parameter", http.StatusBadRequest, h.logger)
			return
		}
		filter.Offset = offset
	}

	keys, err := h.repo.List(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list API keys", slog.String("error", err.Error()))
		respond.Error(w, "failed to list API keys", http.StatusInternalServerError, h.logger)
		return
	}

	total, err := h.repo.Count(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to count API keys", slog.String("error", err.Error()))
		respond.Error(w, "failed to count API keys", http.StatusInternalServerError, h.logger)
		return
	}

	resp := ListAPIKeysResponse{
		Keys:  make([]APIKeyResponse, 0, len(keys)),
		Total: total,
	}
	for _, key := range keys {
		resp.Keys = append(resp.Keys, toAPIKeyResponse(key))
	}

	respond.JSON(w, resp, http.StatusOK, h.logger)
}

// ListAPIKeyNames handles GET /api/v1/api-keys/names. Any
// authenticated key may call it — the response is the minimum needed
// to populate a Grant-access or filter dropdown (id, name, role,
// enabled). All audit-relevant fields (timestamps, rate_limit,
// expires_at, hash) are stripped so non-admins can see who exists
// without seeing the operational metadata only admins should touch.
//
// Today this returns the full enabled set; pagination + free-text
// search can land later under the same shape if catalogues grow.
func (h *APIKeyHandler) ListAPIKeyNames(w http.ResponseWriter, r *http.Request) {
	// ⛔ No method check: GET /api/v1/api-keys/names is method-scoped.
	// Caller is already authenticated by the router (withAuth, not
	// withAuthAndPerm) — anyone with a valid signature gets in.
	keys, err := h.repo.List(r.Context(), storage.APIKeyFilter{
		EnabledOnly: true,
		Limit:       500,
	})
	if err != nil {
		h.logger.Error("failed to list api key names", slog.String("error", err.Error()))
		respond.Error(w, "failed to list api keys", http.StatusInternalServerError, h.logger)
		return
	}
	resp := ListAPIKeyNamesResponse{Keys: make([]APIKeyNameResponse, 0, len(keys))}
	for _, k := range keys {
		resp.Keys = append(resp.Keys, APIKeyNameResponse{
			ID:      k.ID,
			Name:    k.Name,
			Role:    k.Role,
			Enabled: k.Enabled,
		})
	}
	respond.JSON(w, resp, http.StatusOK, h.logger)
}

// getAPIKey handles GET /api/v1/api-keys/{id}.
func (h *APIKeyHandler) getAPIKey(w http.ResponseWriter, r *http.Request, id string) {
	key, err := h.repo.Get(r.Context(), id)
	if err != nil {
		if types.IsNotFound(err) {
			respond.Error(w, "API key not found", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("failed to get API key", slog.String("id", id), slog.String("error", err.Error()))
		respond.Error(w, "failed to get API key", http.StatusInternalServerError, h.logger)
		return
	}

	respond.JSON(w, toAPIKeyResponse(key), http.StatusOK, h.logger)
}

// createAPIKey handles POST /api/v1/api-keys.
func (h *APIKeyHandler) createAPIKey(w http.ResponseWriter, r *http.Request) {
	if h.isReadOnly() {
		respond.Error(w, "API key management is disabled", http.StatusForbidden, h.logger)
		return
	}

	var req CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.Error(w, "invalid request body", http.StatusBadRequest, h.logger)
		return
	}

	// Validate ID
	if req.ID == "" {
		respond.Error(w, "id is required", http.StatusBadRequest, h.logger)
		return
	}
	if len(req.ID) > 64 {
		respond.Error(w, "id must be at most 64 characters", http.StatusBadRequest, h.logger)
		return
	}
	if !apiKeyIDPattern.MatchString(req.ID) {
		respond.Error(w, "id must contain only alphanumeric characters and hyphens", http.StatusBadRequest, h.logger)
		return
	}

	// Validate Name
	if req.Name == "" {
		respond.Error(w, "name is required", http.StatusBadRequest, h.logger)
		return
	}
	if len(req.Name) > 255 {
		respond.Error(w, "name must be at most 255 characters", http.StatusBadRequest, h.logger)
		return
	}

	// Validate PublicKey
	if req.PublicKey == "" {
		respond.Error(w, "public_key is required", http.StatusBadRequest, h.logger)
		return
	}
	if len(req.PublicKey) > 128 {
		respond.Error(w, "public_key exceeds maximum length", http.StatusBadRequest, h.logger)
		return
	}

	// Validate RateLimit
	rateLimit := req.RateLimit
	if rateLimit == 0 {
		rateLimit = 100
	}
	if rateLimit < 1 || rateLimit > 10000 {
		respond.Error(w, "rate_limit must be between 1 and 10000", http.StatusBadRequest, h.logger)
		return
	}

	// Validate role
	if req.Role == "" {
		respond.Error(w, "role is required (admin, dev, agent, strategy)", http.StatusBadRequest, h.logger)
		return
	}
	if !types.IsValidAPIKeyRole(req.Role) {
		respond.Error(w, fmt.Sprintf("invalid role %q (must be admin, dev, agent, or strategy)", req.Role), http.StatusBadRequest, h.logger)
		return
	}

	key := &types.APIKey{
		ID:           req.ID,
		Name:         req.Name,
		PublicKeyHex: req.PublicKey,
		Role:         types.APIKeyRole(req.Role),
		RateLimit:    rateLimit,
		Enabled:      true,
		Source:       types.APIKeySourceAPI,
	}

	if err := h.repo.Create(r.Context(), key); err != nil {
		h.logger.Error("failed to create API key",
			slog.String("id", req.ID),
			slog.String("error", err.Error()),
		)
		respond.Error(w, "failed to create API key", http.StatusInternalServerError, h.logger)
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
		respond.JSON(w, toAPIKeyResponse(key), http.StatusCreated, h.logger)
		return
	}

	respond.JSON(w, toAPIKeyResponse(created), http.StatusCreated, h.logger)
}

// updateAPIKey handles PUT /api/v1/api-keys/{id}.
func (h *APIKeyHandler) updateAPIKey(w http.ResponseWriter, r *http.Request, id string) {
	if h.isReadOnly() {
		respond.Error(w, "API key management is disabled", http.StatusForbidden, h.logger)
		return
	}

	key, err := h.repo.Get(r.Context(), id)
	if err != nil {
		if types.IsNotFound(err) {
			respond.Error(w, "API key not found", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("failed to get API key for update", slog.String("id", id), slog.String("error", err.Error()))
		respond.Error(w, "failed to get API key", http.StatusInternalServerError, h.logger)
		return
	}

	if key.Source == types.APIKeySourceConfig {
		respond.Error(w, "cannot modify config-sourced API key via API", http.StatusForbidden, h.logger)
		return
	}

	var req UpdateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.Error(w, "invalid request body", http.StatusBadRequest, h.logger)
		return
	}

	// Self-protection: cannot change own role
	callerKey := middleware.GetAPIKey(r.Context())
	if callerKey != nil && callerKey.ID == id && req.Role != nil {
		respond.Error(w, "cannot change your own role", http.StatusBadRequest, h.logger)
		return
	}

	// Apply partial updates
	if req.Name != nil {
		if *req.Name == "" {
			respond.Error(w, "name must not be empty", http.StatusBadRequest, h.logger)
			return
		}
		if len(*req.Name) > 255 {
			respond.Error(w, "name must be at most 255 characters", http.StatusBadRequest, h.logger)
			return
		}
		key.Name = *req.Name
	}
	if req.Enabled != nil {
		key.Enabled = *req.Enabled
	}
	if req.Role != nil {
		if !types.IsValidAPIKeyRole(*req.Role) {
			respond.Error(w, fmt.Sprintf("invalid role %q (must be admin, dev, agent, or strategy)", *req.Role), http.StatusBadRequest, h.logger)
			return
		}
		key.Role = types.APIKeyRole(*req.Role)
	}
	if req.RateLimit != nil {
		if *req.RateLimit < 1 || *req.RateLimit > 10000 {
			respond.Error(w, "rate_limit must be between 1 and 10000", http.StatusBadRequest, h.logger)
			return
		}
		key.RateLimit = *req.RateLimit
	}

	if err := h.repo.Update(r.Context(), key); err != nil {
		h.logger.Error("failed to update API key",
			slog.String("id", id),
			slog.String("error", err.Error()),
		)
		respond.Error(w, "failed to update API key", http.StatusInternalServerError, h.logger)
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

	respond.JSON(w, toAPIKeyResponse(key), http.StatusOK, h.logger)
}

// deleteAPIKey handles DELETE /api/v1/api-keys/{id}.
func (h *APIKeyHandler) deleteAPIKey(w http.ResponseWriter, r *http.Request, id string) {
	if h.isReadOnly() {
		respond.Error(w, "API key management is disabled", http.StatusForbidden, h.logger)
		return
	}

	// Self-protection: cannot delete self
	callerKey := middleware.GetAPIKey(r.Context())
	if callerKey != nil && callerKey.ID == id {
		respond.Error(w, "cannot delete your own API key", http.StatusBadRequest, h.logger)
		return
	}

	key, err := h.repo.Get(r.Context(), id)
	if err != nil {
		if types.IsNotFound(err) {
			respond.Error(w, "API key not found", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("failed to get API key for deletion", slog.String("id", id), slog.String("error", err.Error()))
		respond.Error(w, "failed to get API key", http.StatusInternalServerError, h.logger)
		return
	}

	if key.Source == types.APIKeySourceConfig {
		respond.Error(w, "cannot delete config-sourced API key via API", http.StatusForbidden, h.logger)
		return
	}

	// Prevent deleting the last admin key (lockout protection)
	if key.IsAdmin() {
		adminCount, err := h.repo.Count(r.Context(), storage.APIKeyFilter{EnabledOnly: true})
		if err != nil {
			h.logger.Error("failed to count admin keys", slog.String("error", err.Error()))
			respond.Error(w, "failed to verify admin key count", http.StatusInternalServerError, h.logger)
			return
		}
		// Count admin keys by iterating — simpler than adding a Role filter to Count
		allKeys, err := h.repo.List(r.Context(), storage.APIKeyFilter{EnabledOnly: true, Limit: adminCount})
		if err != nil {
			h.logger.Error("failed to list keys for admin check", slog.String("error", err.Error()))
			respond.Error(w, "failed to verify admin key count", http.StatusInternalServerError, h.logger)
			return
		}
		adminKeyCount := 0
		for _, k := range allKeys {
			if k.IsAdmin() && k.Enabled {
				adminKeyCount++
			}
		}
		if adminKeyCount <= 1 {
			respond.Error(w, "cannot delete the last admin API key", http.StatusBadRequest, h.logger)
			return
		}
	}

	// Precondition: key must own 0 signers
	if h.accessService != nil {
		ownedCount, countErr := h.accessService.CountOwnedSigners(r.Context(), id)
		if countErr != nil {
			h.logger.Error("failed to count owned signers", slog.String("id", id), slog.String("error", countErr.Error()))
			respond.Error(w, "failed to check signer ownership", http.StatusInternalServerError, h.logger)
			return
		}
		if ownedCount > 0 {
			respond.Error(w, "delete or transfer signers first", http.StatusBadRequest, h.logger)
			return
		}
	}

	if err := h.repo.Delete(r.Context(), id); err != nil {
		if types.IsNotFound(err) {
			respond.Error(w, "API key not found", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("failed to delete API key",
			slog.String("id", id),
			slog.String("error", err.Error()),
		)
		respond.Error(w, "failed to delete API key", http.StatusInternalServerError, h.logger)
		return
	}

	// Cascade: rules + applied_to + signer_access
	if h.accessService != nil {
		if cleanupErr := h.accessService.CleanupForDeletedKey(r.Context(), id); cleanupErr != nil {
			h.logger.Error("cascade cleanup failed after API key delete",
				slog.String("id", id),
				slog.String("error", cleanupErr.Error()),
			)
			// Key is already deleted — log but do not fail the response
		}
	}

	h.logger.Info("API key deleted",
		slog.String("id", id),
		slog.String("name", key.Name),
	)

	if h.auditLogger != nil {
		actorKeyID := ""
		if callerKey != nil {
			actorKeyID = callerKey.ID
		}
		h.auditLogger.LogAPIKeySynced(r.Context(), "deleted_via_api:"+actorKeyID, key.ID, key.Name)
	}

	w.WriteHeader(http.StatusNoContent)
}

// toAPIKeyResponse converts a types.APIKey to an APIKeyResponse.
// Never includes PublicKeyHex for security.
func toAPIKeyResponse(key *types.APIKey) APIKeyResponse {
	return APIKeyResponse{
		ID:         key.ID,
		Name:       key.Name,
		Source:     key.Source,
		Role:       key.Role,
		Enabled:    key.Enabled,
		RateLimit:  key.RateLimit,
		CreatedAt:  key.CreatedAt,
		UpdatedAt:  key.UpdatedAt,
		LastUsedAt: key.LastUsedAt,
		ExpiresAt:  key.ExpiresAt,
	}
}

// readOnly reports whether write operations are blocked right now.
//
// It is a function, not a bool, because the setting behind it is runtime
// mutable: settings.SecuritySnapshot is reloaded from the database, and a
// value copied into this struct at construction would freeze at boot. That
// was the actual behaviour until 2026-09-10 — internal/settings/model.go
// promises settings become "effective without a daemon restart", and for this
// one, flipping it in the Web UI changed the database, changed the snapshot,
// and changed nothing else.
//
// nil means "never read-only", which is the permissive direction; the router
// only leaves it nil when there is no settings manager at all (tests).
func (h *APIKeyHandler) isReadOnly() bool {
	if h.readOnly == nil {
		return false
	}
	return h.readOnly()
}
