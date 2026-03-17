package evm

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/secure"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

// SignerHandler handles signer management endpoints
type SignerHandler struct {
	signerManager evm.SignerManager
	accessService *service.SignerAccessService
	readOnly      bool // when true, block signer creation via API
	logger        *slog.Logger
	auditLogger   *audit.AuditLogger // optional: audit logging
}

// NewSignerHandler creates a new signer handler
func NewSignerHandler(signerManager evm.SignerManager, accessService *service.SignerAccessService, logger *slog.Logger, readOnly bool) (*SignerHandler, error) {
	if signerManager == nil {
		return nil, fmt.Errorf("signer manager is required")
	}
	if accessService == nil {
		return nil, fmt.Errorf("access service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &SignerHandler{
		signerManager: signerManager,
		accessService: accessService,
		readOnly:      readOnly,
		logger:        logger,
	}, nil
}

// SetAuditLogger sets the audit logger for signer management operations.
func (h *SignerHandler) SetAuditLogger(al *audit.AuditLogger) {
	h.auditLogger = al
}

// SignerResponse represents a signer in API responses
type SignerResponse struct {
	Address    string     `json:"address"`
	Type       string     `json:"type"`
	Enabled    bool       `json:"enabled"`
	Locked     bool       `json:"locked"`
	UnlockedAt *time.Time `json:"unlocked_at,omitempty"`
	OwnerID    string     `json:"owner_id,omitempty"`
	Status     string     `json:"status,omitempty"` // ownership status: active, pending_approval
}

// UnlockSignerRequest represents the request to unlock a locked signer
type UnlockSignerRequest struct {
	Password string `json:"password"`
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

// GrantAccessRequest represents the request to grant access to a signer.
type GrantAccessRequest struct {
	APIKeyID string `json:"api_key_id"`
}

// SignerAccessResponse represents an access grant entry.
type SignerAccessResponse struct {
	APIKeyID  string    `json:"api_key_id"`
	GrantedBy string    `json:"granted_by"`
	CreatedAt time.Time `json:"created_at"`
}

// ServeHTTP handles /api/v1/evm/signers
func (h *SignerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.listSigners(w, r)
	case http.MethodPost:
		h.createSigner(w, r)
	default:
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// listSigners handles GET /api/v1/evm/signers
// All roles see only signers they own or have been granted access to.
func (h *SignerHandler) listSigners(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	apiKey := middleware.GetAPIKey(r.Context())

	// Parse filter parameters
	requestedOffset := 0
	requestedLimit := 20

	var signerType *types.SignerType
	if typeStr := query.Get("type"); typeStr != "" {
		if !validate.IsValidSignerType(typeStr) {
			h.writeError(w, "invalid type filter: must be private_key or keystore", http.StatusBadRequest)
			return
		}
		st := types.SignerType(typeStr)
		signerType = &st
	}

	if offsetStr := query.Get("offset"); offsetStr != "" {
		offset, err := strconv.Atoi(offsetStr)
		if err != nil || offset < 0 {
			h.writeError(w, "invalid offset parameter", http.StatusBadRequest)
			return
		}
		requestedOffset = offset
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
		requestedLimit = limit
	}

	// Get all signers from manager
	filter := types.SignerFilter{
		Type:   signerType,
		Offset: 0,
		Limit:  100000,
	}
	result, err := h.signerManager.ListSigners(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list signers", slog.String("error", err.Error()))
		h.writeError(w, "failed to list signers", http.StatusInternalServerError)
		return
	}

	// Build allowed addresses set from ownership + access
	ownedAddrs, err := h.accessService.GetOwnedAddresses(r.Context(), apiKey.ID)
	if err != nil {
		h.logger.Error("failed to get owned addresses", slog.String("error", err.Error()))
		h.writeError(w, "failed to list signers", http.StatusInternalServerError)
		return
	}
	grantedAddrs, err := h.accessService.GetAccessibleAddresses(r.Context(), apiKey.ID)
	if err != nil {
		h.logger.Error("failed to get accessible addresses", slog.String("error", err.Error()))
		h.writeError(w, "failed to list signers", http.StatusInternalServerError)
		return
	}

	allowedSet := make(map[string]bool)
	for _, a := range ownedAddrs {
		allowedSet[strings.ToLower(a)] = true
	}
	for _, a := range grantedAddrs {
		allowedSet[strings.ToLower(a)] = true
	}

	// Also include HD wallet derived addresses whose parent is allowed
	if h.signerManager != nil {
		hdMgr, hdErr := h.signerManager.HDWalletManager()
		if hdErr == nil && hdMgr != nil {
			for _, primary := range hdMgr.ListPrimaryAddresses() {
				if allowedSet[strings.ToLower(primary)] {
					derived, dErr := hdMgr.ListDerivedAddresses(primary)
					if dErr == nil {
						for _, d := range derived {
							allowedSet[strings.ToLower(d.Address)] = true
						}
					}
				}
			}
		}
	}

	// Filter signers by allowed set
	var filteredSigners []types.SignerInfo
	for _, s := range result.Signers {
		if allowedSet[strings.ToLower(s.Address)] {
			filteredSigners = append(filteredSigners, s)
		}
	}

	total := len(filteredSigners)
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
	hasMore := requestedOffset+requestedLimit < total

	// Convert to response with ownership info
	signers := make([]SignerResponse, len(filteredSigners))
	for i, s := range filteredSigners {
		signers[i] = SignerResponse{
			Address:    s.Address,
			Type:       s.Type,
			Enabled:    s.Enabled,
			Locked:     s.Locked,
			UnlockedAt: s.UnlockedAt,
		}
		ownership, oErr := h.accessService.GetOwnership(r.Context(), s.Address)
		if oErr == nil && ownership != nil {
			signers[i].OwnerID = ownership.OwnerID
			signers[i].Status = string(ownership.Status)
		}
	}

	resp := ListSignersResponse{
		Signers: signers,
		Total:   total,
		HasMore: hasMore,
	}

	h.writeJSON(w, resp, http.StatusOK)
}

// createSigner handles POST /api/v1/evm/signers
func (h *SignerHandler) createSigner(w http.ResponseWriter, r *http.Request) {
	if h.readOnly {
		h.writeError(w, "signer creation via API is disabled (security.signers_api_readonly)", http.StatusForbidden)
		return
	}

	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// RBAC check: PermCreateSigners required (admin, dev, agent via rbac.go)
	if !middleware.HasPermission(apiKey.Role, middleware.PermCreateSigners) {
		h.writeError(w, "permission denied", http.StatusForbidden)
		return
	}

	var req CreateSignerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer func() {
		if req.Keystore != nil {
			secure.ZeroString(&req.Keystore.Password)
		}
	}()

	createReq := types.CreateSignerRequest{
		Type: types.SignerType(req.Type),
	}
	if req.Keystore != nil {
		createReq.Keystore = &types.CreateKeystoreParams{
			Password: req.Keystore.Password,
		}
	}

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

	// Set ownership: admin = active, non-admin = pending_approval
	status := types.SignerOwnershipPendingApproval
	if apiKey.IsAdmin() {
		status = types.SignerOwnershipActive
	}
	if err := h.accessService.SetOwner(r.Context(), signerInfo.Address, apiKey.ID, status); err != nil {
		h.logger.Error("failed to set signer ownership",
			slog.String("address", signerInfo.Address),
			slog.String("error", err.Error()),
		)
		// Non-fatal: signer was created, ownership can be fixed manually
	}

	h.logger.Info("signer created",
		slog.String("address", signerInfo.Address),
		slog.String("type", signerInfo.Type),
		slog.String("owner", apiKey.ID),
		slog.String("status", string(status)),
	)

	if h.auditLogger != nil {
		h.auditLogger.LogSignerCreated(r.Context(), apiKey.ID, r.RemoteAddr, signerInfo.Address, signerInfo.Type)
	}

	resp := CreateSignerResponse{
		Address: signerInfo.Address,
		Type:    signerInfo.Type,
		Enabled: signerInfo.Enabled,
	}

	h.writeJSON(w, resp, http.StatusCreated)
}

// HandleSignerAction handles /api/v1/evm/signers/{address}/{action}
func (h *SignerHandler) HandleSignerAction(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse path: /api/v1/evm/signers/{address}/{action}[/{extra}]
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/evm/signers/")
	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		h.writeError(w, "invalid path: expected /api/v1/evm/signers/{address}/{action}", http.StatusBadRequest)
		return
	}

	address := parts[0]
	action := parts[1]

	switch action {
	case "unlock":
		if r.Method != http.MethodPost {
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleUnlock(w, r, address)
	case "lock":
		if r.Method != http.MethodPost {
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleLock(w, r, address)
	case "approve":
		if r.Method != http.MethodPost {
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleApproveSigner(w, r, address)
	case "access":
		extra := ""
		if len(parts) == 3 {
			extra = parts[2]
		}
		h.handleAccess(w, r, address, extra)
	default:
		h.writeError(w, "unknown action: "+action, http.StatusBadRequest)
	}
}

// handleUnlock handles POST /api/v1/evm/signers/{address}/unlock
func (h *SignerHandler) handleUnlock(w http.ResponseWriter, r *http.Request, address string) {
	apiKey := middleware.GetAPIKey(r.Context())

	// Owner check — return 404 if signer has no ownership record (orphan/non-existent)
	isOwner, err := h.accessService.IsOwner(r.Context(), apiKey.ID, address)
	if err != nil {
		h.writeError(w, "failed to check ownership", http.StatusInternalServerError)
		return
	}
	if !isOwner {
		// Distinguish 404 from 403: if no ownership record exists at all, treat as not found
		if _, oErr := h.accessService.GetOwnership(r.Context(), address); oErr != nil && types.IsNotFound(oErr) {
			h.writeError(w, "signer not found", http.StatusNotFound)
			return
		}
		h.writeError(w, "only the signer owner can unlock", http.StatusForbidden)
		return
	}

	var req UnlockSignerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer secure.ZeroString(&req.Password)

	if req.Password == "" {
		h.writeError(w, "password is required", http.StatusBadRequest)
		return
	}

	info, err := h.signerManager.UnlockSigner(r.Context(), address, req.Password)
	if err != nil {
		if types.IsSignerNotFound(err) {
			h.writeError(w, "signer not found", http.StatusNotFound)
			return
		}
		if err == types.ErrSignerNotLocked {
			h.writeError(w, "signer is already unlocked", http.StatusConflict)
			return
		}
		h.logger.Error("failed to unlock signer",
			slog.String("address", address),
			slog.String("error", err.Error()),
		)
		h.writeError(w, "failed to unlock signer", http.StatusInternalServerError)
		return
	}

	h.logger.Info("signer unlocked via API",
		slog.String("address", address),
		slog.String("type", info.Type),
	)

	if h.auditLogger != nil {
		h.auditLogger.LogSignerUnlocked(r.Context(), apiKey.ID, r.RemoteAddr, address)
	}

	h.writeJSON(w, SignerResponse{
		Address:    info.Address,
		Type:       info.Type,
		Enabled:    info.Enabled,
		Locked:     info.Locked,
		UnlockedAt: info.UnlockedAt,
	}, http.StatusOK)
}

// handleLock handles POST /api/v1/evm/signers/{address}/lock
func (h *SignerHandler) handleLock(w http.ResponseWriter, r *http.Request, address string) {
	apiKey := middleware.GetAPIKey(r.Context())

	// Owner check — return 404 if signer has no ownership record (orphan/non-existent)
	isOwner, err := h.accessService.IsOwner(r.Context(), apiKey.ID, address)
	if err != nil {
		h.writeError(w, "failed to check ownership", http.StatusInternalServerError)
		return
	}
	if !isOwner {
		// Distinguish 404 from 403: if no ownership record exists at all, treat as not found
		if _, oErr := h.accessService.GetOwnership(r.Context(), address); oErr != nil && types.IsNotFound(oErr) {
			h.writeError(w, "signer not found", http.StatusNotFound)
			return
		}
		h.writeError(w, "only the signer owner can lock", http.StatusForbidden)
		return
	}

	info, err := h.signerManager.LockSigner(r.Context(), address)
	if err != nil {
		if types.IsSignerNotFound(err) {
			h.writeError(w, "signer not found", http.StatusNotFound)
			return
		}
		if types.IsSignerLocked(err) {
			h.writeError(w, "signer is already locked", http.StatusConflict)
			return
		}
		h.logger.Error("failed to lock signer",
			slog.String("address", address),
			slog.String("error", err.Error()),
		)
		h.writeError(w, "failed to lock signer", http.StatusInternalServerError)
		return
	}

	h.logger.Info("signer locked via API",
		slog.String("address", address),
		slog.String("type", info.Type),
	)

	if h.auditLogger != nil {
		h.auditLogger.LogSignerLocked(r.Context(), apiKey.ID, r.RemoteAddr, address)
	}

	h.writeJSON(w, SignerResponse{
		Address:    info.Address,
		Type:       info.Type,
		Enabled:    info.Enabled,
		Locked:     info.Locked,
		UnlockedAt: info.UnlockedAt,
	}, http.StatusOK)
}

// handleApproveSigner handles POST /api/v1/evm/signers/{address}/approve (admin only)
func (h *SignerHandler) handleApproveSigner(w http.ResponseWriter, r *http.Request, address string) {
	apiKey := middleware.GetAPIKey(r.Context())
	if !apiKey.IsAdmin() {
		h.writeError(w, "admin access required", http.StatusForbidden)
		return
	}

	ownership, err := h.accessService.GetOwnership(r.Context(), address)
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "no ownership record for this signer", http.StatusNotFound)
			return
		}
		h.writeError(w, "failed to get ownership", http.StatusInternalServerError)
		return
	}

	if ownership.Status == types.SignerOwnershipActive {
		h.writeError(w, "signer is already active", http.StatusConflict)
		return
	}

	if err := h.accessService.SetOwner(r.Context(), address, ownership.OwnerID, types.SignerOwnershipActive); err != nil {
		h.writeError(w, "failed to approve signer", http.StatusInternalServerError)
		return
	}

	h.logger.Info("signer approved",
		slog.String("address", address),
		slog.String("approved_by", apiKey.ID),
	)

	h.writeJSON(w, map[string]string{"status": "approved", "signer_address": address}, http.StatusOK)
}

// handleAccess routes access sub-actions
func (h *SignerHandler) handleAccess(w http.ResponseWriter, r *http.Request, address, extra string) {
	switch r.Method {
	case http.MethodGet:
		// GET /api/v1/evm/signers/{address}/access — list access
		h.handleListAccess(w, r, address)
	case http.MethodPost:
		// POST /api/v1/evm/signers/{address}/access — grant access
		h.handleGrantAccess(w, r, address)
	case http.MethodDelete:
		// DELETE /api/v1/evm/signers/{address}/access/{keyID}
		if extra == "" {
			h.writeError(w, "api_key_id is required in path", http.StatusBadRequest)
			return
		}
		h.handleRevokeAccess(w, r, address, extra)
	default:
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGrantAccess handles POST /api/v1/evm/signers/{address}/access
func (h *SignerHandler) handleGrantAccess(w http.ResponseWriter, r *http.Request, address string) {
	apiKey := middleware.GetAPIKey(r.Context())

	var req GrantAccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.APIKeyID == "" {
		h.writeError(w, "api_key_id is required", http.StatusBadRequest)
		return
	}

	if err := h.accessService.GrantAccess(r.Context(), apiKey.ID, address, req.APIKeyID); err != nil {
		h.logger.Error("failed to grant access",
			slog.String("address", address),
			slog.String("error", err.Error()),
		)
		h.writeError(w, err.Error(), http.StatusForbidden)
		return
	}

	h.writeJSON(w, map[string]string{"status": "granted", "signer_address": address, "api_key_id": req.APIKeyID}, http.StatusOK)
}

// handleRevokeAccess handles DELETE /api/v1/evm/signers/{address}/access/{keyID}
func (h *SignerHandler) handleRevokeAccess(w http.ResponseWriter, r *http.Request, address, keyID string) {
	apiKey := middleware.GetAPIKey(r.Context())

	if err := h.accessService.RevokeAccess(r.Context(), apiKey.ID, address, keyID); err != nil {
		h.logger.Error("failed to revoke access",
			slog.String("address", address),
			slog.String("error", err.Error()),
		)
		h.writeError(w, err.Error(), http.StatusForbidden)
		return
	}

	h.writeJSON(w, map[string]string{"status": "revoked", "signer_address": address, "api_key_id": keyID}, http.StatusOK)
}

// handleListAccess handles GET /api/v1/evm/signers/{address}/access
func (h *SignerHandler) handleListAccess(w http.ResponseWriter, r *http.Request, address string) {
	apiKey := middleware.GetAPIKey(r.Context())

	accesses, err := h.accessService.ListAccess(r.Context(), apiKey.ID, address)
	if err != nil {
		h.logger.Error("failed to list access",
			slog.String("address", address),
			slog.String("error", err.Error()),
		)
		h.writeError(w, err.Error(), http.StatusForbidden)
		return
	}

	resp := make([]SignerAccessResponse, len(accesses))
	for i, a := range accesses {
		resp[i] = SignerAccessResponse{
			APIKeyID:  a.APIKeyID,
			GrantedBy: a.GrantedBy,
			CreatedAt: a.CreatedAt,
		}
	}

	h.writeJSON(w, resp, http.StatusOK)
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
	// #nosec G104 -- HTTP response write error cannot be meaningfully handled
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
