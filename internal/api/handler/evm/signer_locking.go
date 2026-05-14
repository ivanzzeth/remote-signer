// Package evm — signer_locking.go handles signer lock/unlock operations
// and ownership management (approval and transfer). These actions require
// ownership or admin privileges.

package evm

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/secure"
)

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

	h.writeJSON(w, h.newSignerResponse(r.Context(), *info), http.StatusOK)
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

	h.writeJSON(w, h.newSignerResponse(r.Context(), *info), http.StatusOK)
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

// handleTransferOwnership handles POST /api/v1/evm/signers/{address}/transfer
func (h *SignerHandler) handleTransferOwnership(w http.ResponseWriter, r *http.Request, address string) {
	apiKey := middleware.GetAPIKey(r.Context())

	var req TransferOwnershipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.NewOwnerID == "" {
		h.writeError(w, "new_owner_id is required", http.StatusBadRequest)
		return
	}

	if err := h.accessService.TransferOwnership(r.Context(), apiKey.ID, address, req.NewOwnerID); err != nil {
		if strings.Contains(err.Error(), "not the owner") {
			h.writeError(w, err.Error(), http.StatusForbidden)
			return
		}
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if strings.Contains(err.Error(), "cannot transfer signer to yourself") {
			h.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.logger.Error("failed to transfer ownership",
			slog.String("address", address),
			slog.String("error", err.Error()),
		)
		h.writeError(w, "failed to transfer ownership", http.StatusInternalServerError)
		return
	}

	if h.auditLogger != nil {
		h.auditLogger.LogSignerCreated(r.Context(), apiKey.ID, r.RemoteAddr, address, "transfer:"+req.NewOwnerID)
	}

	h.writeJSON(w, map[string]string{
		"status":         "transferred",
		"signer_address": address,
		"new_owner_id":   req.NewOwnerID,
	}, http.StatusOK)
}
