// Package evm — signer_access.go handles access-control list operations:
// granting, revoking, and listing access grants for signers. All operations
// require ownership of the signer.

package evm

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
)

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
