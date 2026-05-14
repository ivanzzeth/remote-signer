// Package evm — signer_create.go handles signer creation via the API.
// Owners are set to the creating API key (admin → active, non-admin → pending_approval).
package evm

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/secure"
)

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

	// Enforce resource limit: max keystores per key
	if h.maxKeystoresPerKey > 0 {
		count, countErr := h.accessService.CountOwnedSigners(r.Context(), apiKey.ID)
		if countErr != nil {
			h.logger.Error("failed to count owned signers", slog.String("error", countErr.Error()))
			h.writeError(w, "failed to check resource limits", http.StatusInternalServerError)
			return
		}
		if int(count) >= h.maxKeystoresPerKey {
			h.writeError(w, fmt.Sprintf("resource limit exceeded: maximum %d keystores per API key", h.maxKeystoresPerKey), http.StatusForbidden)
			return
		}
	}

	var req CreateSignerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer func() {
		if req.Keystore != nil {
			secure.ZeroString(&req.Keystore.Password)
			// PrivateKeyHex / KeystoreJSON are sensitive — overwrite the
			// request struct's copy after handoff to the manager.
			secure.ZeroString(&req.Keystore.PrivateKeyHex)
			secure.ZeroString(&req.Keystore.KeystoreJSON)
		}
	}()

	createReq := types.CreateSignerRequest{
		Type: types.SignerType(req.Type),
	}
	if req.Keystore != nil {
		if req.Keystore.PrivateKeyHex != "" && req.Keystore.KeystoreJSON != "" {
			h.writeError(w, "specify private_key_hex or keystore_json, not both", http.StatusBadRequest)
			return
		}
		createReq.Keystore = &types.CreateKeystoreParams{
			Password:      req.Keystore.Password,
			PrivateKeyHex: req.Keystore.PrivateKeyHex,
			KeystoreJSON:  req.Keystore.KeystoreJSON,
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
	} else {
		var dn *string
		if strings.TrimSpace(req.DisplayName) != "" {
			v := strings.TrimSpace(req.DisplayName)
			dn = &v
		}
		var tg *[]string
		if len(req.Tags) > 0 {
			tg = &req.Tags
		}
		if dn != nil || tg != nil {
			patch := types.SignerLabelPatch{DisplayName: dn, Tags: tg}
			if patchErr := h.accessService.PatchSignerLabels(r.Context(), apiKey.ID, signerInfo.Address, patch); patchErr != nil {
				h.logger.Warn("failed to set initial signer labels",
					slog.String("address", signerInfo.Address),
					slog.String("error", patchErr.Error()),
				)
			}
		}
	}

	h.logger.Info("signer created",
		slog.String("address", signerInfo.Address),
		slog.String("type", signerInfo.Type),
		slog.String("owner", apiKey.ID),
		slog.String("status", string(status)),
	)

	if h.auditLogger != nil {
		// Audit records the creation mode so an operator can later tell
		// "import" provenance apart from a fresh keypair.
		mode := signerInfo.Type
		if req.Keystore != nil {
			switch {
			case req.Keystore.KeystoreJSON != "":
				mode = signerInfo.Type + ":import-keystore-json"
			case req.Keystore.PrivateKeyHex != "":
				mode = signerInfo.Type + ":import-hex"
			}
		}
		h.auditLogger.LogSignerCreated(r.Context(), apiKey.ID, r.RemoteAddr, signerInfo.Address, mode)
	}

	resp := CreateSignerResponse{
		Address: signerInfo.Address,
		Type:    signerInfo.Type,
		Enabled: signerInfo.Enabled,
	}
	if own, oErr := h.accessService.GetOwnership(r.Context(), signerInfo.Address); oErr == nil && own != nil {
		resp.DisplayName = own.DisplayName
		resp.Tags = own.Tags()
	}

	h.writeJSON(w, resp, http.StatusCreated)
}
