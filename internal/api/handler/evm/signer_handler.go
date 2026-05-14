package evm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/secure"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

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

	tagFilter := strings.TrimSpace(query.Get("tag"))

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

	if tagFilter != "" {
		var tagged []types.SignerInfo
		for _, s := range filteredSigners {
			own, oErr := h.accessService.GetOwnership(r.Context(), s.Address)
			if oErr != nil || own == nil {
				continue
			}
			if validate.SignerHasTag(own.Tags(), tagFilter) {
				tagged = append(tagged, s)
			}
		}
		filteredSigners = tagged
	}

	excludeHDDerived := query.Get("exclude_hd_derived") == "true" || query.Get("exclude_hd_derived") == "1"
	if excludeHDDerived {
		var kept []types.SignerInfo
		for _, s := range filteredSigners {
			if h.signerIsHDDerivedNonPrimary(s.Address) {
				continue
			}
			kept = append(kept, s)
		}
		filteredSigners = kept
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
	addresses := make([]string, 0, len(filteredSigners))
	for i, s := range filteredSigners {
		signers[i] = h.newSignerResponse(r.Context(), s)
		addresses = append(addresses, s.Address)
	}
	if h.walletRepo != nil && len(addresses) > 0 {
		walletsMap, mapErr := h.walletRepo.GetWalletsForSigners(r.Context(), addresses)
		if mapErr != nil {
			h.logger.Warn("failed to aggregate wallets for signers", slog.String("error", mapErr.Error()))
		} else {
			for i := range signers {
				ws := walletsMap[signers[i].Address]
				if len(ws) == 0 {
					continue
				}
				signers[i].Wallets = make([]SignerWalletRef, 0, len(ws))
				for _, w := range ws {
					signers[i].Wallets = append(signers[i].Wallets, SignerWalletRef{ID: w.ID, Name: w.Name})
				}
			}
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

// handleDeleteSigner handles DELETE /api/v1/evm/signers/{address}
func (h *SignerHandler) handleDeleteSigner(w http.ResponseWriter, r *http.Request, address string) {
	apiKey := middleware.GetAPIKey(r.Context())

	// Check ownership first
	isOwner, err := h.accessService.IsOwner(r.Context(), apiKey.ID, address)
	if err != nil {
		h.logger.Error("failed to check ownership", slog.String("error", err.Error()))
		h.writeError(w, "failed to check ownership", http.StatusInternalServerError)
		return
	}
	if !isOwner {
		// Distinguish 404 from 403: if no ownership record exists at all, treat as not found
		if _, oErr := h.accessService.GetOwnership(r.Context(), address); oErr != nil && types.IsNotFound(oErr) {
			h.writeError(w, "signer not found", http.StatusNotFound)
			return
		}
		h.writeError(w, "only the signer owner can delete", http.StatusForbidden)
		return
	}

	// Get signer type to determine if HD wallet (for derived address cleanup)
	var signerType string
	info, err := h.signerManager.ListSigners(r.Context(), types.SignerFilter{Offset: 0, Limit: 100000})
	if err == nil {
		for _, s := range info.Signers {
			if strings.EqualFold(s.Address, address) {
				signerType = s.Type
				break
			}
		}
	}

	// Delete signer from provider (files, in-memory state, registry) BEFORE database cleanup
	// This is critical for HD wallets to clean derived addresses too
	if err := h.signerManager.DeleteSigner(r.Context(), address); err != nil {
		if types.IsSignerNotFound(err) {
			h.writeError(w, "signer not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to delete signer from provider",
			slog.String("address", address),
			slog.String("error", err.Error()),
		)
		h.writeError(w, "failed to delete signer", http.StatusInternalServerError)
		return
	}

	// For HD wallets, also delete all derived addresses from ownership DB
	if signerType == string(types.SignerTypeHDWallet) {
		hdMgr, hdErr := h.signerManager.HDWalletManager()
		if hdErr == nil && hdMgr != nil {
			derived, dErr := hdMgr.ListDerivedAddresses(address)
			if dErr == nil {
				for _, d := range derived {
					if strings.EqualFold(d.Address, address) {
						continue // primary already handled
					}
					if delErr := h.accessService.DeleteSigner(r.Context(), apiKey.ID, d.Address); delErr != nil {
						h.logger.Warn("failed to delete derived signer ownership",
							slog.String("address", d.Address),
							slog.String("error", delErr.Error()),
						)
					}
				}
			}
		}
	}

	// Delete ownership and access records from database
	if err := h.accessService.DeleteSigner(r.Context(), apiKey.ID, address); err != nil {
		h.logger.Error("failed to delete signer ownership",
			slog.String("address", address),
			slog.String("error", err.Error()),
		)
		h.writeError(w, "failed to delete signer ownership", http.StatusInternalServerError)
		return
	}

	if h.auditLogger != nil {
		h.auditLogger.LogSignerCreated(r.Context(), apiKey.ID, r.RemoteAddr, address, "deleted")
	}

	w.WriteHeader(http.StatusNoContent)
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

// signerIsHDDerivedNonPrimary reports whether address is an HD-derived signer (derivation index > 0).
// Primary HD addresses use index 0; keystore/private_key and addresses missing from hierarchy are false.
func (h *SignerHandler) signerIsHDDerivedNonPrimary(address string) bool {
	if h.signerManager == nil {
		return false
	}
	hierarchy := h.signerManager.GetHDHierarchy()
	if len(hierarchy) == 0 {
		return false
	}
	key := common.HexToAddress(address).Hex()
	info, ok := hierarchy[key]
	if !ok {
		return false
	}
	return info.DerivationIndex > 0
}

// signerInfoByAddress looks up a signer by address from the signer manager.
func (h *SignerHandler) signerInfoByAddress(ctx context.Context, address string) (types.SignerInfo, error) {
	res, err := h.signerManager.ListSigners(ctx, types.SignerFilter{Limit: 100000})
	if err != nil {
		return types.SignerInfo{}, err
	}
	for _, s := range res.Signers {
		if strings.EqualFold(s.Address, address) {
			return s, nil
		}
	}
	return types.SignerInfo{}, types.ErrSignerNotFound
}

// handlePatchSignerLabels handles PATCH /api/v1/evm/signers/{address}
func (h *SignerHandler) handlePatchSignerLabels(w http.ResponseWriter, r *http.Request, address string) {
	apiKey := middleware.GetAPIKey(r.Context())

	var req PatchSignerLabelsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.DisplayName == nil && req.Tags == nil {
		h.writeError(w, "at least one of display_name or tags is required", http.StatusBadRequest)
		return
	}
	patch := types.SignerLabelPatch{DisplayName: req.DisplayName, Tags: req.Tags}
	if err := h.accessService.PatchSignerLabels(r.Context(), apiKey.ID, address, patch); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "not the owner") {
			h.writeError(w, msg, http.StatusForbidden)
			return
		}
		if types.IsNotFound(err) {
			h.writeError(w, "ownership not found for signer", http.StatusNotFound)
			return
		}
		h.writeError(w, msg, http.StatusBadRequest)
		return
	}

	info, err := h.signerInfoByAddress(r.Context(), address)
	if err != nil {
		if errors.Is(err, types.ErrSignerNotFound) {
			h.writeError(w, "signer not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to load signer after label patch", slog.String("address", address), slog.String("error", err.Error()))
		h.writeError(w, "failed to load signer", http.StatusInternalServerError)
		return
	}

	h.writeJSON(w, h.newSignerResponse(r.Context(), info), http.StatusOK)
}

// listWallets groups signers by wallet and returns wallet list
func (h *SignerHandler) listWallets(w http.ResponseWriter, r *http.Request, signers []types.SignerInfo, offset, limit int, tagFilter string) {
	// Group signers by wallet_id
	walletMap := make(map[string][]types.SignerInfo)
	for _, s := range signers {
		resp := h.newSignerResponse(r.Context(), s)
		walletID := resp.PrimaryAddress
		walletMap[walletID] = append(walletMap[walletID], s)
	}

	// Build wallet list
	var wallets []WalletResponse
	for walletID, signerGroup := range walletMap {
		if len(signerGroup) == 0 {
			continue
		}

		// Use the first signer to build wallet info (all signers in same wallet share ownership/metadata)
		primary := signerGroup[0]
		resp := h.newSignerResponse(r.Context(), primary)

		wallet := WalletResponse{
			WalletID:       walletID,
			WalletType:     primary.Type,
			PrimaryAddress: walletID, // For HD: primary address; for keystore: own address
			SignerCount:    len(signerGroup),
			Enabled:        resp.Enabled,
			Locked:         resp.Locked,
			UnlockedAt:     resp.UnlockedAt,
			OwnerID:        resp.OwnerID,
			Status:         resp.Status,
			DisplayName:    resp.DisplayName,
			Tags:           resp.Tags,
		}
		wallets = append(wallets, wallet)
	}

	// Sort wallets by wallet_id for deterministic pagination
	sort.Slice(wallets, func(i, j int) bool {
		return strings.ToLower(wallets[i].WalletID) < strings.ToLower(wallets[j].WalletID)
	})

	total := len(wallets)

	// Apply pagination at wallet level
	if offset >= len(wallets) {
		wallets = nil
	} else {
		end := offset + limit
		if end > len(wallets) {
			end = len(wallets)
		}
		wallets = wallets[offset:end]
	}

	hasMore := offset+limit < total

	resp := ListWalletsResponse{
		Wallets: wallets,
		Total:   total,
		HasMore: hasMore,
	}

	h.writeJSON(w, resp, http.StatusOK)
}

// listWalletSigners handles GET /api/v1/evm/wallets/{wallet_id}/signers
func (h *SignerHandler) listWalletSigners(w http.ResponseWriter, r *http.Request, walletID string) {
	query := r.URL.Query()
	apiKey := middleware.GetAPIKey(r.Context())

	requestedOffset := 0
	requestedLimit := 20
	excludeHDDerived := query.Get("exclude_hd_derived") == "true" || query.Get("exclude_hd_derived") == "1"

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
		Offset: 0,
		Limit:  100000,
	}
	result, err := h.signerManager.ListSigners(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list signers", slog.String("error", err.Error()))
		h.writeError(w, "failed to list signers", http.StatusInternalServerError)
		return
	}

	// Build allowed addresses set
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

	// Include HD wallet derived addresses
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

	// Filter signers belonging to this wallet
	var walletSigners []types.SignerInfo
	var walletType string
	for _, s := range result.Signers {
		if !allowedSet[strings.ToLower(s.Address)] {
			continue
		}
		if excludeHDDerived && h.signerIsHDDerivedNonPrimary(s.Address) {
			continue
		}
		resp := h.newSignerResponse(r.Context(), s)
		if strings.EqualFold(resp.PrimaryAddress, walletID) {
			walletSigners = append(walletSigners, s)
			if walletType == "" {
				walletType = s.Type
			}
		}
	}

	// Sort by derivation index for HD wallets, or by address for others
	if len(walletSigners) > 0 {
		sort.Slice(walletSigners, func(i, j int) bool {
			respI := h.newSignerResponse(r.Context(), walletSigners[i])
			respJ := h.newSignerResponse(r.Context(), walletSigners[j])
			if respI.HDDerivationIndex != nil && respJ.HDDerivationIndex != nil {
				return *respI.HDDerivationIndex < *respJ.HDDerivationIndex
			}
			return strings.ToLower(walletSigners[i].Address) < strings.ToLower(walletSigners[j].Address)
		})
	}

	total := len(walletSigners)

	// Apply pagination
	if requestedOffset >= len(walletSigners) {
		walletSigners = nil
	} else {
		end := requestedOffset + requestedLimit
		if end > len(walletSigners) {
			end = len(walletSigners)
		}
		walletSigners = walletSigners[requestedOffset:end]
	}

	hasMore := requestedOffset+requestedLimit < total

	// Convert to response
	signers := make([]SignerResponse, len(walletSigners))
	for i, s := range walletSigners {
		signers[i] = h.newSignerResponse(r.Context(), s)
	}

	resp := WalletSignersResponse{
		WalletID:   walletID,
		WalletType: walletType,
		Signers:    signers,
		Total:      total,
		HasMore:    hasMore,
	}

	h.writeJSON(w, resp, http.StatusOK)
}
