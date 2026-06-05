// Package evm — signer_crud.go manages signer listing, deletion, and label
// patching for the API surface (creation lives in signer_create.go).
// Access-control filtering ensures each API key only sees the signers it
// owns or has been granted access to.
package evm

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

// parseTriBool reads a query value as "true" / "false" / "" — the
// third state being "no filter". Empty maps to nil so we don't burn
// CPU iterating signers for a no-op. Any other literal is a 400 at
// the call site, not silently treated as "no filter" (rejected
// misspellings beat permissive parsing).
func parseTriBool(raw string) (*bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return nil, nil
	case "true", "1":
		v := true
		return &v, nil
	case "false", "0":
		v := false
		return &v, nil
	default:
		return nil, errors.New("invalid bool")
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

	tagFilter := strings.TrimSpace(query.Get("tag"))

	// api_key_id pins the address-allowlist to *another* key's view.
	// Non-admins may only target their own key — anything else is a
	// privilege-leak attempt and gets a 403 (cheaper than 200 + empty
	// list, which would mask a UI bug). Default (nil) keeps the legacy
	// "caller's own view" behavior.
	targetKeyID := apiKey.ID
	if v := strings.TrimSpace(query.Get("api_key_id")); v != "" {
		if !apiKey.IsAdmin() && v != apiKey.ID {
			h.writeError(w, "forbidden: only admins can filter by another api key", http.StatusForbidden)
			return
		}
		targetKeyID = v
	}

	// locked / enabled are tri-state — query absent means either, set
	// to "true" or "false" pins exactly that state. Reject any other
	// literal so a misspelled "enabled=yes" 400s instead of silently
	// becoming "no filter".
	lockedFilter, err := parseTriBool(query.Get("locked"))
	if err != nil {
		h.writeError(w, "invalid locked filter: must be true or false", http.StatusBadRequest)
		return
	}
	enabledFilter, err := parseTriBool(query.Get("enabled"))
	if err != nil {
		h.writeError(w, "invalid enabled filter: must be true or false", http.StatusBadRequest)
		return
	}

	ownershipStatusFilter := strings.TrimSpace(query.Get("ownership_status"))
	if ownershipStatusFilter != "" {
		if ownershipStatusFilter != string(types.SignerOwnershipPendingApproval) {
			h.writeError(w, "invalid ownership_status filter: must be pending_approval", http.StatusBadRequest)
			return
		}
		if !apiKey.IsAdmin() {
			h.writeError(w, "forbidden: only admins can list signers pending approval", http.StatusForbidden)
			return
		}
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

	// Build allowed addresses set from ownership + access for the
	// targeted key (defaults to caller). Admin lookups against another
	// key go through the same accessService path — no special-casing,
	// because the access tables are the single source of truth.
	//
	// ownership_status=pending_approval switches to a global admin queue:
	// every signer awaiting approval across all API keys, without requiring
	// the operator to guess which key created each signer.
	allowedSet := make(map[string]bool)
	if ownershipStatusFilter == string(types.SignerOwnershipPendingApproval) {
		pendingAddrs, pErr := h.accessService.GetAddressesByOwnershipStatus(r.Context(), types.SignerOwnershipPendingApproval)
		if pErr != nil {
			h.logger.Error("failed to get pending approval signers", slog.String("error", pErr.Error()))
			h.writeError(w, "failed to list signers", http.StatusInternalServerError)
			return
		}
		for _, a := range pendingAddrs {
			allowedSet[strings.ToLower(a)] = true
		}
	} else {
		ownedAddrs, err := h.accessService.GetOwnedAddresses(r.Context(), targetKeyID)
		if err != nil {
			h.logger.Error("failed to get owned addresses", slog.String("error", err.Error()))
			h.writeError(w, "failed to list signers", http.StatusInternalServerError)
			return
		}
		grantedAddrs, err := h.accessService.GetAccessibleAddresses(r.Context(), targetKeyID)
		if err != nil {
			h.logger.Error("failed to get accessible addresses", slog.String("error", err.Error()))
			h.writeError(w, "failed to list signers", http.StatusInternalServerError)
			return
		}

		for _, a := range ownedAddrs {
			allowedSet[strings.ToLower(a)] = true
		}
		for _, a := range grantedAddrs {
			allowedSet[strings.ToLower(a)] = true
		}
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

	if lockedFilter != nil {
		var kept []types.SignerInfo
		for _, s := range filteredSigners {
			if s.Locked == *lockedFilter {
				kept = append(kept, s)
			}
		}
		filteredSigners = kept
	}
	if enabledFilter != nil {
		var kept []types.SignerInfo
		for _, s := range filteredSigners {
			if s.Enabled == *enabledFilter {
				kept = append(kept, s)
			}
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
