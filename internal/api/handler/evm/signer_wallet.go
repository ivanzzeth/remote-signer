// Package evm — signer_wallet.go groups signers into wallet views and handles
// wallet-level signer listing. It also provides the address-based signer lookup
// helper used by other handler files.

package evm

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

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
