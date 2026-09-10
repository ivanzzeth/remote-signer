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

	"github.com/ivanzzeth/remote-signer/internal/api/respond"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// HandleWalletSigners handles GET /api/v1/evm/wallets/{wallet_id}/signers.
//
// ⛔ NO ROUTE REGISTERS IT. It is mux-facing code — it checks r.Method itself
// and cuts r.URL.Path itself — reachable from nothing but its own tests
// (evm_coverage_boost2_test.go, evm_coverage_boost3_test.go). Grepping the tree
// for the path it claims to serve finds this function, its tests, and nothing
// else: `/api/v1/evm/wallets/` is not a pattern any module or setupRoutes
// registers, and pkg/client, web/src and e2e/ never request it.
//
// ⚠️ It is left in place, unchanged, by the route decomposition rather than
// deleted, and that is a decision to be taken separately: deleting an exported
// method with six tests is not an execution detail of "give each endpoint its
// own route", and a reader who assumes it is dead should be the one to prove it
// against the SDKs rather than have this step assume it. It is why the signer
// family keeps one entry in the handler-path-dispatch baseline.
//
// ⚠️ It moved here from signer.go, which is a file move and nothing else — the
// baseline keys on <pkg>.<Recv>.<FuncName> and does not move with it. The
// reason it moved is that signer.go is now the routed surface, every function
// in it reads r.PathValue, and leaving the one function that does not next to
// them invites the next reader to copy the wrong one.
func (h *SignerHandler) HandleWalletSigners(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respond.Error(w, "method not allowed", http.StatusMethodNotAllowed, h.logger)
		return
	}

	// Parse wallet_id from path: /api/v1/evm/wallets/{wallet_id}/signers
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/evm/wallets/")
	path = strings.TrimSuffix(path, "/signers")
	walletID := strings.TrimSpace(path)

	if walletID == "" {
		respond.Error(w, "wallet_id is required", http.StatusBadRequest, h.logger)
		return
	}

	h.listWalletSigners(w, r, walletID)
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
			respond.Error(w, "invalid offset parameter", http.StatusBadRequest, h.logger)
			return
		}
		requestedOffset = offset
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
		respond.Error(w, "failed to list signers", http.StatusInternalServerError, h.logger)
		return
	}

	// Build allowed addresses set
	ownedAddrs, err := h.accessService.GetOwnedAddresses(r.Context(), apiKey.ID)
	if err != nil {
		h.logger.Error("failed to get owned addresses", slog.String("error", err.Error()))
		respond.Error(w, "failed to list signers", http.StatusInternalServerError, h.logger)
		return
	}
	grantedAddrs, err := h.accessService.GetAccessibleAddresses(r.Context(), apiKey.ID)
	if err != nil {
		h.logger.Error("failed to get accessible addresses", slog.String("error", err.Error()))
		respond.Error(w, "failed to list signers", http.StatusInternalServerError, h.logger)
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

	respond.JSON(w, resp, http.StatusOK, h.logger)
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
