package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/api/respond"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// WalletHandler handles wallet CRUD endpoints.
type WalletHandler struct {
	repo          storage.WalletRepository
	ownershipRepo storage.SignerOwnershipRepository
	accessRepo    storage.SignerAccessRepository
	logger        *slog.Logger
}

// NewWalletHandler creates a new wallet handler.
func NewWalletHandler(repo storage.WalletRepository, ownershipRepo storage.SignerOwnershipRepository, accessRepo storage.SignerAccessRepository, logger *slog.Logger) (*WalletHandler, error) {
	if repo == nil {
		return nil, fmt.Errorf("wallet repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &WalletHandler{
		repo:          repo,
		ownershipRepo: ownershipRepo,
		accessRepo:    accessRepo,
		logger:        logger,
	}, nil
}

// --- Request/Response types ---
//
// ⚠️ Exported, and the reason is not style. These seven types are the wallet
// API's wire contract, and the plan they belong to (docs/drafts/
// openapi-chain-proposal.md §1.4, §3.3) turns each of them into a schema name in
// a generated OpenAPI document and from there into a type name in the generated
// Go and TypeScript SDKs. A generator has nothing to call an unexported type: it
// either invents an unreadable name or skips the type and inlines an anonymous
// schema, and either way the SDK stops matching the handler by name. ⛔ So the
// export is not cosmetic and it is not reversible without breaking that chain —
// renaming one of these later is a client-visible rename of an SDK type.
//
// ⛔ The JSON tags are the actual contract and none of them changed here. A
// field name a client parses lives in the tag, not in the Go identifier.

// CreateWalletRequest is the body of POST /api/v1/wallets.
type CreateWalletRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// UpdateWalletRequest is the body of PATCH /api/v1/wallets/{id}. Both fields are
// pointers so that "absent" and "set to empty" stay distinguishable.
type UpdateWalletRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

// AddMemberRequest is the body of POST /api/v1/wallets/{id}/members.
type AddMemberRequest struct {
	SignerAddress string `json:"signer_address"`
}

// WalletResponse is one wallet as the API returns it.
type WalletResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	OwnerID     string `json:"owner_id"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// WalletListResponse is the body of GET /api/v1/wallets.
type WalletListResponse struct {
	Wallets []WalletResponse `json:"wallets"`
	Total   int              `json:"total"`
	HasMore bool             `json:"has_more"`
}

// MemberResponse is one wallet member: a signer address bound to a wallet.
type MemberResponse struct {
	WalletID      string `json:"wallet_id"`
	SignerAddress string `json:"signer_address"`
	AddedAt       string `json:"added_at"`
}

// MembersListResponse is the body of GET /api/v1/wallets/{id}/members.
type MembersListResponse struct {
	Members []MemberResponse `json:"members"`
}

// --- Handler entry points ---
//
// # One exported function per endpoint (proposal S3)
//
// These eight replace two: ServeHTTP, which switched on r.Method for
// /api/v1/wallets, and ServeWalletHTTP, which took r.URL.Path apart with
// TrimPrefix/TrimSuffix/SplitN and fanned out into six more. The registration
// that used to hide those eight behind two prefix patterns is
// internal/api/module_wallets.go, and it now names each one.
//
// ⭐ Why both halves had to move at once (proposal §1.3): registering
// `GET /api/v1/wallets/{id}` while the handler still read r.URL.Path would leave
// the wildcard decorative — the handler would keep working when reached by some
// other pattern, and the handler-path-dispatch gate would not move. The path
// segments are read through r.PathValue here, which only a matching pattern can
// populate, so these functions are now reachable only from a route that names
// their shape.
//
// ⛔ WalletHandler is deliberately no longer an http.Handler. It has no
// ServeHTTP, so there is no way to hand the whole wallet surface to one pattern
// again by accident.

// ListWallets serves GET /api/v1/wallets.
func (h *WalletHandler) ListWallets(w http.ResponseWriter, r *http.Request) {
	h.listWallets(w, r)
}

// CreateWallet serves POST /api/v1/wallets.
func (h *WalletHandler) CreateWallet(w http.ResponseWriter, r *http.Request) {
	h.createWallet(w, r)
}

// GetWallet serves GET /api/v1/wallets/{id}.
func (h *WalletHandler) GetWallet(w http.ResponseWriter, r *http.Request) {
	_, wallet, ok := h.resolveOwnedWallet(w, r)
	if !ok {
		return
	}
	h.getWallet(w, wallet)
}

// UpdateWallet serves PATCH /api/v1/wallets/{id}.
func (h *WalletHandler) UpdateWallet(w http.ResponseWriter, r *http.Request) {
	_, wallet, ok := h.resolveOwnedWallet(w, r)
	if !ok {
		return
	}
	h.updateWallet(w, r, wallet)
}

// DeleteWallet serves DELETE /api/v1/wallets/{id}.
func (h *WalletHandler) DeleteWallet(w http.ResponseWriter, r *http.Request) {
	walletID, _, ok := h.resolveOwnedWallet(w, r)
	if !ok {
		return
	}
	h.deleteWallet(w, r, walletID)
}

// ListMembers serves GET /api/v1/wallets/{id}/members.
func (h *WalletHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	walletID, _, ok := h.resolveOwnedWallet(w, r)
	if !ok {
		return
	}
	h.listMembers(w, r, walletID)
}

// AddMember serves POST /api/v1/wallets/{id}/members.
func (h *WalletHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	walletID, _, ok := h.resolveOwnedWallet(w, r)
	if !ok {
		return
	}
	h.addMember(w, r, walletID)
}

// RemoveMember serves DELETE /api/v1/wallets/{id}/members/{signerAddress}.
func (h *WalletHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	walletID, _, ok := h.resolveOwnedWallet(w, r)
	if !ok {
		return
	}
	h.removeMember(w, r, walletID, r.PathValue("signerAddress"))
}

// resolveOwnedWallet is the check ServeWalletHTTP ran once, before its own
// dispatch, for every path with an {id} in it. It is called by each of the six
// {id} routes instead.
//
// ⛔ Its three answers are copied verbatim and their order matters, because each
// one is what a caller learns: no API key is 401; a wallet that does not exist
// is 404 "wallet not found"; and a wallet owned by someone else is *also* 404
// "wallet not found", not 403 — telling the two apart would let any key
// enumerate other owners' wallet ids. ⚠️ Reordering the ownership check after
// the repository lookup, or making it a 403, is a security change wearing a
// refactor's clothes.
//
// It returns the id as the path spelled it (which is what the operations below
// take) as well as the loaded wallet, since some callers need each.
func (h *WalletHandler) resolveOwnedWallet(w http.ResponseWriter, r *http.Request) (string, *types.Wallet, bool) {
	walletID := r.PathValue("id")

	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return "", nil, false
	}

	wallet, err := h.repo.Get(r.Context(), walletID)
	if err != nil {
		if types.IsNotFound(err) {
			respond.Error(w, "wallet not found", http.StatusNotFound, h.logger)
			return "", nil, false
		}
		h.logger.Error("failed to get wallet", "error", err)
		respond.Error(w, "internal error", http.StatusInternalServerError, h.logger)
		return "", nil, false
	}

	// Only owner or admin can access.
	if wallet.OwnerID != apiKey.ID && !apiKey.IsAdmin() {
		respond.Error(w, "wallet not found", http.StatusNotFound, h.logger)
		return "", nil, false
	}

	return walletID, wallet, true
}

// --- CRUD operations ---

func (h *WalletHandler) createWallet(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}

	var req CreateWalletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.Error(w, "invalid request body", http.StatusBadRequest, h.logger)
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		respond.Error(w, "name is required", http.StatusBadRequest, h.logger)
		return
	}

	wallet := &types.Wallet{
		Name:        strings.TrimSpace(req.Name),
		Description: req.Description,
		OwnerID:     apiKey.ID,
	}

	if err := h.repo.Create(r.Context(), wallet); err != nil {
		h.logger.Error("failed to create wallet", "error", err)
		respond.Error(w, "failed to create wallet", http.StatusInternalServerError, h.logger)
		return
	}

	respond.JSON(w, h.toResponse(wallet), http.StatusCreated, h.logger)
}

func (h *WalletHandler) listWallets(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}

	filter := types.WalletFilter{
		OwnerID: apiKey.ID,
	}
	// Admin can see all wallets
	if apiKey.IsAdmin() {
		if ownerFilter := r.URL.Query().Get("owner_id"); ownerFilter != "" {
			filter.OwnerID = ownerFilter
		} else {
			filter.OwnerID = "" // admin sees all
		}
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		offset, err := strconv.Atoi(offsetStr)
		if err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err == nil && limit > 0 {
			filter.Limit = limit
		}
	}

	result, err := h.repo.List(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list wallets", "error", err)
		respond.Error(w, "failed to list wallets", http.StatusInternalServerError, h.logger)
		return
	}

	resp := WalletListResponse{
		Wallets: make([]WalletResponse, 0, len(result.Wallets)),
		Total:   result.Total,
		HasMore: result.HasMore,
	}
	for i := range result.Wallets {
		resp.Wallets = append(resp.Wallets, h.toResponse(&result.Wallets[i]))
	}

	respond.JSON(w, resp, http.StatusOK, h.logger)
}

func (h *WalletHandler) getWallet(w http.ResponseWriter, wallet *types.Wallet) {
	respond.JSON(w, h.toResponse(wallet), http.StatusOK, h.logger)
}

func (h *WalletHandler) updateWallet(w http.ResponseWriter, r *http.Request, wallet *types.Wallet) {
	var req UpdateWalletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.Error(w, "invalid request body", http.StatusBadRequest, h.logger)
		return
	}

	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			respond.Error(w, "name cannot be empty", http.StatusBadRequest, h.logger)
			return
		}
		wallet.Name = name
	}
	if req.Description != nil {
		wallet.Description = *req.Description
	}

	if err := h.repo.Update(r.Context(), wallet); err != nil {
		h.logger.Error("failed to update wallet", "error", err)
		respond.Error(w, "failed to update wallet", http.StatusInternalServerError, h.logger)
		return
	}

	respond.JSON(w, h.toResponse(wallet), http.StatusOK, h.logger)
}

func (h *WalletHandler) deleteWallet(w http.ResponseWriter, r *http.Request, walletID string) {
	if err := h.repo.Delete(r.Context(), walletID); err != nil {
		if types.IsNotFound(err) {
			respond.Error(w, "wallet not found", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("failed to delete wallet", "error", err)
		respond.Error(w, "failed to delete wallet", http.StatusInternalServerError, h.logger)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Member operations ---

func (h *WalletHandler) listMembers(w http.ResponseWriter, r *http.Request, walletID string) {
	members, err := h.repo.ListMembers(r.Context(), walletID)
	if err != nil {
		h.logger.Error("failed to list members", "error", err)
		respond.Error(w, "failed to list members", http.StatusInternalServerError, h.logger)
		return
	}

	resp := MembersListResponse{
		Members: make([]MemberResponse, 0, len(members)),
	}
	for _, m := range members {
		resp.Members = append(resp.Members, MemberResponse{
			WalletID:      m.WalletID,
			SignerAddress: m.SignerAddress,
			AddedAt:       m.AddedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}

	respond.JSON(w, resp, http.StatusOK, h.logger)
}

func (h *WalletHandler) addMember(w http.ResponseWriter, r *http.Request, walletID string) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}

	var req AddMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.Error(w, "invalid request body", http.StatusBadRequest, h.logger)
		return
	}

	if strings.TrimSpace(req.SignerAddress) == "" {
		respond.Error(w, "signer_address is required", http.StatusBadRequest, h.logger)
		return
	}

	// Verify caller owns or has access to the wallet being added.
	// Admins bypass this check.
	if !apiKey.IsAdmin() {
		authorized, err := h.callerCanAccessWallet(r.Context(), apiKey.ID, req.SignerAddress)
		if err != nil {
			h.logger.Error("failed to verify wallet access", "error", err)
			respond.Error(w, "internal error", http.StatusInternalServerError, h.logger)
			return
		}
		if !authorized {
			respond.Error(w, "unauthorized to add signer: caller does not own or have access to this signer", http.StatusForbidden, h.logger)
			return
		}
	}

	member := &types.WalletMember{
		WalletID:      walletID,
		SignerAddress: req.SignerAddress,
	}

	if err := h.repo.AddMember(r.Context(), member); err != nil {
		if strings.Contains(err.Error(), "nested wallets are not allowed") {
			respond.Error(w, err.Error(), http.StatusBadRequest, h.logger)
			return
		}
		h.logger.Error("failed to add member", "error", err)
		respond.Error(w, "failed to add member", http.StatusInternalServerError, h.logger)
		return
	}

	respond.JSON(w, MemberResponse{
		WalletID:      member.WalletID,
		SignerAddress: member.SignerAddress,
		AddedAt:       member.AddedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}, http.StatusCreated, h.logger)

}

// callerCanAccessWallet checks whether the caller owns or has access to the given wallet address.
func (h *WalletHandler) callerCanAccessWallet(ctx context.Context, apiKeyID, walletID string) (bool, error) {
	// Check ownership: caller is the owner of the signer
	if h.ownershipRepo != nil {
		ownership, err := h.ownershipRepo.Get(ctx, walletID)
		if err == nil && ownership.OwnerID == apiKeyID && ownership.Status == types.SignerOwnershipActive {
			return true, nil
		}
		if err != nil && !types.IsNotFound(err) {
			return false, fmt.Errorf("failed to check ownership: %w", err)
		}
	}

	// Check access: caller has a signer_access grant for this address
	if h.accessRepo != nil {
		hasAccess, err := h.accessRepo.HasAccess(ctx, walletID, apiKeyID)
		if err != nil {
			return false, fmt.Errorf("failed to check access: %w", err)
		}
		if hasAccess {
			return true, nil
		}
	}

	return false, nil
}

func (h *WalletHandler) removeMember(w http.ResponseWriter, r *http.Request, walletID, signerAddress string) {
	if err := h.repo.RemoveMember(r.Context(), walletID, signerAddress); err != nil {
		if types.IsNotFound(err) {
			respond.Error(w, "member not found", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("failed to remove member", "error", err)
		respond.Error(w, "failed to remove member", http.StatusInternalServerError, h.logger)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Helpers ---

func (h *WalletHandler) toResponse(c *types.Wallet) WalletResponse {
	return WalletResponse{
		ID:          c.ID,
		Name:        c.Name,
		Description: c.Description,
		OwnerID:     c.OwnerID,
		CreatedAt:   c.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt:   c.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}
