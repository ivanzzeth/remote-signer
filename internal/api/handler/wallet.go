package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

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

type createWalletRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type updateWalletRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

type addMemberRequest struct {
	SignerAddress string `json:"signer_address"`
}

type walletResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	OwnerID     string `json:"owner_id"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type walletListResponse struct {
	Wallets []walletResponse `json:"wallets"`
	Total   int              `json:"total"`
	HasMore bool             `json:"has_more"`
}

type memberResponse struct {
	WalletID      string `json:"wallet_id"`
	SignerAddress string `json:"signer_address"`
	AddedAt       string `json:"added_at"`
}

type membersListResponse struct {
	Members []memberResponse `json:"members"`
}

// --- Handler entry points ---

// ServeHTTP handles /api/v1/wallets (list, create).
func (h *WalletHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listWallets(w, r)
	case http.MethodPost:
		h.createWallet(w, r)
	default:
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ServeWalletHTTP handles /api/v1/wallets/{id} and /api/v1/wallets/{id}/members[/{signerAddress}]
func (h *WalletHandler) ServeWalletHTTP(w http.ResponseWriter, r *http.Request) {
	// Parse: /api/v1/wallets/{id}[/members[/{signerAddress}]]
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/wallets/")
	path = strings.TrimSuffix(path, "/")

	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 1 || parts[0] == "" {
		h.writeError(w, "wallet ID required", http.StatusBadRequest)
		return
	}

	walletID := parts[0]

	// Verify the wallet exists and the caller owns it
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	wallet, err := h.repo.Get(r.Context(), walletID)
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "wallet not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to get wallet", "error", err)
		h.writeError(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Only owner or admin can access
	if wallet.OwnerID != apiKey.ID && !apiKey.IsAdmin() {
		h.writeError(w, "wallet not found", http.StatusNotFound)
		return
	}

	if len(parts) == 1 {
		// /api/v1/wallets/{id}
		switch r.Method {
		case http.MethodGet:
			h.getWallet(w, wallet)
		case http.MethodPatch:
			h.updateWallet(w, r, wallet)
		case http.MethodDelete:
			h.deleteWallet(w, r, walletID)
		default:
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	if parts[1] == "members" {
		if len(parts) == 2 {
			// /api/v1/wallets/{id}/members
			switch r.Method {
			case http.MethodGet:
				h.listMembers(w, r, walletID)
			case http.MethodPost:
				h.addMember(w, r, walletID)
			default:
				h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}
		if len(parts) == 3 {
			// /api/v1/wallets/{id}/members/{signerAddress}
			signerAddress := parts[2]
			switch r.Method {
			case http.MethodDelete:
				h.removeMember(w, r, walletID, signerAddress)
			default:
				h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}
	}

	h.writeError(w, "not found", http.StatusNotFound)
}

// --- CRUD operations ---

func (h *WalletHandler) createWallet(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req createWalletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		h.writeError(w, "name is required", http.StatusBadRequest)
		return
	}

	wallet := &types.Wallet{
		Name:        strings.TrimSpace(req.Name),
		Description: req.Description,
		OwnerID:     apiKey.ID,
	}

	if err := h.repo.Create(r.Context(), wallet); err != nil {
		h.logger.Error("failed to create wallet", "error", err)
		h.writeError(w, "failed to create wallet", http.StatusInternalServerError)
		return
	}

	h.writeJSON(w, h.toResponse(wallet), http.StatusCreated)
}

func (h *WalletHandler) listWallets(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
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
		h.writeError(w, "failed to list wallets", http.StatusInternalServerError)
		return
	}

	resp := walletListResponse{
		Wallets: make([]walletResponse, 0, len(result.Wallets)),
		Total:   result.Total,
		HasMore: result.HasMore,
	}
	for i := range result.Wallets {
		resp.Wallets = append(resp.Wallets, h.toResponse(&result.Wallets[i]))
	}

	h.writeJSON(w, resp, http.StatusOK)
}

func (h *WalletHandler) getWallet(w http.ResponseWriter, wallet *types.Wallet) {
	h.writeJSON(w, h.toResponse(wallet), http.StatusOK)
}

func (h *WalletHandler) updateWallet(w http.ResponseWriter, r *http.Request, wallet *types.Wallet) {
	var req updateWalletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			h.writeError(w, "name cannot be empty", http.StatusBadRequest)
			return
		}
		wallet.Name = name
	}
	if req.Description != nil {
		wallet.Description = *req.Description
	}

	if err := h.repo.Update(r.Context(), wallet); err != nil {
		h.logger.Error("failed to update wallet", "error", err)
		h.writeError(w, "failed to update wallet", http.StatusInternalServerError)
		return
	}

	h.writeJSON(w, h.toResponse(wallet), http.StatusOK)
}

func (h *WalletHandler) deleteWallet(w http.ResponseWriter, r *http.Request, walletID string) {
	if err := h.repo.Delete(r.Context(), walletID); err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "wallet not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to delete wallet", "error", err)
		h.writeError(w, "failed to delete wallet", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Member operations ---

func (h *WalletHandler) listMembers(w http.ResponseWriter, r *http.Request, walletID string) {
	members, err := h.repo.ListMembers(r.Context(), walletID)
	if err != nil {
		h.logger.Error("failed to list members", "error", err)
		h.writeError(w, "failed to list members", http.StatusInternalServerError)
		return
	}

	resp := membersListResponse{
		Members: make([]memberResponse, 0, len(members)),
	}
	for _, m := range members {
		resp.Members = append(resp.Members, memberResponse{
			WalletID:      m.WalletID,
			SignerAddress: m.SignerAddress,
			AddedAt:       m.AddedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}

	h.writeJSON(w, resp, http.StatusOK)
}

func (h *WalletHandler) addMember(w http.ResponseWriter, r *http.Request, walletID string) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req addMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.SignerAddress) == "" {
		h.writeError(w, "signer_address is required", http.StatusBadRequest)
		return
	}

	// Verify caller owns or has access to the wallet being added.
	// Admins bypass this check.
	if !apiKey.IsAdmin() {
		authorized, err := h.callerCanAccessWallet(r.Context(), apiKey.ID, req.SignerAddress)
		if err != nil {
			h.logger.Error("failed to verify wallet access", "error", err)
			h.writeError(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !authorized {
			h.writeError(w, "unauthorized to add signer: caller does not own or have access to this signer", http.StatusForbidden)
			return
		}
	}

	member := &types.WalletMember{
		WalletID:      walletID,
		SignerAddress: req.SignerAddress,
	}

	if err := h.repo.AddMember(r.Context(), member); err != nil {
		if strings.Contains(err.Error(), "nested wallets are not allowed") {
			h.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.logger.Error("failed to add member", "error", err)
		h.writeError(w, "failed to add member", http.StatusInternalServerError)
		return
	}

	h.writeJSON(w, memberResponse{
		WalletID:      member.WalletID,
		SignerAddress: member.SignerAddress,
		AddedAt:       member.AddedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}, http.StatusCreated)
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
			h.writeError(w, "member not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to remove member", "error", err)
		h.writeError(w, "failed to remove member", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Helpers ---

func (h *WalletHandler) toResponse(c *types.Wallet) walletResponse {
	return walletResponse{
		ID:          c.ID,
		Name:        c.Name,
		Description: c.Description,
		OwnerID:     c.OwnerID,
		CreatedAt:   c.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt:   c.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

func (h *WalletHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// #nosec G104 -- HTTP response write error cannot be meaningfully handled
	json.NewEncoder(w).Encode(data)
}

func (h *WalletHandler) writeError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// #nosec G104 -- HTTP response write error cannot be meaningfully handled
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
