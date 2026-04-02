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

// CollectionHandler handles wallet collection CRUD endpoints.
type CollectionHandler struct {
	repo          storage.CollectionRepository
	ownershipRepo storage.SignerOwnershipRepository
	accessRepo    storage.SignerAccessRepository
	logger        *slog.Logger
}

// NewCollectionHandler creates a new collection handler.
func NewCollectionHandler(repo storage.CollectionRepository, ownershipRepo storage.SignerOwnershipRepository, accessRepo storage.SignerAccessRepository, logger *slog.Logger) (*CollectionHandler, error) {
	if repo == nil {
		return nil, fmt.Errorf("collection repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &CollectionHandler{
		repo:          repo,
		ownershipRepo: ownershipRepo,
		accessRepo:    accessRepo,
		logger:        logger,
	}, nil
}

// --- Request/Response types ---

type createCollectionRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type updateCollectionRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

type addMemberRequest struct {
	WalletID string `json:"wallet_id"`
}

type collectionResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	OwnerID     string `json:"owner_id"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type collectionListResponse struct {
	Collections []collectionResponse `json:"collections"`
	Total       int                  `json:"total"`
	HasMore     bool                 `json:"has_more"`
}

type memberResponse struct {
	CollectionID string `json:"collection_id"`
	WalletID     string `json:"wallet_id"`
	AddedAt      string `json:"added_at"`
}

type membersListResponse struct {
	Members []memberResponse `json:"members"`
}

// --- Handler entry points ---

// ServeHTTP handles /api/v1/collections (list, create).
func (h *CollectionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listCollections(w, r)
	case http.MethodPost:
		h.createCollection(w, r)
	default:
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ServeCollectionHTTP handles /api/v1/collections/{id} and /api/v1/collections/{id}/members[/{walletID}]
func (h *CollectionHandler) ServeCollectionHTTP(w http.ResponseWriter, r *http.Request) {
	// Parse: /api/v1/collections/{id}[/members[/{walletID}]]
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/collections/")
	path = strings.TrimSuffix(path, "/")

	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 1 || parts[0] == "" {
		h.writeError(w, "collection ID required", http.StatusBadRequest)
		return
	}

	collectionID := parts[0]

	// Verify the collection exists and the caller owns it
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	collection, err := h.repo.Get(r.Context(), collectionID)
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "collection not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to get collection", "error", err)
		h.writeError(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Only owner or admin can access
	if collection.OwnerID != apiKey.ID && !apiKey.IsAdmin() {
		h.writeError(w, "collection not found", http.StatusNotFound)
		return
	}

	if len(parts) == 1 {
		// /api/v1/collections/{id}
		switch r.Method {
		case http.MethodGet:
			h.getCollection(w, collection)
		case http.MethodPatch:
			h.updateCollection(w, r, collection)
		case http.MethodDelete:
			h.deleteCollection(w, r, collectionID)
		default:
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	if parts[1] == "members" {
		if len(parts) == 2 {
			// /api/v1/collections/{id}/members
			switch r.Method {
			case http.MethodGet:
				h.listMembers(w, r, collectionID)
			case http.MethodPost:
				h.addMember(w, r, collectionID)
			default:
				h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}
		if len(parts) == 3 {
			// /api/v1/collections/{id}/members/{walletID}
			walletID := parts[2]
			switch r.Method {
			case http.MethodDelete:
				h.removeMember(w, r, collectionID, walletID)
			default:
				h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}
	}

	h.writeError(w, "not found", http.StatusNotFound)
}

// --- CRUD operations ---

func (h *CollectionHandler) createCollection(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req createCollectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		h.writeError(w, "name is required", http.StatusBadRequest)
		return
	}

	collection := &types.WalletCollection{
		Name:        strings.TrimSpace(req.Name),
		Description: req.Description,
		OwnerID:     apiKey.ID,
	}

	if err := h.repo.Create(r.Context(), collection); err != nil {
		h.logger.Error("failed to create collection", "error", err)
		h.writeError(w, "failed to create collection", http.StatusInternalServerError)
		return
	}

	h.writeJSON(w, h.toResponse(collection), http.StatusCreated)
}

func (h *CollectionHandler) listCollections(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	filter := types.CollectionFilter{
		OwnerID: apiKey.ID,
	}
	// Admin can see all collections
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
		h.logger.Error("failed to list collections", "error", err)
		h.writeError(w, "failed to list collections", http.StatusInternalServerError)
		return
	}

	resp := collectionListResponse{
		Collections: make([]collectionResponse, 0, len(result.Collections)),
		Total:       result.Total,
		HasMore:     result.HasMore,
	}
	for i := range result.Collections {
		resp.Collections = append(resp.Collections, h.toResponse(&result.Collections[i]))
	}

	h.writeJSON(w, resp, http.StatusOK)
}

func (h *CollectionHandler) getCollection(w http.ResponseWriter, collection *types.WalletCollection) {
	h.writeJSON(w, h.toResponse(collection), http.StatusOK)
}

func (h *CollectionHandler) updateCollection(w http.ResponseWriter, r *http.Request, collection *types.WalletCollection) {
	var req updateCollectionRequest
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
		collection.Name = name
	}
	if req.Description != nil {
		collection.Description = *req.Description
	}

	if err := h.repo.Update(r.Context(), collection); err != nil {
		h.logger.Error("failed to update collection", "error", err)
		h.writeError(w, "failed to update collection", http.StatusInternalServerError)
		return
	}

	h.writeJSON(w, h.toResponse(collection), http.StatusOK)
}

func (h *CollectionHandler) deleteCollection(w http.ResponseWriter, r *http.Request, collectionID string) {
	if err := h.repo.Delete(r.Context(), collectionID); err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "collection not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to delete collection", "error", err)
		h.writeError(w, "failed to delete collection", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Member operations ---

func (h *CollectionHandler) listMembers(w http.ResponseWriter, r *http.Request, collectionID string) {
	members, err := h.repo.ListMembers(r.Context(), collectionID)
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
			CollectionID: m.CollectionID,
			WalletID:     m.WalletID,
			AddedAt:      m.AddedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}

	h.writeJSON(w, resp, http.StatusOK)
}

func (h *CollectionHandler) addMember(w http.ResponseWriter, r *http.Request, collectionID string) {
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

	if strings.TrimSpace(req.WalletID) == "" {
		h.writeError(w, "wallet_id is required", http.StatusBadRequest)
		return
	}

	// Verify caller owns or has access to the wallet being added.
	// Admins bypass this check.
	if !apiKey.IsAdmin() {
		authorized, err := h.callerCanAccessWallet(r.Context(), apiKey.ID, req.WalletID)
		if err != nil {
			h.logger.Error("failed to verify wallet access", "error", err)
			h.writeError(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !authorized {
			h.writeError(w, "unauthorized to add wallet: caller does not own or have access to this wallet", http.StatusForbidden)
			return
		}
	}

	member := &types.CollectionMember{
		CollectionID: collectionID,
		WalletID:     req.WalletID,
	}

	if err := h.repo.AddMember(r.Context(), member); err != nil {
		if strings.Contains(err.Error(), "nested collections are not allowed") {
			h.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.logger.Error("failed to add member", "error", err)
		h.writeError(w, "failed to add member", http.StatusInternalServerError)
		return
	}

	h.writeJSON(w, memberResponse{
		CollectionID: member.CollectionID,
		WalletID:     member.WalletID,
		AddedAt:      member.AddedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}, http.StatusCreated)
}

// callerCanAccessWallet checks whether the caller owns or has access to the given wallet address.
func (h *CollectionHandler) callerCanAccessWallet(ctx context.Context, apiKeyID, walletID string) (bool, error) {
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

func (h *CollectionHandler) removeMember(w http.ResponseWriter, r *http.Request, collectionID, walletID string) {
	if err := h.repo.RemoveMember(r.Context(), collectionID, walletID); err != nil {
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

func (h *CollectionHandler) toResponse(c *types.WalletCollection) collectionResponse {
	return collectionResponse{
		ID:          c.ID,
		Name:        c.Name,
		Description: c.Description,
		OwnerID:     c.OwnerID,
		CreatedAt:   c.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt:   c.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

func (h *CollectionHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// #nosec G104 -- HTTP response write error cannot be meaningfully handled
	json.NewEncoder(w).Encode(data)
}

func (h *CollectionHandler) writeError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// #nosec G104 -- HTTP response write error cannot be meaningfully handled
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
