package evm

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// validStatuses defines the known sign request statuses
var validStatuses = map[types.SignRequestStatus]bool{
	types.StatusPending:     true,
	types.StatusAuthorizing: true,
	types.StatusSigning:     true,
	types.StatusCompleted:   true,
	types.StatusRejected:    true,
	types.StatusFailed:      true,
}

// RequestHandler handles request status queries
type RequestHandler struct {
	signService *service.SignService
	logger      *slog.Logger
}

// NewRequestHandler creates a new request handler
func NewRequestHandler(signService *service.SignService, logger *slog.Logger) (*RequestHandler, error) {
	if signService == nil {
		return nil, fmt.Errorf("sign service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &RequestHandler{
		signService: signService,
		logger:      logger,
	}, nil
}

// RequestDetailResponse represents a detailed request response (GET /api/v1/evm/requests/{id}).
// Payload is included so operators can inspect full request content for debugging and rule analysis.
type RequestDetailResponse struct {
	ID             string          `json:"id"`
	APIKeyID       string          `json:"api_key_id"`
	ChainType      string          `json:"chain_type"`
	ChainID        string          `json:"chain_id"`
	SignerAddress  string          `json:"signer_address"`
	SignType       string          `json:"sign_type"`
	Status         string          `json:"status"`
	Payload        json.RawMessage `json:"payload,omitempty"`
	Signature      string          `json:"signature,omitempty"`
	SignedData     string          `json:"signed_data,omitempty"`
	ErrorMessage   string          `json:"error_message,omitempty"`
	RuleMatchedID  *string         `json:"rule_matched_id,omitempty"`
	ApprovedBy     *string         `json:"approved_by,omitempty"`
	CreatedAt      string          `json:"created_at"`
	UpdatedAt      string          `json:"updated_at"`
	CompletedAt    *string         `json:"completed_at,omitempty"`
}

// ListRequestsResponse represents the response for listing requests
type ListRequestsResponse struct {
	Requests     []RequestDetailResponse `json:"requests"`
	Total        int                     `json:"total"`
	NextCursor   *string                 `json:"next_cursor,omitempty"`
	NextCursorID *string                 `json:"next_cursor_id,omitempty"`
	HasMore      bool                    `json:"has_more"`
}

// ServeHTTP handles GET /api/v1/evm/requests/{id}
func (h *RequestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get API key from context
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract request ID from path
	// Expected: /api/v1/evm/requests/{id}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		h.writeError(w, "invalid path", http.StatusBadRequest)
		return
	}
	requestID := parts[len(parts)-1]

	if r.Method == http.MethodGet {
		h.getRequest(w, r, apiKey, requestID)
		return
	}

	h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (h *RequestHandler) getRequest(w http.ResponseWriter, r *http.Request, apiKey *types.APIKey, requestID string) {
	req, err := h.signService.GetRequest(r.Context(), types.SignRequestID(requestID))
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "request not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to get request", "error", err)
		h.writeError(w, "failed to get request", http.StatusInternalServerError)
		return
	}

	// Non-admin may only view requests created with their API key; admin may view any
	if !apiKey.Admin && req.APIKeyID != apiKey.ID {
		h.writeError(w, "not authorized to view this request", http.StatusForbidden)
		return
	}

	h.writeJSON(w, h.toDetailResponse(req, true), http.StatusOK)
}

// ListHandler handles listing requests
type ListHandler struct {
	signService *service.SignService
	logger      *slog.Logger
}

// NewListHandler creates a new list handler
func NewListHandler(signService *service.SignService, logger *slog.Logger) (*ListHandler, error) {
	if signService == nil {
		return nil, fmt.Errorf("sign service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &ListHandler{
		signService: signService,
		logger:      logger,
	}, nil
}

// ServeHTTP handles GET /api/v1/evm/requests
func (h *ListHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get API key from context
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Build filter: non-admin keys only see their own requests; admin sees all
	filter := storage.RequestFilter{
		Limit: 20, // default limit
	}
	if !apiKey.Admin {
		filter.APIKeyID = &apiKey.ID
	}

	// Parse query parameters
	query := r.URL.Query()
	if signerAddress := query.Get("signer_address"); signerAddress != "" {
		filter.SignerAddress = &signerAddress
	}
	if chainID := query.Get("chain_id"); chainID != "" {
		filter.ChainID = &chainID
	}
	if statusStr := query.Get("status"); statusStr != "" {
		statuses := strings.Split(statusStr, ",")
		for _, s := range statuses {
			status := types.SignRequestStatus(strings.TrimSpace(s))
			if !validStatuses[status] {
				h.writeError(w, fmt.Sprintf("invalid status filter: %s", s), http.StatusBadRequest)
				return
			}
			filter.Status = append(filter.Status, status)
		}
	}

	// Parse limit
	if limitStr := query.Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 100 {
			filter.Limit = limit
		}
	}

	// Parse cursor for pagination
	if cursorStr := query.Get("cursor"); cursorStr != "" {
		cursor, err := time.Parse(time.RFC3339Nano, cursorStr)
		if err != nil {
			h.writeError(w, "invalid cursor: must be RFC3339 timestamp", http.StatusBadRequest)
			return
		}
		filter.Cursor = &cursor
	}
	if cursorID := query.Get("cursor_id"); cursorID != "" {
		id := types.SignRequestID(cursorID)
		filter.CursorID = &id
	}

	// Add chain type filter for EVM
	chainType := types.ChainTypeEVM
	filter.ChainType = &chainType

	// Get total count (without cursor filter)
	countFilter := filter
	countFilter.Cursor = nil
	countFilter.CursorID = nil
	total, err := h.signService.CountRequests(r.Context(), countFilter)
	if err != nil {
		h.logger.Error("failed to count requests", "error", err)
		h.writeError(w, "failed to count requests", http.StatusInternalServerError)
		return
	}

	// Fetch one extra to check if there are more
	filter.Limit++
	requests, err := h.signService.ListRequests(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list requests", "error", err)
		h.writeError(w, "failed to list requests", http.StatusInternalServerError)
		return
	}

	// Build response
	hasMore := len(requests) > filter.Limit-1
	if hasMore {
		requests = requests[:filter.Limit-1] // Remove the extra item
	}

	resp := ListRequestsResponse{
		Requests: make([]RequestDetailResponse, 0, len(requests)),
		Total:    total,
		HasMore:  hasMore,
	}
	for _, req := range requests {
		resp.Requests = append(resp.Requests, toDetailResponse(req, false))
	}

	// Set next cursor if there are more results
	if hasMore && len(requests) > 0 {
		lastReq := requests[len(requests)-1]
		cursor := lastReq.CreatedAt.Format(time.RFC3339Nano)
		cursorID := string(lastReq.ID)
		resp.NextCursor = &cursor
		resp.NextCursorID = &cursorID
	}

	h.writeJSON(w, resp, http.StatusOK)
}

func (h *RequestHandler) toDetailResponse(req *types.SignRequest, includePayload bool) RequestDetailResponse {
	return toDetailResponse(req, includePayload)
}

func toDetailResponse(req *types.SignRequest, includePayload bool) RequestDetailResponse {
	resp := RequestDetailResponse{
		ID:            string(req.ID),
		APIKeyID:      req.APIKeyID,
		ChainType:     string(req.ChainType),
		ChainID:       req.ChainID,
		SignerAddress: req.SignerAddress,
		SignType:      req.SignType,
		Status:        string(req.Status),
		ErrorMessage:  req.ErrorMessage,
		RuleMatchedID: req.RuleMatchedID,
		ApprovedBy:    req.ApprovedBy,
		CreatedAt:     req.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:     req.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	if includePayload && len(req.Payload) > 0 {
		resp.Payload = req.Payload
	}
	if len(req.Signature) > 0 {
		resp.Signature = fmt.Sprintf("0x%x", req.Signature)
	}
	if len(req.SignedData) > 0 {
		resp.SignedData = fmt.Sprintf("0x%x", req.SignedData)
	}
	if req.CompletedAt != nil {
		completedAt := req.CompletedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.CompletedAt = &completedAt
	}
	return resp
}

func (h *RequestHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

func (h *RequestHandler) writeError(w http.ResponseWriter, message string, status int) {
	h.writeJSON(w, ErrorResponse{Error: message}, status)
}

func (h *ListHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

func (h *ListHandler) writeError(w http.ResponseWriter, message string, status int) {
	h.writeJSON(w, ErrorResponse{Error: message}, status)
}
