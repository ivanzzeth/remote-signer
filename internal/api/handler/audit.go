package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/validate"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// AuditHandler handles audit log endpoints
type AuditHandler struct {
	auditRepo storage.AuditRepository
	logger    *slog.Logger
}

// NewAuditHandler creates a new audit handler
func NewAuditHandler(auditRepo storage.AuditRepository, logger *slog.Logger) (*AuditHandler, error) {
	if auditRepo == nil {
		return nil, fmt.Errorf("audit repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &AuditHandler{
		auditRepo: auditRepo,
		logger:    logger,
	}, nil
}

// AuditRecordResponse represents an audit record in API responses
type AuditRecordResponse struct {
	ID            string          `json:"id"`
	EventType     string          `json:"event_type"`
	Severity      string          `json:"severity"`
	Timestamp     string          `json:"timestamp"`
	APIKeyID      string          `json:"api_key_id,omitempty"`
	ActorAddress  string          `json:"actor_address,omitempty"`
	SignRequestID *string         `json:"sign_request_id,omitempty"`
	SignerAddress *string         `json:"signer_address,omitempty"`
	ChainType     *string         `json:"chain_type,omitempty"`
	ChainID       *string         `json:"chain_id,omitempty"`
	RuleID        *string         `json:"rule_id,omitempty"`
	Details       json.RawMessage `json:"details,omitempty"`
	ErrorMessage  string          `json:"error_message,omitempty"`
	RequestMethod string          `json:"request_method,omitempty"`
	RequestPath   string          `json:"request_path,omitempty"`
}

// ListAuditResponse represents the response for listing audit records
type ListAuditResponse struct {
	Records      []AuditRecordResponse `json:"records"`
	Total        int                   `json:"total"`
	NextCursor   *string               `json:"next_cursor,omitempty"`
	NextCursorID *string               `json:"next_cursor_id,omitempty"`
	HasMore      bool                  `json:"has_more"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// ServeHTTP handles GET /api/v1/audit
func (h *AuditHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get API key from context (for auth verification)
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodGet {
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.listAuditRecords(w, r)
}

func (h *AuditHandler) listAuditRecords(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// Build filter
	filter := storage.AuditFilter{
		Limit: 30, // default limit
	}

	// Parse query parameters (strict: invalid values return 400)
	if eventType := query.Get("event_type"); eventType != "" {
		if !validate.IsValidAuditEventType(eventType) {
			h.writeError(w, "invalid event_type filter", http.StatusBadRequest)
			return
		}
		et := types.AuditEventType(eventType)
		filter.EventType = &et
	}
	if apiKeyID := query.Get("api_key_id"); apiKeyID != "" {
		filter.APIKeyID = &apiKeyID
	}
	if chainType := query.Get("chain_type"); chainType != "" {
		if !validate.IsValidChainType(chainType) {
			h.writeError(w, "invalid chain_type filter", http.StatusBadRequest)
			return
		}
		ct := types.ChainType(chainType)
		filter.ChainType = &ct
	}
	if startTimeStr := query.Get("start_time"); startTimeStr != "" {
		startTime, err := time.Parse(time.RFC3339, startTimeStr)
		if err != nil {
			h.writeError(w, "invalid start_time: must be RFC3339", http.StatusBadRequest)
			return
		}
		filter.StartTime = &startTime
	}
	if endTimeStr := query.Get("end_time"); endTimeStr != "" {
		endTime, err := time.Parse(time.RFC3339, endTimeStr)
		if err != nil {
			h.writeError(w, "invalid end_time: must be RFC3339", http.StatusBadRequest)
			return
		}
		filter.EndTime = &endTime
	}
	if limitStr := query.Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 100 {
			filter.Limit = limit
		}
	}

	// Parse cursor for pagination
	if cursorStr := query.Get("cursor"); cursorStr != "" {
		cursor, err := time.Parse(time.RFC3339Nano, cursorStr)
		if err != nil {
			h.writeError(w, "invalid cursor: must be RFC3339Nano timestamp", http.StatusBadRequest)
			return
		}
		filter.Cursor = &cursor
	}
	if cursorID := query.Get("cursor_id"); cursorID != "" {
		id := types.AuditID(cursorID)
		filter.CursorID = &id
	}

	// Get total count (without cursor filter)
	countFilter := filter
	countFilter.Cursor = nil
	countFilter.CursorID = nil
	total, err := h.auditRepo.Count(r.Context(), countFilter)
	if err != nil {
		h.logger.Error("failed to count audit records", "error", err)
		h.writeError(w, "failed to count audit records", http.StatusInternalServerError)
		return
	}

	// Fetch one extra to check if there are more
	filter.Limit++
	records, err := h.auditRepo.Query(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to query audit records", "error", err)
		h.writeError(w, "failed to query audit records", http.StatusInternalServerError)
		return
	}

	// Build response
	hasMore := len(records) > filter.Limit-1
	if hasMore {
		records = records[:filter.Limit-1] // Remove the extra item
	}

	resp := ListAuditResponse{
		Records: make([]AuditRecordResponse, 0, len(records)),
		Total:   total,
		HasMore: hasMore,
	}
	for _, record := range records {
		resp.Records = append(resp.Records, h.toAuditRecordResponse(record))
	}

	// Set next cursor if there are more results
	if hasMore && len(records) > 0 {
		lastRecord := records[len(records)-1]
		cursor := lastRecord.Timestamp.Format(time.RFC3339Nano)
		cursorID := string(lastRecord.ID)
		resp.NextCursor = &cursor
		resp.NextCursorID = &cursorID
	}

	h.writeJSON(w, resp, http.StatusOK)
}

func (h *AuditHandler) toAuditRecordResponse(record *types.AuditRecord) AuditRecordResponse {
	resp := AuditRecordResponse{
		ID:            string(record.ID),
		EventType:     string(record.EventType),
		Severity:      string(record.Severity),
		Timestamp:     record.Timestamp.Format(time.RFC3339),
		APIKeyID:      record.APIKeyID,
		ActorAddress:  record.ActorAddress,
		Details:       record.Details,
		ErrorMessage:  record.ErrorMessage,
		RequestMethod: record.RequestMethod,
		RequestPath:   record.RequestPath,
	}

	if record.SignRequestID != nil {
		reqID := string(*record.SignRequestID)
		resp.SignRequestID = &reqID
	}
	if record.SignerAddress != nil {
		resp.SignerAddress = record.SignerAddress
	}
	if record.ChainType != nil {
		ct := string(*record.ChainType)
		resp.ChainType = &ct
	}
	if record.ChainID != nil {
		resp.ChainID = record.ChainID
	}
	if record.RuleID != nil {
		ruleID := string(*record.RuleID)
		resp.RuleID = &ruleID
	}

	return resp
}

func (h *AuditHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

func (h *AuditHandler) writeError(w http.ResponseWriter, message string, status int) {
	h.writeJSON(w, ErrorResponse{Error: message}, status)
}
