package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/respond"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/ivanzzeth/remote-signer/internal/validate"
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
//
//	@Summary		Query the audit log
//	@Description	Cursor-paginated. Follow `next_cursor` **and** `next_cursor_id` together — the cursor is a RFC3339Nano timestamp and ties are broken by id, so sending one without the other skips or repeats rows.
//	@Description	⚠️ Filter validation is asymmetric and that is the handler's actual behaviour, not an oversight in this description: `event_type`, `severity`, `signer_address`, `chain_type`, `chain_id`, `exclude_event_type`, `start_time`, `end_time` and `cursor` answer 400 when malformed, while `limit` is silently ignored unless it is in 1..100 (the default 30 stands), and `api_key_id`, `sign_request_id` and `cursor_id` are taken as given with no validation at all.
//	@Description	⚠️ `total` is counted with the cursor filters removed, so it is the size of the whole filtered set rather than of the page.
//	@Tags			audit
//	@Produce		json
//	@Param			event_type			query		string	false	"exact event type; 400 if unknown"
//	@Param			exclude_event_type	query		string	false	"comma-separated event types to omit; 400 if any is unknown"
//	@Param			severity			query		string	false	"info, warning or critical"
//	@Param			api_key_id			query		string	false	"records produced by this api key"
//	@Param			signer_address		query		string	false	"0x + 40 hex"
//	@Param			sign_request_id		query		string	false	"records belonging to one sign request"
//	@Param			chain_type			query		string	false	"chain family; 400 if unknown"
//	@Param			chain_id			query		string	false	"positive decimal integer"
//	@Param			start_time			query		string	false	"RFC3339 lower bound"
//	@Param			end_time			query		string	false	"RFC3339 upper bound"
//	@Param			limit				query		int		false	"1..100; anything else leaves the default 30 in place"
//	@Param			cursor				query		string	false	"RFC3339Nano timestamp from next_cursor"
//	@Param			cursor_id			query		string	false	"audit id from next_cursor_id; pair it with cursor"
//	@Success		200					{object}	ListAuditResponse
//	@Failure		400					{object}	map[string]string
//	@Failure		401					{object}	map[string]string
//	@Failure		500					{object}	map[string]string
//	@Security		Ed25519Signature
//	@Router			/api/v1/audit [get]
func (h *AuditHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get API key from context (for auth verification)
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}

	// ⛔ No method check: the route is method-scoped (see setupRoutes) and Go's
	// ServeMux answers 405 for anything else before this runs.

	h.listAuditRecords(w, r)
}

// ServeRequestHTTP handles GET /api/v1/audit/requests/{requestID}
func (h *AuditHandler) ServeRequestHTTP(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}

	// ⛔ No method check: the route is method-scoped (see setupRoutes) and Go's
	// ServeMux answers 405 for anything else before this runs.

	// Extract request ID from path: /api/v1/audit/requests/{requestID}
	requestID := strings.TrimPrefix(r.URL.Path, "/api/v1/audit/requests/")
	if requestID == "" {
		respond.Error(w, "request_id is required", http.StatusBadRequest, h.logger)
		return
	}

	reqID := types.SignRequestID(requestID)
	records, err := h.auditRepo.GetByRequestID(r.Context(), reqID)
	if err != nil {
		h.logger.Error("failed to get audit records by request ID", "error", err, "request_id", requestID)
		respond.Error(w, "failed to get audit records", http.StatusInternalServerError, h.logger)
		return
	}

	resp := ListAuditResponse{
		Records: make([]AuditRecordResponse, 0, len(records)),
		Total:   len(records),
		HasMore: false,
	}
	for _, record := range records {
		resp.Records = append(resp.Records, h.toAuditRecordResponse(record))
	}

	respond.JSON(w, resp, http.StatusOK, h.logger)
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
			respond.Error(w, "invalid event_type filter", http.StatusBadRequest, h.logger)
			return
		}
		et := types.AuditEventType(eventType)
		filter.EventType = &et
	}
	if severity := query.Get("severity"); severity != "" {
		if !validate.IsValidAuditSeverity(severity) {
			respond.Error(w, "invalid severity filter: must be one of info, warning, critical", http.StatusBadRequest, h.logger)
			return
		}
		sev := types.AuditSeverity(severity)
		filter.Severity = &sev
	}
	if apiKeyID := query.Get("api_key_id"); apiKeyID != "" {
		filter.APIKeyID = &apiKeyID
	}
	if signerAddress := query.Get("signer_address"); signerAddress != "" {
		if !validate.IsValidEthereumAddress(signerAddress) {
			respond.Error(w, "invalid signer_address: must be 0x followed by 40 hex characters", http.StatusBadRequest, h.logger)
			return
		}
		filter.SignerAddress = &signerAddress
	}
	if signRequestID := query.Get("sign_request_id"); signRequestID != "" {
		reqID := types.SignRequestID(signRequestID)
		filter.RequestID = &reqID
	}
	if chainType := query.Get("chain_type"); chainType != "" {
		if !validate.IsValidChainType(chainType) {
			respond.Error(w, "invalid chain_type filter", http.StatusBadRequest, h.logger)
			return
		}
		ct := types.ChainType(chainType)
		filter.ChainType = &ct
	}
	if chainID := query.Get("chain_id"); chainID != "" {
		if _, err := strconv.ParseUint(chainID, 10, 64); err != nil {
			respond.Error(w, "invalid chain_id: must be a positive decimal integer", http.StatusBadRequest, h.logger)
			return
		}
		filter.ChainID = &chainID
	}
	if excludeStr := query.Get("exclude_event_type"); excludeStr != "" {
		for _, part := range strings.Split(excludeStr, ",") {
			et := strings.TrimSpace(part)
			if et == "" {
				continue
			}
			if !validate.IsValidAuditEventType(et) {
				respond.Error(w, fmt.Sprintf("invalid exclude_event_type: %s", et), http.StatusBadRequest, h.logger)
				return
			}
			filter.ExcludeEventTypes = append(filter.ExcludeEventTypes, types.AuditEventType(et))
		}
	}
	if startTimeStr := query.Get("start_time"); startTimeStr != "" {
		startTime, err := time.Parse(time.RFC3339, startTimeStr)
		if err != nil {
			respond.Error(w, "invalid start_time: must be RFC3339", http.StatusBadRequest, h.logger)
			return
		}
		filter.StartTime = &startTime
	}
	if endTimeStr := query.Get("end_time"); endTimeStr != "" {
		endTime, err := time.Parse(time.RFC3339, endTimeStr)
		if err != nil {
			respond.Error(w, "invalid end_time: must be RFC3339", http.StatusBadRequest, h.logger)
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
			respond.Error(w, "invalid cursor: must be RFC3339Nano timestamp", http.StatusBadRequest, h.logger)
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
		respond.Error(w, "failed to count audit records", http.StatusInternalServerError, h.logger)
		return
	}

	// Fetch one extra to check if there are more
	filter.Limit++
	records, err := h.auditRepo.Query(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to query audit records", "error", err)
		respond.Error(w, "failed to query audit records", http.StatusInternalServerError, h.logger)
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

	respond.JSON(w, resp, http.StatusOK, h.logger)
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
