package evm

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/api/respond"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

const maxBatchApprovalHTTPSize = service.MaxBatchApprovalSize

// BatchApprovalHandler handles POST /api/v1/evm/requests/batch-approve
type BatchApprovalHandler struct {
	signService   service.SignServiceAPI
	accessService *service.SignerAccessService
	logger        *slog.Logger
}

// NewBatchApprovalHandler creates a new batch approval handler.
func NewBatchApprovalHandler(signService service.SignServiceAPI, accessService *service.SignerAccessService, logger *slog.Logger) (*BatchApprovalHandler, error) {
	if signService == nil {
		return nil, fmt.Errorf("sign service is required")
	}
	if accessService == nil {
		return nil, fmt.Errorf("access service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &BatchApprovalHandler{
		signService:   signService,
		accessService: accessService,
		logger:        logger,
	}, nil
}

// BatchApprovalAPIRequest is the JSON body for batch approve/reject.
type BatchApprovalAPIRequest struct {
	// Rejected when absent, empty, or entirely blank after trimming: 400
	// "request_ids is required and must not be empty".
	RequestIDs []string `json:"request_ids" binding:"required"`
	// ⛔ NOT required — same trap as the single-request endpoint: absent means
	// false, which REJECTS every id in the batch. Reported, not fixed.
	Approved bool `json:"approved"`
}

// BatchApprovalItemAPIResult is a single row in the batch response.
type BatchApprovalItemAPIResult struct {
	RequestID  string `json:"request_id"`
	Status     string `json:"status,omitempty"`
	Signature  string `json:"signature,omitempty"`
	SignedData string `json:"signed_data,omitempty"`
	Message    string `json:"message,omitempty"`
	Idempotent bool   `json:"idempotent"`
	Error      string `json:"error,omitempty"`
}

// BatchApprovalAPIResponse is returned for a successful batch HTTP call.
type BatchApprovalAPIResponse struct {
	Results []BatchApprovalItemAPIResult `json:"results"`
	Summary service.BatchApprovalSummary `json:"summary"`
}

// ServeHTTP handles POST /api/v1/evm/requests/batch-approve
//
//	@Summary	Approve or reject several sign requests
//	@Description	⛔ `approved` defaults to FALSE, so a body carrying only `request_ids` REJECTS all of them.
//	@Description	⚠️ Partial success is normal and arrives as 200: per-id outcomes are in `results[].error` and the counts in `summary`. A 4xx here means the batch was refused before any of it ran.
//	@Description	⚠️ Blank ids are dropped silently rather than rejected; a list of only blanks is a 400.
//	@Description	⛔ A caller without approve_request permission must own the signer behind EVERY id — one foreign id fails the whole call with 403 before anything is decided.
//	@Description	⚠️ `idempotent: true` on a row means that request had already been decided and this call did not change it.
//	@Tags	requests
//	@Accept	json
//	@Produce	json
//	@Param	body	body	BatchApprovalAPIRequest	true	"ids and the decision"
//	@Success	200	{object}	BatchApprovalAPIResponse	"read results[].error for per-id outcomes"
//	@Failure	400	{object}	map[string]string	"empty or oversized batch"
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"not the owner of every signer in the batch"
//	@Failure	500	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/requests/batch-approve [post]
func (h *BatchApprovalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// ⛔ No method check: the route is method-scoped
	// (internal/api/module_requests.go) and Go's ServeMux answers 405 before this
	// runs. ⚠️ It moved into that module in S7 along with the five endpoints the
	// "/api/v1/evm/requests/" prefix used to hide; the pattern and permission are
	// unchanged.

	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}

	var req BatchApprovalAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("failed to decode batch approval request", "error", err)
		respond.Error(w, "invalid request body", http.StatusBadRequest, h.logger)
		return
	}

	if len(req.RequestIDs) == 0 {
		respond.Error(w, "request_ids is required and must not be empty", http.StatusBadRequest, h.logger)
		return
	}
	if len(req.RequestIDs) > maxBatchApprovalHTTPSize {
		respond.Error(w, fmt.Sprintf("batch size %d exceeds maximum %d", len(req.RequestIDs), maxBatchApprovalHTTPSize), http.StatusBadRequest, h.logger)
		return
	}

	ids := make([]types.SignRequestID, 0, len(req.RequestIDs))
	for _, raw := range req.RequestIDs {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		ids = append(ids, types.SignRequestID(id))
	}
	if len(ids) == 0 {
		respond.Error(w, "request_ids is required and must not be empty", http.StatusBadRequest, h.logger)
		return
	}

	// Authorization: admin may batch any queue; others must own each signer.
	if !middleware.HasPermission(apiKey.Role, middleware.PermApproveRequest) {
		for _, id := range ids {
			signReq, err := h.signService.GetRequest(r.Context(), id)
			if err != nil {
				if types.IsNotFound(err) {
					continue
				}
				h.logger.Error("failed to get request for batch auth", "request_id", id, "error", err)
				respond.Error(w, "failed to verify signer ownership", http.StatusInternalServerError, h.logger)
				return
			}
			ownership, err := h.accessService.GetOwnership(r.Context(), signReq.SignerAddress)
			if err != nil {
				h.logger.Error("failed to get signer ownership", "signer", signReq.SignerAddress, "error", err)
				respond.Error(w, "failed to verify signer ownership", http.StatusInternalServerError, h.logger)
				return
			}
			if ownership.OwnerID != apiKey.ID {
				respond.Error(w, "not authorized: only the signer owner can approve requests", http.StatusForbidden, h.logger)
				return
			}
		}
	}

	approvalReq := &service.ApprovalRequest{
		Approved:   req.Approved,
		ApprovedBy: apiKey.ID,
	}

	batchResp, err := h.signService.ProcessBatchApproval(r.Context(), ids, approvalReq)
	if err != nil {
		h.logger.Error("failed to process batch approval", "error", err)
		respond.Error(w, err.Error(), http.StatusBadRequest, h.logger)
		return
	}

	apiResp := BatchApprovalAPIResponse{
		Results: make([]BatchApprovalItemAPIResult, 0, len(batchResp.Results)),
		Summary: batchResp.Summary,
	}
	for _, item := range batchResp.Results {
		row := BatchApprovalItemAPIResult{
			RequestID:  string(item.RequestID),
			Status:     string(item.Status),
			Message:    item.Message,
			Idempotent: item.Idempotent,
			Error:      item.Error,
		}
		if len(item.Signature) > 0 {
			row.Signature = fmt.Sprintf("0x%x", item.Signature)
		}
		if len(item.SignedData) > 0 {
			row.SignedData = fmt.Sprintf("0x%x", item.SignedData)
		}
		apiResp.Results = append(apiResp.Results, row)
	}

	respond.JSON(w, apiResp, http.StatusOK, h.logger)
}
