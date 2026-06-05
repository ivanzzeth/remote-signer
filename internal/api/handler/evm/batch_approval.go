package evm

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

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
	RequestIDs []string `json:"request_ids"`
	Approved   bool     `json:"approved"`
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
func (h *BatchApprovalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req BatchApprovalAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("failed to decode batch approval request", "error", err)
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.RequestIDs) == 0 {
		h.writeError(w, "request_ids is required and must not be empty", http.StatusBadRequest)
		return
	}
	if len(req.RequestIDs) > maxBatchApprovalHTTPSize {
		h.writeError(w, fmt.Sprintf("batch size %d exceeds maximum %d", len(req.RequestIDs), maxBatchApprovalHTTPSize), http.StatusBadRequest)
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
		h.writeError(w, "request_ids is required and must not be empty", http.StatusBadRequest)
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
				h.writeError(w, "failed to verify signer ownership", http.StatusInternalServerError)
				return
			}
			ownership, err := h.accessService.GetOwnership(r.Context(), signReq.SignerAddress)
			if err != nil {
				h.logger.Error("failed to get signer ownership", "signer", signReq.SignerAddress, "error", err)
				h.writeError(w, "failed to verify signer ownership", http.StatusInternalServerError)
				return
			}
			if ownership.OwnerID != apiKey.ID {
				h.writeError(w, "not authorized: only the signer owner can approve requests", http.StatusForbidden)
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
		h.writeError(w, err.Error(), http.StatusBadRequest)
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

	h.writeJSON(w, apiResp, http.StatusOK)
}

func (h *BatchApprovalHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

func (h *BatchApprovalHandler) writeError(w http.ResponseWriter, message string, status int) {
	h.writeJSON(w, ErrorResponse{Error: message}, status)
}
