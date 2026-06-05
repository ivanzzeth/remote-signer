package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// MaxBatchApprovalSize caps how many request IDs a single batch-approve call may carry.
const MaxBatchApprovalSize = 200

// ErrApprovalConflict is returned when an approve/reject action conflicts with the
// request's current terminal state (e.g. approving an already-rejected request).
var ErrApprovalConflict = errors.New("approval state conflict")

// BatchApprovalItemResult is the per-request outcome of ProcessBatchApproval.
type BatchApprovalItemResult struct {
	RequestID  types.SignRequestID     `json:"request_id"`
	Status     types.SignRequestStatus `json:"status,omitempty"`
	Signature  []byte                  `json:"-"`
	SignedData []byte                  `json:"-"`
	Message    string                  `json:"message,omitempty"`
	Idempotent bool                    `json:"idempotent"`
	Error      string                  `json:"error,omitempty"`
}

// BatchApprovalSummary aggregates batch-approve outcomes.
type BatchApprovalSummary struct {
	Total      int `json:"total"`
	Succeeded  int `json:"succeeded"`
	Failed     int `json:"failed"`
	Idempotent int `json:"idempotent"`
}

// BatchApprovalResponse is returned by ProcessBatchApproval.
type BatchApprovalResponse struct {
	Results []BatchApprovalItemResult `json:"results"`
	Summary BatchApprovalSummary      `json:"summary"`
}

func approvalResponseFromSignRequest(signReq *types.SignRequest, message string, idempotent bool) *ApprovalResponse {
	msg := message
	if msg == "" && signReq.ErrorMessage != "" {
		msg = signReq.ErrorMessage
	}
	return &ApprovalResponse{
		SignResponse: &SignResponse{
			RequestID:  signReq.ID,
			Status:     signReq.Status,
			Signature:  signReq.Signature,
			SignedData: signReq.SignedData,
			Message:    msg,
		},
		Idempotent: idempotent,
	}
}

// resolveApprovalIdempotency handles replay-safe outcomes before mutating state.
// Returns handled=true when no further work is needed (success or conflict error).
func resolveApprovalIdempotency(signReq *types.SignRequest, approved bool) (*ApprovalResponse, bool, error) {
	switch signReq.Status {
	case types.StatusAuthorizing:
		return nil, false, nil
	case types.StatusRejected:
		if approved {
			return nil, true, fmt.Errorf("%w: cannot approve rejected request", ErrApprovalConflict)
		}
		return approvalResponseFromSignRequest(signReq, "request rejected", true), true, nil
	case types.StatusCompleted:
		if approved {
			return approvalResponseFromSignRequest(signReq, "request already completed", true), true, nil
		}
		return nil, true, fmt.Errorf("%w: cannot reject completed request", ErrApprovalConflict)
	case types.StatusSigning:
		if approved {
			return approvalResponseFromSignRequest(signReq, "request is being signed", true), true, nil
		}
		return nil, true, fmt.Errorf("%w: cannot reject request while signing", ErrApprovalConflict)
	case types.StatusFailed:
		if approved {
			return nil, true, fmt.Errorf("%w: cannot approve failed request", ErrApprovalConflict)
		}
		return nil, true, fmt.Errorf("%w: cannot reject failed request", ErrApprovalConflict)
	default:
		return nil, true, fmt.Errorf("request is not pending approval (status: %s)", signReq.Status)
	}
}

// ProcessBatchApproval applies the same approve/reject decision to many requests in one call.
// Each item is processed independently; partial success is normal. Duplicate IDs in the
// input are de-duplicated while preserving first-seen order.
func (s *SignService) ProcessBatchApproval(ctx context.Context, requestIDs []types.SignRequestID, req *ApprovalRequest) (*BatchApprovalResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("approval request is required")
	}
	if len(requestIDs) == 0 {
		return nil, fmt.Errorf("request_ids is required")
	}
	if len(requestIDs) > MaxBatchApprovalSize {
		return nil, fmt.Errorf("batch size %d exceeds maximum %d", len(requestIDs), MaxBatchApprovalSize)
	}

	seen := make(map[types.SignRequestID]struct{}, len(requestIDs))
	unique := make([]types.SignRequestID, 0, len(requestIDs))
	for _, id := range requestIDs {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}

	resp := &BatchApprovalResponse{
		Results: make([]BatchApprovalItemResult, 0, len(unique)),
		Summary: BatchApprovalSummary{Total: len(unique)},
	}

	for _, id := range unique {
		item := BatchApprovalItemResult{RequestID: id}
		approvalResp, err := s.ProcessApproval(ctx, id, req)
		if err != nil {
			item.Error = err.Error()
			resp.Summary.Failed++
			resp.Results = append(resp.Results, item)
			continue
		}

		item.Status = approvalResp.SignResponse.Status
		item.Signature = approvalResp.SignResponse.Signature
		item.SignedData = approvalResp.SignResponse.SignedData
		item.Message = approvalResp.SignResponse.Message
		item.Idempotent = approvalResp.Idempotent
		resp.Summary.Succeeded++
		if item.Idempotent {
			resp.Summary.Idempotent++
		}
		resp.Results = append(resp.Results, item)
	}

	return resp, nil
}
