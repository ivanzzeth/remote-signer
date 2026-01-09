package statemachine

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

/*
State Transitions:

pending → authorizing  (on validation pass)
pending → rejected     (on validation fail)

authorizing → signing  (on rule match OR manual approval)
authorizing → rejected (on manual rejection)

signing → completed    (on sign success)
signing → failed       (on sign error)
*/

// StateMachine manages the lifecycle of sign requests
type StateMachine struct {
	requestRepo storage.RequestRepository
	auditRepo   storage.AuditRepository
	logger      *slog.Logger
}

// NewStateMachine creates a new state machine
func NewStateMachine(requestRepo storage.RequestRepository, auditRepo storage.AuditRepository, logger *slog.Logger) (*StateMachine, error) {
	if requestRepo == nil {
		return nil, fmt.Errorf("request repository is required")
	}
	if auditRepo == nil {
		return nil, fmt.Errorf("audit repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &StateMachine{
		requestRepo: requestRepo,
		auditRepo:   auditRepo,
		logger:      logger,
	}, nil
}

// TransitionResult contains the result of a state transition
type TransitionResult struct {
	PreviousStatus types.SignRequestStatus
	NewStatus      types.SignRequestStatus
	Reason         string
}

// ValidateAndStartAuthorizing transitions from pending to authorizing
func (sm *StateMachine) ValidateAndStartAuthorizing(ctx context.Context, reqID types.SignRequestID) (*TransitionResult, error) {
	return sm.transition(ctx, reqID, types.StatusPending, types.StatusAuthorizing, "validation passed")
}

// RejectOnValidation transitions from pending to rejected due to validation failure
func (sm *StateMachine) RejectOnValidation(ctx context.Context, reqID types.SignRequestID, reason string) (*TransitionResult, error) {
	return sm.transition(ctx, reqID, types.StatusPending, types.StatusRejected, reason)
}

// ApproveForSigning transitions from authorizing to signing (after rule match or manual approval)
func (sm *StateMachine) ApproveForSigning(ctx context.Context, reqID types.SignRequestID, ruleID *types.RuleID, approvedBy *string, reason string) (*TransitionResult, error) {
	req, err := sm.requestRepo.Get(ctx, reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to get request: %w", err)
	}

	if req.Status != types.StatusAuthorizing {
		return nil, fmt.Errorf("invalid state transition: cannot move from %s to %s", req.Status, types.StatusSigning)
	}

	now := time.Now()
	req.Status = types.StatusSigning
	req.RuleMatchedID = nil
	if ruleID != nil {
		ruleIDStr := string(*ruleID)
		req.RuleMatchedID = &ruleIDStr
	}
	req.ApprovedBy = approvedBy
	req.ApprovedAt = &now
	req.UpdatedAt = now

	if err := sm.requestRepo.Update(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to update request: %w", err)
	}

	// Log audit event
	eventType := types.AuditEventTypeRuleMatched
	if approvedBy != nil {
		eventType = types.AuditEventTypeApprovalGranted
	}
	sm.logAudit(ctx, req, eventType, reason)

	sm.logger.Info("request approved for signing",
		"request_id", reqID,
		"rule_id", ruleID,
		"approved_by", approvedBy,
	)

	return &TransitionResult{
		PreviousStatus: types.StatusAuthorizing,
		NewStatus:      types.StatusSigning,
		Reason:         reason,
	}, nil
}

// RejectOnAuthorization transitions from authorizing to rejected
func (sm *StateMachine) RejectOnAuthorization(ctx context.Context, reqID types.SignRequestID, rejectedBy string, reason string) (*TransitionResult, error) {
	req, err := sm.requestRepo.Get(ctx, reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to get request: %w", err)
	}

	if req.Status != types.StatusAuthorizing {
		return nil, fmt.Errorf("invalid state transition: cannot reject from %s", req.Status)
	}

	now := time.Now()
	req.Status = types.StatusRejected
	req.ErrorMessage = reason
	req.UpdatedAt = now
	req.CompletedAt = &now

	if err := sm.requestRepo.Update(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to update request: %w", err)
	}

	sm.logAudit(ctx, req, types.AuditEventTypeApprovalDenied, reason)

	sm.logger.Info("request rejected",
		"request_id", reqID,
		"rejected_by", rejectedBy,
		"reason", reason,
	)

	return &TransitionResult{
		PreviousStatus: types.StatusAuthorizing,
		NewStatus:      types.StatusRejected,
		Reason:         reason,
	}, nil
}

// CompleteSign transitions from signing to completed
func (sm *StateMachine) CompleteSign(ctx context.Context, reqID types.SignRequestID, signature []byte, signedData []byte) (*TransitionResult, error) {
	req, err := sm.requestRepo.Get(ctx, reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to get request: %w", err)
	}

	if req.Status != types.StatusSigning {
		return nil, fmt.Errorf("invalid state transition: cannot complete from %s", req.Status)
	}

	now := time.Now()
	req.Status = types.StatusCompleted
	req.Signature = signature
	req.SignedData = signedData
	req.UpdatedAt = now
	req.CompletedAt = &now

	if err := sm.requestRepo.Update(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to update request: %w", err)
	}

	sm.logAudit(ctx, req, types.AuditEventTypeSignComplete, "signing completed successfully")

	sm.logger.Info("request completed",
		"request_id", reqID,
		"signature_len", len(signature),
	)

	return &TransitionResult{
		PreviousStatus: types.StatusSigning,
		NewStatus:      types.StatusCompleted,
		Reason:         "signing completed successfully",
	}, nil
}

// FailSign transitions from signing to failed
func (sm *StateMachine) FailSign(ctx context.Context, reqID types.SignRequestID, errorMsg string) (*TransitionResult, error) {
	req, err := sm.requestRepo.Get(ctx, reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to get request: %w", err)
	}

	if req.Status != types.StatusSigning {
		return nil, fmt.Errorf("invalid state transition: cannot fail from %s", req.Status)
	}

	now := time.Now()
	req.Status = types.StatusFailed
	req.ErrorMessage = errorMsg
	req.UpdatedAt = now
	req.CompletedAt = &now

	if err := sm.requestRepo.Update(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to update request: %w", err)
	}

	sm.logAudit(ctx, req, types.AuditEventTypeSignFailed, errorMsg)

	sm.logger.Error("request failed",
		"request_id", reqID,
		"error", errorMsg,
	)

	return &TransitionResult{
		PreviousStatus: types.StatusSigning,
		NewStatus:      types.StatusFailed,
		Reason:         errorMsg,
	}, nil
}

// transition performs a generic state transition
func (sm *StateMachine) transition(ctx context.Context, reqID types.SignRequestID, fromStatus, toStatus types.SignRequestStatus, reason string) (*TransitionResult, error) {
	req, err := sm.requestRepo.Get(ctx, reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to get request: %w", err)
	}

	if req.Status != fromStatus {
		return nil, fmt.Errorf("invalid state transition: expected %s, got %s", fromStatus, req.Status)
	}

	now := time.Now()
	req.Status = toStatus
	req.UpdatedAt = now
	if toStatus == types.StatusRejected || toStatus == types.StatusCompleted || toStatus == types.StatusFailed {
		req.CompletedAt = &now
	}
	if toStatus == types.StatusRejected || toStatus == types.StatusFailed {
		req.ErrorMessage = reason
	}

	if err := sm.requestRepo.Update(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to update request: %w", err)
	}

	sm.logger.Debug("state transition",
		"request_id", reqID,
		"from", fromStatus,
		"to", toStatus,
		"reason", reason,
	)

	return &TransitionResult{
		PreviousStatus: fromStatus,
		NewStatus:      toStatus,
		Reason:         reason,
	}, nil
}

// logAudit creates an audit log entry for a state transition
func (sm *StateMachine) logAudit(ctx context.Context, req *types.SignRequest, eventType types.AuditEventType, details string) {
	record := &types.AuditRecord{
		ID:            types.AuditID(uuid.New().String()),
		EventType:     eventType,
		Severity:      types.AuditSeverityInfo,
		Timestamp:     time.Now(),
		APIKeyID:      req.APIKeyID,
		SignRequestID: &req.ID,
		SignerAddress: &req.SignerAddress,
		ChainType:     &req.ChainType,
		ChainID:       &req.ChainID,
		ErrorMessage:  details,
	}

	if err := sm.auditRepo.Log(ctx, record); err != nil {
		sm.logger.Error("failed to log audit record",
			"error", err,
			"event_type", eventType,
			"request_id", req.ID,
		)
	}
}

// IsValidTransition checks if a state transition is valid
func IsValidTransition(from, to types.SignRequestStatus) bool {
	validTransitions := map[types.SignRequestStatus][]types.SignRequestStatus{
		types.StatusPending: {
			types.StatusAuthorizing,
			types.StatusRejected,
		},
		types.StatusAuthorizing: {
			types.StatusSigning,
			types.StatusRejected,
		},
		types.StatusSigning: {
			types.StatusCompleted,
			types.StatusFailed,
		},
		// Terminal states - no transitions allowed
		types.StatusCompleted: {},
		types.StatusRejected:  {},
		types.StatusFailed:    {},
	}

	allowedTargets, exists := validTransitions[from]
	if !exists {
		return false
	}

	for _, target := range allowedTargets {
		if target == to {
			return true
		}
	}
	return false
}
