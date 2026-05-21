package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/chain"
	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/statemachine"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ErrManualApprovalDisabled is returned when no whitelist rule matches and manual approval is disabled.
// Caller should respond with 403 Forbidden.
var ErrManualApprovalDisabled = errors.New("no matching whitelist rule and manual approval is disabled")

// isLockedSignerErr reports whether the sign error came from a locked
// signer. Chain adapters surface this with phrasing like
// "failed to get signer: signer is locked" — matching on "is locked"
// is intentionally loose so adapter wording changes don't silently
// turn this back into a "failed" request.
func isLockedSignerErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "is locked")
}

// SignServiceAPI defines the methods used by HTTP handlers for sign operations.
// This interface enables mock-based unit testing of handlers without constructing a full SignService.
type SignServiceAPI interface {
	Sign(ctx context.Context, req *SignRequest) (*SignResponse, error)
	GetRequest(ctx context.Context, id types.SignRequestID) (*types.SignRequest, error)
	ListRequests(ctx context.Context, filter storage.RequestFilter) ([]*types.SignRequest, error)
	CountRequests(ctx context.Context, filter storage.RequestFilter) (int, error)
	ProcessApproval(ctx context.Context, requestID types.SignRequestID, req *ApprovalRequest) (*ApprovalResponse, error)
	PreviewRuleForRequest(ctx context.Context, requestID types.SignRequestID, opts *rule.RuleGenerateOptions) (*types.Rule, error)
}

// Compile-time interface check.
var _ SignServiceAPI = (*SignService)(nil)

// SignService orchestrates the signing request lifecycle
type SignService struct {
	chainRegistry         *chain.Registry
	requestRepo           storage.RequestRepository
	ruleEngine            rule.RuleEngine
	stateMachine          *statemachine.StateMachine
	approvalService       *ApprovalService
	auditLogger           *audit.AuditLogger   // optional: persistent audit logging
	approvalGuard         *ManualApprovalGuard        // optional: pauses requests when too many consecutive manual-approval outcomes
	simulationRule        *evmchain.SimulationBudgetRule // optional: simulation-based budget fallback for unmatched transactions
	manualApprovalEnabled bool                         // when false, no whitelist match → reject immediately
	logger                *slog.Logger
}

// NewSignService creates a new sign service
func NewSignService(
	chainRegistry *chain.Registry,
	requestRepo storage.RequestRepository,
	ruleEngine rule.RuleEngine,
	stateMachine *statemachine.StateMachine,
	approvalService *ApprovalService,
	logger *slog.Logger,
) (*SignService, error) {
	if chainRegistry == nil {
		return nil, fmt.Errorf("chain registry is required")
	}
	if requestRepo == nil {
		return nil, fmt.Errorf("request repository is required")
	}
	if ruleEngine == nil {
		return nil, fmt.Errorf("rule engine is required")
	}
	if stateMachine == nil {
		return nil, fmt.Errorf("state machine is required")
	}
	if approvalService == nil {
		return nil, fmt.Errorf("approval service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	return &SignService{
		chainRegistry:   chainRegistry,
		requestRepo:     requestRepo,
		ruleEngine:      ruleEngine,
		stateMachine:    stateMachine,
		approvalService: approvalService,
		logger:          logger,
	}, nil
}

// SetAuditLogger sets the audit logger for persistent event logging.
func (s *SignService) SetAuditLogger(al *audit.AuditLogger) {
	s.auditLogger = al
}

// SetApprovalGuard sets the optional guard that pauses sign requests when too many
// consecutive manual-approval outcomes occur. Call after construction when enabled.
func (s *SignService) SetApprovalGuard(guard *ManualApprovalGuard) {
	s.approvalGuard = guard
}

// SetManualApprovalEnabled sets whether requests with no whitelist match go to manual approval (true)
// or are rejected immediately (false). Default is false. Call after construction from config.
func (s *SignService) SetManualApprovalEnabled(enabled bool) {
	s.manualApprovalEnabled = enabled
}

// SetSimulationRule sets the optional simulation-based budget fallback rule.
// When set, unmatched transactions are simulated via eth_simulateV1 and budget
// is checked against actual token outflows before signing.
func (s *SignService) SetSimulationRule(rule *evmchain.SimulationBudgetRule) {
	s.simulationRule = rule
}

// ErrStrategyRoleSimulationBlocked is returned when a strategy role request reaches simulation fallback,
// indicating rule misconfiguration. Strategy keys must have explicit rules for all operations.
var ErrStrategyRoleSimulationBlocked = errors.New("strategy role request has no matching whitelist rule: explicit rules required for all operations")

// SignRequest represents a request to sign data
type SignRequest struct {
	APIKeyID      string          `json:"api_key_id"`
	APIKeyRole    types.APIKeyRole `json:"api_key_role"`
	ChainType     types.ChainType `json:"chain_type"`
	ChainID       string          `json:"chain_id"`
	SignerAddress string          `json:"signer_address"`
	SignType      string          `json:"sign_type"`
	Payload       []byte          `json:"payload"`
	ClientIP      string          `json:"client_ip"` // source IP (set by handler from request context)
}

// SignResponse represents the response to a sign request
type SignResponse struct {
	RequestID  types.SignRequestID     `json:"request_id"`
	Status     types.SignRequestStatus `json:"status"`
	Signature  []byte                  `json:"signature,omitempty"`
	SignedData []byte                  `json:"signed_data,omitempty"`
	Message    string                  `json:"message,omitempty"`
}

// Sign processes a sign request.
// Requests are persisted only after basic checks pass (chain adapter + ValidateBasicRequest: format and size).
// Then signer existence, ValidatePayload, and rules run; failures update the same record to rejected for audit.
func (s *SignService) Sign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	adapter, err := s.chainRegistry.Get(req.ChainType)
	if err != nil {
		return nil, fmt.Errorf("unsupported chain type %s: %w", req.ChainType, err)
	}

	// Basic check: format and size only (chain_id, signer_address, sign_type, payload). No persist until this passes.
	if err := adapter.ValidateBasicRequest(req.ChainID, req.SignerAddress, req.SignType, req.Payload); err != nil {
		return nil, fmt.Errorf("basic request validation failed: %w", err)
	}

	// Persist for audit: basic check passed; store before signer/payload/rule validation
	now := time.Now()
	signReq := &types.SignRequest{
		ID:            types.SignRequestID(uuid.New().String()),
		APIKeyID:      req.APIKeyID,
		ChainType:     req.ChainType,
		ChainID:       req.ChainID,
		SignerAddress: req.SignerAddress,
		SignType:      req.SignType,
		Payload:       req.Payload,
		ClientIP:      req.ClientIP,
		Status:        types.StatusPending,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := s.requestRepo.Create(ctx, signReq); err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	s.logger.Info("sign request created",
		"request_id", signReq.ID,
		"chain_type", signReq.ChainType,
		"signer", signReq.SignerAddress,
		"sign_type", signReq.SignType,
	)
	if s.auditLogger != nil {
		s.auditLogger.LogSignRequest(ctx, signReq)
	}

	// Reject if approval guard is paused (still persisted for audit)
	if s.approvalGuard != nil && s.approvalGuard.IsPaused() {
		if _, smErr := s.stateMachine.RejectOnValidation(ctx, signReq.ID, "sign requests are paused due to approval guard; use admin API to resume"); smErr != nil {
			s.logger.Error("failed to reject request", "error", smErr)
		}
		return nil, fmt.Errorf("sign requests are paused due to approval guard; use admin API to resume")
	}

	// Signer must exist in registry
	if !adapter.HasSigner(ctx, req.SignerAddress) {
		s.logger.Warn("signer not found in registry",
			"request_id", signReq.ID,
			"signer_address", req.SignerAddress,
			"chain_type", req.ChainType,
			"chain_id", req.ChainID,
			"sign_type", req.SignType,
		)
		if _, smErr := s.stateMachine.RejectOnValidation(ctx, signReq.ID, "signer not found in registry"); smErr != nil {
			s.logger.Error("failed to reject request", "error", smErr)
		}
		return nil, types.ErrSignerNotFound
	}

	// Payload must pass chain-specific validation
	if err := adapter.ValidatePayload(ctx, req.SignType, req.Payload); err != nil {
		s.logger.Warn("invalid payload", "request_id", signReq.ID, "error", err)
		if _, smErr := s.stateMachine.RejectOnValidation(ctx, signReq.ID, "invalid payload: "+err.Error()); smErr != nil {
			s.logger.Error("failed to reject request", "error", smErr)
		}
		return nil, fmt.Errorf("%w: %w", types.ErrInvalidPayload, err)
	}

	// Transition to authorizing (pending → authorizing)
	if _, err := s.stateMachine.ValidateAndStartAuthorizing(ctx, signReq.ID); err != nil {
		return nil, fmt.Errorf("failed to start authorization: %w", err)
	}

	// Parse payload for rule evaluation
	parsed, err := adapter.ParsePayload(ctx, req.SignType, req.Payload)
	if err != nil {
		s.logger.Warn("failed to parse payload for rule evaluation", "error", err)
		parsed = &types.ParsedPayload{RawData: req.Payload}
	}

	// Reload request after status change
	signReq, err = s.requestRepo.Get(ctx, signReq.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to reload request: %w", err)
	}

	// Evaluate rules (two-tier: blocklist first, then whitelist). We use
	// EvaluateWithResult (not the shorter Evaluate) so we can capture the
	// engine's NoMatchReason on the request row when nothing matches.
	// That reason is what the activity-drawer in the popup surfaces, and
	// it's the diagnostic operators want when "the rule I just created
	// didn't fire" — sparing them a grep through server logs.
	evalResult, err := s.ruleEngine.EvaluateWithResult(ctx, signReq, parsed)
	if err != nil {
		// Check if blocked by a blocklist rule (delegation path raises this
		// as a typed error even though EvaluateWithResult exists).
		var blockedErr *rule.BlockedError
		if errors.As(err, &blockedErr) {
			if s.approvalGuard != nil {
				s.approvalGuard.RecordRuleRejected()
			}
			s.logger.Warn("request blocked by rule",
				"request_id", signReq.ID,
				"rule_id", blockedErr.RuleID,
				"rule_name", blockedErr.RuleName,
				"reason", blockedErr.Reason,
			)
			rejectReason := fmt.Sprintf("blocked by rule %s: %s", blockedErr.RuleName, blockedErr.Reason)
			if _, smErr := s.stateMachine.RejectOnAuthorization(ctx, signReq.ID, "system", rejectReason); smErr != nil {
				s.logger.Error("failed to reject blocked request", "error", smErr)
			}
			return &SignResponse{
				RequestID: signReq.ID,
				Status:    types.StatusRejected,
				Message:   rejectReason,
			}, nil
		}
		// Other errors - log and continue to manual approval
		s.logger.Error("rule evaluation error", "error", err)
	}

	// EvaluateWithResult also returns the blocked path via the result
	// struct (in addition to the typed error above) — handle it here for
	// the non-delegation case.
	if evalResult != nil && evalResult.Blocked {
		if s.approvalGuard != nil {
			s.approvalGuard.RecordRuleRejected()
		}
		blockedName := ""
		blockedID := ""
		if evalResult.BlockedBy != nil {
			blockedName = evalResult.BlockedBy.Name
			blockedID = string(evalResult.BlockedBy.ID)
		}
		s.logger.Warn("request blocked by rule",
			"request_id", signReq.ID,
			"rule_id", blockedID,
			"rule_name", blockedName,
			"reason", evalResult.BlockReason,
		)
		rejectReason := fmt.Sprintf("blocked by rule %s: %s", blockedName, evalResult.BlockReason)
		if _, smErr := s.stateMachine.RejectOnAuthorization(ctx, signReq.ID, "system", rejectReason); smErr != nil {
			s.logger.Error("failed to reject blocked request", "error", smErr)
		}
		return &SignResponse{
			RequestID: signReq.ID,
			Status:    types.StatusRejected,
			Message:   rejectReason,
		}, nil
	}

	var matchedRuleID *types.RuleID
	var reason string
	var noMatchReason string
	if evalResult != nil {
		if evalResult.Allowed && evalResult.AllowedBy != nil {
			id := evalResult.AllowedBy.ID
			matchedRuleID = &id
			reason = evalResult.AllowReason
		}
		noMatchReason = evalResult.NoMatchReason
	}

	if matchedRuleID != nil {
		// Auto-approved by whitelist rule - proceed to signing
		if s.approvalGuard != nil {
			s.approvalGuard.RecordNonManualApproval()
		}
		return s.processApprovedRequest(ctx, signReq, matchedRuleID, nil, reason, adapter)
	}

	// No whitelist match — persist the engine's reason on the request row
	// so subsequent GET /requests/{id} reads it back. Best-effort: the
	// request might be moments away from manual-approval or simulation,
	// so failure here doesn't gate the rest of the flow.
	if noMatchReason != "" {
		if upErr := s.requestRepo.UpdateLastNoMatchReason(ctx, signReq.ID, noMatchReason); upErr != nil {
			s.logger.Warn("failed to persist last_no_match_reason",
				"request_id", signReq.ID,
				"error", upErr,
			)
		} else {
			signReq.LastNoMatchReason = noMatchReason
		}
	}

	// No whitelist rule matched — strategy role must have explicit rules for all operations.
	// Reaching this point means rules are misconfigured; reject immediately without simulation.
	if req.APIKeyRole == types.RoleStrategy {
		s.logger.Warn("strategy role request has no matching whitelist rule, skipping simulation fallback",
			"request_id", signReq.ID,
			"api_key_id", req.APIKeyID,
		)
		if s.approvalGuard != nil {
			s.approvalGuard.RecordRuleRejected()
		}
		rejectReason := "strategy role requires explicit rules for all operations; no matching whitelist rule found"
		if _, smErr := s.stateMachine.RejectOnAuthorization(ctx, signReq.ID, "system", rejectReason); smErr != nil {
			s.logger.Error("failed to reject request", "error", smErr)
		}
		return &SignResponse{
			RequestID: signReq.ID,
			Status:    types.StatusRejected,
			Message:   rejectReason,
		}, nil
	}

	// No whitelist rule matched — try simulation fallback before manual approval
	if s.simulationRule != nil && s.simulationRule.Available() {
		outcome, simErr := s.simulationRule.EvaluateSingle(ctx, signReq, parsed)
		if simErr != nil {
			s.logger.Error("simulation fallback error", "request_id", signReq.ID, "error", simErr)
		} else if outcome.Decision == "allow" {
			s.logger.Info("request allowed by simulation fallback",
				"request_id", signReq.ID,
			)
			if s.approvalGuard != nil {
				s.approvalGuard.RecordNonManualApproval()
			}
			return s.processApprovedRequest(ctx, signReq, nil, nil, "simulation-approved", adapter)
		} else if outcome.Decision == "deny" {
			reason := outcome.Reason
			if reason == "" {
				reason = "simulation denied"
			}
			s.logger.Warn("request denied by simulation fallback",
				"request_id", signReq.ID,
				"reason", reason,
			)
			if s.approvalGuard != nil {
				s.approvalGuard.RecordRuleRejected()
			}
			if _, smErr := s.stateMachine.RejectOnAuthorization(ctx, signReq.ID, "simulation", reason); smErr != nil {
				s.logger.Error("failed to reject request", "error", smErr)
			}
			return &SignResponse{
				RequestID: signReq.ID,
				Status:    types.StatusRejected,
				Message:   reason,
			}, nil
		}
		// outcome.Decision == "no_match" — simulation didn't apply, fall through to manual approval
	}

	if !s.manualApprovalEnabled {
		if s.approvalGuard != nil {
			s.approvalGuard.RecordRuleRejected()
		}
		if _, smErr := s.stateMachine.RejectOnAuthorization(ctx, signReq.ID, "system", "no matching whitelist rule and manual approval is disabled"); smErr != nil {
			s.logger.Error("failed to reject request", "error", smErr)
		}
		return nil, ErrManualApprovalDisabled
	}

	// Request manual approval
	if s.approvalGuard != nil {
		s.approvalGuard.RecordManualApproval()
	}
	if s.auditLogger != nil {
		s.auditLogger.LogApprovalRequest(ctx, signReq)
	}
	if err := s.approvalService.RequestApproval(ctx, signReq); err != nil {
		s.logger.Error("failed to request approval", "error", err)
	}

	return &SignResponse{
		RequestID: signReq.ID,
		Status:    types.StatusAuthorizing,
		Message:   "pending manual approval",
	}, nil
}

// processApprovedRequest handles signing for approved requests
func (s *SignService) processApprovedRequest(
	ctx context.Context,
	signReq *types.SignRequest,
	ruleID *types.RuleID,
	approvedBy *string,
	reason string,
	adapter types.ChainAdapter,
) (*SignResponse, error) {
	// Re-fetch the current state — between the time we got `signReq`
	// and now, an out-of-band actor (operator clicking Approve in the
	// popup; another simulation tick; SIGHUP rule reload) may have
	// already completed or rejected the request. The pre-fix path
	// blindly drove ApproveForSigning and surfaced
	// "cannot move from completed to signing" as a 500 to the dApp,
	// even though the signature was sitting in the database. Detect
	// the race and return what's already there.
	current, getErr := s.requestRepo.Get(ctx, signReq.ID)
	if getErr != nil {
		return nil, fmt.Errorf("failed to re-read request before signing: %w", getErr)
	}
	switch current.Status {
	case types.StatusCompleted:
		s.logger.Info("request already completed by another path; returning cached signature",
			"request_id", signReq.ID, "approved_by", approvedBy)
		return &SignResponse{
			RequestID:  current.ID,
			Status:     types.StatusCompleted,
			Signature:  current.Signature,
			SignedData: current.SignedData,
		}, nil
	case types.StatusRejected, types.StatusFailed:
		s.logger.Info("request already in terminal non-success state; returning status",
			"request_id", signReq.ID, "status", current.Status,
			"approved_by", approvedBy)
		return &SignResponse{
			RequestID: current.ID,
			Status:    current.Status,
			Message:   current.ErrorMessage,
		}, nil
	case types.StatusSigning:
		// Another goroutine is actively signing this one. Don't double-
		// drive it; just observe the final state via the existing
		// caller path. We return signing so the SDK's long-poll keeps
		// polling for completion (it's only a few hundred ms away).
		return &SignResponse{
			RequestID: current.ID,
			Status:    types.StatusSigning,
			Message:   "request is being signed by another path",
		}, nil
	}

	// Transition to signing
	if _, err := s.stateMachine.ApproveForSigning(ctx, signReq.ID, ruleID, approvedBy, reason); err != nil {
		return nil, fmt.Errorf("failed to approve for signing: %w", err)
	}

	// Perform signing
	result, err := adapter.Sign(ctx, signReq.SignerAddress, signReq.SignType, signReq.ChainID, signReq.Payload)
	if err != nil {
		// A locked signer is a transient operator-fixable state, not a
		// final decision on the request. Revert to authorizing so the
		// same approval can be retried after unlock, instead of burning
		// the request to "failed" and forcing the caller to resubmit.
		if isLockedSignerErr(err) {
			if _, smErr := s.stateMachine.RevertSigningToAuthorizing(ctx, signReq.ID, err.Error()); smErr != nil {
				s.logger.Error("failed to revert request to authorizing", "error", smErr)
			}
			return nil, fmt.Errorf("signing failed: %w", err)
		}
		// Permanent failure: transition to failed
		if _, smErr := s.stateMachine.FailSign(ctx, signReq.ID, err.Error()); smErr != nil {
			s.logger.Error("failed to transition to failed state", "error", smErr)
		}
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	// Transition to completed
	if _, err := s.stateMachine.CompleteSign(ctx, signReq.ID, result.Signature, result.SignedData); err != nil {
		return nil, fmt.Errorf("failed to complete signing: %w", err)
	}

	return &SignResponse{
		RequestID:  signReq.ID,
		Status:     types.StatusCompleted,
		Signature:  result.Signature,
		SignedData: result.SignedData,
	}, nil
}

// GetRequest retrieves a sign request by ID
func (s *SignService) GetRequest(ctx context.Context, id types.SignRequestID) (*types.SignRequest, error) {
	return s.requestRepo.Get(ctx, id)
}

// ListRequests lists sign requests with filter
func (s *SignService) ListRequests(ctx context.Context, filter storage.RequestFilter) ([]*types.SignRequest, error) {
	return s.requestRepo.List(ctx, filter)
}

// CountRequests counts sign requests matching the filter
func (s *SignService) CountRequests(ctx context.Context, filter storage.RequestFilter) (int, error) {
	return s.requestRepo.Count(ctx, filter)
}

// ApprovalRequest represents the request to approve or reject a signing request
type ApprovalRequest struct {
	Approved   bool                     `json:"approved"`
	ApprovedBy string                   `json:"approved_by"`
	RuleOpts   *rule.RuleGenerateOptions `json:"rule_opts,omitempty"` // Optional: generate rule with these options
}

// ApprovalResponse represents the response to an approval request
type ApprovalResponse struct {
	SignResponse *SignResponse `json:"sign_response"`
	GeneratedRule *types.Rule  `json:"generated_rule,omitempty"`
}

// PreviewRuleForRequest generates a rule preview for a pending request
func (s *SignService) PreviewRuleForRequest(ctx context.Context, requestID types.SignRequestID, opts *rule.RuleGenerateOptions) (*types.Rule, error) {
	signReq, err := s.requestRepo.Get(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to get request: %w", err)
	}

	if signReq.Status != types.StatusAuthorizing {
		return nil, fmt.Errorf("request is not pending approval (status: %s)", signReq.Status)
	}

	// Get chain adapter to parse payload
	adapter, err := s.chainRegistry.Get(signReq.ChainType)
	if err != nil {
		return nil, fmt.Errorf("unsupported chain type: %w", err)
	}

	parsed, err := adapter.ParsePayload(ctx, signReq.SignType, signReq.Payload)
	if err != nil {
		s.logger.Warn("failed to parse payload for rule preview", "error", err)
		parsed = &types.ParsedPayload{RawData: signReq.Payload}
	}

	preview, err := s.approvalService.PreviewRule(ctx, signReq, parsed, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to preview rule: %w", err)
	}

	return preview, nil
}

// SupportedRuleTypes returns the rule types that can be generated
func (s *SignService) SupportedRuleTypes() []types.RuleType {
	return s.approvalService.SupportedRuleTypes()
}

// ProcessApproval processes a manual approval for a pending request
func (s *SignService) ProcessApproval(ctx context.Context, requestID types.SignRequestID, req *ApprovalRequest) (*ApprovalResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("approval request is required")
	}

	signReq, err := s.requestRepo.Get(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to get request: %w", err)
	}

	if signReq.Status != types.StatusAuthorizing {
		return nil, fmt.Errorf("request is not pending approval (status: %s)", signReq.Status)
	}

	if !req.Approved {
		// Reject the request
		if _, err := s.stateMachine.RejectOnAuthorization(ctx, requestID, req.ApprovedBy, "manually rejected"); err != nil {
			return nil, fmt.Errorf("failed to reject request: %w", err)
		}
		return &ApprovalResponse{
			SignResponse: &SignResponse{
				RequestID: requestID,
				Status:    types.StatusRejected,
				Message:   "request rejected",
			},
		}, nil
	}

	// Get chain adapter
	adapter, err := s.chainRegistry.Get(signReq.ChainType)
	if err != nil {
		return nil, fmt.Errorf("unsupported chain type: %w", err)
	}

	// Process the approval
	signResponse, err := s.processApprovedRequest(ctx, signReq, nil, &req.ApprovedBy, "manually approved", adapter)
	if err != nil {
		return nil, err
	}

	response := &ApprovalResponse{
		SignResponse: signResponse,
	}

	// Generate rule if options provided
	if req.RuleOpts != nil {
		parsed, err := adapter.ParsePayload(ctx, signReq.SignType, signReq.Payload)
		if err != nil {
			s.logger.Warn("failed to parse payload for rule generation", "error", err)
			parsed = &types.ParsedPayload{RawData: signReq.Payload}
		}

		generatedRule, err := s.approvalService.GenerateRule(ctx, signReq, parsed, req.RuleOpts)
		if err != nil {
			s.logger.Error("failed to generate rule from approval", "error", err)
			// Don't fail the response, rule generation is optional but log the error
		} else {
			response.GeneratedRule = generatedRule
		}
	}

	return response, nil
}
