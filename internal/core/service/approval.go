package service

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// Notifier interface for sending notifications
type Notifier interface {
	// SendApprovalRequest sends a notification about a pending approval request
	SendApprovalRequest(ctx context.Context, req *types.SignRequest) error
}

// ApprovalService handles manual approval workflow
type ApprovalService struct {
	ruleRepo      storage.RuleRepository
	ruleGenerator rule.RuleGenerator
	notifier      Notifier
	logger        *slog.Logger
}

// NewApprovalService creates a new approval service
func NewApprovalService(
	ruleRepo storage.RuleRepository,
	ruleGenerator rule.RuleGenerator,
	notifier Notifier,
	logger *slog.Logger,
) (*ApprovalService, error) {
	if ruleRepo == nil {
		return nil, fmt.Errorf("rule repository is required")
	}
	if ruleGenerator == nil {
		return nil, fmt.Errorf("rule generator is required")
	}
	if notifier == nil {
		return nil, fmt.Errorf("notifier is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	return &ApprovalService{
		ruleRepo:      ruleRepo,
		ruleGenerator: ruleGenerator,
		notifier:      notifier,
		logger:        logger,
	}, nil
}

// RequestApproval sends a notification for manual approval
func (s *ApprovalService) RequestApproval(ctx context.Context, req *types.SignRequest) error {
	if req == nil {
		return fmt.Errorf("request is required")
	}

	s.logger.Info("requesting manual approval",
		"request_id", req.ID,
		"chain_type", req.ChainType,
		"signer", req.SignerAddress,
	)

	if err := s.notifier.SendApprovalRequest(ctx, req); err != nil {
		s.logger.Error("failed to send approval notification",
			"error", err,
			"request_id", req.ID,
		)
		return fmt.Errorf("failed to send approval notification: %w", err)
	}

	return nil
}

// PreviewRule generates a rule preview without saving it
// This allows users to see what rule would be created before confirming
func (s *ApprovalService) PreviewRule(ctx context.Context, req *types.SignRequest, parsed *types.ParsedPayload, opts *rule.RuleGenerateOptions) (*types.Rule, error) {
	if req == nil {
		return nil, fmt.Errorf("request is required")
	}
	if opts == nil {
		return nil, fmt.Errorf("options are required")
	}

	preview, err := s.ruleGenerator.Preview(req, parsed, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rule preview: %w", err)
	}

	s.logger.Debug("rule preview generated",
		"request_id", req.ID,
		"rule_type", opts.RuleType,
		"rule_mode", opts.RuleMode,
	)

	return preview, nil
}

// GenerateRule creates and saves a rule based on an approved request with explicit options
func (s *ApprovalService) GenerateRule(ctx context.Context, req *types.SignRequest, parsed *types.ParsedPayload, opts *rule.RuleGenerateOptions) (*types.Rule, error) {
	if req == nil {
		return nil, fmt.Errorf("request is required")
	}
	if opts == nil {
		return nil, fmt.Errorf("options are required")
	}

	newRule, err := s.ruleGenerator.Generate(req, parsed, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rule: %w", err)
	}

	if err := s.ruleRepo.Create(ctx, newRule); err != nil {
		return nil, fmt.Errorf("failed to create rule: %w", err)
	}

	s.logger.Info("rule created",
		"rule_id", newRule.ID,
		"rule_name", newRule.Name,
		"rule_type", newRule.Type,
		"rule_mode", newRule.Mode,
		"request_id", req.ID,
	)

	return newRule, nil
}

// SupportedRuleTypes returns the rule types that can be generated
func (s *ApprovalService) SupportedRuleTypes() []types.RuleType {
	return s.ruleGenerator.SupportedTypes()
}

// NoopNotifier is a notifier that does nothing (used when notifications are disabled)
type NoopNotifier struct{}

// NewNoopNotifier creates a new no-op notifier
func NewNoopNotifier() (*NoopNotifier, error) {
	return &NoopNotifier{}, nil
}

// SendApprovalRequest does nothing
func (n *NoopNotifier) SendApprovalRequest(ctx context.Context, req *types.SignRequest) error {
	return nil
}

// Compile-time check
var _ Notifier = (*NoopNotifier)(nil)
