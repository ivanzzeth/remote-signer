package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/chain"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/statemachine"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------------------------------------------------------------------------
// Mock chain adapter
// ---------------------------------------------------------------------------

type mockChainAdapter struct {
	chainType          types.ChainType
	validateBasicErr   error
	validatePayloadErr error
	hasSigner          bool
	signResult         *types.SignResult
	signErr            error
	parsedPayload      *types.ParsedPayload
	parseErr           error
}

func (a *mockChainAdapter) Type() types.ChainType { return a.chainType }

func (a *mockChainAdapter) ValidateBasicRequest(_, _, _ string, _ []byte) error {
	return a.validateBasicErr
}

func (a *mockChainAdapter) ValidatePayload(_ context.Context, _ string, _ []byte) error {
	return a.validatePayloadErr
}

func (a *mockChainAdapter) Sign(_ context.Context, _, _, _ string, _ []byte) (*types.SignResult, error) {
	return a.signResult, a.signErr
}

func (a *mockChainAdapter) ParsePayload(_ context.Context, _ string, _ []byte) (*types.ParsedPayload, error) {
	return a.parsedPayload, a.parseErr
}

func (a *mockChainAdapter) ListSigners(_ context.Context) ([]types.SignerInfo, error) {
	return nil, nil
}

func (a *mockChainAdapter) HasSigner(_ context.Context, _ string) bool {
	return a.hasSigner
}

var _ types.ChainAdapter = (*mockChainAdapter)(nil)

// ---------------------------------------------------------------------------
// Mock rule engine
// ---------------------------------------------------------------------------

type mockRuleEngine struct {
	matchedRuleID *types.RuleID
	matchReason   string
	evalErr       error
}

func (e *mockRuleEngine) Evaluate(_ context.Context, _ *types.SignRequest, _ *types.ParsedPayload) (*types.RuleID, string, error) {
	return e.matchedRuleID, e.matchReason, e.evalErr
}

func (e *mockRuleEngine) EvaluateWithResult(_ context.Context, _ *types.SignRequest, _ *types.ParsedPayload) (*rule.EvaluationResult, error) {
	return nil, nil
}

func (e *mockRuleEngine) RegisterEvaluator(_ rule.RuleEvaluator) {}

var _ rule.RuleEngine = (*mockRuleEngine)(nil)

// ---------------------------------------------------------------------------
// Mock request repository
// ---------------------------------------------------------------------------

type mockRequestRepo struct {
	mu       sync.RWMutex
	requests map[types.SignRequestID]*types.SignRequest
}

func newMockRequestRepo() *mockRequestRepo {
	return &mockRequestRepo{requests: make(map[types.SignRequestID]*types.SignRequest)}
}

func (r *mockRequestRepo) Create(_ context.Context, req *types.SignRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.requests[req.ID]; exists {
		return types.ErrAlreadyExists
	}
	cp := *req
	r.requests[req.ID] = &cp
	return nil
}

func (r *mockRequestRepo) Get(_ context.Context, id types.SignRequestID) (*types.SignRequest, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	req, ok := r.requests[id]
	if !ok {
		return nil, types.ErrNotFound
	}
	cp := *req
	return &cp, nil
}

func (r *mockRequestRepo) Update(_ context.Context, req *types.SignRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.requests[req.ID]; !exists {
		return types.ErrNotFound
	}
	cp := *req
	r.requests[req.ID] = &cp
	return nil
}

func (r *mockRequestRepo) CompareAndUpdate(_ context.Context, req *types.SignRequest, expectedStatus types.SignRequestStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, exists := r.requests[req.ID]
	if !exists {
		return types.ErrNotFound
	}
	if existing.Status != expectedStatus {
		return storage.ErrStateConflict
	}
	cp := *req
	r.requests[req.ID] = &cp
	return nil
}

func (r *mockRequestRepo) List(_ context.Context, filter storage.RequestFilter) ([]*types.SignRequest, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*types.SignRequest
	for _, req := range r.requests {
		cp := *req
		out = append(out, &cp)
	}
	return out, nil
}

func (r *mockRequestRepo) Count(_ context.Context, _ storage.RequestFilter) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.requests), nil
}

func (r *mockRequestRepo) UpdateStatus(_ context.Context, id types.SignRequestID, status types.SignRequestStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	req, exists := r.requests[id]
	if !exists {
		return types.ErrNotFound
	}
	req.Status = status
	return nil
}

var _ storage.RequestRepository = (*mockRequestRepo)(nil)

// ---------------------------------------------------------------------------
// Mock audit repository
// ---------------------------------------------------------------------------

type mockAuditRepo struct {
	mu      sync.Mutex
	records []*types.AuditRecord
}

func newMockAuditRepo() *mockAuditRepo {
	return &mockAuditRepo{}
}

func (r *mockAuditRepo) Log(_ context.Context, record *types.AuditRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, record)
	return nil
}

func (r *mockAuditRepo) Query(_ context.Context, _ storage.AuditFilter) ([]*types.AuditRecord, error) {
	return nil, nil
}

func (r *mockAuditRepo) Count(_ context.Context, _ storage.AuditFilter) (int, error) {
	return 0, nil
}

func (r *mockAuditRepo) GetByRequestID(_ context.Context, _ types.SignRequestID) ([]*types.AuditRecord, error) {
	return nil, nil
}

var _ storage.AuditRepository = (*mockAuditRepo)(nil)

// ---------------------------------------------------------------------------
// Test helpers for sign service
// ---------------------------------------------------------------------------

// signServiceFixture bundles all deps to easily construct a SignService.
type signServiceFixture struct {
	chainRegistry   *chain.Registry
	requestRepo     *mockRequestRepo
	auditRepo       *mockAuditRepo
	ruleEngine      *mockRuleEngine
	stateMachine    *statemachine.StateMachine
	approvalService *ApprovalService
	adapter         *mockChainAdapter
}

func newSignServiceFixture(t *testing.T) *signServiceFixture {
	t.Helper()

	adapter := &mockChainAdapter{
		chainType: types.ChainTypeEVM,
		hasSigner: true,
		signResult: &types.SignResult{
			Signature:  []byte("test-signature"),
			SignedData: []byte("test-signed-data"),
			SignerUsed: "0xsigner",
		},
		parsedPayload: &types.ParsedPayload{},
	}

	registry := chain.NewRegistry()
	if err := registry.Register(adapter); err != nil {
		t.Fatalf("failed to register adapter: %v", err)
	}

	requestRepo := newMockRequestRepo()
	auditRepo := newMockAuditRepo()

	sm, err := statemachine.NewStateMachine(requestRepo, auditRepo, newTestLogger())
	if err != nil {
		t.Fatalf("failed to create state machine: %v", err)
	}

	ruleEngine := &mockRuleEngine{}

	approvalSvc, err := NewApprovalService(
		newMockRuleRepo(),
		&mockRuleGenerator{
			types: []types.RuleType{types.RuleTypeEVMAddressList},
		},
		&mockNotifier{},
		newTestLogger(),
	)
	if err != nil {
		t.Fatalf("failed to create approval service: %v", err)
	}

	return &signServiceFixture{
		chainRegistry:   registry,
		requestRepo:     requestRepo,
		auditRepo:       auditRepo,
		ruleEngine:      ruleEngine,
		stateMachine:    sm,
		approvalService: approvalSvc,
		adapter:         adapter,
	}
}

func (f *signServiceFixture) build(t *testing.T) *SignService {
	t.Helper()
	svc, err := NewSignService(
		f.chainRegistry,
		f.requestRepo,
		f.ruleEngine,
		f.stateMachine,
		f.approvalService,
		newTestLogger(),
	)
	if err != nil {
		t.Fatalf("failed to build sign service: %v", err)
	}
	return svc
}

// ---------------------------------------------------------------------------
// TestNewSignService
// ---------------------------------------------------------------------------

func TestNewSignService(t *testing.T) {
	f := newSignServiceFixture(t)

	t.Run("all_valid_args", func(t *testing.T) {
		svc := f.build(t)
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
	})

	t.Run("nil_chain_registry", func(t *testing.T) {
		_, err := NewSignService(nil, f.requestRepo, f.ruleEngine, f.stateMachine, f.approvalService, newTestLogger())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "chain registry is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nil_request_repo", func(t *testing.T) {
		_, err := NewSignService(f.chainRegistry, nil, f.ruleEngine, f.stateMachine, f.approvalService, newTestLogger())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "request repository is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nil_rule_engine", func(t *testing.T) {
		_, err := NewSignService(f.chainRegistry, f.requestRepo, nil, f.stateMachine, f.approvalService, newTestLogger())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "rule engine is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nil_state_machine", func(t *testing.T) {
		_, err := NewSignService(f.chainRegistry, f.requestRepo, f.ruleEngine, nil, f.approvalService, newTestLogger())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "state machine is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nil_approval_service", func(t *testing.T) {
		_, err := NewSignService(f.chainRegistry, f.requestRepo, f.ruleEngine, f.stateMachine, nil, newTestLogger())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "approval service is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nil_logger", func(t *testing.T) {
		_, err := NewSignService(f.chainRegistry, f.requestRepo, f.ruleEngine, f.stateMachine, f.approvalService, nil)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "logger is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// TestSign
// ---------------------------------------------------------------------------

func TestSign(t *testing.T) {
	ctx := context.Background()

	t.Run("auto_approved_by_whitelist_rule", func(t *testing.T) {
		f := newSignServiceFixture(t)
		ruleID := types.RuleID("rule-1")
		f.ruleEngine.matchedRuleID = &ruleID
		f.ruleEngine.matchReason = "address whitelisted"

		svc := f.build(t)

		resp, err := svc.Sign(ctx, &SignRequest{
			APIKeyID:      "key-1",
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{"to":"0xrecipient"}`),
		})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if resp.Status != types.StatusCompleted {
			t.Errorf("expected status %q, got %q", types.StatusCompleted, resp.Status)
		}
		if resp.Signature == nil {
			t.Error("expected non-nil signature")
		}
		if resp.SignedData == nil {
			t.Error("expected non-nil signed data")
		}
	})

	t.Run("unsupported_chain_type", func(t *testing.T) {
		f := newSignServiceFixture(t)
		svc := f.build(t)

		_, err := svc.Sign(ctx, &SignRequest{
			ChainType: "unknown_chain",
		})
		if err == nil {
			t.Fatal("expected error for unsupported chain type")
		}
		if !strings.Contains(err.Error(), "unsupported chain type") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("basic_validation_failure", func(t *testing.T) {
		f := newSignServiceFixture(t)
		f.adapter.validateBasicErr = fmt.Errorf("invalid address format")
		svc := f.build(t)

		_, err := svc.Sign(ctx, &SignRequest{
			ChainType:     types.ChainTypeEVM,
			SignerAddress: "bad",
		})
		if err == nil {
			t.Fatal("expected error for basic validation failure")
		}
		if !strings.Contains(err.Error(), "basic request validation failed") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("signer_not_found", func(t *testing.T) {
		f := newSignServiceFixture(t)
		f.adapter.hasSigner = false
		svc := f.build(t)

		_, err := svc.Sign(ctx, &SignRequest{
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xnonexistent",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
		})
		if err == nil {
			t.Fatal("expected error for missing signer")
		}
		if err != types.ErrSignerNotFound {
			t.Errorf("expected ErrSignerNotFound, got: %v", err)
		}
	})

	t.Run("payload_validation_failure", func(t *testing.T) {
		f := newSignServiceFixture(t)
		f.adapter.validatePayloadErr = fmt.Errorf("invalid payload structure")
		svc := f.build(t)

		_, err := svc.Sign(ctx, &SignRequest{
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`bad`),
		})
		if err == nil {
			t.Fatal("expected error for invalid payload")
		}
		if !strings.Contains(err.Error(), "invalid payload") {
			t.Errorf("unexpected error: %v", err)
		}
		if !errors.Is(err, types.ErrInvalidPayload) {
			t.Errorf("expected error to wrap ErrInvalidPayload, got: %v", err)
		}
	})

	t.Run("blocked_by_blocklist_rule", func(t *testing.T) {
		f := newSignServiceFixture(t)
		f.ruleEngine.evalErr = &rule.BlockedError{
			RuleID:   "blocklist-1",
			RuleName: "Block Bad Address",
			Reason:   "address is on blocklist",
		}
		svc := f.build(t)

		resp, err := svc.Sign(ctx, &SignRequest{
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
		})
		if err != nil {
			t.Fatalf("Sign should not return error for blocked: %v", err)
		}
		if resp.Status != types.StatusRejected {
			t.Errorf("expected status %q, got %q", types.StatusRejected, resp.Status)
		}
		if !strings.Contains(resp.Message, "blocked by rule") {
			t.Errorf("expected blocked message, got: %q", resp.Message)
		}
	})

	t.Run("no_whitelist_match_manual_approval_disabled", func(t *testing.T) {
		f := newSignServiceFixture(t)
		// No rule match (nil RuleID)
		f.ruleEngine.matchedRuleID = nil
		svc := f.build(t)
		// manualApprovalEnabled defaults to false

		_, err := svc.Sign(ctx, &SignRequest{
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
		})
		if err == nil {
			t.Fatal("expected error when manual approval is disabled")
		}
		if err != ErrManualApprovalDisabled {
			t.Errorf("expected ErrManualApprovalDisabled, got: %v", err)
		}
	})

	t.Run("no_whitelist_match_manual_approval_enabled", func(t *testing.T) {
		f := newSignServiceFixture(t)
		f.ruleEngine.matchedRuleID = nil
		svc := f.build(t)
		svc.SetManualApprovalEnabled(true)

		resp, err := svc.Sign(ctx, &SignRequest{
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
		})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if resp.Status != types.StatusAuthorizing {
			t.Errorf("expected status %q, got %q", types.StatusAuthorizing, resp.Status)
		}
		if !strings.Contains(resp.Message, "pending manual approval") {
			t.Errorf("unexpected message: %q", resp.Message)
		}
	})

	t.Run("signing_fails", func(t *testing.T) {
		f := newSignServiceFixture(t)
		ruleID := types.RuleID("rule-1")
		f.ruleEngine.matchedRuleID = &ruleID
		f.adapter.signErr = fmt.Errorf("hardware wallet disconnected")
		f.adapter.signResult = nil
		svc := f.build(t)

		_, err := svc.Sign(ctx, &SignRequest{
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
		})
		if err == nil {
			t.Fatal("expected error when signing fails")
		}
		if !strings.Contains(err.Error(), "signing failed") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("approval_guard_paused", func(t *testing.T) {
		f := newSignServiceFixture(t)
		svc := f.build(t)

		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    time.Minute,
			Threshold: 1,
			Logger:    newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}
		// Trigger pause by recording a rejection
		guard.RecordManualApproval()
		svc.SetApprovalGuard(guard)

		_, err = svc.Sign(ctx, &SignRequest{
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
		})
		if err == nil {
			t.Fatal("expected error when guard is paused")
		}
		if !strings.Contains(err.Error(), "paused due to approval guard") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("parse_payload_error_still_evaluates", func(t *testing.T) {
		f := newSignServiceFixture(t)
		f.adapter.parseErr = fmt.Errorf("cannot parse")
		f.adapter.parsedPayload = nil
		ruleID := types.RuleID("rule-fallback")
		f.ruleEngine.matchedRuleID = &ruleID
		svc := f.build(t)

		resp, err := svc.Sign(ctx, &SignRequest{
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
		})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if resp.Status != types.StatusCompleted {
			t.Errorf("expected completed status, got %q", resp.Status)
		}
	})

	t.Run("auto_approved_with_guard_records_non_manual", func(t *testing.T) {
		f := newSignServiceFixture(t)
		ruleID := types.RuleID("rule-guard")
		f.ruleEngine.matchedRuleID = &ruleID
		svc := f.build(t)

		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    5 * time.Minute,
			Threshold: 5,
			Logger:    newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}
		// Record some rejections but below threshold
		guard.RecordManualApproval()
		svc.SetApprovalGuard(guard)

		resp, err := svc.Sign(ctx, &SignRequest{
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
		})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if resp.Status != types.StatusCompleted {
			t.Errorf("expected completed, got %q", resp.Status)
		}
		// Guard should not be paused (non-manual approval resets counter)
		if guard.IsPaused() {
			t.Error("guard should not be paused after auto-approved request")
		}
	})

	t.Run("blocked_by_rule_with_guard", func(t *testing.T) {
		f := newSignServiceFixture(t)
		f.ruleEngine.evalErr = &rule.BlockedError{
			RuleID:   "blocklist-guard",
			RuleName: "Block Test",
			Reason:   "blocked",
		}
		svc := f.build(t)

		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    5 * time.Minute,
			Threshold: 10,
			Logger:    newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}
		svc.SetApprovalGuard(guard)

		resp, err := svc.Sign(ctx, &SignRequest{
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
		})
		if err != nil {
			t.Fatalf("Sign should not error for blocked: %v", err)
		}
		if resp.Status != types.StatusRejected {
			t.Errorf("expected rejected, got %q", resp.Status)
		}
	})

	t.Run("no_match_manual_disabled_with_guard", func(t *testing.T) {
		f := newSignServiceFixture(t)
		f.ruleEngine.matchedRuleID = nil
		svc := f.build(t)

		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    5 * time.Minute,
			Threshold: 10,
			Logger:    newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}
		svc.SetApprovalGuard(guard)

		_, err = svc.Sign(ctx, &SignRequest{
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
		})
		if err != ErrManualApprovalDisabled {
			t.Errorf("expected ErrManualApprovalDisabled, got: %v", err)
		}
	})

	t.Run("manual_approval_enabled_with_guard", func(t *testing.T) {
		f := newSignServiceFixture(t)
		f.ruleEngine.matchedRuleID = nil
		svc := f.build(t)
		svc.SetManualApprovalEnabled(true)

		guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
			Window:    5 * time.Minute,
			Threshold: 10,
			Logger:    newTestLogger(),
		})
		if err != nil {
			t.Fatalf("failed to create guard: %v", err)
		}
		svc.SetApprovalGuard(guard)

		resp, err := svc.Sign(ctx, &SignRequest{
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
		})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if resp.Status != types.StatusAuthorizing {
			t.Errorf("expected authorizing, got %q", resp.Status)
		}
	})

	t.Run("non_blocked_rule_evaluation_error", func(t *testing.T) {
		f := newSignServiceFixture(t)
		// Return a generic error (not BlockedError), no rule match
		f.ruleEngine.evalErr = fmt.Errorf("rule engine internal error")
		f.ruleEngine.matchedRuleID = nil
		svc := f.build(t)
		svc.SetManualApprovalEnabled(true)

		resp, err := svc.Sign(ctx, &SignRequest{
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
		})
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		// Should continue to manual approval despite rule eval error
		if resp.Status != types.StatusAuthorizing {
			t.Errorf("expected authorizing, got %q", resp.Status)
		}
	})
}

// ---------------------------------------------------------------------------
// TestSetApprovalGuard
// ---------------------------------------------------------------------------

func TestSetApprovalGuard(t *testing.T) {
	f := newSignServiceFixture(t)
	svc := f.build(t)

	guard, err := NewManualApprovalGuard(ManualApprovalGuardConfig{
		Window:    time.Minute,
		Threshold: 5,
		Logger:    newTestLogger(),
	})
	if err != nil {
		t.Fatalf("failed to create guard: %v", err)
	}

	svc.SetApprovalGuard(guard)
	// Verify it was set by checking that it doesn't panic on Sign
	// (guard is checked in Sign path)
	if svc.approvalGuard != guard {
		t.Error("guard was not set correctly")
	}
}

// ---------------------------------------------------------------------------
// TestSetManualApprovalEnabled
// ---------------------------------------------------------------------------

func TestSetManualApprovalEnabled(t *testing.T) {
	f := newSignServiceFixture(t)
	svc := f.build(t)

	if svc.manualApprovalEnabled {
		t.Error("expected manualApprovalEnabled to default to false")
	}

	svc.SetManualApprovalEnabled(true)
	if !svc.manualApprovalEnabled {
		t.Error("expected manualApprovalEnabled to be true after setting")
	}

	svc.SetManualApprovalEnabled(false)
	if svc.manualApprovalEnabled {
		t.Error("expected manualApprovalEnabled to be false after clearing")
	}
}

// ---------------------------------------------------------------------------
// TestGetRequest
// ---------------------------------------------------------------------------

func TestGetRequest(t *testing.T) {
	ctx := context.Background()
	f := newSignServiceFixture(t)
	svc := f.build(t)

	// Seed a request
	req := &types.SignRequest{
		ID:        "req-get-1",
		APIKeyID:  "key-1",
		ChainType: types.ChainTypeEVM,
		Status:    types.StatusPending,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := f.requestRepo.Create(ctx, req); err != nil {
		t.Fatalf("failed to seed request: %v", err)
	}

	t.Run("found", func(t *testing.T) {
		result, err := svc.GetRequest(ctx, "req-get-1")
		if err != nil {
			t.Fatalf("GetRequest failed: %v", err)
		}
		if result.ID != "req-get-1" {
			t.Errorf("expected ID %q, got %q", "req-get-1", result.ID)
		}
	})

	t.Run("not_found", func(t *testing.T) {
		_, err := svc.GetRequest(ctx, "nonexistent")
		if err == nil {
			t.Fatal("expected error for nonexistent request")
		}
	})
}

// ---------------------------------------------------------------------------
// TestListRequests
// ---------------------------------------------------------------------------

func TestListRequests(t *testing.T) {
	ctx := context.Background()
	f := newSignServiceFixture(t)
	svc := f.build(t)

	// Seed two requests
	for _, id := range []types.SignRequestID{"req-list-1", "req-list-2"} {
		req := &types.SignRequest{
			ID:        id,
			ChainType: types.ChainTypeEVM,
			Status:    types.StatusPending,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := f.requestRepo.Create(ctx, req); err != nil {
			t.Fatalf("failed to seed request: %v", err)
		}
	}

	result, err := svc.ListRequests(ctx, storage.RequestFilter{})
	if err != nil {
		t.Fatalf("ListRequests failed: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 requests, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// TestCountRequests
// ---------------------------------------------------------------------------

func TestCountRequests(t *testing.T) {
	ctx := context.Background()
	f := newSignServiceFixture(t)
	svc := f.build(t)

	// Seed requests
	for _, id := range []types.SignRequestID{"req-count-1", "req-count-2", "req-count-3"} {
		req := &types.SignRequest{
			ID:        id,
			ChainType: types.ChainTypeEVM,
			Status:    types.StatusPending,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := f.requestRepo.Create(ctx, req); err != nil {
			t.Fatalf("failed to seed request: %v", err)
		}
	}

	count, err := svc.CountRequests(ctx, storage.RequestFilter{})
	if err != nil {
		t.Fatalf("CountRequests failed: %v", err)
	}
	if count != 3 {
		t.Errorf("expected count 3, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// TestSupportedRuleTypes_SignService
// ---------------------------------------------------------------------------

func TestSupportedRuleTypes_SignService(t *testing.T) {
	f := newSignServiceFixture(t)
	svc := f.build(t)

	result := svc.SupportedRuleTypes()
	if len(result) == 0 {
		t.Error("expected at least one supported rule type")
	}
}

// ---------------------------------------------------------------------------
// TestProcessApproval
// ---------------------------------------------------------------------------

func TestProcessApproval(t *testing.T) {
	ctx := context.Background()

	t.Run("nil_request", func(t *testing.T) {
		f := newSignServiceFixture(t)
		svc := f.build(t)

		_, err := svc.ProcessApproval(ctx, "req-1", nil)
		if err == nil {
			t.Fatal("expected error for nil request")
		}
		if !strings.Contains(err.Error(), "approval request is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("request_not_found", func(t *testing.T) {
		f := newSignServiceFixture(t)
		svc := f.build(t)

		_, err := svc.ProcessApproval(ctx, "nonexistent", &ApprovalRequest{
			Approved:   true,
			ApprovedBy: "admin",
		})
		if err == nil {
			t.Fatal("expected error for nonexistent request")
		}
		if !strings.Contains(err.Error(), "failed to get request") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("request_not_in_authorizing_state", func(t *testing.T) {
		f := newSignServiceFixture(t)
		svc := f.build(t)

		// Seed a request in pending state (not authorizing)
		req := &types.SignRequest{
			ID:        "req-pending",
			ChainType: types.ChainTypeEVM,
			Status:    types.StatusPending,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := f.requestRepo.Create(ctx, req); err != nil {
			t.Fatalf("failed to seed request: %v", err)
		}

		_, err := svc.ProcessApproval(ctx, "req-pending", &ApprovalRequest{
			Approved:   true,
			ApprovedBy: "admin",
		})
		if err == nil {
			t.Fatal("expected error for non-authorizing request")
		}
		if !strings.Contains(err.Error(), "not pending approval") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("manual_rejection", func(t *testing.T) {
		f := newSignServiceFixture(t)
		svc := f.build(t)

		// Seed a request in authorizing state
		req := &types.SignRequest{
			ID:        "req-reject",
			ChainType: types.ChainTypeEVM,
			Status:    types.StatusAuthorizing,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := f.requestRepo.Create(ctx, req); err != nil {
			t.Fatalf("failed to seed request: %v", err)
		}

		resp, err := svc.ProcessApproval(ctx, "req-reject", &ApprovalRequest{
			Approved:   false,
			ApprovedBy: "admin",
		})
		if err != nil {
			t.Fatalf("ProcessApproval failed: %v", err)
		}
		if resp.SignResponse.Status != types.StatusRejected {
			t.Errorf("expected rejected status, got %q", resp.SignResponse.Status)
		}
		if !strings.Contains(resp.SignResponse.Message, "request rejected") {
			t.Errorf("unexpected message: %q", resp.SignResponse.Message)
		}
	})

	t.Run("manual_approval_signs_successfully", func(t *testing.T) {
		f := newSignServiceFixture(t)
		svc := f.build(t)

		// Seed a request in authorizing state
		req := &types.SignRequest{
			ID:            "req-approve",
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
			Status:        types.StatusAuthorizing,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		if err := f.requestRepo.Create(ctx, req); err != nil {
			t.Fatalf("failed to seed request: %v", err)
		}

		resp, err := svc.ProcessApproval(ctx, "req-approve", &ApprovalRequest{
			Approved:   true,
			ApprovedBy: "admin",
		})
		if err != nil {
			t.Fatalf("ProcessApproval failed: %v", err)
		}
		if resp.SignResponse.Status != types.StatusCompleted {
			t.Errorf("expected completed status, got %q", resp.SignResponse.Status)
		}
		if resp.SignResponse.Signature == nil {
			t.Error("expected non-nil signature")
		}
	})

	t.Run("manual_approval_with_rule_generation", func(t *testing.T) {
		f := newSignServiceFixture(t)

		// Set up approval service with a working rule generator
		recipient := "0xrecipient"
		genRule := &types.Rule{
			ID:   "gen-rule-from-approval",
			Name: "Allow: 0xrecipient",
			Type: types.RuleTypeEVMAddressList,
			Mode: types.RuleModeWhitelist,
		}
		ruleRepo := newMockRuleRepo()
		approvalSvc, err := NewApprovalService(
			ruleRepo,
			&mockRuleGenerator{
				genRule: genRule,
				types:   []types.RuleType{types.RuleTypeEVMAddressList},
			},
			&mockNotifier{},
			newTestLogger(),
		)
		if err != nil {
			t.Fatalf("failed to create approval service: %v", err)
		}
		f.approvalService = approvalSvc

		// Set up adapter to return parsed payload with recipient
		f.adapter.parsedPayload = &types.ParsedPayload{
			Recipient: &recipient,
		}

		svc := f.build(t)

		// Seed a request in authorizing state
		req := &types.SignRequest{
			ID:            "req-approve-gen",
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
			Status:        types.StatusAuthorizing,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		if err := f.requestRepo.Create(ctx, req); err != nil {
			t.Fatalf("failed to seed request: %v", err)
		}

		resp, err := svc.ProcessApproval(ctx, "req-approve-gen", &ApprovalRequest{
			Approved:   true,
			ApprovedBy: "admin",
			RuleOpts: &rule.RuleGenerateOptions{
				RuleType: types.RuleTypeEVMAddressList,
				RuleMode: types.RuleModeWhitelist,
			},
		})
		if err != nil {
			t.Fatalf("ProcessApproval failed: %v", err)
		}
		if resp.SignResponse.Status != types.StatusCompleted {
			t.Errorf("expected completed status, got %q", resp.SignResponse.Status)
		}
		if resp.GeneratedRule == nil {
			t.Error("expected generated rule")
		} else if resp.GeneratedRule.ID != genRule.ID {
			t.Errorf("expected rule ID %q, got %q", genRule.ID, resp.GeneratedRule.ID)
		}
	})

	t.Run("manual_approval_signing_fails", func(t *testing.T) {
		f := newSignServiceFixture(t)
		f.adapter.signErr = fmt.Errorf("signing hardware error")
		f.adapter.signResult = nil
		svc := f.build(t)

		req := &types.SignRequest{
			ID:            "req-approve-fail",
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
			Status:        types.StatusAuthorizing,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		if err := f.requestRepo.Create(ctx, req); err != nil {
			t.Fatalf("failed to seed request: %v", err)
		}

		_, err := svc.ProcessApproval(ctx, "req-approve-fail", &ApprovalRequest{
			Approved:   true,
			ApprovedBy: "admin",
		})
		if err == nil {
			t.Fatal("expected error when signing fails")
		}
		if !strings.Contains(err.Error(), "signing failed") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("manual_approval_rule_generation_fails_still_signs", func(t *testing.T) {
		f := newSignServiceFixture(t)

		// Set up approval service with a failing rule generator
		approvalSvc, err := NewApprovalService(
			newMockRuleRepo(),
			&mockRuleGenerator{
				genErr: fmt.Errorf("generation failed"),
				types:  []types.RuleType{types.RuleTypeEVMAddressList},
			},
			&mockNotifier{},
			newTestLogger(),
		)
		if err != nil {
			t.Fatalf("failed to create approval service: %v", err)
		}
		f.approvalService = approvalSvc
		svc := f.build(t)

		req := &types.SignRequest{
			ID:            "req-gen-fail",
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
			Status:        types.StatusAuthorizing,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		if err := f.requestRepo.Create(ctx, req); err != nil {
			t.Fatalf("failed to seed request: %v", err)
		}

		resp, err := svc.ProcessApproval(ctx, "req-gen-fail", &ApprovalRequest{
			Approved:   true,
			ApprovedBy: "admin",
			RuleOpts: &rule.RuleGenerateOptions{
				RuleType: types.RuleTypeEVMAddressList,
				RuleMode: types.RuleModeWhitelist,
			},
		})
		if err != nil {
			t.Fatalf("ProcessApproval should succeed even if rule gen fails: %v", err)
		}
		if resp.SignResponse.Status != types.StatusCompleted {
			t.Errorf("expected completed, got %q", resp.SignResponse.Status)
		}
		// Generated rule should be nil since generation failed
		if resp.GeneratedRule != nil {
			t.Error("expected nil generated rule when generation fails")
		}
	})

	t.Run("manual_approval_parse_payload_error_for_rule_gen", func(t *testing.T) {
		f := newSignServiceFixture(t)

		genRule := &types.Rule{
			ID:   "gen-rule-parse-err",
			Name: "Rule from parse error",
			Type: types.RuleTypeEVMAddressList,
			Mode: types.RuleModeWhitelist,
		}
		approvalSvc, err := NewApprovalService(
			newMockRuleRepo(),
			&mockRuleGenerator{
				genRule: genRule,
				types:   []types.RuleType{types.RuleTypeEVMAddressList},
			},
			&mockNotifier{},
			newTestLogger(),
		)
		if err != nil {
			t.Fatalf("failed to create approval service: %v", err)
		}
		f.approvalService = approvalSvc
		// Set parse error on the adapter
		f.adapter.parseErr = fmt.Errorf("parse error")
		f.adapter.parsedPayload = nil
		svc := f.build(t)

		req := &types.SignRequest{
			ID:            "req-parse-err-gen",
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
			Status:        types.StatusAuthorizing,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		if err := f.requestRepo.Create(ctx, req); err != nil {
			t.Fatalf("failed to seed request: %v", err)
		}

		resp, err := svc.ProcessApproval(ctx, "req-parse-err-gen", &ApprovalRequest{
			Approved:   true,
			ApprovedBy: "admin",
			RuleOpts: &rule.RuleGenerateOptions{
				RuleType: types.RuleTypeEVMAddressList,
				RuleMode: types.RuleModeWhitelist,
			},
		})
		if err != nil {
			t.Fatalf("ProcessApproval should succeed: %v", err)
		}
		if resp.SignResponse.Status != types.StatusCompleted {
			t.Errorf("expected completed, got %q", resp.SignResponse.Status)
		}
	})

	t.Run("approval_unsupported_chain_type", func(t *testing.T) {
		f := newSignServiceFixture(t)
		svc := f.build(t)

		// Seed a request with unknown chain type
		req := &types.SignRequest{
			ID:            "req-bad-chain",
			ChainType:     "unknown_chain",
			ChainID:       "1",
			SignerAddress: "0xsigner",
			Status:        types.StatusAuthorizing,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		if err := f.requestRepo.Create(ctx, req); err != nil {
			t.Fatalf("failed to seed request: %v", err)
		}

		_, err := svc.ProcessApproval(ctx, "req-bad-chain", &ApprovalRequest{
			Approved:   true,
			ApprovedBy: "admin",
		})
		if err == nil {
			t.Fatal("expected error for unsupported chain type")
		}
		if !strings.Contains(err.Error(), "unsupported chain type") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// TestPreviewRuleForRequest
// ---------------------------------------------------------------------------

func TestPreviewRuleForRequest(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		f := newSignServiceFixture(t)

		// Set up approval service with a preview-returning generator
		previewRule := &types.Rule{
			ID:   "preview-1",
			Name: "Preview Rule",
			Type: types.RuleTypeEVMAddressList,
		}
		approvalSvc, err := NewApprovalService(
			newMockRuleRepo(),
			&mockRuleGenerator{previewRule: previewRule, types: []types.RuleType{types.RuleTypeEVMAddressList}},
			&mockNotifier{},
			newTestLogger(),
		)
		if err != nil {
			t.Fatalf("failed to create approval service: %v", err)
		}
		f.approvalService = approvalSvc
		svc := f.build(t)

		// Seed a request in authorizing state
		req := &types.SignRequest{
			ID:            "req-preview",
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
			Status:        types.StatusAuthorizing,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		if err := f.requestRepo.Create(ctx, req); err != nil {
			t.Fatalf("failed to seed request: %v", err)
		}

		result, err := svc.PreviewRuleForRequest(ctx, "req-preview", &rule.RuleGenerateOptions{
			RuleType: types.RuleTypeEVMAddressList,
			RuleMode: types.RuleModeWhitelist,
		})
		if err != nil {
			t.Fatalf("PreviewRuleForRequest failed: %v", err)
		}
		if result.ID != previewRule.ID {
			t.Errorf("expected rule ID %q, got %q", previewRule.ID, result.ID)
		}
	})

	t.Run("request_not_found", func(t *testing.T) {
		f := newSignServiceFixture(t)
		svc := f.build(t)

		_, err := svc.PreviewRuleForRequest(ctx, "nonexistent", &rule.RuleGenerateOptions{})
		if err == nil {
			t.Fatal("expected error for nonexistent request")
		}
		if !strings.Contains(err.Error(), "failed to get request") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("request_not_in_authorizing_state", func(t *testing.T) {
		f := newSignServiceFixture(t)
		svc := f.build(t)

		req := &types.SignRequest{
			ID:        "req-completed",
			ChainType: types.ChainTypeEVM,
			Status:    types.StatusCompleted,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := f.requestRepo.Create(ctx, req); err != nil {
			t.Fatalf("failed to seed request: %v", err)
		}

		_, err := svc.PreviewRuleForRequest(ctx, "req-completed", &rule.RuleGenerateOptions{})
		if err == nil {
			t.Fatal("expected error for non-authorizing request")
		}
		if !strings.Contains(err.Error(), "not pending approval") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("parse_payload_error_uses_fallback", func(t *testing.T) {
		f := newSignServiceFixture(t)

		previewRule := &types.Rule{
			ID:   "preview-parse-err",
			Name: "Preview with parse error",
		}
		approvalSvc, err := NewApprovalService(
			newMockRuleRepo(),
			&mockRuleGenerator{previewRule: previewRule, types: []types.RuleType{types.RuleTypeEVMAddressList}},
			&mockNotifier{},
			newTestLogger(),
		)
		if err != nil {
			t.Fatalf("failed to create approval service: %v", err)
		}
		f.approvalService = approvalSvc
		f.adapter.parseErr = fmt.Errorf("parse error")
		f.adapter.parsedPayload = nil
		svc := f.build(t)

		req := &types.SignRequest{
			ID:            "req-preview-parse",
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
			Status:        types.StatusAuthorizing,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		if err := f.requestRepo.Create(ctx, req); err != nil {
			t.Fatalf("failed to seed request: %v", err)
		}

		result, err := svc.PreviewRuleForRequest(ctx, "req-preview-parse", &rule.RuleGenerateOptions{
			RuleType: types.RuleTypeEVMAddressList,
			RuleMode: types.RuleModeWhitelist,
		})
		if err != nil {
			t.Fatalf("PreviewRuleForRequest should succeed with parse fallback: %v", err)
		}
		if result.ID != previewRule.ID {
			t.Errorf("expected rule ID %q, got %q", previewRule.ID, result.ID)
		}
	})

	t.Run("preview_error", func(t *testing.T) {
		f := newSignServiceFixture(t)

		approvalSvc, err := NewApprovalService(
			newMockRuleRepo(),
			&mockRuleGenerator{previewErr: fmt.Errorf("preview internal error"), types: []types.RuleType{types.RuleTypeEVMAddressList}},
			&mockNotifier{},
			newTestLogger(),
		)
		if err != nil {
			t.Fatalf("failed to create approval service: %v", err)
		}
		f.approvalService = approvalSvc
		svc := f.build(t)

		req := &types.SignRequest{
			ID:            "req-preview-err",
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xsigner",
			SignType:      "eth_signTransaction",
			Payload:       []byte(`{}`),
			Status:        types.StatusAuthorizing,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		if err := f.requestRepo.Create(ctx, req); err != nil {
			t.Fatalf("failed to seed request: %v", err)
		}

		_, err = svc.PreviewRuleForRequest(ctx, "req-preview-err", &rule.RuleGenerateOptions{
			RuleType: types.RuleTypeEVMAddressList,
			RuleMode: types.RuleModeWhitelist,
		})
		if err == nil {
			t.Fatal("expected error from preview")
		}
		if !strings.Contains(err.Error(), "failed to preview rule") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("unsupported_chain_type_in_preview", func(t *testing.T) {
		f := newSignServiceFixture(t)
		svc := f.build(t)

		req := &types.SignRequest{
			ID:        "req-preview-bad-chain",
			ChainType: "unknown_chain",
			Status:    types.StatusAuthorizing,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := f.requestRepo.Create(ctx, req); err != nil {
			t.Fatalf("failed to seed request: %v", err)
		}

		_, err := svc.PreviewRuleForRequest(ctx, "req-preview-bad-chain", &rule.RuleGenerateOptions{
			RuleType: types.RuleTypeEVMAddressList,
			RuleMode: types.RuleModeWhitelist,
		})
		if err == nil {
			t.Fatal("expected error for unsupported chain type")
		}
		if !strings.Contains(err.Error(), "unsupported chain type") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
