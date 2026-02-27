package service

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ---------------------------------------------------------------------------
// Mock notifier
// ---------------------------------------------------------------------------

type mockNotifier struct {
	called bool
	err    error
}

func (n *mockNotifier) SendApprovalRequest(_ context.Context, _ *types.SignRequest) error {
	n.called = true
	return n.err
}

// ---------------------------------------------------------------------------
// Mock rule generator
// ---------------------------------------------------------------------------

type mockRuleGenerator struct {
	previewRule *types.Rule
	previewErr  error
	genRule     *types.Rule
	genErr      error
	types       []types.RuleType
}

func (g *mockRuleGenerator) Preview(_ *types.SignRequest, _ *types.ParsedPayload, _ *rule.RuleGenerateOptions) (*types.Rule, error) {
	return g.previewRule, g.previewErr
}

func (g *mockRuleGenerator) Generate(_ *types.SignRequest, _ *types.ParsedPayload, _ *rule.RuleGenerateOptions) (*types.Rule, error) {
	return g.genRule, g.genErr
}

func (g *mockRuleGenerator) SupportedTypes() []types.RuleType {
	return g.types
}

// ---------------------------------------------------------------------------
// TestNewApprovalService
// ---------------------------------------------------------------------------

func TestNewApprovalService(t *testing.T) {
	ruleRepo := newMockRuleRepo()
	gen := &mockRuleGenerator{}
	notif := &mockNotifier{}
	logger := newTestLogger()

	t.Run("all_valid_args", func(t *testing.T) {
		svc, err := NewApprovalService(ruleRepo, gen, notif, logger)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
	})

	t.Run("nil_rule_repo", func(t *testing.T) {
		_, err := NewApprovalService(nil, gen, notif, logger)
		if err == nil {
			t.Fatal("expected error for nil rule repository")
		}
		if !strings.Contains(err.Error(), "rule repository is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nil_rule_generator", func(t *testing.T) {
		_, err := NewApprovalService(ruleRepo, nil, notif, logger)
		if err == nil {
			t.Fatal("expected error for nil rule generator")
		}
		if !strings.Contains(err.Error(), "rule generator is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nil_notifier", func(t *testing.T) {
		_, err := NewApprovalService(ruleRepo, gen, nil, logger)
		if err == nil {
			t.Fatal("expected error for nil notifier")
		}
		if !strings.Contains(err.Error(), "notifier is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nil_logger", func(t *testing.T) {
		_, err := NewApprovalService(ruleRepo, gen, notif, nil)
		if err == nil {
			t.Fatal("expected error for nil logger")
		}
		if !strings.Contains(err.Error(), "logger is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// TestRequestApproval
// ---------------------------------------------------------------------------

func TestRequestApproval(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		notif := &mockNotifier{}
		svc, err := NewApprovalService(newMockRuleRepo(), &mockRuleGenerator{}, notif, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		req := &types.SignRequest{
			ID:            "req-1",
			ChainType:     types.ChainTypeEVM,
			SignerAddress: "0x1234567890abcdef1234567890abcdef12345678",
		}
		if err := svc.RequestApproval(ctx, req); err != nil {
			t.Fatalf("RequestApproval failed: %v", err)
		}
		if !notif.called {
			t.Error("expected notifier to be called")
		}
	})

	t.Run("nil_request", func(t *testing.T) {
		svc, err := NewApprovalService(newMockRuleRepo(), &mockRuleGenerator{}, &mockNotifier{}, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		err = svc.RequestApproval(ctx, nil)
		if err == nil {
			t.Fatal("expected error for nil request")
		}
		if !strings.Contains(err.Error(), "request is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("notifier_error", func(t *testing.T) {
		notif := &mockNotifier{err: fmt.Errorf("send failed")}
		svc, err := NewApprovalService(newMockRuleRepo(), &mockRuleGenerator{}, notif, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		req := &types.SignRequest{ID: "req-2"}
		err = svc.RequestApproval(ctx, req)
		if err == nil {
			t.Fatal("expected error from notifier")
		}
		if !strings.Contains(err.Error(), "failed to send approval notification") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// TestPreviewRule
// ---------------------------------------------------------------------------

func TestPreviewRule(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		expectedRule := &types.Rule{
			ID:   "preview_123",
			Name: "Preview Rule",
			Type: types.RuleTypeEVMAddressList,
			Mode: types.RuleModeWhitelist,
		}
		gen := &mockRuleGenerator{previewRule: expectedRule}
		svc, err := NewApprovalService(newMockRuleRepo(), gen, &mockNotifier{}, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		req := &types.SignRequest{ID: "req-1", ChainType: types.ChainTypeEVM}
		parsed := &types.ParsedPayload{}
		opts := &rule.RuleGenerateOptions{
			RuleType: types.RuleTypeEVMAddressList,
			RuleMode: types.RuleModeWhitelist,
		}

		result, err := svc.PreviewRule(ctx, req, parsed, opts)
		if err != nil {
			t.Fatalf("PreviewRule failed: %v", err)
		}
		if result.ID != expectedRule.ID {
			t.Errorf("expected rule ID %q, got %q", expectedRule.ID, result.ID)
		}
	})

	t.Run("nil_request", func(t *testing.T) {
		svc, err := NewApprovalService(newMockRuleRepo(), &mockRuleGenerator{}, &mockNotifier{}, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.PreviewRule(ctx, nil, nil, &rule.RuleGenerateOptions{})
		if err == nil {
			t.Fatal("expected error for nil request")
		}
		if !strings.Contains(err.Error(), "request is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nil_options", func(t *testing.T) {
		svc, err := NewApprovalService(newMockRuleRepo(), &mockRuleGenerator{}, &mockNotifier{}, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		req := &types.SignRequest{ID: "req-1"}
		_, err = svc.PreviewRule(ctx, req, nil, nil)
		if err == nil {
			t.Fatal("expected error for nil options")
		}
		if !strings.Contains(err.Error(), "options are required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("generator_error", func(t *testing.T) {
		gen := &mockRuleGenerator{previewErr: fmt.Errorf("preview failed")}
		svc, err := NewApprovalService(newMockRuleRepo(), gen, &mockNotifier{}, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		req := &types.SignRequest{ID: "req-1"}
		opts := &rule.RuleGenerateOptions{
			RuleType: types.RuleTypeEVMAddressList,
			RuleMode: types.RuleModeWhitelist,
		}
		_, err = svc.PreviewRule(ctx, req, nil, opts)
		if err == nil {
			t.Fatal("expected error from generator")
		}
		if !strings.Contains(err.Error(), "failed to generate rule preview") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// TestGenerateRule
// ---------------------------------------------------------------------------

func TestGenerateRule(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		genRule := &types.Rule{
			ID:   "gen-rule-1",
			Name: "Generated Rule",
			Type: types.RuleTypeEVMAddressList,
			Mode: types.RuleModeWhitelist,
		}
		gen := &mockRuleGenerator{genRule: genRule}
		ruleRepo := newMockRuleRepo()
		svc, err := NewApprovalService(ruleRepo, gen, &mockNotifier{}, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		req := &types.SignRequest{ID: "req-1", ChainType: types.ChainTypeEVM}
		parsed := &types.ParsedPayload{}
		opts := &rule.RuleGenerateOptions{
			RuleType: types.RuleTypeEVMAddressList,
			RuleMode: types.RuleModeWhitelist,
		}

		result, err := svc.GenerateRule(ctx, req, parsed, opts)
		if err != nil {
			t.Fatalf("GenerateRule failed: %v", err)
		}
		if result.ID != genRule.ID {
			t.Errorf("expected rule ID %q, got %q", genRule.ID, result.ID)
		}

		// Rule should be persisted in repo
		_, err = ruleRepo.Get(ctx, genRule.ID)
		if err != nil {
			t.Errorf("rule should be in repo: %v", err)
		}
	})

	t.Run("nil_request", func(t *testing.T) {
		svc, err := NewApprovalService(newMockRuleRepo(), &mockRuleGenerator{}, &mockNotifier{}, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.GenerateRule(ctx, nil, nil, &rule.RuleGenerateOptions{})
		if err == nil {
			t.Fatal("expected error for nil request")
		}
		if !strings.Contains(err.Error(), "request is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nil_options", func(t *testing.T) {
		svc, err := NewApprovalService(newMockRuleRepo(), &mockRuleGenerator{}, &mockNotifier{}, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		req := &types.SignRequest{ID: "req-1"}
		_, err = svc.GenerateRule(ctx, req, nil, nil)
		if err == nil {
			t.Fatal("expected error for nil options")
		}
		if !strings.Contains(err.Error(), "options are required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("generator_error", func(t *testing.T) {
		gen := &mockRuleGenerator{genErr: fmt.Errorf("generation failed")}
		svc, err := NewApprovalService(newMockRuleRepo(), gen, &mockNotifier{}, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		req := &types.SignRequest{ID: "req-1"}
		opts := &rule.RuleGenerateOptions{
			RuleType: types.RuleTypeEVMAddressList,
			RuleMode: types.RuleModeWhitelist,
		}
		_, err = svc.GenerateRule(ctx, req, nil, opts)
		if err == nil {
			t.Fatal("expected error from generator")
		}
		if !strings.Contains(err.Error(), "failed to generate rule") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("repo_create_error", func(t *testing.T) {
		genRule := &types.Rule{
			ID:   "gen-dup",
			Name: "Dup Rule",
			Type: types.RuleTypeEVMAddressList,
			Mode: types.RuleModeWhitelist,
		}
		gen := &mockRuleGenerator{genRule: genRule}
		ruleRepo := newMockRuleRepo()
		// Pre-seed the same rule ID to cause a conflict
		seedRule(t, ruleRepo, &types.Rule{ID: genRule.ID, Name: "Existing"})

		svc, err := NewApprovalService(ruleRepo, gen, &mockNotifier{}, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		req := &types.SignRequest{ID: "req-1"}
		opts := &rule.RuleGenerateOptions{
			RuleType: types.RuleTypeEVMAddressList,
			RuleMode: types.RuleModeWhitelist,
		}
		_, err = svc.GenerateRule(ctx, req, nil, opts)
		if err == nil {
			t.Fatal("expected error from repo create")
		}
		if !strings.Contains(err.Error(), "failed to create rule") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// TestSupportedRuleTypes
// ---------------------------------------------------------------------------

func TestSupportedRuleTypes(t *testing.T) {
	expectedTypes := []types.RuleType{
		types.RuleTypeEVMAddressList,
		types.RuleTypeEVMContractMethod,
	}
	gen := &mockRuleGenerator{types: expectedTypes}
	svc, err := NewApprovalService(newMockRuleRepo(), gen, &mockNotifier{}, newTestLogger())
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	result := svc.SupportedRuleTypes()
	if len(result) != len(expectedTypes) {
		t.Errorf("expected %d types, got %d", len(expectedTypes), len(result))
	}
	for i, rt := range result {
		if rt != expectedTypes[i] {
			t.Errorf("type[%d]: expected %q, got %q", i, expectedTypes[i], rt)
		}
	}
}

// ---------------------------------------------------------------------------
// TestNoopNotifier
// ---------------------------------------------------------------------------

func TestNoopNotifier(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		n, err := NewNoopNotifier()
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if n == nil {
			t.Fatal("expected non-nil notifier")
		}
	})

	t.Run("send_returns_nil", func(t *testing.T) {
		n := &NoopNotifier{}
		err := n.SendApprovalRequest(context.Background(), &types.SignRequest{ID: "req-1"})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
	})
}
