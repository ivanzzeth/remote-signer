package config

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// =============================================================================
// Template repository mock
// =============================================================================

type stubTemplateRepo struct {
	getByNameFn    func(ctx context.Context, name string) (*types.RuleTemplate, error)
	getByNameCalls []string
}

func (s *stubTemplateRepo) Create(_ context.Context, _ *types.RuleTemplate) error { return nil }
func (s *stubTemplateRepo) Get(_ context.Context, _ string) (*types.RuleTemplate, error) {
	return nil, types.ErrNotFound
}
func (s *stubTemplateRepo) GetByName(ctx context.Context, name string) (*types.RuleTemplate, error) {
	s.getByNameCalls = append(s.getByNameCalls, name)
	if s.getByNameFn != nil {
		return s.getByNameFn(ctx, name)
	}
	return nil, types.ErrNotFound
}
func (s *stubTemplateRepo) Update(_ context.Context, _ *types.RuleTemplate) error { return nil }
func (s *stubTemplateRepo) Delete(_ context.Context, _ string) error              { return nil }
func (s *stubTemplateRepo) List(_ context.Context, _ storage.TemplateFilter) ([]*types.RuleTemplate, error) {
	return nil, nil
}
func (s *stubTemplateRepo) Count(_ context.Context, _ storage.TemplateFilter) (int, error) { return 0, nil }
func (s *stubTemplateRepo) Upsert(_ context.Context, _ *types.RuleTemplate) (bool, error) { return false, nil }
func (s *stubTemplateRepo) ListIDsBySource(_ context.Context, _ types.RuleSource) ([]string, error) {
	return nil, nil
}
func (s *stubTemplateRepo) GetByIDOrName(_ context.Context, _ string) (*types.RuleTemplate, error) {
	return nil, types.ErrNotFound
}
func (s *stubTemplateRepo) DeleteMany(_ context.Context, _ []string) error { return nil }

// Verify stubTemplateRepo implements TemplateRepository
var _ storage.TemplateRepository = (*stubTemplateRepo)(nil)

// =============================================================================
// errorGetByRuleIDRepo: returns a custom error from GetByRuleID
// =============================================================================

type errorGetByRuleIDRepo struct {
	*spyBudgetRepo
	getByRuleIDErr error
}

func (e *errorGetByRuleIDRepo) GetByRuleID(_ context.Context, _ types.RuleID, _ string) (*types.RuleBudget, error) {
	return nil, e.getByRuleIDErr
}

// =============================================================================
// stubBudgetRepo: spy with error injection for Create/Delete/CreateOrGet
// =============================================================================

type stubBudgetRepo struct {
	*spyBudgetRepo
	createErr     error
	createOrGetFn func(ctx context.Context, budget *types.RuleBudget) (*types.RuleBudget, bool, error)
	deleteErr     error
}

func (s *stubBudgetRepo) Create(ctx context.Context, budget *types.RuleBudget) error {
	if s.spyBudgetRepo != nil {
		s.spyBudgetRepo.createCalls = append(s.spyBudgetRepo.createCalls, budget)
	}
	if s.createErr != nil {
		return s.createErr
	}
	return nil
}

func (s *stubBudgetRepo) CreateOrGet(ctx context.Context, budget *types.RuleBudget) (*types.RuleBudget, bool, error) {
	if s.createOrGetFn != nil {
		return s.createOrGetFn(ctx, budget)
	}
	if s.spyBudgetRepo != nil {
		return s.spyBudgetRepo.CreateOrGet(ctx, budget)
	}
	return budget, true, nil
}

func (s *stubBudgetRepo) Delete(ctx context.Context, id string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	if s.spyBudgetRepo != nil {
		s.spyBudgetRepo.deleteCalls = append(s.spyBudgetRepo.deleteCalls, id)
	}
	return nil
}

func (s *stubBudgetRepo) DeleteByRuleID(ctx context.Context, id types.RuleID) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	if s.spyBudgetRepo != nil {
		s.spyBudgetRepo.deleteByRuleIDCalls = append(s.spyBudgetRepo.deleteByRuleIDCalls, id)
	}
	return nil
}
func (s *stubBudgetRepo) AtomicSpend(_ context.Context, _ types.RuleID, _, _ string) error { return nil }
func (s *stubBudgetRepo) ResetBudget(_ context.Context, _ types.RuleID, _ string, _ time.Time) error {
	return nil
}
func (s *stubBudgetRepo) MarkAlertSent(_ context.Context, _ types.RuleID, _ string) error { return nil }
func (s *stubBudgetRepo) CountByRuleID(_ context.Context, _ types.RuleID) (int, error)   { return 0, nil }
func (s *stubBudgetRepo) Get(_ context.Context, _ string) (*types.RuleBudget, error)     { return nil, types.ErrNotFound }
func (s *stubBudgetRepo) Update(_ context.Context, _ *types.RuleBudget) error            { return nil }
func (s *stubBudgetRepo) GetByRuleID(ctx context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error) {
	if s.spyBudgetRepo != nil {
		return s.spyBudgetRepo.GetByRuleID(ctx, ruleID, unit)
	}
	return nil, types.ErrNotFound
}
func (s *stubBudgetRepo) ListByRuleID(ctx context.Context, ruleID types.RuleID) ([]*types.RuleBudget, error) {
	if s.spyBudgetRepo != nil {
		return s.spyBudgetRepo.ListByRuleID(ctx, ruleID)
	}
	return nil, nil
}
func (s *stubBudgetRepo) ListByRuleIDs(_ context.Context, _ []types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (s *stubBudgetRepo) ListAll(_ context.Context) ([]*types.RuleBudget, error) { return nil, nil }

// =============================================================================
// preloadTemplatesForSync tests (12.5% → 90%+)
// =============================================================================

func TestPreloadTemplatesForSync_NilTemplateRepo(t *testing.T) {
	init, _ := newTestRuleInit(t)
	result := init.preloadTemplatesForSync(context.Background(), nil)
	assert.Nil(t, result)
}

func TestPreloadTemplatesForSync_NoInstanceRules(t *testing.T) {
	init, _ := newTestRuleInit(t)
	init.SetTemplateRepo(&stubTemplateRepo{})
	rules := []RuleConfig{
		enabledRule("rule-1", "Rule 1", "whitelist"),
	}
	result := init.preloadTemplatesForSync(context.Background(), rules)
	assert.Nil(t, result, "no __template_name in config → no templates to load")
}

func TestPreloadTemplatesForSync_TemplateFound(t *testing.T) {
	init, _ := newTestRuleInit(t)
	tmpl := &types.RuleTemplate{ID: "tmpl-agent", Name: "agent"}
	stub := &stubTemplateRepo{
		getByNameFn: func(_ context.Context, name string) (*types.RuleTemplate, error) {
			if name == "agent" {
				return tmpl, nil
			}
			return nil, types.ErrNotFound
		},
	}
	init.SetTemplateRepo(stub)

	rules := []RuleConfig{
		enabledRule("rule-1", "Rule 1", "whitelist"),
	}
	rules[0].Config["__template_name"] = "agent"

	result := init.preloadTemplatesForSync(context.Background(), rules)
	require.NotNil(t, result)
	assert.Equal(t, tmpl, result["agent"])
	assert.Contains(t, stub.getByNameCalls, "agent")
}

func TestPreloadTemplatesForSync_TemplateNotFound(t *testing.T) {
	init, _ := newTestRuleInit(t)
	stub := &stubTemplateRepo{}
	init.SetTemplateRepo(stub)

	rules := []RuleConfig{
		enabledRule("rule-1", "Rule 1", "whitelist"),
	}
	rules[0].Config["__template_name"] = "nonexistent"

	result := init.preloadTemplatesForSync(context.Background(), rules)
	assert.NotNil(t, result)
	assert.Empty(t, result, "template not found → not in map")
}

func TestPreloadTemplatesForSync_EmptyTemplateName(t *testing.T) {
	init, _ := newTestRuleInit(t)
	init.SetTemplateRepo(&stubTemplateRepo{})

	rules := []RuleConfig{
		enabledRule("rule-1", "Rule 1", "whitelist"),
	}
	rules[0].Config["__template_name"] = ""

	result := init.preloadTemplatesForSync(context.Background(), rules)
	assert.Nil(t, result, "empty template name → skip")
}

func TestPreloadTemplatesForSync_MultipleTemplates(t *testing.T) {
	init, _ := newTestRuleInit(t)
	tmplA := &types.RuleTemplate{ID: "tmpl-a", Name: "template-a"}
	tmplB := &types.RuleTemplate{ID: "tmpl-b", Name: "template-b"}
	stub := &stubTemplateRepo{
		getByNameFn: func(_ context.Context, name string) (*types.RuleTemplate, error) {
			switch name {
			case "template-a":
				return tmplA, nil
			case "template-b":
				return tmplB, nil
			default:
				return nil, types.ErrNotFound
			}
		},
	}
	init.SetTemplateRepo(stub)

	rules := []RuleConfig{
		enabledRule("rule-1", "Rule 1", "whitelist"),
		enabledRule("rule-2", "Rule 2", "whitelist"),
	}
	rules[0].Config["__template_name"] = "template-a"
	rules[1].Config["__template_name"] = "template-b"

	result := init.preloadTemplatesForSync(context.Background(), rules)
	require.NotNil(t, result)
	assert.Len(t, result, 2)
	assert.Equal(t, tmplA, result["template-a"])
	assert.Equal(t, tmplB, result["template-b"])
}

func TestPreloadTemplatesForSync_NilConfig(t *testing.T) {
	init, _ := newTestRuleInit(t)
	init.SetTemplateRepo(&stubTemplateRepo{})

	rules := []RuleConfig{
		{Id: "nil-config-rule", Name: "Nil Config", Type: "evm_address_list", Mode: "whitelist", Enabled: true, Config: nil},
	}
	result := init.preloadTemplatesForSync(context.Background(), rules)
	assert.Nil(t, result)
}

// =============================================================================
// validateSkipBreakingChanges tests (42.9% → 90%+)
// =============================================================================

func TestValidateSkipBreakingChanges_ValidConfig(t *testing.T) {
	cfg := validConfig()
	err := validateSkipBreakingChanges(cfg)
	assert.NoError(t, err)
}

func TestValidateSkipBreakingChanges_InvalidPortZero(t *testing.T) {
	cfg := validConfig()
	cfg.Server.Port = 0
	err := validateSkipBreakingChanges(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid server port")
}

func TestValidateSkipBreakingChanges_InvalidPortTooHigh(t *testing.T) {
	cfg := validConfig()
	cfg.Server.Port = 70000
	err := validateSkipBreakingChanges(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid server port")
}

func TestValidateSkipBreakingChanges_EmptyDSN(t *testing.T) {
	cfg := validConfig()
	cfg.Database.DSN = ""
	err := validateSkipBreakingChanges(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database DSN is required")
}

func TestValidateSkipBreakingChanges_NoChainEnabled_NilEVM(t *testing.T) {
	cfg := validConfig()
	cfg.Chains.EVM = nil
	err := validateSkipBreakingChanges(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one chain must be enabled")
}

func TestValidateSkipBreakingChanges_NoChainEnabled_EVMDisabled(t *testing.T) {
	cfg := validConfig()
	cfg.Chains.EVM.Enabled = false
	err := validateSkipBreakingChanges(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one chain must be enabled")
}

func TestValidateSkipBreakingChanges_TLSEnabledMissingCert(t *testing.T) {
	cfg := validConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.KeyFile = "/some/key"
	err := validateSkipBreakingChanges(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cert_file is not set")
}

func TestValidateSkipBreakingChanges_TLSEnabledMissingKey(t *testing.T) {
	cfg := validConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = "/some/cert"
	err := validateSkipBreakingChanges(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key_file is not set")
}

func TestValidateSkipBreakingChanges_TLSEnabledMissingCA(t *testing.T) {
	cfg := validConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = "/some/cert"
	cfg.Server.TLS.KeyFile = "/some/key"
	err := validateSkipBreakingChanges(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca_file is not set")
}

func TestValidateSkipBreakingChanges_TLSValid(t *testing.T) {
	cfg := validConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = "/some/cert"
	cfg.Server.TLS.KeyFile = "/some/key"
	cfg.Server.TLS.CAFile = "/some/ca"
	err := validateSkipBreakingChanges(cfg)
	assert.NoError(t, err)
}

// =============================================================================
// syncRule tests (69.7% → 90%+)
// =============================================================================

func TestSyncRule_InvalidMode(t *testing.T) {
	init, _ := newTestRuleInit(t)
	ctx := context.Background()

	ruleCfg := enabledRule("test-rule", "Test Rule", "invalid_mode")
	err := init.syncRule(ctx, init.repo, types.RuleID("test-rule"), ruleCfg, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mode must be whitelist or blocklist")
}

func TestSyncRule_InvalidChainType(t *testing.T) {
	init, _ := newTestRuleInit(t)
	ctx := context.Background()

	ruleCfg := enabledRule("test-rule", "Test Rule", "whitelist")
	ruleCfg.ChainType = "invalid_chain"
	err := init.syncRule(ctx, init.repo, types.RuleID("test-rule"), ruleCfg, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid chain_type")
}

func TestSyncRule_InvalidSignerAddress(t *testing.T) {
	init, _ := newTestRuleInit(t)
	ctx := context.Background()

	ruleCfg := enabledRule("test-rule", "Test Rule", "whitelist")
	ruleCfg.SignerAddress = "not-a-valid-address"
	err := init.syncRule(ctx, init.repo, types.RuleID("test-rule"), ruleCfg, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signer_address")
}

func TestSyncRule_ValidSignerAddress(t *testing.T) {
	init, _ := newTestRuleInit(t)
	ctx := context.Background()

	ruleCfg := enabledRule("test-rule", "Test Rule", "whitelist")
	ruleCfg.SignerAddress = "0x1234567890abcdef1234567890abcdef12345678"
	err := init.syncRule(ctx, init.repo, types.RuleID("test-rule"), ruleCfg, nil, nil)
	require.NoError(t, err)

	rule, err := init.repo.Get(ctx, types.RuleID("test-rule"))
	require.NoError(t, err)
	require.NotNil(t, rule.SignerAddress)
	assert.Equal(t, "0x1234567890abcdef1234567890abcdef12345678", *rule.SignerAddress)
}

func TestSyncRule_InvalidRuleConfig(t *testing.T) {
	init, _ := newTestRuleInit(t)
	ctx := context.Background()

	ruleCfg := RuleConfig{
		Id:      "test-rule",
		Name:    "Test Rule",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{}, // empty config for address_list (requires addresses)
	}
	err := init.syncRule(ctx, init.repo, types.RuleID("test-rule"), ruleCfg, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "addresses")
}

func TestSyncRule_CreateNewRule(t *testing.T) {
	init, _ := newTestRuleInit(t)
	ctx := context.Background()

	ruleCfg := enabledRule("new-rule", "New Rule", "whitelist")
	err := init.syncRule(ctx, init.repo, types.RuleID("new-rule"), ruleCfg, nil, nil)
	require.NoError(t, err)

	rule, err := init.repo.Get(ctx, types.RuleID("new-rule"))
	require.NoError(t, err)
	assert.Equal(t, "New Rule", rule.Name)
	assert.Equal(t, types.RuleSourceConfig, rule.Source)
	assert.Equal(t, types.RuleStatusActive, rule.Status)
	assert.Equal(t, "config", rule.Owner)
}

func TestSyncRule_UpdateExistingRule(t *testing.T) {
	init, _ := newTestRuleInit(t)
	ctx := context.Background()

	ruleCfg := enabledRule("update-rule", "Original Name", "whitelist")
	require.NoError(t, init.syncRule(ctx, init.repo, types.RuleID("update-rule"), ruleCfg, nil, nil))

	ruleCfg.Name = "Updated Name"
	ruleCfg.Mode = "blocklist"
	require.NoError(t, init.syncRule(ctx, init.repo, types.RuleID("update-rule"), ruleCfg, nil, nil))

	rule, err := init.repo.Get(ctx, types.RuleID("update-rule"))
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", rule.Name)
	assert.Equal(t, types.RuleMode("blocklist"), rule.Mode)
}

func TestSyncRule_DBGetNotFoundCreates(t *testing.T) {
	init, _ := newTestRuleInit(t)
	ctx := context.Background()

	ruleID := types.RuleID("nonexistent-rule")
	_, err := init.repo.Get(ctx, ruleID)
	assert.True(t, types.IsNotFound(err))

	ruleCfg := enabledRule("nonexistent-rule", "Create from nil", "whitelist")
	err = init.syncRule(ctx, init.repo, ruleID, ruleCfg, nil, nil)
	require.NoError(t, err)

	rule, err := init.repo.Get(ctx, ruleID)
	require.NoError(t, err)
	assert.Equal(t, "Create from nil", rule.Name)
}

func TestSyncRule_WithInstanceTemplate(t *testing.T) {
	init, _ := newTestRuleInit(t)
	ctx := context.Background()

	tmpl := &types.RuleTemplate{
		ID:             "tmpl-agent",
		Name:           "agent",
		BudgetMetering: []byte(`{"method":"count_only","unit":"native"}`),
	}
	stubTmpl := &stubTemplateRepo{
		getByNameFn: func(_ context.Context, name string) (*types.RuleTemplate, error) {
			if name == "agent" {
				return tmpl, nil
			}
			return nil, types.ErrNotFound
		},
	}
	init.SetTemplateRepo(stubTmpl)
	init.SetBudgetRepo(&spyBudgetRepo{})

	ruleCfg := enabledRule("instance-rule", "Instance Rule", "whitelist")
	ruleCfg.Config["__template_name"] = "agent"
	ruleCfg.Config["__budget"] = map[string]interface{}{
		"unit":      "native",
		"max_total": "100",
	}
	ruleCfg.Config["__schedule"] = map[string]interface{}{
		"period": "1h",
	}

	templatesByName := map[string]*types.RuleTemplate{"agent": tmpl}
	var pendingBudgets []pendingBudgetCreate

	err := init.syncRule(ctx, init.repo, types.RuleID("instance-rule"), ruleCfg, templatesByName, &pendingBudgets)
	require.NoError(t, err)

	rule, err := init.repo.Get(ctx, types.RuleID("instance-rule"))
	require.NoError(t, err)
	require.NotNil(t, rule.TemplateID)
	assert.Equal(t, tmpl.ID, *rule.TemplateID)
	assert.Len(t, pendingBudgets, 1)
	assert.Equal(t, types.RuleID("instance-rule"), pendingBudgets[0].Rule.ID)
	require.NotNil(t, rule.BudgetPeriod)
	assert.Equal(t, 1*time.Hour, *rule.BudgetPeriod)
}

func TestSyncRule_WithInstanceTemplateNoBudgetRepo(t *testing.T) {
	init, _ := newTestRuleInit(t)
	ctx := context.Background()

	tmpl := &types.RuleTemplate{
		ID:             "tmpl-agent",
		Name:           "agent",
		BudgetMetering: []byte(`{"method":"count_only","unit":"native"}`),
	}
	stubTmpl := &stubTemplateRepo{
		getByNameFn: func(_ context.Context, name string) (*types.RuleTemplate, error) {
			if name == "agent" {
				return tmpl, nil
			}
			return nil, types.ErrNotFound
		},
	}
	init.SetTemplateRepo(stubTmpl)

	ruleCfg := enabledRule("instance-rule-2", "Instance Rule 2", "whitelist")
	ruleCfg.Config["__template_name"] = "agent"
	ruleCfg.Config["__budget"] = map[string]interface{}{
		"unit":      "native",
		"max_total": "100",
	}

	templatesByName := map[string]*types.RuleTemplate{"agent": tmpl}

	err := init.syncRule(ctx, init.repo, types.RuleID("instance-rule-2"), ruleCfg, templatesByName, nil)
	require.NoError(t, err)

	rule, err := init.repo.Get(ctx, types.RuleID("instance-rule-2"))
	require.NoError(t, err)
	require.NotNil(t, rule.TemplateID)
	assert.Equal(t, tmpl.ID, *rule.TemplateID)
}

func TestSyncRule_WithChainIDInjection(t *testing.T) {
	init, _ := newTestRuleInit(t)
	ctx := context.Background()

	ruleCfg := enabledRule("chain-rule", "Chain Rule", "whitelist")
	ruleCfg.ChainID = "137"

	err := init.syncRule(ctx, init.repo, types.RuleID("chain-rule"), ruleCfg, nil, nil)
	require.NoError(t, err)

	rule, err := init.repo.Get(ctx, types.RuleID("chain-rule"))
	require.NoError(t, err)
	require.NotNil(t, rule.ChainID)
	assert.Equal(t, "137", *rule.ChainID)
	assert.Contains(t, string(rule.Variables), `"chain_id"`)
	assert.Contains(t, string(rule.Variables), `"137"`)
}

func TestSyncRule_WithVariables(t *testing.T) {
	init, _ := newTestRuleInit(t)
	ctx := context.Background()

	ruleCfg := enabledRule("var-rule", "Var Rule", "whitelist")
	ruleCfg.Variables = map[string]interface{}{
		"custom_var": "custom_value",
	}

	err := init.syncRule(ctx, init.repo, types.RuleID("var-rule"), ruleCfg, nil, nil)
	require.NoError(t, err)

	rule, err := init.repo.Get(ctx, types.RuleID("var-rule"))
	require.NoError(t, err)
	assert.Contains(t, string(rule.Variables), `"custom_var"`)
	assert.Contains(t, string(rule.Variables), `"custom_value"`)
}

func TestSyncRule_InstanceTemplateFallbackToTemplateRepo(t *testing.T) {
	init, _ := newTestRuleInit(t)
	ctx := context.Background()

	tmpl := &types.RuleTemplate{ID: "tmpl-fallback", Name: "fallback-template"}
	stubTmpl := &stubTemplateRepo{
		getByNameFn: func(_ context.Context, name string) (*types.RuleTemplate, error) {
			if name == "fallback-template" {
				return tmpl, nil
			}
			return nil, types.ErrNotFound
		},
	}
	init.SetTemplateRepo(stubTmpl)

	ruleCfg := enabledRule("fallback-rule", "Fallback Rule", "whitelist")
	ruleCfg.Config["__template_name"] = "fallback-template"

	// templatesByName is nil, so it falls back to templateRepo.GetByName
	err := init.syncRule(ctx, init.repo, types.RuleID("fallback-rule"), ruleCfg, nil, nil)
	require.NoError(t, err)

	rule, err := init.repo.Get(ctx, types.RuleID("fallback-rule"))
	require.NoError(t, err)
	require.NotNil(t, rule.TemplateID)
	assert.Equal(t, tmpl.ID, *rule.TemplateID)
}

func TestSyncRule_ScheduleWithStartAt(t *testing.T) {
	init, _ := newTestRuleInit(t)
	ctx := context.Background()

	ruleCfg := enabledRule("schedule-rule", "Schedule Rule", "whitelist")
	ruleCfg.Config["__schedule"] = map[string]interface{}{
		"period":   "24h",
		"start_at": "2025-01-01T00:00:00Z",
	}

	err := init.syncRule(ctx, init.repo, types.RuleID("schedule-rule"), ruleCfg, nil, nil)
	require.NoError(t, err)

	rule, err := init.repo.Get(ctx, types.RuleID("schedule-rule"))
	require.NoError(t, err)
	require.NotNil(t, rule.BudgetPeriod)
	assert.Equal(t, 24*time.Hour, *rule.BudgetPeriod)
	expectedStart := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, expectedStart, *rule.BudgetPeriodStart)
}

func TestSyncRule_ScheduleInvalidPeriodIgnored(t *testing.T) {
	init, _ := newTestRuleInit(t)
	ctx := context.Background()

	ruleCfg := enabledRule("bad-period-rule", "Bad Period", "whitelist")
	ruleCfg.Config["__schedule"] = map[string]interface{}{
		"period": "not-a-duration",
	}

	err := init.syncRule(ctx, init.repo, types.RuleID("bad-period-rule"), ruleCfg, nil, nil)
	require.NoError(t, err)

	rule, err := init.repo.Get(ctx, types.RuleID("bad-period-rule"))
	require.NoError(t, err)
	assert.Nil(t, rule.BudgetPeriod, "invalid period should be ignored")
}

// =============================================================================
// syncDynamicBudgetFromConfig tests (54.2% → 90%+)
// =============================================================================

func TestSyncDynamicBudgetFromConfig_MapInterfaceInterface(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{ID: "dyn-rule", Variables: []byte(`{}`)}
	tmpl := &types.RuleTemplate{
		ID:             "tmpl-dyn",
		BudgetMetering: []byte(`{"method":"js","dynamic":true}`),
	}

	budgetMap := map[string]interface{}{
		"dynamic": true,
		"known_units": map[interface{}]interface{}{
			"native": map[interface{}]interface{}{
				"max_total":  "0.01",
				"max_per_tx": "0.005",
				"decimals":   18,
			},
		},
	}

	spy := &spyBudgetRepo{listByRuleIDReturn: nil}
	metering := &types.BudgetMetering{
		Dynamic: true,
		KnownUnits: map[string]types.UnitConf{
			"native": {MaxTotal: "0.01", MaxPerTx: "0.005", Decimals: 18},
		},
	}

	err := syncDynamicBudgetFromConfig(ctx, rule, tmpl, budgetMap, spy, metering)
	require.NoError(t, err)
}

func TestSyncDynamicBudgetFromConfig_DeletesStaleUnits(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{ID: "dyn-rule-2", Variables: []byte(`{}`)}
	tmpl := &types.RuleTemplate{
		ID:             "tmpl-dyn",
		BudgetMetering: []byte(`{"method":"js","dynamic":true}`),
	}

	budgetMap := map[string]interface{}{
		"dynamic": true,
		"known_units": map[string]interface{}{
			"native": map[string]interface{}{
				"max_total":  "0.01",
				"max_per_tx": "0.005",
			},
		},
	}

	spy := &spyBudgetRepo{
		listByRuleIDReturn: []*types.RuleBudget{
			{ID: "bdg-native", RuleID: "dyn-rule-2", Unit: "native"},
			{ID: "bdg-stale", RuleID: "dyn-rule-2", Unit: "old_unit"},
		},
	}

	metering := &types.BudgetMetering{
		Dynamic: true,
		KnownUnits: map[string]types.UnitConf{
			"native": {MaxTotal: "0.01", MaxPerTx: "0.005"},
		},
	}

	err := syncDynamicBudgetFromConfig(ctx, rule, tmpl, budgetMap, spy, metering)
	require.NoError(t, err)
	assert.Contains(t, spy.deleteCalls, "bdg-stale")
	assert.NotContains(t, spy.deleteCalls, "bdg-native")
}

func TestSyncDynamicBudgetFromConfig_ListError(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{ID: "dyn-rule-3", Variables: []byte(`{}`)}
	tmpl := &types.RuleTemplate{
		ID:             "tmpl-dyn",
		BudgetMetering: []byte(`{"method":"js","dynamic":true}`),
	}

	spy := &spyBudgetRepo{listErr: assert.AnError}
	metering := &types.BudgetMetering{Dynamic: true}

	err := syncDynamicBudgetFromConfig(ctx, rule, tmpl, map[string]interface{}{}, spy, metering)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list budgets")
}

func TestSyncDynamicBudgetFromConfig_CreateOrGetError(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{ID: "dyn-rule-4", Variables: []byte(`{}`)}
	tmpl := &types.RuleTemplate{
		ID:             "tmpl-dyn",
		BudgetMetering: []byte(`{"method":"js","dynamic":true}`),
	}

	budgetMap := map[string]interface{}{
		"dynamic": true,
		"known_units": map[string]interface{}{
			"native": map[string]interface{}{
				"max_total":  "0.01",
				"max_per_tx": "0.005",
			},
		},
	}

	createErr := errors.New("db write failed")
	spy := &spyBudgetRepo{listByRuleIDReturn: nil}
	errBudgetRepo := &stubBudgetRepo{
		spyBudgetRepo: spy,
		createOrGetFn: func(_ context.Context, _ *types.RuleBudget) (*types.RuleBudget, bool, error) {
			return nil, false, createErr
		},
	}

	metering := &types.BudgetMetering{
		Dynamic: true,
		KnownUnits: map[string]types.UnitConf{
			"native": {MaxTotal: "0.01", MaxPerTx: "0.005"},
		},
	}

	err := syncDynamicBudgetFromConfig(ctx, rule, tmpl, budgetMap, errBudgetRepo, metering)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create budget")
}

func TestSyncDynamicBudgetFromConfig_DeleteError(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{ID: "dyn-rule-5", Variables: []byte(`{}`)}
	tmpl := &types.RuleTemplate{
		ID:             "tmpl-dyn",
		BudgetMetering: []byte(`{"method":"js","dynamic":true}`),
	}

	budgetMap := map[string]interface{}{
		"dynamic": true,
		"known_units": map[string]interface{}{
			"native": map[string]interface{}{
				"max_total": "0.01",
			},
		},
	}

	delErr := errors.New("delete failed")
	spy := &spyBudgetRepo{
		listByRuleIDReturn: []*types.RuleBudget{
			{ID: "bdg-stale", RuleID: "dyn-rule-5", Unit: "old_unit"},
		},
	}
	errBudgetRepo := &stubBudgetRepo{
		spyBudgetRepo: spy,
		deleteErr:     delErr,
	}

	metering := &types.BudgetMetering{
		Dynamic: true,
		KnownUnits: map[string]types.UnitConf{
			"native": {MaxTotal: "0.01"},
		},
	}

	err := syncDynamicBudgetFromConfig(ctx, rule, tmpl, budgetMap, errBudgetRepo, metering)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete stale")
}

func TestSyncDynamicBudgetFromConfig_WithAlertPct(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{ID: "dyn-alert", Variables: []byte(`{}`)}
	tmpl := &types.RuleTemplate{
		ID:             "tmpl-dyn",
		BudgetMetering: []byte(`{"method":"js","dynamic":true}`),
	}

	budgetMap := map[string]interface{}{
		"dynamic":   true,
		"alert_pct": 75,
		"known_units": map[string]interface{}{
			"native": map[string]interface{}{
				"max_total": "0.01",
			},
		},
	}

	spy := &spyBudgetRepo{listByRuleIDReturn: nil}
	metering := &types.BudgetMetering{
		Dynamic: true,
		KnownUnits: map[string]types.UnitConf{
			"native": {MaxTotal: "0.01"},
		},
	}

	var capturedBudget *types.RuleBudget
	errBudgetRepo := &stubBudgetRepo{
		spyBudgetRepo: spy,
		createOrGetFn: func(_ context.Context, b *types.RuleBudget) (*types.RuleBudget, bool, error) {
			capturedBudget = b
			return b, true, nil
		},
	}

	err := syncDynamicBudgetFromConfig(ctx, rule, tmpl, budgetMap, errBudgetRepo, metering)
	require.NoError(t, err)
	require.NotNil(t, capturedBudget)
	assert.Equal(t, 75, capturedBudget.AlertPct)
}

func TestSyncDynamicBudgetFromConfig_InvalidMaxTxCount(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{ID: "dyn-bad-count", Variables: []byte(`{}`)}
	tmpl := &types.RuleTemplate{
		ID:             "tmpl-dyn",
		BudgetMetering: []byte(`{"method":"js","dynamic":true}`),
	}

	budgetMap := map[string]interface{}{
		"dynamic": true,
		"known_units": map[string]interface{}{
			"native": map[string]interface{}{
				"max_total":    "0.01",
				"max_tx_count": "not-a-number",
			},
		},
	}

	spy := &spyBudgetRepo{listByRuleIDReturn: nil}
	metering := &types.BudgetMetering{
		Dynamic: true,
		KnownUnits: map[string]types.UnitConf{
			"native": {MaxTotal: "0.01", MaxTxCount: 0},
		},
	}

	err := syncDynamicBudgetFromConfig(ctx, rule, tmpl, budgetMap, spy, metering)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid max_tx_count")
}

// =============================================================================
// createBudgetFromInstanceConfig tests (70.6% → 90%+)
// =============================================================================

func TestCreateBudgetFromInstanceConfig_GetByRuleIDDBError(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{ID: "r-db-err", Variables: []byte(`{"chain_id":"137","token":"0xabc"}`)}
	tmpl := &types.RuleTemplate{ID: "t1"}

	dbErr := errors.New("db connection lost")

	budgetMap := map[string]interface{}{
		"unit":      "137:0xabc",
		"max_total": "100",
	}

	err := createBudgetFromInstanceConfig(ctx, rule, tmpl, budgetMap, &errorGetByRuleIDRepo{getByRuleIDErr: dbErr})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check existing budget")
}

func TestCreateBudgetFromInstanceConfig_MaxTxCountInt(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{ID: "r-int", Variables: []byte(`{"chain_id":"1","token":"0xabc"}`)}
	tmpl := &types.RuleTemplate{ID: "t1"}
	spy := &spyBudgetRepo{}

	budgetMap := map[string]interface{}{
		"unit":         "1:0xabc",
		"max_total":    "1000",
		"max_tx_count": 50,
	}

	err := createBudgetFromInstanceConfig(ctx, rule, tmpl, budgetMap, spy)
	require.NoError(t, err)
	assert.Len(t, spy.createCalls, 1)
	assert.Equal(t, 50, spy.createCalls[0].MaxTxCount)
}

func TestCreateBudgetFromInstanceConfig_MaxTxCountFloat64(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{ID: "r-float", Variables: []byte(`{"chain_id":"1","token":"0xabc"}`)}
	tmpl := &types.RuleTemplate{ID: "t1"}
	spy := &spyBudgetRepo{}

	budgetMap := map[string]interface{}{
		"unit":         "1:0xabc",
		"max_total":    "1000",
		"max_tx_count": float64(25),
	}

	err := createBudgetFromInstanceConfig(ctx, rule, tmpl, budgetMap, spy)
	require.NoError(t, err)
	assert.Len(t, spy.createCalls, 1)
	assert.Equal(t, 25, spy.createCalls[0].MaxTxCount)
}

func TestCreateBudgetFromInstanceConfig_AlertPctNonNumeric(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{ID: "r-alert-str", Variables: []byte(`{"chain_id":"1","token":"0xabc"}`)}
	tmpl := &types.RuleTemplate{ID: "t1"}
	spy := &spyBudgetRepo{}

	budgetMap := map[string]interface{}{
		"unit":      "1:0xabc",
		"alert_pct": "not-a-number",
	}

	err := createBudgetFromInstanceConfig(ctx, rule, tmpl, budgetMap, spy)
	require.NoError(t, err)
	assert.Len(t, spy.createCalls, 1)
	assert.Equal(t, 80, spy.createCalls[0].AlertPct)
}

func TestCreateBudgetFromInstanceConfig_AlertPctZero(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{ID: "r-alert-zero", Variables: []byte(`{"chain_id":"1","token":"0xabc"}`)}
	tmpl := &types.RuleTemplate{ID: "t1"}
	spy := &spyBudgetRepo{}

	budgetMap := map[string]interface{}{
		"unit":      "1:0xabc",
		"alert_pct": 0,
	}

	err := createBudgetFromInstanceConfig(ctx, rule, tmpl, budgetMap, spy)
	require.NoError(t, err)
	assert.Len(t, spy.createCalls, 1)
	assert.Equal(t, 80, spy.createCalls[0].AlertPct)
}

func TestCreateBudgetFromInstanceConfig_MaxTotalEmpty(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{ID: "r-no-max", Variables: []byte(`{"chain_id":"1","token":"0xabc"}`)}
	tmpl := &types.RuleTemplate{ID: "t1"}
	spy := &spyBudgetRepo{}

	budgetMap := map[string]interface{}{
		"unit": "1:0xabc",
	}

	err := createBudgetFromInstanceConfig(ctx, rule, tmpl, budgetMap, spy)
	require.NoError(t, err)
	assert.Len(t, spy.createCalls, 1)
	assert.Equal(t, "-1", spy.createCalls[0].MaxTotal)
}

func TestCreateBudgetFromInstanceConfig_ExistingBudgetSkip(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{ID: "r-exists", Variables: []byte(`{"chain_id":"1","token":"0xabc"}`)}
	tmpl := &types.RuleTemplate{ID: "t1"}

	existing := &types.RuleBudget{ID: "existing-bdg", RuleID: "r-exists", Unit: "1:0xabc"}
	spy := &spyBudgetRepo{
		getByRuleIDReturn: map[string]*types.RuleBudget{
			"r-exists|1:0xabc": existing,
		},
	}

	budgetMap := map[string]interface{}{
		"unit":      "1:0xabc",
		"max_total": "999",
	}

	err := createBudgetFromInstanceConfig(ctx, rule, tmpl, budgetMap, spy)
	require.NoError(t, err)
	assert.Empty(t, spy.createCalls)
}

// =============================================================================
// SyncFromConfig: instance rule with budget
// =============================================================================

func TestSyncFromConfig_InstanceRuleWithBudget(t *testing.T) {
	init, repo := newTestRuleInit(t)

	tmpl := &types.RuleTemplate{
		ID:             "tmpl-inst",
		Name:           "instance-template",
		BudgetMetering: []byte(`{"method":"count_only","unit":"native"}`),
	}
	stubTmpl := &stubTemplateRepo{
		getByNameFn: func(_ context.Context, name string) (*types.RuleTemplate, error) {
			if name == "instance-template" {
				return tmpl, nil
			}
			return nil, types.ErrNotFound
		},
	}
	init.SetTemplateRepo(stubTmpl)
	init.SetBudgetRepo(&spyBudgetRepo{})

	rules := []RuleConfig{
		{
			Id:      "inst-rule",
			Name:    "Instance Rule with Budget",
			Type:    "evm_address_list",
			Mode:    "whitelist",
			Enabled: true,
			Config: map[string]interface{}{
				"addresses":       []interface{}{"0x1234567890abcdef1234567890abcdef12345678"},
				"__template_name": "instance-template",
				"__budget": map[string]interface{}{
					"unit":      "native",
					"max_total": "200",
				},
			},
		},
	}

	err := init.SyncFromConfig(context.Background(), rules)
	require.NoError(t, err)

	rule, err := repo.Get(context.Background(), types.RuleID("inst-rule"))
	require.NoError(t, err)
	require.NotNil(t, rule.TemplateID)
	assert.Equal(t, "tmpl-inst", *rule.TemplateID)
}

// =============================================================================
// SyncFromConfig: delete stale budget error path
// =============================================================================

func TestSyncFromConfig_DeleteStaleBudgetError(t *testing.T) {
	init, repo := newTestRuleInit(t)

	spy := &spyBudgetRepo{}
	budgetRepo := &stubBudgetRepo{spyBudgetRepo: spy}

	tmpl := &types.RuleTemplate{
		ID:             "tmpl-del-err",
		Name:           "delete-err-template",
		BudgetMetering: []byte(`{"method":"count_only","unit":"native"}`),
	}
	stubTmpl := &stubTemplateRepo{
		getByNameFn: func(_ context.Context, name string) (*types.RuleTemplate, error) {
			if name == "delete-err-template" {
				return tmpl, nil
			}
			return nil, types.ErrNotFound
		},
	}
	init.SetTemplateRepo(stubTmpl)
	init.SetBudgetRepo(budgetRepo)

	ctx := context.Background()

	rules := []RuleConfig{
		{
			Id:      "will-be-stale",
			Name:    "Will Be Stale",
			Type:    "evm_address_list",
			Mode:    "whitelist",
			Enabled: true,
			Config: map[string]interface{}{
				"addresses":       []interface{}{"0x1234567890abcdef1234567890abcdef12345678"},
				"__template_name": "delete-err-template",
				"__budget": map[string]interface{}{
					"unit":      "native",
					"max_total": "100",
				},
			},
		},
	}
	require.NoError(t, init.SyncFromConfig(ctx, rules))

	_, err := repo.Get(ctx, types.RuleID("will-be-stale"))
	require.NoError(t, err)

	budgetRepo.deleteErr = errors.New("budget delete failed")
	err = init.SyncFromConfig(ctx, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete budgets")
}

// =============================================================================
// LoadUnvalidated: validation failure
// =============================================================================

func TestLoadUnvalidated_NoChainsEnabled(t *testing.T) {
	dir := t.TempDir()
	cfgPath := dir + "/config.yaml"
	yamlContent := `
server:
  port: 8080
database:
  dsn: "file:test.db"
chains:
  evm:
    enabled: false
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0644))
	_, err := LoadUnvalidated(cfgPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one chain must be enabled")
}
