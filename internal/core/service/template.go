package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// TemplateService manages rule templates and instance creation
type TemplateService struct {
	templateRepo storage.TemplateRepository
	ruleRepo     storage.RuleRepository
	budgetRepo   storage.BudgetRepository
	logger       *slog.Logger
}

// NewTemplateService creates a new template service
func NewTemplateService(
	templateRepo storage.TemplateRepository,
	ruleRepo storage.RuleRepository,
	budgetRepo storage.BudgetRepository,
	logger *slog.Logger,
) (*TemplateService, error) {
	if templateRepo == nil {
		return nil, fmt.Errorf("template repository is required")
	}
	if ruleRepo == nil {
		return nil, fmt.Errorf("rule repository is required")
	}
	if budgetRepo == nil {
		return nil, fmt.Errorf("budget repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &TemplateService{
		templateRepo: templateRepo,
		ruleRepo:     ruleRepo,
		budgetRepo:   budgetRepo,
		logger:       logger,
	}, nil
}

// CreateInstanceRequest contains all parameters for creating a rule instance from a template
type CreateInstanceRequest struct {
	TemplateID   string            `json:"template_id"`
	TemplateName string            `json:"template_name,omitempty"` // alternative: look up by name
	Name         string            `json:"name,omitempty"`          // optional override for rule name
	Variables    map[string]string `json:"variables"`

	// Scope
	ChainType     *string `json:"chain_type,omitempty"`
	ChainID       *string `json:"chain_id,omitempty"`
	APIKeyID      *string `json:"api_key_id,omitempty"`
	SignerAddress *string `json:"signer_address,omitempty"`

	// RBAC ownership fields — set by handler, not request body.
	// When set, these override the defaults (owner="config", applied_to=["*"], status=active).
	Owner     string           `json:"-"`
	AppliedTo []string         `json:"-"`
	Status    types.RuleStatus `json:"-"`

	// Optional: time-limited
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	ExpiresIn *time.Duration `json:"expires_in,omitempty"` // alternative: duration from now

	// Optional: budget
	Budget *BudgetConfig `json:"budget,omitempty"`

	// Optional: periodic renewal (session with schedule)
	Schedule *ScheduleConfig `json:"schedule,omitempty"`
}

// BudgetConfig defines budget limits for an instance
type BudgetConfig struct {
	MaxTotal   string `json:"max_total"`              // per-unit total cap (per period if schedule set)
	MaxPerTx   string `json:"max_per_tx"`             // per-unit per-tx cap
	MaxTxCount int    `json:"max_tx_count,omitempty"` // 0 = unlimited (per period if schedule set)
	AlertPct   int    `json:"alert_pct,omitempty"`    // default 80
}

// ScheduleConfig defines periodic budget renewal
type ScheduleConfig struct {
	Period  time.Duration `json:"period"`              // e.g. 24h, 168h (7 days)
	StartAt *time.Time   `json:"start_at,omitempty"`  // default: now
}

// CreateInstanceResult contains the created rule(s) and optional budget(s).
// For single-rule templates, Rule and Budget are set directly.
// For template_bundle templates, SubRules and SubBudgets contain all expanded sub-rules;
// Rule/Budget point to the first sub-rule for backward compatibility.
type CreateInstanceResult struct {
	Rule         *types.Rule            `json:"rule"`
	Budget       *types.RuleBudget      `json:"budget,omitempty"`
	SubRules     []*types.Rule          `json:"sub_rules,omitempty"`
	SubBudgets   []*types.RuleBudget    `json:"sub_budgets,omitempty"`
	SubRuleIDMap map[string]types.RuleID `json:"-"`
}

// CreateInstance creates a rule instance from a template with bound variables
func (s *TemplateService) CreateInstance(ctx context.Context, req *CreateInstanceRequest) (*CreateInstanceResult, error) {
	if req == nil {
		return nil, fmt.Errorf("request is required")
	}

	// 1. Load template
	tmpl, err := s.resolveTemplate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve template: %w", err)
	}

	// Delegate to createInstanceFromResolved which handles both single-rule and bundle templates
	return s.createInstanceFromResolved(ctx, s.ruleRepo, s.budgetRepo, tmpl, req)
}

// CreateInstanceWithTx creates a rule instance from a template using the given repos (e.g. tx-scoped).
// Resolves template via DB; for preset apply use ResolveTemplate outside tx then CreateInstanceFromResolvedWithTx inside tx to avoid deadlock with single DB connection.
func (s *TemplateService) CreateInstanceWithTx(
	ctx context.Context,
	ruleRepo storage.RuleRepository,
	budgetRepo storage.BudgetRepository,
	req *CreateInstanceRequest,
) (*CreateInstanceResult, error) {
	if req == nil {
		return nil, fmt.Errorf("request is required")
	}
	if ruleRepo == nil || budgetRepo == nil {
		return nil, fmt.Errorf("rule and budget repositories are required")
	}
	tmpl, err := s.resolveTemplate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve template: %w", err)
	}
	return s.createInstanceFromResolved(ctx, ruleRepo, budgetRepo, tmpl, req)
}

// CreateInstanceFromResolvedWithTx creates a rule instance using an already-resolved template and tx-scoped repos.
// Use after ResolveTemplate outside the transaction so preset apply does not need a second DB connection.
func (s *TemplateService) CreateInstanceFromResolvedWithTx(
	ctx context.Context,
	ruleRepo storage.RuleRepository,
	budgetRepo storage.BudgetRepository,
	tmpl *types.RuleTemplate,
	req *CreateInstanceRequest,
) (*CreateInstanceResult, error) {
	if tmpl == nil || req == nil {
		return nil, fmt.Errorf("template and request are required")
	}
	if ruleRepo == nil || budgetRepo == nil {
		return nil, fmt.Errorf("rule and budget repositories are required")
	}
	return s.createInstanceFromResolved(ctx, ruleRepo, budgetRepo, tmpl, req)
}

func (s *TemplateService) createInstanceFromResolved(
	ctx context.Context,
	ruleRepo storage.RuleRepository,
	budgetRepo storage.BudgetRepository,
	tmpl *types.RuleTemplate,
	req *CreateInstanceRequest,
) (*CreateInstanceResult, error) {
	var varDefs []types.TemplateVariable
	if len(tmpl.Variables) > 0 {
		if err := json.Unmarshal(tmpl.Variables, &varDefs); err != nil {
			return nil, fmt.Errorf("failed to parse template variables: %w", err)
		}
	}
	if err := validateVariables(varDefs, req.Variables); err != nil {
		return nil, fmt.Errorf("variable validation failed: %w", err)
	}
	resolvedVars := resolveDefaults(varDefs, req.Variables)
	injectReservedVariables(resolvedVars, req, s.logger)
	// Merge in test_variables so test-case placeholders in the config
	// (e.g. ${test_wrong_signer}) resolve during substitution. These
	// only appear in test case input data, never in actual rule config.
	s.mergeTestVariables(resolvedVars, tmpl)
	resolvedConfig, err := SubstituteVariables(tmpl.Config, resolvedVars)
	if err != nil {
		return nil, fmt.Errorf("variable substitution failed: %w", err)
	}

	// If template is a bundle, expand into sub-rules
	if tmpl.Type == "template_bundle" {
		return s.createInstanceFromBundle(ctx, ruleRepo, budgetRepo, tmpl, req, resolvedVars, resolvedConfig)
	}

	ruleID := s.generateInstanceRuleID(tmpl.ID, resolvedVars)
	variablesJSON, err := json.Marshal(resolvedVars)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal resolved variables: %w", err)
	}
	// Determine ownership: prefer RBAC fields from handler, fall back to legacy defaults
	owner := "config"
	if req.Owner != "" {
		owner = req.Owner
	} else if req.APIKeyID != nil {
		owner = *req.APIKeyID
	}
	appliedTo := pq.StringArray{"*"}
	if len(req.AppliedTo) > 0 {
		appliedTo = pq.StringArray(req.AppliedTo)
	}
	status := types.RuleStatusActive
	if req.Status != "" {
		status = req.Status
	}

	rule := &types.Rule{
		ID:          ruleID,
		Name:        s.resolveInstanceName(req, tmpl),
		Description: tmpl.Description,
		Type:        tmpl.Type,
		Mode:        tmpl.Mode,
		Source:      types.RuleSourceInstance,
		Config:      resolvedConfig,
		TemplateID:  &tmpl.ID,
		Variables:   variablesJSON,
		Enabled:     true,
		AppliedTo:   appliedTo,
		Owner:       owner,
		Status:      status,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	if req.ChainType != nil {
		ct := types.ChainType(*req.ChainType)
		rule.ChainType = &ct
	}
	if req.ChainID != nil {
		rule.ChainID = req.ChainID
	}
	if req.SignerAddress != nil {
		rule.SignerAddress = req.SignerAddress
	}
	if req.ExpiresAt != nil {
		rule.ExpiresAt = req.ExpiresAt
	} else if req.ExpiresIn != nil {
		expiresAt := time.Now().Add(*req.ExpiresIn)
		rule.ExpiresAt = &expiresAt
	}
	if req.Schedule != nil {
		rule.BudgetPeriod = &req.Schedule.Period
		if req.Schedule.StartAt != nil {
			rule.BudgetPeriodStart = req.Schedule.StartAt
		} else {
			now := time.Now()
			rule.BudgetPeriodStart = &now
		}
	}
	if err := ruleRepo.Create(ctx, rule); err != nil {
		return nil, fmt.Errorf("failed to create rule: %w", err)
	}
	result := &CreateInstanceResult{Rule: rule}
	if req.Budget != nil {
		budget, err := s.createBudgetWithRepo(ctx, budgetRepo, rule, tmpl, req.Budget)
		if err != nil {
			if delErr := ruleRepo.Delete(ctx, rule.ID); delErr != nil {
				s.logger.Error("failed to rollback rule creation in tx", "error", delErr)
			}
			return nil, fmt.Errorf("failed to create budget: %w", err)
		}
		result.Budget = budget
	}
	return result, nil
}

// bundleSubRule represents a single sub-rule parsed from a template_bundle's rules_json.
type bundleSubRule struct {
	ID          string                 `json:"id,omitempty"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Type        string                 `json:"type"`
	Mode        string                 `json:"mode"`
	Config      map[string]interface{} `json:"config"`
	Enabled     bool                   `json:"enabled"`
}

// createInstanceFromBundle expands a template_bundle into individual sub-rules,
// creating each as a separate rule in the database. Uses a two-pass approach:
//  1. First pass: generate IDs for all sub-rules, build template-ID-to-actual-ID map
//  2. Resolve delegate_to/delegate_to_by_target cross-references using the map
//  3. Second pass: persist rules with resolved configs
//
// This ensures that cross-template delegation references using template YAML IDs
// (e.g., safe.yaml's delegate_to: "polymarket-v2-transactions") resolve to the
// correct inst_<hash> rule IDs before any rule is persisted.
func (s *TemplateService) createInstanceFromBundle(
	ctx context.Context,
	ruleRepo storage.RuleRepository,
	budgetRepo storage.BudgetRepository,
	tmpl *types.RuleTemplate,
	req *CreateInstanceRequest,
	resolvedVars map[string]string,
	resolvedConfig []byte,
) (*CreateInstanceResult, error) {
	var configMap map[string]interface{}
	if err := json.Unmarshal(resolvedConfig, &configMap); err != nil {
		return nil, fmt.Errorf("failed to parse resolved bundle config: %w", err)
	}
	rulesJSON, ok := configMap["rules_json"].(string)
	if !ok {
		return nil, fmt.Errorf("template_bundle %q has no rules_json in config", tmpl.Name)
	}

	var subRules []bundleSubRule
	if err := json.Unmarshal([]byte(rulesJSON), &subRules); err != nil {
		return nil, fmt.Errorf("failed to parse bundle rules_json: %w", err)
	}
	if len(subRules) == 0 {
		return nil, fmt.Errorf("template_bundle %q has no sub-rules", tmpl.Name)
	}

	variablesJSON, err := json.Marshal(resolvedVars)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal resolved variables: %w", err)
	}

	baseName := s.resolveInstanceName(req, tmpl)

	// ---- Pass 1: generate IDs and build the template-ID→actual-ID map ----
	type pendingSubRule struct {
		rule   *types.Rule
		config map[string]interface{}
	}
	subIDToRuleID := make(map[string]types.RuleID)
	pending := make([]pendingSubRule, 0, len(subRules))

	for _, sub := range subRules {
		subConfigJSON, err := json.Marshal(sub.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal sub-rule config: %w", err)
		}

		var subConfig map[string]interface{}
		if err := json.Unmarshal(subConfigJSON, &subConfig); err != nil {
			return nil, fmt.Errorf("failed to parse sub-rule config: %w", err)
		}
		for k, v := range resolvedVars {
			subConfig[k] = v
		}

		subConfigJSON, err = json.Marshal(subConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to re-marshal sub-rule config: %w", err)
		}

		subIDSuffix := sub.ID
		if subIDSuffix == "" {
			subIDSuffix = sub.Name
		}
		subRuleID := s.generateBundleSubRuleID(tmpl.ID, resolvedVars, subIDSuffix)

		ruleName := baseName
		if len(subRules) > 1 {
			ruleName = baseName + " / " + sub.Name
		}

		owner := "config"
		if req.Owner != "" {
			owner = req.Owner
		} else if req.APIKeyID != nil {
			owner = *req.APIKeyID
		}
		bundleAppliedTo := pq.StringArray{"*"}
		if len(req.AppliedTo) > 0 {
			bundleAppliedTo = pq.StringArray(req.AppliedTo)
		}
		bundleStatus := types.RuleStatusActive
		if req.Status != "" {
			bundleStatus = req.Status
		}

		rule := &types.Rule{
			ID:          subRuleID,
			Name:        ruleName,
			Description: sub.Description,
			Type:        types.RuleType(sub.Type),
			Mode:        types.RuleMode(sub.Mode),
			Source:      types.RuleSourceInstance,
			Config:      subConfigJSON,
			TemplateID:  &tmpl.ID,
			Variables:   variablesJSON,
			Enabled:     true,
			AppliedTo:   bundleAppliedTo,
			Owner:       owner,
			Status:      bundleStatus,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		if req.ChainType != nil {
			ct := types.ChainType(*req.ChainType)
			rule.ChainType = &ct
		}
		if req.ChainID != nil {
			rule.ChainID = req.ChainID
		}
		if req.SignerAddress != nil {
			rule.SignerAddress = req.SignerAddress
		}
		if req.ExpiresAt != nil {
			rule.ExpiresAt = req.ExpiresAt
		} else if req.ExpiresIn != nil {
			expiresAt := time.Now().Add(*req.ExpiresIn)
			rule.ExpiresAt = &expiresAt
		}
		if req.Schedule != nil {
			rule.BudgetPeriod = &req.Schedule.Period
			if req.Schedule.StartAt != nil {
				rule.BudgetPeriodStart = req.Schedule.StartAt
			} else {
				now := time.Now()
				rule.BudgetPeriodStart = &now
			}
		}

		if sub.ID != "" {
			subIDToRuleID[sub.ID] = subRuleID
		}
		pending = append(pending, pendingSubRule{rule: rule, config: subConfig})
	}

	// ---- Resolve delegate_to references using the template-ID→actual-ID map ----
	// Sub-rules may reference each other by template YAML ID (e.g., safe.yaml has
	// delegate_to: "polymarket-v2-transactions"). Resolve to actual inst_<hash> IDs.
	for i, p := range pending {
		newConfig, changed, err := ResolveDelegateToConfig(p.config, subIDToRuleID)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve delegate config for sub-rule %q: %w", p.rule.Name, err)
		}
		if changed {
			pending[i].rule.Config = newConfig
		}
	}

	// ---- Pass 2: persist all rules ----
	result := &CreateInstanceResult{
		SubRules:     make([]*types.Rule, 0, len(pending)),
		SubBudgets:   make([]*types.RuleBudget, 0),
		SubRuleIDMap: subIDToRuleID,
	}
	var createdRuleIDs []types.RuleID

	for _, p := range pending {
		if err := ruleRepo.Create(ctx, p.rule); err != nil {
			s.rollbackRules(ctx, ruleRepo, createdRuleIDs)
			return nil, fmt.Errorf("failed to create sub-rule %q: %w", p.rule.Name, err)
		}
		createdRuleIDs = append(createdRuleIDs, p.rule.ID)
		result.SubRules = append(result.SubRules, p.rule)

		if req.Budget != nil {
			budget, err := s.createBudgetWithRepo(ctx, budgetRepo, p.rule, tmpl, req.Budget)
			if err != nil {
				s.rollbackRules(ctx, ruleRepo, createdRuleIDs)
				return nil, fmt.Errorf("failed to create budget for sub-rule %q: %w", p.rule.Name, err)
			}
			result.SubBudgets = append(result.SubBudgets, budget)
		}

		s.logger.Info("Created sub-rule from template bundle",
			"rule_id", p.rule.ID,
			"sub_rule_name", p.rule.Name,
			"template_id", tmpl.ID,
			"template_name", tmpl.Name,
			"type", p.rule.Type,
			"mode", p.rule.Mode,
		)
	}

	if len(result.SubRules) > 0 {
		result.Rule = result.SubRules[0]
	}
	if len(result.SubBudgets) > 0 {
		result.Budget = result.SubBudgets[0]
	}

	return result, nil
}

// rollbackRules deletes all previously created rules (used on bundle expansion failure).
func (s *TemplateService) rollbackRules(ctx context.Context, ruleRepo storage.RuleRepository, ruleIDs []types.RuleID) {
	for _, id := range ruleIDs {
		if err := ruleRepo.Delete(ctx, id); err != nil {
			s.logger.Error("failed to rollback sub-rule creation", "rule_id", id, "error", err)
		}
	}
}

// generateBundleSubRuleID generates a deterministic rule ID for a sub-rule within a bundle.
func (s *TemplateService) generateBundleSubRuleID(templateID string, vars map[string]string, subRuleSuffix string) types.RuleID {
	data := fmt.Sprintf("instance:%s:%v:%s:%d", templateID, vars, subRuleSuffix, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return types.RuleID("inst_" + hex.EncodeToString(hash[:8]))
}

// ResolveDelegateToConfig resolves delegate_to and delegate_to_by_target references
// in a rule config map using the provided template-ID→rule-ID map.
// Returns the new marshalled config, whether it changed, and any error.
// This is exported so that callers (e.g., preset apply) can resolve cross-template
// references after all instances have been created.
func ResolveDelegateToConfig(cfg map[string]interface{}, ruleIDMap map[string]types.RuleID) ([]byte, bool, error) {
	changed := false

	if d, _ := cfg["delegate_to"].(string); d != "" {
		parts := strings.Split(d, ",")
		for j, part := range parts {
			part = strings.TrimSpace(part)
			if actualID, ok := ruleIDMap[part]; ok {
				parts[j] = string(actualID)
				changed = true
			}
		}
		if changed {
			cfg["delegate_to"] = strings.Join(parts, ",")
		}
	}

	if dtbt, _ := cfg["delegate_to_by_target"].(string); dtbt != "" {
		pairs := strings.Split(dtbt, ",")
		btChanged := false
		for j, pair := range pairs {
			pair = strings.TrimSpace(pair)
			idx := strings.Index(pair, ":")
			if idx <= 0 {
				continue
			}
			rulePart := strings.TrimSpace(pair[idx+1:])
			if actualID, ok := ruleIDMap[rulePart]; ok {
				pairs[j] = pair[:idx+1] + string(actualID)
				btChanged = true
			}
		}
		if btChanged {
			cfg["delegate_to_by_target"] = strings.Join(pairs, ",")
			changed = true
		}
	}

	if !changed {
		return nil, false, nil
	}

	newConfig, err := json.Marshal(cfg)
	if err != nil {
		return nil, true, fmt.Errorf("failed to marshal resolved config: %w", err)
	}
	return newConfig, true, nil
}

// RevokeInstance disables a rule instance and deletes its budgets
func (s *TemplateService) RevokeInstance(ctx context.Context, ruleID types.RuleID) error {
	rule, err := s.ruleRepo.Get(ctx, ruleID)
	if err != nil {
		return fmt.Errorf("failed to get rule: %w", err)
	}

	if rule.Source != types.RuleSourceInstance {
		return fmt.Errorf("rule %s is not an instance (source=%s)", ruleID, rule.Source)
	}

	rule.Enabled = false
	rule.UpdatedAt = time.Now()
	if err := s.ruleRepo.Update(ctx, rule); err != nil {
		return fmt.Errorf("failed to disable rule: %w", err)
	}

	// Delete associated budgets
	if err := s.budgetRepo.DeleteByRuleID(ctx, ruleID); err != nil {
		s.logger.Error("failed to delete budgets for revoked instance", "rule_id", ruleID, "error", err)
	}

	s.logger.Info("Revoked rule instance", "rule_id", ruleID)
	return nil
}

// ResolveTemplate finds the template by ID or name (for use outside a DB transaction, e.g. preset apply).
func (s *TemplateService) ResolveTemplate(ctx context.Context, req *CreateInstanceRequest) (*types.RuleTemplate, error) {
	return s.resolveTemplate(ctx, req)
}

// resolveTemplate finds the template by ID or name
func (s *TemplateService) resolveTemplate(ctx context.Context, req *CreateInstanceRequest) (*types.RuleTemplate, error) {
	if req.TemplateID != "" {
		return s.templateRepo.Get(ctx, req.TemplateID)
	}
	if req.TemplateName != "" {
		return s.templateRepo.GetByName(ctx, req.TemplateName)
	}
	return nil, fmt.Errorf("template_id or template_name is required")
}

// resolveInstanceName determines the name for the instance
func (s *TemplateService) resolveInstanceName(req *CreateInstanceRequest, tmpl *types.RuleTemplate) string {
	if req.Name != "" {
		return req.Name
	}
	return tmpl.Name + " (instance)"
}

// generateInstanceRuleID generates a deterministic rule ID for an instance
func (s *TemplateService) generateInstanceRuleID(templateID string, vars map[string]string) types.RuleID {
	data := fmt.Sprintf("instance:%s:%v:%d", templateID, vars, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return types.RuleID("inst_" + hex.EncodeToString(hash[:8]))
}

// createBudgetWithRepo creates a budget using the given repo (for use with tx-scoped repo).
func (s *TemplateService) createBudgetWithRepo(ctx context.Context, budgetRepo storage.BudgetRepository, rule *types.Rule, tmpl *types.RuleTemplate, budgetCfg *BudgetConfig) (*types.RuleBudget, error) {
	unit := "count"
	if len(tmpl.BudgetMetering) > 0 {
		var metering types.BudgetMetering
		if err := json.Unmarshal(tmpl.BudgetMetering, &metering); err == nil && metering.Unit != "" {
			unit = metering.Unit
			if strings.Contains(unit, "${") && len(rule.Variables) > 0 {
				var vars map[string]string
				if err := json.Unmarshal(rule.Variables, &vars); err == nil {
					for k, v := range vars {
						unit = strings.ReplaceAll(unit, "${"+k+"}", v)
					}
				}
			}
		}
	}
	alertPct := budgetCfg.AlertPct
	if alertPct <= 0 {
		alertPct = 80
	}
	budget := &types.RuleBudget{
		ID:         types.BudgetID(rule.ID, unit),
		RuleID:     rule.ID,
		Unit:       unit,
		MaxTotal:   budgetCfg.MaxTotal,
		MaxPerTx:   budgetCfg.MaxPerTx,
		Spent:      "0",
		AlertPct:   alertPct,
		TxCount:    0,
		MaxTxCount: budgetCfg.MaxTxCount,
	}
	if err := budgetRepo.Create(ctx, budget); err != nil {
		return nil, err
	}
	attrs := []any{"rule_id", rule.ID, "budget_id", budget.ID, "unit", unit, "max_total", budgetCfg.MaxTotal}
	if rule.BudgetPeriod != nil {
		attrs = append(attrs, "budget_period", rule.BudgetPeriod.String(), "period_renewal", true)
		if rule.BudgetPeriodStart != nil {
			attrs = append(attrs, "budget_period_start", rule.BudgetPeriodStart.Format(time.RFC3339))
		}
	}
	s.logger.Info("Created budget for instance", attrs...)
	return budget, nil
}

// injectReservedVariables injects reserved variables from the rule-level scope
// into the resolved variables map. chain_id is always taken from
// CreateInstanceRequest.ChainID (the rule-level scope), never from user input.
// If the user supplied a chain_id in variables, it is overwritten and a warning
// is logged — this is a backward-compat path for old presets/configs that still
// have chain_id in their variables section (which is now deprecated).
func injectReservedVariables(vars map[string]string, req *CreateInstanceRequest, logger *slog.Logger) {
	if req.ChainID != nil {
		if old, exists := vars["chain_id"]; exists && old != *req.ChainID {
			logger.Warn("overriding user-supplied chain_id variable with rule-level scope",
				"user_value", old, "scope_value", *req.ChainID)
		}
		vars["chain_id"] = *req.ChainID
	}
}

// mergeTestVariables merges tmpl.TestVariables into vars so that
// test-case placeholders (e.g. ${test_wrong_signer}) resolve during
// substitution. User-supplied variables (already in vars) take precedence.
func (s *TemplateService) mergeTestVariables(vars map[string]string, tmpl *types.RuleTemplate) {
	if len(tmpl.TestVariables) == 0 {
		return
	}
	var tv map[string]string
	if err := json.Unmarshal(tmpl.TestVariables, &tv); err != nil {
		return
	}
	for k, v := range tv {
		if _, exists := vars[k]; !exists {
			vars[k] = v
		}
	}
}

// reservedVariables are auto-injected from rule scope and should not be
// declared in template variable definitions or preset variables sections.
//
// DEPRECATED in variables: chain_id is now always injected from the rule-level
// chain_id scope field. Do NOT declare chain_id in template variables or preset
// variables — it will be ignored and overwritten. Use the top-level chain_id
// field in presets/config instead.
//
// Old templates/presets that still list chain_id as a variable are tolerated
// (backward-compat) but the definition is silently skipped during validation.
var reservedVariables = map[string]bool{
	"chain_id": true,
}

// validateVariables validates the provided variables against the template definitions
func validateVariables(defs []types.TemplateVariable, vars map[string]string) error {
	for _, def := range defs {
		// Skip reserved variables – they are injected from rule scope.
		if reservedVariables[def.Name] {
			continue
		}

		val, provided := vars[def.Name]

		// Check required. Default is typed (any) post-R1 — missing
		// means nil, or a string that's still empty after the
		// no-default zero value. Non-string defaults (bool, []string)
		// always count as "has a default" since their zero values are
		// legitimate concrete defaults the operator chose.
		hasDefault := def.Default != nil
		if s, ok := def.Default.(string); ok && s == "" {
			hasDefault = false
		}
		if def.Required && !provided && !hasDefault {
			return fmt.Errorf("required variable '%s' is missing", def.Name)
		}

		// Skip validation if not provided and has default
		if !provided {
			continue
		}

		// Type validation
		if err := validateVariableType(def.Name, def.Type, val); err != nil {
			return err
		}
	}

	return nil
}

// validateVariableType validates a variable value against its declared
// type. value is the wire string at apply time; the typed re-parse for
// substitution happens later in R5's typed substituter — this is the
// legacy validator kept alive while the type system migrates.
func validateVariableType(name string, varType types.VariableType, value string) error {
	switch varType {
	case types.VarTypeAddress:
		if !isValidAddress(value) {
			return fmt.Errorf("variable '%s': invalid address format '%s'", name, value)
		}
	case types.VarTypeBigInt:
		if !isValidUint256(value) {
			return fmt.Errorf("variable '%s': invalid bigint format '%s'", name, value)
		}
	case types.VarTypeAddressList:
		parts := strings.Split(value, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" && !isValidAddress(part) {
				return fmt.Errorf("variable '%s': invalid address in list '%s'", name, part)
			}
		}
	case types.VarTypeBigIntList:
		parts := strings.Split(value, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" && !isValidUint256(part) {
				return fmt.Errorf("variable '%s': invalid bigint in list '%s'", name, part)
			}
		}
	case types.VarTypeString:
		// Any string is valid
	default:
		// Unknown type, skip validation
	}
	return nil
}

// resolveDefaults fills in default values for optional variables that
// were not provided. Default is typed (any) — R5 will rewrite the
// substituter to dispatch on type; for now this legacy path coerces
// string defaults straight through and uses fmt.Sprint for the rest
// so the existing tests keep passing through R1.
func resolveDefaults(defs []types.TemplateVariable, vars map[string]string) map[string]string {
	result := make(map[string]string, len(vars))
	for k, v := range vars {
		result[k] = v
	}
	for _, def := range defs {
		if _, provided := result[def.Name]; provided {
			continue
		}
		if def.Default == nil {
			continue
		}
		if s, ok := def.Default.(string); ok {
			if s != "" {
				result[def.Name] = s
			}
			continue
		}
		result[def.Name] = fmt.Sprint(def.Default)
	}
	return result
}

// isValidAddress checks if a string is a valid hex address (0x-prefixed, 40 hex chars)
func isValidAddress(s string) bool {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return false
	}
	hex := s[2:]
	if len(hex) != 40 {
		return false
	}
	for _, c := range hex {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// isValidUint256 checks if a string is a valid uint256 (decimal number, non-negative)
func isValidUint256(s string) bool {
	if s == "" {
		return false
	}
	n := new(big.Int)
	_, ok := n.SetString(s, 10)
	if !ok {
		return false
	}
	return n.Sign() >= 0
}
