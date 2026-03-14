package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"regexp"
	"strings"
	"time"

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

// CreateInstanceResult contains the created rule and optional budget
type CreateInstanceResult struct {
	Rule   *types.Rule       `json:"rule"`
	Budget *types.RuleBudget `json:"budget,omitempty"`
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

	// 2. Parse variable definitions
	var varDefs []types.TemplateVariable
	if len(tmpl.Variables) > 0 {
		if err := json.Unmarshal(tmpl.Variables, &varDefs); err != nil {
			return nil, fmt.Errorf("failed to parse template variables: %w", err)
		}
	}

	// 3. Validate variables
	if err := validateVariables(varDefs, req.Variables); err != nil {
		return nil, fmt.Errorf("variable validation failed: %w", err)
	}

	// 4. Fill defaults for optional variables
	resolvedVars := resolveDefaults(varDefs, req.Variables)

	// 5. Substitute variables in config
	resolvedConfig, err := SubstituteVariables(tmpl.Config, resolvedVars)
	if err != nil {
		return nil, fmt.Errorf("variable substitution failed: %w", err)
	}

	// 6. Build Rule
	ruleID := s.generateInstanceRuleID(tmpl.ID, resolvedVars)
	variablesJSON, _ := json.Marshal(resolvedVars)

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
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Set scope
	if req.ChainType != nil {
		ct := types.ChainType(*req.ChainType)
		rule.ChainType = &ct
	}
	if req.ChainID != nil {
		rule.ChainID = req.ChainID
	}
	if req.APIKeyID != nil {
		rule.APIKeyID = req.APIKeyID
	}
	if req.SignerAddress != nil {
		rule.SignerAddress = req.SignerAddress
	}

	// Set expiry
	if req.ExpiresAt != nil {
		rule.ExpiresAt = req.ExpiresAt
	} else if req.ExpiresIn != nil {
		expiresAt := time.Now().Add(*req.ExpiresIn)
		rule.ExpiresAt = &expiresAt
	}

	// Set schedule
	if req.Schedule != nil {
		rule.BudgetPeriod = &req.Schedule.Period
		if req.Schedule.StartAt != nil {
			rule.BudgetPeriodStart = req.Schedule.StartAt
		} else {
			now := time.Now()
			rule.BudgetPeriodStart = &now
		}
	}

	// 7. Save Rule
	if err := s.ruleRepo.Create(ctx, rule); err != nil {
		return nil, fmt.Errorf("failed to create rule: %w", err)
	}

	s.logger.Info("Created rule instance from template",
		"rule_id", rule.ID,
		"template_id", tmpl.ID,
		"template_name", tmpl.Name,
	)

	result := &CreateInstanceResult{Rule: rule}

	// 8. Create budget if specified
	if req.Budget != nil {
		budget, err := s.createBudget(ctx, rule, tmpl, req.Budget)
		if err != nil {
			// Rollback rule creation
			if delErr := s.ruleRepo.Delete(ctx, rule.ID); delErr != nil {
				s.logger.Error("failed to rollback rule creation", "error", delErr)
			}
			return nil, fmt.Errorf("failed to create budget: %w", err)
		}
		result.Budget = budget
	}

	return result, nil
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
	resolvedConfig, err := SubstituteVariables(tmpl.Config, resolvedVars)
	if err != nil {
		return nil, fmt.Errorf("variable substitution failed: %w", err)
	}
	ruleID := s.generateInstanceRuleID(tmpl.ID, resolvedVars)
	variablesJSON, err := json.Marshal(resolvedVars)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal resolved variables: %w", err)
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
	if req.APIKeyID != nil {
		rule.APIKeyID = req.APIKeyID
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

// createBudget creates a budget record for the instance
func (s *TemplateService) createBudget(ctx context.Context, rule *types.Rule, tmpl *types.RuleTemplate, budgetCfg *BudgetConfig) (*types.RuleBudget, error) {
	return s.createBudgetWithRepo(ctx, s.budgetRepo, rule, tmpl, budgetCfg)
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
	budgetID := fmt.Sprintf("bdg_%s_%s", rule.ID, unit)
	budget := &types.RuleBudget{
		ID:         budgetID,
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

// SubstituteVariables replaces ${var} placeholders in config JSON with actual values
func SubstituteVariables(configJSON []byte, vars map[string]string) ([]byte, error) {
	result := string(configJSON)
	for k, v := range vars {
		result = strings.ReplaceAll(result, "${"+k+"}", v)
	}
	// Check for unresolved variables
	if strings.Contains(result, "${") {
		// Find unresolved variable names for error message
		re := regexp.MustCompile(`\$\{([^}]+)\}`)
		matches := re.FindAllStringSubmatch(result, -1)
		var unresolved []string
		for _, m := range matches {
			if len(m) >= 2 {
				unresolved = append(unresolved, m[1])
			}
		}
		return nil, fmt.Errorf("unresolved variables: %s", strings.Join(unresolved, ", "))
	}
	return []byte(result), nil
}

// validateVariables validates the provided variables against the template definitions
func validateVariables(defs []types.TemplateVariable, vars map[string]string) error {
	for _, def := range defs {
		val, provided := vars[def.Name]

		// Check required
		if def.Required && !provided && def.Default == "" {
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

// validateVariableType validates a variable value against its declared type
func validateVariableType(name, varType, value string) error {
	switch varType {
	case "address":
		if !isValidAddress(value) {
			return fmt.Errorf("variable '%s': invalid address format '%s'", name, value)
		}
	case "uint256":
		if !isValidUint256(value) {
			return fmt.Errorf("variable '%s': invalid uint256 format '%s'", name, value)
		}
	case "address_list":
		parts := strings.Split(value, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" && !isValidAddress(part) {
				return fmt.Errorf("variable '%s': invalid address in list '%s'", name, part)
			}
		}
	case "uint256_list":
		parts := strings.Split(value, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" && !isValidUint256(part) {
				return fmt.Errorf("variable '%s': invalid uint256 in list '%s'", name, part)
			}
		}
	case "string":
		// Any string is valid
	default:
		// Unknown type, skip validation
	}
	return nil
}

// resolveDefaults fills in default values for optional variables that were not provided
func resolveDefaults(defs []types.TemplateVariable, vars map[string]string) map[string]string {
	result := make(map[string]string, len(vars))
	for k, v := range vars {
		result[k] = v
	}
	for _, def := range defs {
		if _, provided := result[def.Name]; !provided && def.Default != "" {
			result[def.Name] = def.Default
		}
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
