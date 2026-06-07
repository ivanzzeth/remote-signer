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

	// Optional: per-chain variable overrides stored as JSONB on the rule.
	Matrix json.RawMessage `json:"matrix,omitempty"`

	// CrossTemplateIDMap maps template sub-rule IDs (YAML IDs) to actual
	// instance rule IDs (inst_<hash>) from other templates in the same batch.
	// Used by BatchCreateInstances to resolve delegate_to cross-references
	// before persisting. Single-instance callers leave this nil.
	CrossTemplateIDMap map[string]types.RuleID `json:"-"`

	// PrecomputedRuleID overrides auto-generation of the rule ID.
	// Set by BatchCreateInstances Phase 1 so the ID matches what was
	// already published to CrossTemplateIDMap.
	PrecomputedRuleID types.RuleID `json:"-"`

	// PrecomputedSubRuleIDs maps sub-rule ID suffix → pre-computed rule ID.
	// Same purpose as PrecomputedRuleID but for template_bundle sub-rules.
	PrecomputedSubRuleIDs map[string]types.RuleID `json:"-"`
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

// BatchCreateItem pairs a resolved template with its creation request for batch operations.
type BatchCreateItem struct {
	Template *types.RuleTemplate
	Request  *CreateInstanceRequest
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
	return s.createInstanceFromResolved(ctx, s.ruleRepo, s.budgetRepo, tmpl, req, nil)
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
	return s.createInstanceFromResolved(ctx, ruleRepo, budgetRepo, tmpl, req, nil)
}

// BatchCreateInstances creates multiple rule instances in a single batch,
// resolving cross-template delegate_to references before any rule is persisted.
// Each item must have a resolved Template (from ResolveTemplate) and Request.
// Uses the provided repos (typically tx-scoped) for all DB operations.
//
// Phase 1: pre-compute all instance IDs across all items, building a combined
// map of template sub-rule ID → actual inst_<hash> ID.
// Phase 2: inject the combined map into each request's CrossTemplateIDMap,
// then create each instance. Inside createInstanceFromResolved/Bundle, the
// delegate_to/delegate_to_by_target fields are resolved before persisting.
//
// After creation, each result's SubRuleIDMap is merged into the global map
// so that templates later in the batch can reference rules created earlier.
func (s *TemplateService) BatchCreateInstances(
	ctx context.Context,
	ruleRepo storage.RuleRepository,
	budgetRepo storage.BudgetRepository,
	items []BatchCreateItem,
) ([]*CreateInstanceResult, error) {
	if len(items) == 0 {
		return nil, nil
	}

	// Phase 1: pre-compute all rule IDs and build cross-template ID map
	globalSubRuleIDMap := make(map[string]types.RuleID)
	type pendingItem struct {
		item         BatchCreateItem
		resolvedVars map[string]string
	}
	pending := make([]pendingItem, 0, len(items))

	for _, item := range items {
		if item.Template == nil {
			return nil, fmt.Errorf("template is required for item %q", item.Request.TemplateID)
		}
		if item.Request == nil {
			return nil, fmt.Errorf("request is required for template %q", item.Template.ID)
		}

		var varDefs []types.TemplateVariable
		if len(item.Template.Variables) > 0 {
			if err := json.Unmarshal(item.Template.Variables, &varDefs); err != nil {
				return nil, fmt.Errorf("failed to parse template variables for %q: %w", item.Template.ID, err)
			}
		}
		if err := validateVariables(varDefs, item.Request.Variables); err != nil {
			return nil, fmt.Errorf("variable validation failed for %q: %w", item.Template.ID, err)
		}
		resolvedVars := resolveDefaults(varDefs, item.Request.Variables)
		injectReservedVariables(resolvedVars, item.Request, s.logger)
		s.mergeTestVariables(resolvedVars, item.Template)

		// Pre-compute rule IDs for this template
		if err := s.collectRuleIDs(globalSubRuleIDMap, item.Template, item.Request, resolvedVars); err != nil {
			return nil, fmt.Errorf("pre-compute IDs for %q: %w", item.Template.ID, err)
		}

		pending = append(pending, pendingItem{item: item, resolvedVars: resolvedVars})
	}

	// Phase 2: inject cross-template map and create each instance
	results := make([]*CreateInstanceResult, 0, len(pending))
	for _, p := range pending {
		p.item.Request.CrossTemplateIDMap = globalSubRuleIDMap

		result, err := s.createInstanceFromResolved(ctx, ruleRepo, budgetRepo, p.item.Template, p.item.Request, p.resolvedVars)
		if err != nil {
			return nil, fmt.Errorf("create instance for %q: %w", p.item.Request.TemplateID, err)
		}

		// Merge this result's sub-rule IDs into the global map for later items
		for k, v := range result.SubRuleIDMap {
			globalSubRuleIDMap[k] = v
		}
		results = append(results, result)
	}

	return results, nil
}

// collectRuleIDs pre-computes the rule IDs that a template will generate and
// adds them to the provided map. For bundle templates, each sub-rule ID is
// mapped. For single-rule templates, the template ID itself is the key.
// The precomputed IDs are also stored on the request (PrecomputedRuleID /
// PrecomputedSubRuleIDs) so Phase 2 of BatchCreateInstances reuses them.
func (s *TemplateService) collectRuleIDs(m map[string]types.RuleID, tmpl *types.RuleTemplate, req *CreateInstanceRequest, resolvedVars map[string]string) error {
	if tmpl.Type == "template_bundle" {
		configMap := make(map[string]interface{})
		resolvedConfig, err := SubstituteVariables(tmpl.Config, resolvedVars)
		if err != nil {
			return fmt.Errorf("variable substitution failed: %w", err)
		}
		if err := json.Unmarshal(resolvedConfig, &configMap); err != nil {
			return fmt.Errorf("failed to parse resolved bundle config: %w", err)
		}
		rulesJSON, ok := configMap["rules_json"].(string)
		if !ok {
			return fmt.Errorf("template_bundle %q has no rules_json", tmpl.Name)
		}
		var subRules []bundleSubRule
		if err := json.Unmarshal([]byte(rulesJSON), &subRules); err != nil {
			return fmt.Errorf("failed to parse bundle rules_json: %w", err)
		}
		precomputed := make(map[string]types.RuleID, len(subRules))
		for _, sub := range subRules {
			subIDSuffix := sub.ID
			if subIDSuffix == "" {
				subIDSuffix = sub.Name
			}
			subRuleID := req.PrecomputedSubRuleIDs[subIDSuffix]
			if subRuleID == "" {
				subRuleID = s.generateBundleSubRuleID(tmpl.ID, resolvedVars, subIDSuffix)
			}
			precomputed[subIDSuffix] = subRuleID
			if sub.ID != "" {
				m[sub.ID] = subRuleID
			}
		}
		req.PrecomputedSubRuleIDs = precomputed
		return nil
	}

	ruleID := s.generateInstanceRuleID(tmpl.ID, resolvedVars)
	m[tmpl.ID] = ruleID
	req.PrecomputedRuleID = ruleID
	return nil
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
	return s.createInstanceFromResolved(ctx, ruleRepo, budgetRepo, tmpl, req, nil)
}

func (s *TemplateService) createInstanceFromResolved(
	ctx context.Context,
	ruleRepo storage.RuleRepository,
	budgetRepo storage.BudgetRepository,
	tmpl *types.RuleTemplate,
	req *CreateInstanceRequest,
	precomputedVars map[string]string,
) (*CreateInstanceResult, error) {
	var varDefs []types.TemplateVariable
	if len(tmpl.Variables) > 0 {
		if err := json.Unmarshal(tmpl.Variables, &varDefs); err != nil {
			return nil, fmt.Errorf("failed to parse template variables: %w", err)
		}
	}
	resolvedVars := precomputedVars
	if resolvedVars == nil {
		if err := validateVariables(varDefs, req.Variables); err != nil {
			return nil, fmt.Errorf("variable validation failed: %w", err)
		}
		resolvedVars = resolveDefaults(varDefs, req.Variables)
		injectReservedVariables(resolvedVars, req, s.logger)
		s.mergeTestVariables(resolvedVars, tmpl)
	}

	// Validate that every ${var} placeholder resolves with the bound variables.
	// We do NOT persist the substituted result: instance rules store their Config
	// in TEMPLATE form (placeholders intact) and the rule engine substitutes
	// Variables (+Matrix+chain_id) live at evaluation. Variables is the single
	// source of truth — editing it takes effect with no rendered snapshot to
	// drift. This call is kept purely to fail fast on unresolved/unknown
	// variables at create time. Cross-template delegate_to references are
	// resolved in Variables below (resolveDelegateToInVars), so the live
	// substitution of ${delegate_to} yields the correct inst IDs.
	if _, err := SubstituteVariables(tmpl.Config, resolvedVars); err != nil {
		return nil, fmt.Errorf("variable substitution failed: %w", err)
	}

	// If template is a bundle, expand into sub-rules (each stored template-form).
	if tmpl.Type == "template_bundle" {
		return s.createInstanceFromBundle(ctx, ruleRepo, budgetRepo, tmpl, req, resolvedVars)
	}

	// Config is persisted template-form so Variables resolve live at evaluation.
	// However, cross-template delegate_to LITERALS (e.g. "polymarket-transactions")
	// reference rule IDs generated at create time via CrossTemplateIDMap and
	// cannot be recovered at eval, so resolve them now. ${delegate_to} variable
	// placeholders are left intact and resolve from Variables at evaluation.
	storedConfig := append([]byte(nil), tmpl.Config...)
	if req.CrossTemplateIDMap != nil {
		var cfg map[string]interface{}
		if err := json.Unmarshal(storedConfig, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config for delegate resolution: %w", err)
		}
		newConfig, changed, err := ResolveDelegateToConfig(cfg, req.CrossTemplateIDMap)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve delegate config: %w", err)
		}
		if changed {
			storedConfig = newConfig
		}
	}

	ruleID := req.PrecomputedRuleID
	if ruleID == "" {
		ruleID = s.generateInstanceRuleID(tmpl.ID, resolvedVars)
	}
	// Resolve delegate_to in Variables so the JS runtime (which passes
	// Variables as config to scripts) reads resolved IDs, not template IDs.
	if len(req.CrossTemplateIDMap) > 0 {
		if err := resolveDelegateToInVars(resolvedVars, req.CrossTemplateIDMap); err != nil {
			return nil, fmt.Errorf("failed to resolve delegate_to in variables: %w", err)
		}
	}
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
		Config:      storedConfig, // template-form (delegate literals resolved); Variables resolved live at eval
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
	Priority    *int                   `json:"priority,omitempty"`
	Config      map[string]interface{} `json:"config"`
	Enabled     bool                   `json:"enabled"`
}

func coalesceBundlePriority(p *int) int {
	if p == nil {
		return 100 // default matches types.Rule gorm default
	}
	if *p < 1 {
		return 1
	}
	return *p
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
) (*CreateInstanceResult, error) {
	// Parse rules_json from the TEMPLATE-form config (placeholders intact): each
	// sub-rule is persisted template-form and resolved live at evaluation.
	var configMap map[string]interface{}
	if err := json.Unmarshal(tmpl.Config, &configMap); err != nil {
		return nil, fmt.Errorf("failed to parse bundle template config: %w", err)
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
		// Persist the sub-rule config in TEMPLATE form (no variable injection):
		// Variables are substituted live at evaluation, so the engine-evaluated
		// config always reflects the rule's current Variables.
		subConfigJSON, err := json.Marshal(sub.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal sub-rule config: %w", err)
		}

		var subConfig map[string]interface{}
		if err := json.Unmarshal(subConfigJSON, &subConfig); err != nil {
			return nil, fmt.Errorf("failed to parse sub-rule config: %w", err)
		}

		subIDSuffix := sub.ID
		if subIDSuffix == "" {
			subIDSuffix = sub.Name
		}
		subRuleID := req.PrecomputedSubRuleIDs[subIDSuffix]
			if subRuleID == "" {
				subRuleID = s.generateBundleSubRuleID(tmpl.ID, resolvedVars, subIDSuffix)
			}

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
			Priority:    coalesceBundlePriority(sub.Priority),
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
		if len(req.Matrix) > 0 {
			rule.Matrix = []byte(req.Matrix)
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

		// ---- Build combined resolution map ----
		// Merge cross-template IDs (from BatchCreateInstances) into local
		// sub-rule IDs so delegate_to can reference rules from other templates.
		resolveMap := subIDToRuleID
		if req.CrossTemplateIDMap != nil {
			resolveMap = make(map[string]types.RuleID, len(subIDToRuleID)+len(req.CrossTemplateIDMap))
			for k, v := range subIDToRuleID {
				resolveMap[k] = v
			}
			for k, v := range req.CrossTemplateIDMap {
				resolveMap[k] = v
			}
		}

		// ---- Resolve delegate_to references using the combined map ----
		for i, p := range pending {
			newConfig, changed, err := ResolveDelegateToConfig(p.config, resolveMap)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve delegate config for sub-rule %q: %w", p.rule.Name, err)
			}
			if changed {
				pending[i].rule.Config = newConfig
			}
		}

		// Resolve delegate_to in Variables JSON so the JS runtime (which
		// passes Variables as config to scripts) reads resolved IDs.
		// Without this, the script returns the unresolved template-level
		// ID (e.g. "polymarket-v2-transactions") as the delegation target,
		// which doesn't exist in the DB.
		if len(req.CrossTemplateIDMap) > 0 {
			if err := resolveDelegateToInVars(resolvedVars, resolveMap); err != nil {
				return nil, fmt.Errorf("failed to resolve delegate_to in variables for bundle %q: %w", tmpl.Name, err)
			}
			var err error
			variablesJSON, err = json.Marshal(resolvedVars)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal resolved variables: %w", err)
			}
			for i := range pending {
				pending[i].rule.Variables = variablesJSON
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

// rollbackRules deletes all previously created rules and their budgets (used on
// bundle expansion failure). Budgets are removed first so rows cannot linger
// when FK CASCADE is unavailable.
func (s *TemplateService) rollbackRules(ctx context.Context, ruleRepo storage.RuleRepository, ruleIDs []types.RuleID) {
	for _, id := range ruleIDs {
		if s.budgetRepo != nil {
			if err := s.budgetRepo.DeleteByRuleID(ctx, id); err != nil {
				s.logger.Error("failed to rollback sub-rule budgets", "rule_id", id, "error", err)
			}
		}
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

// resolveDelegateToInVars resolves delegate_to and delegate_to_by_target references
// in the Variables map (string→string) so the JS runtime reads resolved DB rule IDs.
func resolveDelegateToInVars(vars map[string]string, resolveMap map[string]types.RuleID) error {
	if dt, ok := vars["delegate_to"]; ok && dt != "" {
		parts := strings.Split(dt, ",")
		changed := false
		for j, part := range parts {
			part = strings.TrimSpace(part)
			if actualID, ok := resolveMap[part]; ok {
				parts[j] = string(actualID)
				changed = true
			}
		}
		if changed {
			vars["delegate_to"] = strings.Join(parts, ",")
		}
	}
	if dtbt, ok := vars["delegate_to_by_target"]; ok && dtbt != "" {
		pairs := strings.Split(dtbt, ",")
		changed := false
		for j, pair := range pairs {
			pair = strings.TrimSpace(pair)
			idx := strings.Index(pair, ":")
			if idx <= 0 {
				continue
			}
			rulePart := strings.TrimSpace(pair[idx+1:])
			if actualID, ok := resolveMap[rulePart]; ok {
				pairs[j] = pair[:idx+1] + string(actualID)
				changed = true
			}
		}
		if changed {
			vars["delegate_to_by_target"] = strings.Join(pairs, ",")
		}
	}
	return nil
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
		// Empty means optional / unconstrained (e.g. Agent preset token_address
		// for approve-any-token). Same convention as address_list entries.
		if value != "" && !isValidAddress(value) {
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