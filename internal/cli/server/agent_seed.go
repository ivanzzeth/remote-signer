package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/lib/pq"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// bootstrapAgentPresetIfNeeded checks whether any instance rules owned by
// "agent" already exist and, if not, loads the evm/agent preset from the
// DB (populated by registry sync on the same boot) and creates rule instances
// for each sub-rule in the template.
//
// Rules are associated with the agent API key so they have the correct RBAC
// ownership at first launch. Subsequent boots are no-ops.
func bootstrapAgentPresetIfNeeded(
	ctx context.Context,
	presetRepo storage.PresetRepository,
	templateRepo storage.TemplateRepository,
	ruleRepo storage.RuleRepository,
	budgetRepo storage.BudgetRepository,
	log *slog.Logger,
) error {
	if has, err := hasInstanceRules(ctx, ruleRepo); err != nil {
		return err
	} else if has {
		return nil
	}

	preset, tmpl, err := loadAgentPresetAndTemplate(ctx, presetRepo, templateRepo, log)
	if err != nil {
		return err
	}
	if preset == nil {
		return nil
	}

	configDoc, err := parseTemplateConfig(tmpl.Config)
	if err != nil {
		return err
	}

	resolved, err := resolvePresetVariables(preset.Variables, tmpl.Variables)
	if err != nil {
		return fmt.Errorf("resolve preset variables: %w", err)
	}

	created, err := createRulesFromConfig(ctx, ruleRepo, budgetRepo, configDoc, resolved, preset.ChainType, tmpl.ID, log)
	if err != nil {
		return err
	}
	if created == 0 {
		return fmt.Errorf("no enabled sub-rules found in agent template")
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "[BOOTSTRAP] Agent preset \"evm/agent\" applied —", fmt.Sprintf("%d rule(s)", created), "created for \"agent\" API key.")
	fmt.Fprintln(os.Stderr)

	log.Info("bootstrap agent preset applied", "rules_created", created)
	return nil
}

// hasInstanceRules returns true if any instance-source rules already exist.
func hasInstanceRules(ctx context.Context, ruleRepo storage.RuleRepository) (bool, error) {
	source := types.RuleSourceInstance
	count, err := ruleRepo.Count(ctx, storage.RuleFilter{Source: &source})
	if err != nil {
		return false, fmt.Errorf("count rules: %w", err)
	}
	return count > 0, nil
}

// loadAgentPresetAndTemplate loads the evm/agent preset and template from the
// DB. Returns nil, nil (no error) when the preset or template is not found
// or disabled.
func loadAgentPresetAndTemplate(
	ctx context.Context,
	presetRepo storage.PresetRepository,
	templateRepo storage.TemplateRepository,
	log *slog.Logger,
) (*types.RulePreset, *types.RuleTemplate, error) {
	preset, err := presetRepo.Get(ctx, "evm/agent")
	if err != nil {
		if types.IsNotFound(err) {
			log.Info("agent preset not found in registry, skipping bootstrap")
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("get agent preset: %w", err)
	}
	if !preset.Enabled {
		log.Info("agent preset is disabled, skipping bootstrap")
		return nil, nil, nil
	}

	tmpl, err := templateRepo.Get(ctx, "evm/agent")
	if err != nil {
		if types.IsNotFound(err) {
			log.Info("agent template not found in registry, skipping bootstrap")
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("get agent template: %w", err)
	}
	return preset, tmpl, nil
}

type templateSubRule struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Type        string         `json:"type"`
	Mode        string         `json:"mode"`
	Enabled     bool           `json:"enabled"`
	Description string         `json:"description"`
	Config      map[string]any `json:"config"`
}

type templateConfigDoc struct {
	Rules []templateSubRule `json:"rules"`
}

// parseTemplateConfig unmarshals the template config JSON into sub-rules.
func parseTemplateConfig(configJSON []byte) (*templateConfigDoc, error) {
	var doc templateConfigDoc
	if err := json.Unmarshal(configJSON, &doc); err != nil {
		return nil, fmt.Errorf("parse template config: %w", err)
	}
	return &doc, nil
}

// resolvePresetVariables merges preset variable overrides with template
// variable defaults and injects chain_id=1.
func resolvePresetVariables(presetVarsJSON, tmplVarsJSON []byte) (map[string]string, error) {
	presetVars, err := decodeStringMap(presetVarsJSON)
	if err != nil {
		return nil, fmt.Errorf("decode preset variables: %w", err)
	}

	var varDefs []struct {
		Name    string `json:"name"`
		Default any    `json:"default,omitempty"`
	}
	if len(tmplVarsJSON) > 0 {
		if err := json.Unmarshal(tmplVarsJSON, &varDefs); err != nil {
			return nil, fmt.Errorf("parse template variables: %w", err)
		}
	}

	resolved := make(map[string]string, len(presetVars))
	for k, v := range presetVars {
		resolved[k] = v
	}
	for _, def := range varDefs {
		if _, ok := resolved[def.Name]; !ok && def.Default != nil {
			if s, ok := def.Default.(string); ok && s != "" {
				resolved[def.Name] = s
			}
		}
	}
	resolved["chain_id"] = "1"
	return resolved, nil
}

// createRulesFromConfig creates a Rule (and optionally a Budget) for each
// enabled sub-rule in the template config. Returns the number of rules created.
func createRulesFromConfig(
	ctx context.Context,
	ruleRepo storage.RuleRepository,
	budgetRepo storage.BudgetRepository,
	configDoc *templateConfigDoc,
	resolved map[string]string,
	chainType types.ChainType,
	templateID string,
	log *slog.Logger,
) (int, error) {
	variablesJSON, _ := json.Marshal(resolved)

	created := 0
	for _, sub := range configDoc.Rules {
		if !sub.Enabled || sub.Type == "" || sub.Mode == "" {
			continue
		}

		configWithVars, err := injectVariables(sub.Config, resolved)
		if err != nil {
			return created, fmt.Errorf("inject variables for sub-rule %q: %w", sub.Name, err)
		}

		ruleID := types.RuleID("inst_" + hashForID("evm/agent", resolved, sub.ID, time.Now().UnixNano()))
		if err := createRule(ctx, ruleRepo, ruleID, sub, configWithVars, variablesJSON, chainType, templateID); err != nil {
			return created, fmt.Errorf("create sub-rule %q: %w", sub.Name, err)
		}
		created++

		log.Info("bootstrap agent preset: created rule",
			"rule_id", ruleID, "name", sub.Name, "type", sub.Type, "mode", sub.Mode,
		)

		if types.RuleMode(sub.Mode) == types.RuleModeWhitelist {
			if err := createBudget(ctx, budgetRepo, ruleID, log); err != nil {
				return created, fmt.Errorf("create budget for sub-rule %q: %w", sub.Name, err)
			}
		}
	}
	return created, nil
}

// injectVariables merges resolved variables into the sub-rule config map.
func injectVariables(config map[string]any, resolved map[string]string) ([]byte, error) {
	merged := make(map[string]any, len(config)+len(resolved))
	for k, v := range config {
		merged[k] = v
	}
	for k, v := range resolved {
		merged[k] = v
	}
	return json.Marshal(merged)
}

// createRule inserts a single rule instance into the DB.
func createRule(
	ctx context.Context,
	ruleRepo storage.RuleRepository,
	ruleID types.RuleID,
	sub templateSubRule,
	configJSON, variablesJSON []byte,
	chainType types.ChainType,
	templateID string,
) error {
	now := time.Now()
	rule := &types.Rule{
		ID:          ruleID,
		Name:        "Agent — " + sub.Name,
		Description: sub.Description,
		Type:        types.RuleType(sub.Type),
		Mode:        types.RuleMode(sub.Mode),
		Source:      types.RuleSourceInstance,
		Config:      configJSON,
		TemplateID:  &templateID,
		Variables:   variablesJSON,
		Enabled:     true,
		AppliedTo:   pq.StringArray{"agent"},
		Owner:       "agent",
		Status:      types.RuleStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	ct := types.ChainType(string(chainType))
	rule.ChainType = &ct
	return ruleRepo.Create(ctx, rule)
}

// createBudget inserts a default count budget for a whitelist rule.
func createBudget(ctx context.Context, budgetRepo storage.BudgetRepository, ruleID types.RuleID, log *slog.Logger) error {
	budget := &types.RuleBudget{
		ID:         types.BudgetID(ruleID, "count"),
		RuleID:     ruleID,
		Unit:       "count",
		MaxTotal:   "1000",
		MaxPerTx:   "1",
		Spent:      "0",
		AlertPct:   80,
		TxCount:    0,
		MaxTxCount: 1000,
	}
	if err := budgetRepo.Create(ctx, budget); err != nil {
		return err
	}
	log.Info("bootstrap agent preset: created budget",
		"rule_id", ruleID, "budget_id", budget.ID,
	)
	return nil
}

// hashForID generates a deterministic hex suffix for rule IDs.
func hashForID(templateID string, vars map[string]string, subID string, nano int64) string {
	data := fmt.Sprintf("instance:%s:%v:%s:%d", templateID, vars, subID, nano)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

// decodeStringMap decodes a JSONB column ([]byte) as map[string]string,
// coercing any non-string values via fmt.Sprint.
func decodeStringMap(b []byte) (map[string]string, error) {
	if len(b) == 0 {
		return map[string]string{}, nil
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		switch x := v.(type) {
		case string:
			out[k] = x
		case nil:
			out[k] = ""
		default:
			enc, _ := json.Marshal(v)
			out[k] = string(enc)
		}
	}
	return out, nil
}
