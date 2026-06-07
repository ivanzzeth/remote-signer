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
// for each sub-rule in every composed template.
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

	preset, err := presetRepo.Get(ctx, "evm/agent")
	if err != nil {
		if types.IsNotFound(err) {
			log.Info("agent preset not found in registry, skipping bootstrap")
			return nil
		}
		return fmt.Errorf("get agent preset: %w", err)
	}
	if !preset.Enabled {
		log.Info("agent preset is disabled, skipping bootstrap")
		return nil
	}

	templateIDs, err := decodeStringSlice(preset.TemplateIDs)
	if err != nil {
		return fmt.Errorf("decode agent preset template_ids: %w", err)
	}
	if len(templateIDs) == 0 {
		log.Info("agent preset has no template_ids, skipping bootstrap")
		return nil
	}

	allVarDefs, err := collectTemplateVarDefs(ctx, templateRepo, templateIDs)
	if err != nil {
		return err
	}
	resolved, err := resolvePresetVariables(preset.Variables, allVarDefs)
	if err != nil {
		return fmt.Errorf("resolve preset variables: %w", err)
	}

	created := 0
	for _, templateID := range templateIDs {
		tmpl, err := templateRepo.Get(ctx, templateID)
		if err != nil {
			if types.IsNotFound(err) {
				log.Info("agent bootstrap: template not found, skipping", "template_id", templateID)
				continue
			}
			return fmt.Errorf("get template %q: %w", templateID, err)
		}

		configDoc, err := parseTemplateConfig(tmpl.Config)
		if err != nil {
			return err
		}

		n, err := createRulesFromConfig(ctx, ruleRepo, budgetRepo, configDoc, resolved, preset.ChainType, templateID, log)
		if err != nil {
			return err
		}
		created += n
	}

	if created == 0 {
		return fmt.Errorf("no enabled sub-rules found in agent preset templates")
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "[BOOTSTRAP] Agent preset \"evm/agent\" applied —", fmt.Sprintf("%d rule(s)", created), "created for \"agent\" API key.")
	fmt.Fprintln(os.Stderr)

	log.Info("bootstrap agent preset applied", "rules_created", created, "template_count", len(templateIDs))
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

type templateSubRule struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Type        string         `json:"type"`
	Mode        string         `json:"mode"`
	Priority    *int           `json:"priority,omitempty"`
	Enabled     bool           `json:"enabled"`
	Description string         `json:"description"`
	Config      map[string]any `json:"config"`
}

func coalesceAgentRulePriority(p *int) int {
	if p == nil {
		return 100
	}
	if *p < 1 {
		return 1
	}
	return *p
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

type templateVarDef struct {
	Name    string `json:"name"`
	Default any    `json:"default,omitempty"`
}

// collectTemplateVarDefs merges variable definitions from all composed templates.
// First occurrence wins (same semantics as preset apply).
func collectTemplateVarDefs(ctx context.Context, templateRepo storage.TemplateRepository, templateIDs []string) ([]templateVarDef, error) {
	seen := make(map[string]struct{})
	var defs []templateVarDef
	for _, id := range templateIDs {
		tmpl, err := templateRepo.Get(ctx, id)
		if err != nil {
			if types.IsNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("get template %q: %w", id, err)
		}
		if len(tmpl.Variables) == 0 {
			continue
		}
		var varDefs []templateVarDef
		if err := json.Unmarshal(tmpl.Variables, &varDefs); err != nil {
			return nil, fmt.Errorf("parse template variables for %q: %w", id, err)
		}
		for _, def := range varDefs {
			if _, ok := seen[def.Name]; ok {
				continue
			}
			seen[def.Name] = struct{}{}
			defs = append(defs, def)
		}
	}
	return defs, nil
}

// resolvePresetVariables merges preset variable overrides with template defaults.
// Agent preset is chain-agnostic — chain_id is not injected.
func resolvePresetVariables(presetVarsJSON []byte, varDefs []templateVarDef) (map[string]string, error) {
	presetVars, err := decodeStringMap(presetVarsJSON)
	if err != nil {
		return nil, fmt.Errorf("decode preset variables: %w", err)
	}

	resolved := make(map[string]string, len(presetVars)+len(varDefs))
	for k, v := range presetVars {
		resolved[k] = v
	}
	for _, def := range varDefs {
		if _, ok := resolved[def.Name]; ok {
			continue
		}
		if def.Default != nil {
			if s, ok := def.Default.(string); ok {
				resolved[def.Name] = s
			}
		}
	}
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

		ruleID := types.RuleID("inst_" + hashForID(templateID, resolved, sub.ID, time.Now().UnixNano()))
		if err := createRule(ctx, ruleRepo, ruleID, sub, configWithVars, variablesJSON, chainType, templateID); err != nil {
			return created, fmt.Errorf("create sub-rule %q: %w", sub.Name, err)
		}
		created++

		log.Info("bootstrap agent preset: created rule",
			"rule_id", ruleID, "template_id", templateID, "name", sub.Name, "type", sub.Type, "mode", sub.Mode,
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
		Priority:    coalesceAgentRulePriority(sub.Priority),
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

// decodeStringSlice decodes a JSONB column as []string.
func decodeStringSlice(b []byte) ([]string, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
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
