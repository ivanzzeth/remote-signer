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
	// Check if agent rules already exist (idempotency guard).
	source := types.RuleSourceInstance
	count, err := ruleRepo.Count(ctx, storage.RuleFilter{
		Source: &source,
	})
	if err != nil {
		return fmt.Errorf("count rules: %w", err)
	}
	if count > 0 {
		return nil
	}

	// Load the preset and template from DB (seeded by registry sync).
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

	tmpl, err := templateRepo.Get(ctx, "evm/agent")
	if err != nil {
		if types.IsNotFound(err) {
			log.Info("agent template not found in registry, skipping bootstrap")
			return nil
		}
		return fmt.Errorf("get agent template: %w", err)
	}

	// Parse preset variables and template sub-rules.
	presetVars, _ := decodeStringMap(preset.Variables)
	var configDoc struct {
		Rules []struct {
			ID          string                 `json:"id"`
			Name        string                 `json:"name"`
			Type        string                 `json:"type"`
			Mode        string                 `json:"mode"`
			Enabled     bool                   `json:"enabled"`
			Description string                 `json:"description"`
			Config      map[string]any         `json:"config"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(tmpl.Config, &configDoc); err != nil {
		return fmt.Errorf("parse template config: %w", err)
	}
	if len(configDoc.Rules) == 0 {
		return fmt.Errorf("agent template has no sub-rules")
	}

	// Resolve variable defaults from template definitions.
	var varDefs []struct {
		Name    string `json:"name"`
		Default any    `json:"default,omitempty"`
	}
	if len(tmpl.Variables) > 0 {
		if err := json.Unmarshal(tmpl.Variables, &varDefs); err != nil {
			return fmt.Errorf("parse template variables: %w", err)
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
	variablesJSON, _ := json.Marshal(resolved)

	// Parse budget_metering from template for budget creation.
	var budgetMetering struct {
		Dynamic      bool `json:"dynamic"`
		UnitDecimal  bool `json:"unit_decimal"`
	}

	created := 0
	for _, sub := range configDoc.Rules {
		if !sub.Enabled {
			continue
		}
		if sub.Type == "" || sub.Mode == "" {
			continue
		}

		subConfigJSON, err := json.Marshal(sub.Config)
		if err != nil {
			return fmt.Errorf("marshal sub-rule config: %w", err)
		}

		// Inject instance variables into sub-rule config for evaluators.
		subConfigMap := make(map[string]any)
		if err := json.Unmarshal(subConfigJSON, &subConfigMap); err != nil {
			return fmt.Errorf("unmarshal sub-rule config: %w", err)
		}
		for k, v := range resolved {
			subConfigMap[k] = v
		}
		subConfigJSON, err = json.Marshal(subConfigMap)
		if err != nil {
			return fmt.Errorf("re-marshal sub-rule config: %w", err)
		}

		ruleID := types.RuleID("inst_" + hashForID("evm/agent", resolved, sub.ID, time.Now().UnixNano()))

		now := time.Now()
		rule := &types.Rule{
			ID:          ruleID,
			Name:        "Agent — " + sub.Name,
			Description: sub.Description,
			Type:        types.RuleType(sub.Type),
			Mode:        types.RuleMode(sub.Mode),
			Source:      types.RuleSourceInstance,
			Config:      subConfigJSON,
			TemplateID:  &tmpl.ID,
			Variables:   variablesJSON,
			Enabled:     true,
			AppliedTo:   pq.StringArray{"agent"},
			Owner:       "agent",
			Status:      types.RuleStatusActive,
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		ct := types.ChainType(string(preset.ChainType))
		rule.ChainType = &ct

		if err := ruleRepo.Create(ctx, rule); err != nil {
			return fmt.Errorf("create sub-rule %q: %w", sub.Name, err)
		}
		created++

		log.Info("bootstrap agent preset: created rule",
			"rule_id", ruleID, "name", sub.Name, "type", sub.Type, "mode", sub.Mode,
		)

		// Create budget for whitelist rules.
		if types.RuleMode(sub.Mode) == types.RuleModeWhitelist {
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

			budgetMetering.Dynamic = true
			budgetMetering.UnitDecimal = true

			if err := budgetRepo.Create(ctx, budget); err != nil {
				return fmt.Errorf("create budget for sub-rule %q: %w", sub.Name, err)
			}
			log.Info("bootstrap agent preset: created budget",
				"rule_id", ruleID, "budget_id", budget.ID,
			)
		}
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

// hashForID generates a deterministic hex suffix for rule IDs.
func hashForID(templateID string, vars map[string]string, subID string, nano int64) string {
	data := fmt.Sprintf("instance:%s:%v:%s:%d", templateID, vars, subID, nano)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

// decodeStringSlice decodes a JSONB column ([]byte) as []string.
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
