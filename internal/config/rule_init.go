package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// RuleInitializer handles syncing rules from config to database
type RuleInitializer struct {
	repo   storage.RuleRepository
	logger *slog.Logger
}

// NewRuleInitializer creates a new rule initializer
func NewRuleInitializer(repo storage.RuleRepository, logger *slog.Logger) (*RuleInitializer, error) {
	if repo == nil {
		return nil, fmt.Errorf("rule repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &RuleInitializer{
		repo:   repo,
		logger: logger,
	}, nil
}

// SyncFromConfig syncs rules from config to database
// - Creates new rules that don't exist (identified by generated ID from config)
// - Updates existing rules with new values from config
// - Deletes config-sourced rules that are no longer in config (preserves API-created rules)
func (i *RuleInitializer) SyncFromConfig(ctx context.Context, rules []RuleConfig) error {
	// Build set of expected rule IDs from config
	expectedIDs := make(map[types.RuleID]bool)
	for idx, ruleCfg := range rules {
		ruleID := i.generateRuleID(idx, ruleCfg)
		expectedIDs[ruleID] = true
	}

	// Get all existing config-sourced rules from database
	configSource := types.RuleSourceConfig
	existingRules, err := i.repo.List(ctx, storage.RuleFilter{
		Source: &configSource,
		Limit:  1000, // Get all config rules
	})
	if err != nil {
		return fmt.Errorf("failed to list config rules: %w", err)
	}

	// Delete config rules that are no longer in config
	deleted := 0
	for _, rule := range existingRules {
		if !expectedIDs[rule.ID] {
			if err := i.repo.Delete(ctx, rule.ID); err != nil {
				return fmt.Errorf("failed to delete stale config rule %s: %w", rule.ID, err)
			}
			i.logger.Info("Deleted stale config rule",
				"id", rule.ID,
				"name", rule.Name,
			)
			deleted++
		}
	}

	if len(rules) == 0 {
		i.logger.Info("No rules configured in config file", "deleted", deleted)
		return nil
	}

	// Sync rules from config
	synced := 0
	for idx, ruleCfg := range rules {
		if err := i.syncRule(ctx, idx, ruleCfg); err != nil {
			return fmt.Errorf("failed to sync rule %s: %w", ruleCfg.Name, err)
		}
		synced++
	}

	i.logger.Info("Rules synced from config", "synced", synced, "deleted", deleted)
	return nil
}

// generateRuleID generates a deterministic rule ID based on config content
// This ensures the same config always produces the same ID
func (i *RuleInitializer) generateRuleID(idx int, ruleCfg RuleConfig) types.RuleID {
	// Create a hash from the rule name and type to generate deterministic ID
	// This allows the same rule in config to be updated rather than duplicated
	data := fmt.Sprintf("config:%d:%s:%s", idx, ruleCfg.Name, ruleCfg.Type)
	hash := sha256.Sum256([]byte(data))
	return types.RuleID("cfg_" + hex.EncodeToString(hash[:8]))
}

func (i *RuleInitializer) syncRule(ctx context.Context, idx int, ruleCfg RuleConfig) error {
	// Skip disabled rules
	if !ruleCfg.Enabled {
		i.logger.Debug("Skipping disabled rule", "name", ruleCfg.Name)
		return nil
	}

	// Generate deterministic rule ID
	ruleID := i.generateRuleID(idx, ruleCfg)

	// Marshal config to JSON
	configJSON, err := json.Marshal(ruleCfg.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal rule config: %w", err)
	}

	// Check if rule exists
	existing, err := i.repo.Get(ctx, ruleID)
	if err != nil && !types.IsNotFound(err) {
		return fmt.Errorf("failed to check existing rule: %w", err)
	}

	// Build rule
	rule := &types.Rule{
		ID:          ruleID,
		Name:        ruleCfg.Name,
		Description: ruleCfg.Description,
		Type:        types.RuleType(ruleCfg.Type),
		Mode:        types.RuleMode(ruleCfg.Mode),
		Source:      types.RuleSourceConfig,
		Config:      configJSON,
		Enabled:     ruleCfg.Enabled,
	}

	// Set optional scope fields
	if ruleCfg.ChainType != "" {
		ct := types.ChainType(ruleCfg.ChainType)
		rule.ChainType = &ct
	} else {
		// Default to EVM
		ct := types.ChainTypeEVM
		rule.ChainType = &ct
	}
	if ruleCfg.ChainID != "" {
		rule.ChainID = &ruleCfg.ChainID
	}
	if ruleCfg.APIKeyID != "" {
		rule.APIKeyID = &ruleCfg.APIKeyID
	}
	if ruleCfg.SignerAddress != "" {
		rule.SignerAddress = &ruleCfg.SignerAddress
	}

	if existing == nil {
		// Create new rule
		rule.CreatedAt = time.Now()
		rule.UpdatedAt = time.Now()

		if err := i.repo.Create(ctx, rule); err != nil {
			return fmt.Errorf("failed to create rule: %w", err)
		}

		i.logger.Info("Created rule from config",
			"id", ruleID,
			"name", ruleCfg.Name,
			"type", ruleCfg.Type,
			"mode", ruleCfg.Mode,
		)
	} else {
		// Update existing rule with config values
		existing.Name = rule.Name
		existing.Description = rule.Description
		existing.Type = rule.Type
		existing.Mode = rule.Mode
		existing.Config = rule.Config
		existing.ChainType = rule.ChainType
		existing.ChainID = rule.ChainID
		existing.APIKeyID = rule.APIKeyID
		existing.SignerAddress = rule.SignerAddress
		existing.Enabled = rule.Enabled
		existing.UpdatedAt = time.Now()

		if err := i.repo.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update rule: %w", err)
		}

		i.logger.Info("Updated rule from config",
			"id", ruleID,
			"name", ruleCfg.Name,
			"type", ruleCfg.Type,
			"mode", ruleCfg.Mode,
		)
	}

	return nil
}
