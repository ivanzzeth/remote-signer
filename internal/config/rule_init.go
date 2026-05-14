package config

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// RuleFileType is the special rule type for including rules from external files
const RuleFileType = "file"

// RuleFileConfig represents the config structure for file-type rules
type RuleFileConfig struct {
	Path string `yaml:"path"` // Path to the YAML file containing rules
}

// RuleInitializer handles syncing rules from config to database
type RuleInitializer struct {
	repo         storage.RuleRepository
	templateRepo storage.TemplateRepository // optional: for instance rules — set TemplateID and create budget
	budgetRepo   storage.BudgetRepository   // optional: for instance rules with budget
	logger       *slog.Logger
	configDir    string // Base directory for resolving relative file paths
	auditLogger  *audit.AuditLogger
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
		repo:      repo,
		logger:    logger,
		configDir: ".", // Default to current directory
	}, nil
}

// SetTemplateRepo sets the template repository for instance-rule sync (TemplateID + budget).
func (i *RuleInitializer) SetTemplateRepo(repo storage.TemplateRepository) {
	i.templateRepo = repo
}

// SetBudgetRepo sets the budget repository for instance-rule sync (create budget records).
func (i *RuleInitializer) SetBudgetRepo(repo storage.BudgetRepository) {
	i.budgetRepo = repo
}

// SetConfigDir sets the base directory for resolving relative file paths in rule files
func (i *RuleInitializer) SetConfigDir(dir string) {
	i.configDir = dir
}

// SetAuditLogger sets the audit logger for recording config rule sync events.
func (i *RuleInitializer) SetAuditLogger(al *audit.AuditLogger) {
	i.auditLogger = al
}

// ValidateExplicitRuleIDs ensures every rule has an explicit id. Returns error if any rule lacks id.
// Required to keep rule IDs stable across preset/config changes (avoids index-based ID drift).
func ValidateExplicitRuleIDs(rules []RuleConfig) error {
	var missing []string
	for idx, r := range rules {
		if strings.TrimSpace(r.Id) == "" {
			missing = append(missing, fmt.Sprintf("rule %q (index %d)", r.Name, idx))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("rules must have explicit id; missing id for: %s", strings.Join(missing, ", "))
	}
	return nil
}

// ValidateDelegationTargets checks that all delegate_to references in rules
// resolve to existing rule IDs. Returns error if any target is missing.
func ValidateDelegationTargets(rules []RuleConfig) error {
	// Build set of all known rule IDs
	knownIDs := make(map[types.RuleID]bool, len(rules))
	for idx, r := range rules {
		knownIDs[EffectiveRuleID(idx, r)] = true
	}
	// Check each rule's delegate_to
	var errs []string
	for idx, r := range rules {
		delegateTo, _ := r.Config["delegate_to"].(string)
		if delegateTo == "" {
			continue
		}
		ruleID := EffectiveRuleID(idx, r)
		for _, part := range strings.Split(delegateTo, ",") {
			targetID := types.RuleID(strings.TrimSpace(part))
			if targetID == "" {
				continue
			}
			if strings.Contains(string(targetID), "${") {
				continue // unresolved variable — skip
			}
			if !knownIDs[targetID] {
				errs = append(errs, fmt.Sprintf("rule %q (%s) delegate_to references non-existent target %q", r.Name, ruleID, targetID))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("delegation target validation failed:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}
