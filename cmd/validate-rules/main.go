package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/ruleconfig"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

const version = "0.1.14"

// resolvePath resolves path relative to baseDir if path is not absolute.
func resolvePath(baseDir, path string) string {
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

// RuleConfig defines a rule in configuration (copied from config package to avoid circular imports)
type RuleConfig struct {
	Id            string                 `yaml:"id,omitempty" json:"id,omitempty"`
	Name          string                 `yaml:"name"`
	Description   string                 `yaml:"description,omitempty"`
	Type          string                 `yaml:"type"`
	Mode          string                 `yaml:"mode"`
	ChainType     string                 `yaml:"chain_type,omitempty"`
	ChainID       string                 `yaml:"chain_id,omitempty"`
	APIKeyID      string                 `yaml:"api_key_id,omitempty"`
	SignerAddress string                 `yaml:"signer_address,omitempty"`
	Config        map[string]any         `yaml:"config"`
	Variables     map[string]interface{} `yaml:"variables,omitempty" json:"variables,omitempty"` // instance vars (from -config); used for rule.Variables and input substitution
	TestVariables map[string]string      `yaml:"test_variables,omitempty" json:"test_variables,omitempty"` // from template; use for validation so expected-fail cases get template test_variables
	TestCases     []TestCaseConfig       `yaml:"test_cases,omitempty" json:"test_cases,omitempty"`
	Enabled       bool                   `yaml:"enabled"`
}

// TestCaseConfig is a single test case for evm_js (from YAML test_cases).
type TestCaseConfig struct {
	Name               string                 `yaml:"name" json:"name"`
	Input              map[string]interface{} `yaml:"input" json:"input"`
	ExpectPass         bool                   `yaml:"expect_pass" json:"expect_pass"`
	ExpectReason       string                 `yaml:"expect_reason,omitempty" json:"expect_reason,omitempty"`
	ExpectBudgetAmount string                 `yaml:"expect_budget_amount,omitempty" json:"expect_budget_amount,omitempty"`
}

// RuleFile represents a YAML file containing rules (plain rule file)
type RuleFile struct {
	Rules []RuleConfig `yaml:"rules"`
}

// TemplateVarConfig defines a template variable (for template file parsing only).
// Optional variables (Required: false) must declare Default.
type TemplateVarConfig struct {
	Name        string  `yaml:"name"`
	Type        string  `yaml:"type"`
	Description string  `yaml:"description,omitempty"`
	Required    bool    `yaml:"required"`
	Default     *string `yaml:"default,omitempty"` // nil = not declared; optional vars must declare default
}

// TemplateFile represents a YAML template file (variables + test_variables + rules)
// When present, validate-rules substitutes test_variables into rules before validating.
type TemplateFile struct {
	Variables      []TemplateVarConfig `yaml:"variables"`
	TestVariables  map[string]string  `yaml:"test_variables"`
	Rules          []RuleConfig       `yaml:"rules"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Parse command line flags
	configPath := flag.String("config", "", "validate rules from config file (same expansion as server: templates + instance + file rules)")
	listRuleIDs := flag.Bool("list-rule-ids", false, "with -config: print deterministic rule IDs for each expanded rule (for delegate_to); then exit")
	forgePath := flag.String("forge", "", "path to forge binary (default: auto-detect from PATH)")
	cacheDir := flag.String("cache", "", "cache directory for compiled scripts (default: /tmp/remote-signer-validator)")
	timeout := flag.Duration("timeout", 30*time.Second, "timeout for rule validation")
	verbose := flag.Bool("v", false, "verbose output (show all test case results)")
	jsonOutput := flag.Bool("json", false, "output results as JSON")
	versionFlag := flag.Bool("version", false, "print version")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <rule-file.yaml> [rule-file2.yaml ...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       %s -config config.yaml\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Validate remote-signer rule files without starting the server.\n")
		fmt.Fprintf(os.Stderr, "  - Rule/template files: use test_variables (template) or plain rules.\n")
		fmt.Fprintf(os.Stderr, "  - -config: load config.yaml, expand templates and instance rules (same as server), then validate.\n")
		fmt.Fprintf(os.Stderr, "    Use this after changing config to catch mismatches before starting the server.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s rules/treasury.example.yaml\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s rules/templates/safe.template.js.yaml   # template (uses test_variables)\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -config config.yaml   # validate expanded rules (templates + instance variables)\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -config config.yaml -list-rule-ids   # print rule IDs for delegate_to in evm_js rules\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -v rules/*.yaml\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -json rules/myapp.yaml > results.json\n", os.Args[0])
	}
	flag.Parse()

	if *versionFlag {
		name := "remote-signer-validate-rules"
		if len(os.Args) > 0 {
			name = filepath.Base(os.Args[0])
		}
		fmt.Printf("%s %s\n", name, version)
		return nil
	}

	if *listRuleIDs {
		if *configPath == "" {
			return fmt.Errorf("-list-rule-ids requires -config <path>")
		}
		return listConfigRuleIDs(*configPath)
	}

	args := flag.Args()
	if *configPath == "" && len(args) == 0 {
		flag.Usage()
		return fmt.Errorf("at least one rule file or -config is required")
	}
	if *configPath != "" && len(args) > 0 {
		return fmt.Errorf("use either -config <path> or rule file(s), not both")
	}

	// Setup logger
	var logLevel slog.Level
	if *verbose {
		logLevel = slog.LevelDebug
	} else {
		logLevel = slog.LevelWarn
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	log := slog.New(handler)

	// Resolve cache dir, temp dir, timeout: when -config is set, use config's foundry settings
	// so local validation and Docker (same config) share the same paths and cache.
	cacheDirectory := *cacheDir
	var tempDirectory string
	timeoutDuration := *timeout
	if *configPath != "" {
		cfg, loadErr := config.Load(*configPath)
		if loadErr != nil {
			return fmt.Errorf("load config for foundry paths: %w", loadErr)
		}
		configDir := filepath.Dir(*configPath)
		if cfg.Chains.EVM != nil && cfg.Chains.EVM.Foundry.Enabled {
			if cfg.Chains.EVM.Foundry.CacheDir != "" {
				cacheDirectory = resolvePath(configDir, cfg.Chains.EVM.Foundry.CacheDir)
			}
			if cfg.Chains.EVM.Foundry.TempDir != "" {
				tempDirectory = resolvePath(configDir, cfg.Chains.EVM.Foundry.TempDir)
			}
			if cfg.Chains.EVM.Foundry.Timeout > 0 {
				timeoutDuration = cfg.Chains.EVM.Foundry.Timeout
			}
			if cfg.Chains.EVM.Foundry.ForgePath != "" && *forgePath == "" {
				*forgePath = cfg.Chains.EVM.Foundry.ForgePath
			}
		}
	}
	if cacheDirectory == "" {
		cacheDirectory = filepath.Join(os.TempDir(), "remote-signer-validator")
	}
	if err := os.MkdirAll(cacheDirectory, 0750); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Initialize Solidity evaluator (same cache/temp/timeout as server when -config is used)
	evaluator, err := evm.NewSolidityRuleEvaluator(evm.SolidityEvaluatorConfig{
		ForgePath: *forgePath,
		CacheDir:  cacheDirectory,
		TempDir:   tempDirectory,
		Timeout:   timeoutDuration,
	}, log)
	if err != nil {
		return fmt.Errorf("failed to create Solidity evaluator: %w", err)
	}

	// Debug: Check if foundry.toml was created
	tempDir := evaluator.GetTempDir()
	foundryPath := filepath.Join(tempDir, "foundry.toml")
	if _, statErr := os.Stat(foundryPath); statErr == nil {
		log.Debug("foundry.toml exists", "path", foundryPath)
	} else {
		log.Error("foundry.toml does NOT exist", "path", foundryPath, "error", statErr)
	}

	// Create validator
	validator, err := evm.NewSolidityRuleValidator(evaluator, log)
	if err != nil {
		return fmt.Errorf("failed to create validator: %w", err)
	}

	// Create message pattern validator
	msgValidator, err := evm.NewMessagePatternRuleValidator(log)
	if err != nil {
		return fmt.Errorf("failed to create message pattern validator: %w", err)
	}

	// Create JS rule evaluator and validator (for evm_js test_cases)
	jsEvaluator, err := evm.NewJSRuleEvaluator(log)
	if err != nil {
		return fmt.Errorf("failed to create JS evaluator: %w", err)
	}
	jsValidator, err := evm.NewJSRuleValidator(jsEvaluator, log)
	if err != nil {
		return fmt.Errorf("failed to create JS validator: %w", err)
	}

	// Validate each file or config
	ctx := context.Background()
	allResults := make(map[string][]ValidationFileResult)
	totalRules := 0
	passedRules := 0
	failedRules := 0

	if *configPath != "" {
		fileResults, passed, failed, err := validateConfig(ctx, *configPath, validator, msgValidator, jsValidator, log, *verbose)
		if err != nil {
			return fmt.Errorf("failed to validate config: %w", err)
		}
		allResults[*configPath] = fileResults
		totalRules += len(fileResults)
		passedRules += passed
		failedRules += failed
	} else {
		for _, filePath := range args {
			fileResults, passed, failed, err := validateFile(ctx, filePath, validator, msgValidator, jsValidator, log, *verbose)
			if err != nil {
				return fmt.Errorf("failed to validate %s: %w", filePath, err)
			}
			allResults[filePath] = fileResults
			totalRules += len(fileResults)
			passedRules += passed
			failedRules += failed
		}
	}

	// Output results
	if *jsonOutput {
		return outputJSON(allResults, totalRules, passedRules, failedRules)
	}

	return outputText(allResults, totalRules, passedRules, failedRules, *verbose)
}

// ValidationFileResult contains validation result for a single rule
type ValidationFileResult struct {
	RuleName        string                 `json:"rule_name"`
	RuleType        string                 `json:"rule_type"`
	Valid           bool                   `json:"valid"`
	Error           string                 `json:"error,omitempty"`
	SyntaxError     *evm.SyntaxError       `json:"syntax_error,omitempty"`
	TestCaseResults []evm.TestCaseResult   `json:"test_case_results,omitempty"`
	FailedTestCases int                    `json:"failed_test_cases,omitempty"`
	Skipped         bool                   `json:"skipped,omitempty"`
	SkipReason      string                 `json:"skip_reason,omitempty"`
}

// validateTemplateOptionalVarsHaveDefault ensures optional variables declare default.
func validateTemplateOptionalVarsHaveDefault(vars []TemplateVarConfig, filePath string) error {
	for _, v := range vars {
		if v.Required {
			continue
		}
		if v.Default == nil {
			return fmt.Errorf("optional variable %q must declare default (file: %s)", v.Name, filePath)
		}
	}
	return nil
}

func validateFile(ctx context.Context, filePath string, validator *evm.SolidityRuleValidator, msgValidator *evm.MessagePatternRuleValidator, jsValidator *evm.JSRuleValidator, log *slog.Logger, verbose bool) ([]ValidationFileResult, int, int, error) {
	// Read file
	data, err := os.ReadFile(filePath) // #nosec G304 -- filePath is CLI argument
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to read file: %w", err)
	}

	// Try template format first (has variables + rules)
	var templateFile TemplateFile
	if err := yaml.Unmarshal(data, &templateFile); err != nil {
		return nil, 0, 0, fmt.Errorf("failed to parse YAML: %w", err)
	}

	var rules []RuleConfig
	if len(templateFile.Variables) > 0 && len(templateFile.Rules) > 0 {
		// Template file: validate optional vars have default, substitute test_variables, then validate
		if err := validateTemplateOptionalVarsHaveDefault(templateFile.Variables, filePath); err != nil {
			return nil, 0, 0, err
		}
		if len(templateFile.TestVariables) == 0 {
			return nil, 0, 0, fmt.Errorf("template file requires test_variables for validation (file: %s)", filePath)
		}
		rulesJSON, err := json.Marshal(templateFile.Rules)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("failed to marshal template rules: %w", err)
		}
		resolved, err := substituteVarsInString(string(rulesJSON), templateFile.TestVariables)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("template variable substitution failed: %w", err)
		}
		if err := json.Unmarshal([]byte(resolved), &rules); err != nil {
			return nil, 0, 0, fmt.Errorf("failed to unmarshal resolved template rules: %w", err)
		}
		log.Debug("Validating template file with test_variables", "file", filePath, "rules", len(rules))
	} else {
		// Plain rule file
		rules = templateFile.Rules
	}

	if len(rules) == 0 {
		log.Warn("No rules found in file", "file", filePath)
		return nil, 0, 0, nil
	}
	if err := validateExplicitRuleIDsLocal(rules); err != nil {
		return nil, 0, 0, fmt.Errorf("rule id validation: %w", err)
	}

	// Template files use isolated engines (per-rule) so other rules don't interfere with template test cases.
	return validateRules(ctx, rules, validator, msgValidator, jsValidator, templateFile.TestVariables, log, verbose, false)
}

// validateExplicitRuleIDsLocal ensures every rule has an explicit id (for validate-rules local RuleConfig).
func validateExplicitRuleIDsLocal(rules []RuleConfig) error {
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

// validateConfig loads config, expands templates and instance/file rules (same as server), then validates.
func validateConfig(ctx context.Context, configPath string, validator *evm.SolidityRuleValidator, msgValidator *evm.MessagePatternRuleValidator, jsValidator *evm.JSRuleValidator, log *slog.Logger, verbose bool) ([]ValidationFileResult, int, int, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("load config: %w", err)
	}
	configDir := filepath.Dir(configPath)

	templates, err := config.ExpandTemplatesFromFiles(cfg.Templates, configDir, log)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("expand templates: %w", err)
	}
	rules, err := config.ExpandInstanceRules(cfg.Rules, templates)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("expand instance rules: %w", err)
	}
	rules, err = config.ExpandFileRules(rules, configDir, log)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("expand file rules: %w", err)
	}
	if err := config.ValidateExplicitRuleIDs(rules); err != nil {
		return nil, 0, 0, fmt.Errorf("rule id validation: %w", err)
	}
	if err := config.ValidateDelegationTargets(rules); err != nil {
		return nil, 0, 0, fmt.Errorf("delegation target validation: %w", err)
	}

	localRules := make([]RuleConfig, 0, len(rules))
	for _, r := range rules {
		// Copy test_cases (from template rules_json), instance variables, and template test_variables for evm_js validation.
		testCases := make([]TestCaseConfig, 0, len(r.TestCases))
		for _, tc := range r.TestCases {
			testCases = append(testCases, TestCaseConfig{
				Name:               tc.Name,
				Input:              tc.Input,
				ExpectPass:         tc.ExpectPass,
				ExpectReason:       tc.ExpectReason,
				ExpectBudgetAmount: tc.ExpectBudgetAmount,
			})
		}
		var testVars map[string]string
		if len(r.TestVariables) > 0 {
			testVars = make(map[string]string, len(r.TestVariables))
			for k, v := range r.TestVariables {
				testVars[k] = v
			}
		}
		localRules = append(localRules, RuleConfig{
			Id: r.Id, Name: r.Name, Description: r.Description, Type: r.Type, Mode: r.Mode,
			ChainType: r.ChainType, ChainID: r.ChainID, APIKeyID: r.APIKeyID, SignerAddress: r.SignerAddress,
			Config: r.Config, Variables: r.Variables, TestVariables: testVars, TestCases: testCases, Enabled: r.Enabled,
		})
	}
	log.Debug("Validating expanded rules from config", "config", configPath, "rules", len(localRules))
	// Validate each rule in isolation (blocklist + rule under test) so template expected-fail cases apply per-rule.
	return validateRules(ctx, localRules, validator, msgValidator, jsValidator, nil, log, verbose, false)
}

// configRuleID returns the deterministic rule ID for a config rule (same formula as internal/config/rule_init.go).
func configRuleID(idx int, name, ruleType string) string {
	data := fmt.Sprintf("config:%d:%s:%s", idx, name, ruleType)
	hash := sha256.Sum256([]byte(data))
	return "cfg_" + hex.EncodeToString(hash[:8])
}

// listConfigRuleIDs loads config, expands rules (templates + instance + file), and prints rule_id and name for each.
// Use this to fill delegate_to in evm_js rules (delegate_to must be the target rule's rule ID).
func listConfigRuleIDs(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	configDir := filepath.Dir(configPath)
	log := slog.Default()

	templates, err := config.ExpandTemplatesFromFiles(cfg.Templates, configDir, log)
	if err != nil {
		return fmt.Errorf("expand templates: %w", err)
	}
	rules, err := config.ExpandInstanceRules(cfg.Rules, templates)
	if err != nil {
		return fmt.Errorf("expand instance rules: %w", err)
	}
	rules, err = config.ExpandFileRules(rules, configDir, log)
	if err != nil {
		return fmt.Errorf("expand file rules: %w", err)
	}

	fmt.Println("# Rule IDs (use as delegate_to in evm_js rules; same order as server)")
	fmt.Println("# Format: rule_id  name  (type); id is custom if set in config, else auto-generated")
	for i, r := range rules {
		effectiveID := strings.TrimSpace(r.Id)
		if effectiveID == "" {
			effectiveID = configRuleID(i, r.Name, r.Type)
		}
		fmt.Printf("%s  %s  (%s)\n", effectiveID, r.Name, r.Type)
	}
	return nil
}

func effectiveRuleID(idx int, cfg RuleConfig) string {
	if s := strings.TrimSpace(cfg.Id); s != "" {
		return s
	}
	return configRuleID(idx, cfg.Name, cfg.Type)
}

// validateRules validates a list of rules. When useFullEngine is true (config instances),
// evm_js test cases run through the full engine with ALL rules to verify combined behavior.
// When useFullEngine is false (template files), each evm_js rule uses an isolated engine
// (blocklist + rule under test only) so other rules don't interfere with template test cases.
func validateRules(ctx context.Context, rules []RuleConfig, validator *evm.SolidityRuleValidator, msgValidator *evm.MessagePatternRuleValidator, jsValidator *evm.JSRuleValidator, templateTestVariables map[string]string, log *slog.Logger, verbose bool, useFullEngine bool) ([]ValidationFileResult, int, int, error) {
	var results []ValidationFileResult
	passed := 0
	failed := 0

	// Build in-memory repo and engine for evm_js when any evm_js rule exists (same path as production: all rule types, delegation + scope).
	var ruleEngine *rule.WhitelistRuleEngine
	hasEVMJS := false
	hasSolidity := false
	for _, c := range rules {
		if c.Type == string(types.RuleTypeEVMJS) && c.Enabled {
			hasEVMJS = true
		}
		if c.Type == string(types.RuleTypeEVMSolidityExpression) && c.Enabled {
			hasSolidity = true
		}
		if hasEVMJS && hasSolidity {
			break
		}
	}
	var fullRepo *storage.MemoryRuleRepository
	var jsEval *evm.JSRuleEvaluator
	if hasEVMJS {
		fullRepo = storage.NewMemoryRuleRepository()
		for i, ruleCfg := range rules {
			if !ruleCfg.Enabled {
				continue
			}
			r, err := configToRuleWithID(i, ruleCfg)
			if err != nil {
				continue
			}
			// So JS script sees config.* (allowed_safe_addresses, etc.) same as production.
			// Prefer template test_variables (from expanded rule) so expected-fail cases validate correctly.
			var varsToSeed map[string]interface{}
			if len(ruleCfg.TestVariables) > 0 {
				varsToSeed = make(map[string]interface{}, len(ruleCfg.TestVariables))
				for k, v := range ruleCfg.TestVariables {
					varsToSeed[k] = v
				}
			} else if len(ruleCfg.Variables) > 0 {
				varsToSeed = ruleCfg.Variables
			} else if len(templateTestVariables) > 0 {
				varsToSeed = make(map[string]interface{}, len(templateTestVariables))
				for k, v := range templateTestVariables {
					varsToSeed[k] = v
				}
			}
			if len(varsToSeed) > 0 {
				varsJSON, err := json.Marshal(varsToSeed)
				if err != nil {
					return nil, 0, 0, fmt.Errorf("marshal rule variables: %w", err)
				}
				r.Variables = varsJSON
			}
			if err := fullRepo.Create(ctx, r); err != nil {
				log.Debug("validator repo create skip (duplicate id)", "id", r.ID, "error", err)
			}
		}
		var err error
		ruleEngine, err = rule.NewWhitelistRuleEngine(fullRepo, log, rule.WithDelegationPayloadConverter(evm.DelegatePayloadToSignRequest))
		if err != nil {
			return nil, 0, 0, fmt.Errorf("evm_js engine init: %w", err)
		}
		ruleEngine.RegisterEvaluator(&evm.AddressListEvaluator{})
		ruleEngine.RegisterEvaluator(&evm.ContractMethodEvaluator{})
		ruleEngine.RegisterEvaluator(&evm.ValueLimitEvaluator{})
		ruleEngine.RegisterEvaluator(&evm.SignerRestrictionEvaluator{})
		ruleEngine.RegisterEvaluator(&evm.SignTypeRestrictionEvaluator{})
		ruleEngine.RegisterEvaluator(&evm.MessagePatternEvaluator{})
		// Internal transfer evaluator: nil repo for validation-only mode
		internalTransferEval, err := evm.NewInternalTransferEvaluator(nil)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("internal transfer evaluator: %w", err)
		}
		ruleEngine.RegisterEvaluator(internalTransferEval)
		if hasSolidity && validator != nil {
			if solidityEval := validator.Evaluator(); solidityEval != nil {
				ruleEngine.RegisterEvaluator(solidityEval)
			}
		}
		jsEval, err = evm.NewJSRuleEvaluator(log)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("evm_js evaluator: %w", err)
		}
		ruleEngine.RegisterEvaluator(jsEval)
	}

	// Collect Solidity expression rules for batch validation
	var rulesToValidate []*types.Rule
	for i, ruleCfg := range rules {
		result := ValidationFileResult{
			RuleName: ruleCfg.Name,
			RuleType: ruleCfg.Type,
		}

		// Skip disabled rules
		if !ruleCfg.Enabled {
			result.Skipped = true
			result.SkipReason = "rule is disabled"
			result.Valid = true
			results = append(results, result)
			passed++
			continue
		}

		switch ruleCfg.Type {
		case string(types.RuleTypeEVMSolidityExpression):
			// Solidity expression rules → collect for batch validation
			rule, err := configToRule(i, ruleCfg)
			if err != nil {
				result.Valid = false
				result.Error = fmt.Sprintf("failed to convert rule: %v", err)
				results = append(results, result)
				failed++
				continue
			}
			rulesToValidate = append(rulesToValidate, rule)

		case string(types.RuleTypeMessagePattern):
			// Message pattern rules → validate with MessagePatternRuleValidator
			rule, err := configToRule(i, ruleCfg)
			if err != nil {
				result.Valid = false
				result.Error = fmt.Sprintf("failed to convert rule: %v", err)
				results = append(results, result)
				failed++
				continue
			}
			vResult, err := msgValidator.ValidateRule(ctx, rule)
			if err != nil {
				result.Valid = false
				result.Error = fmt.Sprintf("validation error: %v", err)
				results = append(results, result)
				failed++
				continue
			}
			result.Valid = vResult.Valid
			result.SyntaxError = vResult.SyntaxError
			result.TestCaseResults = vResult.TestCaseResults
			result.FailedTestCases = vResult.FailedTestCases
			results = append(results, result)
			if result.Valid {
				passed++
			} else {
				failed++
			}

		case string(types.RuleTypeEVMJS):
			rule, err := configToRuleWithID(i, ruleCfg)
			if err != nil {
				result.Valid = false
				result.Error = fmt.Sprintf("failed to convert rule: %v", err)
				results = append(results, result)
				failed++
				continue
			}
			validationErr := validateDeclarativeRule(rule)
			if validationErr != nil {
				result.Valid = false
				result.Error = validationErr.Error()
				results = append(results, result)
				failed++
				continue
			}
			// evm_js must have test_cases and be validated through the full engine (same as production).
			if len(ruleCfg.TestCases) < 2 {
				result.Valid = false
				result.Error = fmt.Sprintf("evm_js rules require at least 2 test cases (got %d): need at least one positive and one negative", len(ruleCfg.TestCases))
				results = append(results, result)
				failed++
				continue
			}
			var pos, neg int
			for _, tc := range ruleCfg.TestCases {
				if tc.ExpectPass {
					pos++
				} else {
					neg++
				}
			}
			if err := ruleconfig.ValidateJSRuleTestCasesRequirement(pos, neg); err != nil {
				result.Valid = false
				result.Error = err.Error()
				results = append(results, result)
				failed++
				continue
			}
			if ruleEngine == nil {
				result.Valid = false
				result.Error = "evm_js engine not initialized"
				results = append(results, result)
				failed++
				continue
			}
			// Set Variables on rule so JS script sees config.* (same as in full repo). Prefer TestVariables for validation.
			var varsToSeed map[string]interface{}
			if len(ruleCfg.TestVariables) > 0 {
				varsToSeed = make(map[string]interface{}, len(ruleCfg.TestVariables))
				for k, v := range ruleCfg.TestVariables {
					varsToSeed[k] = v
				}
			} else if len(ruleCfg.Variables) > 0 {
				varsToSeed = ruleCfg.Variables
			} else if len(templateTestVariables) > 0 {
				varsToSeed = make(map[string]interface{}, len(templateTestVariables))
				for k, v := range templateTestVariables {
					varsToSeed[k] = v
				}
			}
			if len(varsToSeed) > 0 {
				varsJSON, err := json.Marshal(varsToSeed)
				if err != nil {
					result.Valid = false
					result.Error = fmt.Sprintf("marshal rule variables: %v", err)
					results = append(results, result)
					failed++
					continue
				}
				rule.Variables = varsJSON
			}
			// When using template test_variables, override rule scope (ChainID)
			// so the rule matches the test case's chain_id (test_cases use
			// test_variables values, not the instance's actual chain_id).
			// This mirrors the same logic in cmd/remote-signer/main.go startup validation.
			if len(ruleCfg.TestVariables) > 0 {
				if v, ok := ruleCfg.TestVariables["chain_id"]; ok && v != "" {
					chainIDVal := v
					rule.ChainID = &chainIDVal
				}
			}
			// Template files: isolated engine (blocklist + rule under test only) so other rules don't interfere.
			// Config instances: full engine (all rules) to validate combined behavior in production context.
			// When using the full engine, if another whitelist rule allows a request that this rule's
			// negative test case expects to reject, the mismatch surfaces as a test failure.
			testEngine := ruleEngine // default: full engine (all rules)
			if !useFullEngine {
				var buildErr error
				testEngine, buildErr = buildEngineForRuleTest(ctx, fullRepo, rule, hasSolidity, validator, log)
				if buildErr != nil {
					result.Valid = false
					result.Error = fmt.Sprintf("build test engine: %v", buildErr)
					results = append(results, result)
					failed++
					continue
				}
			} else {
				log.Debug("Using full engine for rule test", "rule", ruleCfg.Name)
			}
			result.Valid = true // pass unless a test case fails
			// Run each test case through the test engine (blocklist + this rule only).
			for _, tc := range ruleCfg.TestCases {
				tcResult := evm.TestCaseResult{
					Name:           tc.Name,
					ExpectedPass:   tc.ExpectPass,
					ExpectedReason: tc.ExpectReason,
				}
				inputCopy := make(map[string]interface{})
				for k, v := range tc.Input {
					inputCopy[k] = v
				}
				// Substitute ${var} in test input: prefer per-rule TestVariables (template test_variables) for validation.
				var varsForSubst map[string]string
				if len(ruleCfg.TestVariables) > 0 {
					varsForSubst = ruleCfg.TestVariables
				} else if len(ruleCfg.Variables) > 0 {
					varsForSubst = interfaceMapToStringMap(ruleCfg.Variables)
				} else {
					varsForSubst = templateTestVariables
				}
				if len(varsForSubst) > 0 {
					jsonBytes, _ := json.Marshal(inputCopy)
					subst, err := substituteVarsInString(string(jsonBytes), varsForSubst)
					if err != nil {
						tcResult.Passed = false
						tcResult.Error = fmt.Sprintf("variable substitution: %v", err)
						result.TestCaseResults = append(result.TestCaseResults, tcResult)
						result.FailedTestCases++
						result.Valid = false
						continue
					}
					if err := json.Unmarshal([]byte(subst), &inputCopy); err != nil {
						tcResult.Passed = false
						tcResult.Error = fmt.Sprintf("substituted input invalid: %v", err)
						result.TestCaseResults = append(result.TestCaseResults, tcResult)
						result.FailedTestCases++
						result.Valid = false
						continue
					}
				}
				req, parsed, err := evm.TestCaseInputToSignRequest(inputCopy)
				if err != nil {
					tcResult.Passed = false
					tcResult.Error = fmt.Sprintf("build request: %v", err)
					result.TestCaseResults = append(result.TestCaseResults, tcResult)
					result.FailedTestCases++
					result.Valid = false
					continue
				}
				evalResult, err := testEngine.EvaluateWithResult(ctx, req, parsed)
				if err != nil {
					tcResult.Passed = false
					tcResult.Error = fmt.Sprintf("engine: %v", err)
					result.TestCaseResults = append(result.TestCaseResults, tcResult)
					result.FailedTestCases++
					result.Valid = false
					continue
				}
				// For blocklist rules, "pass" means "not blocked"; for whitelist, "pass" means "allowed".
				if rule.Mode == types.RuleModeBlocklist {
					tcResult.ActualPass = !evalResult.Blocked
				} else {
					tcResult.ActualPass = evalResult.Allowed
				}
				if evalResult.Allowed {
					tcResult.ActualReason = evalResult.AllowReason
				} else if evalResult.Blocked {
					tcResult.ActualReason = evalResult.BlockReason
				} else {
					tcResult.ActualReason = evalResult.NoMatchReason
				}
				if tcResult.ExpectedPass != tcResult.ActualPass {
					tcResult.Passed = false
					if tcResult.ExpectedPass {
						tcResult.Error = fmt.Sprintf("expected pass but got: %s", tcResult.ActualReason)
					} else {
						tcResult.Error = "expected fail but passed"
					}
					result.FailedTestCases++
					result.Valid = false
				} else if tc.ExpectReason != "" && !strings.Contains(tcResult.ActualReason, tc.ExpectReason) {
					// In a multi-rule full engine, the NoMatchReason for whitelist rules depends on
					// evaluation order and may come from a different rule. Only enforce expect_reason
					// when the result is blocked/allowed or when using isolated (non-full) engine.
					isNoMatch := !evalResult.Blocked && !evalResult.Allowed
					isWhitelistRule := rule.Mode != types.RuleModeBlocklist
					if useFullEngine && isNoMatch && isWhitelistRule {
						tcResult.Passed = true
					} else {
						tcResult.Passed = false
						tcResult.Error = fmt.Sprintf("expected reason containing %q but got %q", tc.ExpectReason, tcResult.ActualReason)
						result.FailedTestCases++
						result.Valid = false
					}
				} else {
					tcResult.Passed = true
				}
				// If expect_budget_amount is set, assert validateBudget(input) return value
				if tcResult.Passed && tc.ExpectBudgetAmount != "" && jsEval != nil {
					ruleInput, err := evm.MapToRuleInput(inputCopy)
					if err != nil {
						tcResult.Passed = false
						tcResult.Error = fmt.Sprintf("budget input: %v", err)
						result.FailedTestCases++
						result.Valid = false
					} else {
						budgetResult, err := jsEval.EvaluateBudgetWithInput(ctx, rule, ruleInput)
						if err != nil {
							tcResult.Passed = false
							tcResult.Error = fmt.Sprintf("validateBudget: %v", err)
							result.FailedTestCases++
							result.Valid = false
						} else {
							expected := new(big.Int)
							if _, ok := expected.SetString(strings.TrimSpace(tc.ExpectBudgetAmount), 10); !ok {
								tcResult.Passed = false
								tcResult.Error = fmt.Sprintf("invalid expect_budget_amount %q", tc.ExpectBudgetAmount)
								result.FailedTestCases++
								result.Valid = false
							} else if budgetResult.Amount.Cmp(expected) != 0 {
								tcResult.Passed = false
								tcResult.Error = fmt.Sprintf("expect_budget_amount %s but got %s", tc.ExpectBudgetAmount, budgetResult.Amount.String())
								result.FailedTestCases++
								result.Valid = false
							}
						}
					}
				}
				result.TestCaseResults = append(result.TestCaseResults, tcResult)
			}
			if result.Valid {
				passed++
			} else {
				failed++
			}
			results = append(results, result)

		case string(types.RuleTypeEVMAddressList), "evm_address_whitelist",
			string(types.RuleTypeEVMContractMethod),
			string(types.RuleTypeEVMValueLimit),
			string(types.RuleTypeSignerRestriction),
			string(types.RuleTypeSignTypeRestriction),
			string(types.RuleTypeChainRestriction),
			string(types.RuleTypeEVMDynamicBlocklist):
			// Declarative rules → JSON deserialization + basic validation
			rule, err := configToRule(i, ruleCfg)
			if err != nil {
				result.Valid = false
				result.Error = fmt.Sprintf("failed to convert rule: %v", err)
				results = append(results, result)
				failed++
				continue
			}
			validationErr := validateDeclarativeRule(rule)
			if validationErr != nil {
				result.Valid = false
				result.Error = validationErr.Error()
				results = append(results, result)
				failed++
			} else {
				result.Valid = true
				results = append(results, result)
				passed++
			}

		default:
			// Unknown rule type → error (not skip!)
			result.Valid = false
			result.Error = fmt.Sprintf("unknown rule type: %s", ruleCfg.Type)
			results = append(results, result)
			failed++
		}
	}

	// Batch validate all rules in the file (automatically groups by mode)
	if len(rulesToValidate) > 0 {
		batchResults, err := validator.ValidateRulesBatch(ctx, rulesToValidate)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("batch validation failed: %w", err)
		}

		for idx, validationResult := range batchResults.Results {
			rule := rulesToValidate[idx]
			result := ValidationFileResult{
				RuleName:        rule.Name,
				RuleType:        string(rule.Type),
				Valid:           validationResult.Valid,
				SyntaxError:     validationResult.SyntaxError,
				TestCaseResults: validationResult.TestCaseResults,
				FailedTestCases: validationResult.FailedTestCases,
			}
			if result.Valid {
				passed++
			} else {
				failed++
			}
			results = append(results, result)
		}
	}

	return results, passed, failed, nil
}

// buildEngineForRuleTest builds an engine containing only blocklist rules plus the given rule.
// This ensures evm_js test cases (especially "expect fail") are evaluated without another whitelist
// rule allowing the request (e.g. E2E Delegate Target with script that allows all).
func buildEngineForRuleTest(ctx context.Context, fullRepo *storage.MemoryRuleRepository, ruleUnderTest *types.Rule, hasSolidity bool, validator *evm.SolidityRuleValidator, log *slog.Logger) (*rule.WhitelistRuleEngine, error) {
	const listLimit = 10000
	allRules, err := fullRepo.List(ctx, storage.RuleFilter{EnabledOnly: true, Limit: listLimit})
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	allRulesMap := make(map[types.RuleID]*types.Rule, len(allRules))
	for _, r := range allRules {
		allRulesMap[r.ID] = r
	}
	minimalRepo := storage.NewMemoryRuleRepository()
	for _, r := range allRules {
		if r.Mode == types.RuleModeBlocklist {
			if err := minimalRepo.Create(ctx, r); err != nil {
				return nil, fmt.Errorf("add blocklist rule %s: %w", r.ID, err)
			}
		}
	}
	// Add the rule under test (whitelist); blocklist rules were already added above.
	if ruleUnderTest.Mode != types.RuleModeBlocklist {
		if err := minimalRepo.Create(ctx, ruleUnderTest); err != nil {
			return nil, fmt.Errorf("add rule under test %s: %w", ruleUnderTest.ID, err)
		}
	}
	// Recursively add delegation target rules so delegate_to resolution works.
	if err := addDelegationTargets(ctx, ruleUnderTest, allRulesMap, minimalRepo, make(map[types.RuleID]bool), log); err != nil {
		return nil, err
	}
	eng, err := rule.NewWhitelistRuleEngine(minimalRepo, log, rule.WithDelegationPayloadConverter(evm.DelegatePayloadToSignRequest))
	if err != nil {
		return nil, err
	}
	eng.RegisterEvaluator(&evm.AddressListEvaluator{})
	eng.RegisterEvaluator(&evm.ContractMethodEvaluator{})
	eng.RegisterEvaluator(&evm.ValueLimitEvaluator{})
	eng.RegisterEvaluator(&evm.SignerRestrictionEvaluator{})
	eng.RegisterEvaluator(&evm.SignTypeRestrictionEvaluator{})
	eng.RegisterEvaluator(&evm.MessagePatternEvaluator{})
	// Internal transfer evaluator: nil repo for validation-only mode
	internalTransferEval, err := evm.NewInternalTransferEvaluator(nil)
	if err != nil {
		return nil, err
	}
	eng.RegisterEvaluator(internalTransferEval)
	if hasSolidity && validator != nil {
		if solidityEval := validator.Evaluator(); solidityEval != nil {
			eng.RegisterEvaluator(solidityEval)
		}
	}
	jsEval, err := evm.NewJSRuleEvaluator(log)
	if err != nil {
		return nil, err
	}
	eng.RegisterEvaluator(jsEval)
	return eng, nil
}

// addDelegationTargets recursively adds delegation target rules to the minimal repo
// with Enabled=false so they are reachable via Get() (for delegation resolution)
// but NOT included in top-level List(EnabledOnly=true) evaluation.
func addDelegationTargets(ctx context.Context, r *types.Rule, allRulesMap map[types.RuleID]*types.Rule, minimalRepo *storage.MemoryRuleRepository, visited map[types.RuleID]bool, log *slog.Logger) error {
	if visited[r.ID] {
		return nil
	}
	visited[r.ID] = true
	var cfg struct {
		DelegateTo string `json:"delegate_to"`
	}
	if err := json.Unmarshal(r.Config, &cfg); err != nil || cfg.DelegateTo == "" {
		return nil
	}
	for _, part := range strings.Split(cfg.DelegateTo, ",") {
		targetID := types.RuleID(strings.TrimSpace(part))
		if targetID == "" {
			continue
		}
		target, ok := allRulesMap[targetID]
		if !ok {
			return fmt.Errorf("rule %q delegate_to references non-existent target %q", r.ID, targetID)
		}
		clone := *target
		clone.Enabled = false
		if err := minimalRepo.Create(ctx, &clone); err != nil {
			log.Debug("delegation target already in minimal repo", "target", targetID)
		}
		if err := addDelegationTargets(ctx, target, allRulesMap, minimalRepo, visited, log); err != nil {
			return err
		}
	}
	return nil
}

func configToRule(idx int, cfg RuleConfig) (*types.Rule, error) {
	return configToRuleWithID(idx, cfg)
}

// configToRuleWithID converts RuleConfig to types.Rule using effectiveRuleID (for delegate_to resolution).
func configToRuleWithID(idx int, cfg RuleConfig) (*types.Rule, error) {
	configJSON, err := json.Marshal(cfg.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	rule := &types.Rule{
		ID:          types.RuleID(effectiveRuleID(idx, cfg)),
		Name:        cfg.Name,
		Description: cfg.Description,
		Type:        types.RuleType(cfg.Type),
		Mode:        types.RuleMode(cfg.Mode),
		Source:      types.RuleSourceConfig,
		Config:      configJSON,
		Enabled:     cfg.Enabled,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if cfg.ChainType != "" {
		ct := types.ChainType(cfg.ChainType)
		rule.ChainType = &ct
	} else {
		ct := types.ChainTypeEVM
		rule.ChainType = &ct
	}
	if cfg.ChainID != "" {
		rule.ChainID = &cfg.ChainID
	}
	if cfg.APIKeyID != "" {
		rule.Owner = cfg.APIKeyID
	}
	if cfg.SignerAddress != "" {
		rule.SignerAddress = &cfg.SignerAddress
	}

	return rule, nil
}

// JSONOutput represents the JSON output format
type JSONOutput struct {
	Files       map[string][]ValidationFileResult `json:"files"`
	Summary     Summary                           `json:"summary"`
}

type Summary struct {
	TotalRules  int  `json:"total_rules"`
	PassedRules int  `json:"passed_rules"`
	FailedRules int  `json:"failed_rules"`
	Success     bool `json:"success"`
}

func outputJSON(results map[string][]ValidationFileResult, total, passed, failed int) error {
	output := JSONOutput{
		Files: results,
		Summary: Summary{
			TotalRules:  total,
			PassedRules: passed,
			FailedRules: failed,
			Success:     failed == 0,
		},
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	if failed > 0 {
		return fmt.Errorf("%d rule(s) failed validation", failed)
	}

	return nil
}

func outputText(results map[string][]ValidationFileResult, total, passed, failed int, verbose bool) error {
	for filePath, fileResults := range results {
		fmt.Printf("\n📄 %s\n", filePath)
		fmt.Printf("%s\n", strings.Repeat("─", 60))

		for _, result := range fileResults {
			if result.Skipped {
				if verbose {
					fmt.Printf("  ⏭️  %s (skipped: %s)\n", result.RuleName, result.SkipReason)
				}
				continue
			}

			if result.Valid {
				fmt.Printf("  ✅ %s\n", result.RuleName)
				if verbose && len(result.TestCaseResults) > 0 {
					fmt.Printf("     Test cases: %d passed\n", len(result.TestCaseResults))
					for _, tc := range result.TestCaseResults {
						status := "✓"
						if !tc.Passed {
							status = "✗"
						}
						fmt.Printf("       %s %s\n", status, tc.Name)
					}
				}
			} else {
				fmt.Printf("  ❌ %s\n", result.RuleName)
				if result.Error != "" {
					fmt.Printf("     Error: %s\n", result.Error)
				}
				if result.SyntaxError != nil {
					fmt.Printf("     Syntax error: %s\n", result.SyntaxError.Message)
				}
				if result.FailedTestCases > 0 {
					fmt.Printf("     Failed test cases: %d\n", result.FailedTestCases)
					for _, tc := range result.TestCaseResults {
						if !tc.Passed {
							fmt.Printf("       ✗ %s: %s\n", tc.Name, tc.Error)
						}
					}
				}
			}
		}
	}

	// Summary
	fmt.Printf("\n%s\n", strings.Repeat("═", 60))
	fmt.Printf("Summary: %d total, %d passed, %d failed\n", total, passed, failed)

	if failed > 0 {
		fmt.Printf("\n❌ Validation failed\n")
		return fmt.Errorf("%d rule(s) failed validation", failed)
	}

	fmt.Printf("\n✅ All rules validated successfully\n")
	return nil
}

// substituteVarsInString replaces ${var} placeholders with values from vars.
// Returns an error if any ${name} (without colon) remains after substitution.
// interfaceMapToStringMap converts map[string]interface{} to map[string]string for variable substitution.
func interfaceMapToStringMap(m map[string]interface{}) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if v == nil {
			out[k] = ""
		} else {
			out[k] = fmt.Sprintf("%v", v)
		}
	}
	return out
}

func substituteVarsInString(s string, vars map[string]string) (string, error) {
	result := s
	for k, v := range vars {
		result = strings.ReplaceAll(result, "${"+k+"}", v)
	}
	if idx := strings.Index(result, "${"); idx >= 0 {
		if end := strings.Index(result[idx:], "}"); end > 0 {
			varName := result[idx+2 : idx+end]
			if !strings.Contains(varName, ":") {
				return "", fmt.Errorf("unresolved template variable: ${%s}", varName)
			}
		}
	}
	return result, nil
}

// validateDeclarativeRule validates declarative rule config format using shared ruleconfig (same as API and config load).
func validateDeclarativeRule(rule *types.Rule) error {
	var config map[string]interface{}
	if err := json.Unmarshal(rule.Config, &config); err != nil {
		return fmt.Errorf("invalid rule config JSON: %w", err)
	}
	return ruleconfig.ValidateRuleConfig(string(rule.Type), config)
}
