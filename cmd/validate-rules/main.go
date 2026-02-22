package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

const version = "1.0.0"

// RuleConfig defines a rule in configuration (copied from config package to avoid circular imports)
type RuleConfig struct {
	Name          string                 `yaml:"name"`
	Description   string                 `yaml:"description,omitempty"`
	Type          string                 `yaml:"type"`
	Mode          string                 `yaml:"mode"`
	ChainType     string                 `yaml:"chain_type,omitempty"`
	ChainID       string                 `yaml:"chain_id,omitempty"`
	APIKeyID      string                 `yaml:"api_key_id,omitempty"`
	SignerAddress string                 `yaml:"signer_address,omitempty"`
	Config        map[string]any `yaml:"config"`
	Enabled       bool                   `yaml:"enabled"`
}

// RuleFile represents a YAML file containing rules
type RuleFile struct {
	Rules []RuleConfig `yaml:"rules"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Parse command line flags
	forgePath := flag.String("forge", "", "path to forge binary (default: auto-detect from PATH)")
	cacheDir := flag.String("cache", "", "cache directory for compiled scripts (default: /tmp/remote-signer-validator)")
	timeout := flag.Duration("timeout", 30*time.Second, "timeout for rule validation")
	verbose := flag.Bool("v", false, "verbose output (show all test case results)")
	jsonOutput := flag.Bool("json", false, "output results as JSON")
	versionFlag := flag.Bool("version", false, "print version")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <rule-file.yaml> [rule-file2.yaml ...]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Validate remote-signer rule files without starting the server.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s rules/polymarket.yaml\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -v rules/*.yaml\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -json rules/myapp.yaml > results.json\n", os.Args[0])
	}
	flag.Parse()

	if *versionFlag {
		fmt.Printf("validate-rules %s\n", version)
		return nil
	}

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		return fmt.Errorf("at least one rule file is required")
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

	// Setup cache directory
	cacheDirectory := *cacheDir
	if cacheDirectory == "" {
		cacheDirectory = filepath.Join(os.TempDir(), "remote-signer-validator")
	}
	if err := os.MkdirAll(cacheDirectory, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Initialize Solidity evaluator
	evaluator, err := evm.NewSolidityRuleEvaluator(evm.SolidityEvaluatorConfig{
		ForgePath: *forgePath,
		CacheDir:  cacheDirectory,
		Timeout:   *timeout,
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

	// Validate each file
	ctx := context.Background()
	allResults := make(map[string][]ValidationFileResult)
	totalRules := 0
	passedRules := 0
	failedRules := 0

	for _, filePath := range args {
		fileResults, passed, failed, err := validateFile(ctx, filePath, validator, msgValidator, log, *verbose)
		if err != nil {
			return fmt.Errorf("failed to validate %s: %w", filePath, err)
		}
		allResults[filePath] = fileResults
		totalRules += len(fileResults)
		passedRules += passed
		failedRules += failed
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

func validateFile(ctx context.Context, filePath string, validator *evm.SolidityRuleValidator, msgValidator *evm.MessagePatternRuleValidator, log *slog.Logger, _ bool) ([]ValidationFileResult, int, int, error) {
	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to read file: %w", err)
	}

	// Parse YAML
	var ruleFile RuleFile
	if err := yaml.Unmarshal(data, &ruleFile); err != nil {
		return nil, 0, 0, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if len(ruleFile.Rules) == 0 {
		log.Warn("No rules found in file", "file", filePath)
		return nil, 0, 0, nil
	}

	var results []ValidationFileResult
	passed := 0
	failed := 0

	// Collect Solidity expression rules for batch validation
	var rulesToValidate []*types.Rule
	for i, ruleCfg := range ruleFile.Rules {
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

		case string(types.RuleTypeEVMAddressList), "evm_address_whitelist",
			string(types.RuleTypeEVMContractMethod),
			string(types.RuleTypeEVMValueLimit),
			string(types.RuleTypeSignerRestriction),
			string(types.RuleTypeSignTypeRestriction),
			string(types.RuleTypeChainRestriction):
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

func configToRule(idx int, cfg RuleConfig) (*types.Rule, error) {
	// Marshal config to JSON
	configJSON, err := json.Marshal(cfg.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	rule := &types.Rule{
		ID:          types.RuleID(fmt.Sprintf("validate_%d", idx)),
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

// validateDeclarativeRule validates declarative rules by attempting to deserialize their config
func validateDeclarativeRule(rule *types.Rule) error {
	switch rule.Type {
	case types.RuleTypeEVMAddressList, "evm_address_whitelist":
		var config evm.AddressListConfig
		if err := json.Unmarshal(rule.Config, &config); err != nil {
			return fmt.Errorf("invalid address list config: %w", err)
		}
		if len(config.Addresses) == 0 {
			return fmt.Errorf("addresses list is empty")
		}
		// Validate addresses are valid hex
		for _, addr := range config.Addresses {
			if len(addr) != 42 || addr[:2] != "0x" {
				return fmt.Errorf("invalid address format: %s", addr)
			}
		}

	case types.RuleTypeEVMContractMethod:
		var config evm.ContractMethodConfig
		if err := json.Unmarshal(rule.Config, &config); err != nil {
			return fmt.Errorf("invalid contract method config: %w", err)
		}
		if len(config.MethodSigs) == 0 {
			return fmt.Errorf("method_sigs list is empty")
		}
		for _, sig := range config.MethodSigs {
			if len(sig) != 10 || sig[:2] != "0x" {
				return fmt.Errorf("invalid method selector format: %s (expected 0x + 8 hex chars)", sig)
			}
		}

	case types.RuleTypeEVMValueLimit:
		var config evm.ValueLimitConfig
		if err := json.Unmarshal(rule.Config, &config); err != nil {
			return fmt.Errorf("invalid value limit config: %w", err)
		}
		if config.MaxValue == "" {
			return fmt.Errorf("max_value is empty")
		}

	case types.RuleTypeSignerRestriction:
		var config evm.SignerRestrictionConfig
		if err := json.Unmarshal(rule.Config, &config); err != nil {
			return fmt.Errorf("invalid signer restriction config: %w", err)
		}
		if len(config.AllowedSigners) == 0 {
			return fmt.Errorf("allowed_signers list is empty")
		}

	case types.RuleTypeSignTypeRestriction:
		var config evm.SignTypeRestrictionConfig
		if err := json.Unmarshal(rule.Config, &config); err != nil {
			return fmt.Errorf("invalid sign type restriction config: %w", err)
		}
		if len(config.AllowedSignTypes) == 0 {
			return fmt.Errorf("allowed_sign_types list is empty")
		}

	case types.RuleTypeChainRestriction:
		// chain_restriction has no evaluator implementation — just do basic JSON parse check
		var raw map[string]interface{}
		if err := json.Unmarshal(rule.Config, &raw); err != nil {
			return fmt.Errorf("invalid chain restriction config: %w", err)
		}

	default:
		return fmt.Errorf("unknown declarative rule type: %s", rule.Type)
	}
	return nil
}
