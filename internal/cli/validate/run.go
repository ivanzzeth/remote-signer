// Package validate provides the rule-validation CLI logic for `remote-signer validate`.
// Run is the entrypoint; cmd/remote-signer wires it as a cobra subcommand.
package validate

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/config"
	versionpkg "github.com/ivanzzeth/remote-signer/internal/version"
)

// Run executes the validate CLI with the given args (not including argv[0]).
// Returns a non-nil error on validation failure or invalid usage.
func Run(args []string) error {
	fs := flag.NewFlagSet("remote-signer validate", flag.ContinueOnError)
	configPath := fs.String("config", "", "validate rules from config file (same expansion as server: templates + instance + file rules)")
	listRuleIDs := fs.Bool("list-rule-ids", false, "with -config: print deterministic rule IDs for each expanded rule (for delegate_to); then exit")
	forgePath := fs.String("forge", "", "path to forge binary (default: auto-detect from PATH)")
	cacheDir := fs.String("cache", "", "cache directory for compiled scripts (default: /tmp/remote-signer-validator)")
	timeout := fs.Duration("timeout", 30*time.Second, "timeout for rule validation")
	verbose := fs.Bool("v", false, "verbose output (show all test case results)")
	jsonOutput := fs.Bool("json", false, "output results as JSON")
	versionFlag := fs.Bool("version", false, "print version")
	fs.Usage = func() {
		prog := "remote-signer validate"
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <rule-file.yaml> [rule-file2.yaml ...]\n", prog)
		fmt.Fprintf(os.Stderr, "       %s -config config.yaml\n\n", prog)
		fmt.Fprintf(os.Stderr, "Validate remote-signer rule files without starting the server.\n")
		fmt.Fprintf(os.Stderr, "  - Rule/template files: use test_variables (template) or plain rules.\n")
		fmt.Fprintf(os.Stderr, "  - -config: load config.yaml, expand templates and instance rules (same as server), then validate.\n")
		fmt.Fprintf(os.Stderr, "    Use this after changing config to catch mismatches before starting the server.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s rules/treasury.example.yaml\n", prog)
		fmt.Fprintf(os.Stderr, "  %s rules/templates/safe.template.js.yaml   # template (uses test_variables)\n", prog)
		fmt.Fprintf(os.Stderr, "  %s -config config.yaml   # validate expanded rules (templates + instance variables)\n", prog)
		fmt.Fprintf(os.Stderr, "  %s -config config.yaml -list-rule-ids   # print rule IDs for delegate_to in evm_js rules\n", prog)
		fmt.Fprintf(os.Stderr, "  %s -v rules/*.yaml\n", prog)
		fmt.Fprintf(os.Stderr, "  %s -json rules/myapp.yaml > results.json\n", prog)
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	if *versionFlag {
		fmt.Printf("remote-signer validate %s\n", versionpkg.Version)
		return nil
	}

	if *listRuleIDs {
		if *configPath == "" {
			return fmt.Errorf("-list-rule-ids requires -config <path>")
		}
		return listConfigRuleIDs(*configPath)
	}

	files := fs.Args()
	if *configPath == "" && len(files) == 0 {
		fs.Usage()
		return fmt.Errorf("at least one rule file or -config is required")
	}
	if *configPath != "" && len(files) > 0 {
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
		for _, filePath := range files {
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
