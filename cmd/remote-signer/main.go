package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog"

	"github.com/ivanzzeth/remote-signer/internal/api"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/chain"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/core/auth"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/statemachine"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/logger"
	"github.com/ivanzzeth/remote-signer/internal/notify"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

const version = "1.0.0"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Parse command line flags
	configPath := flag.String("config", "config.yaml", "path to config file")
	envFile := flag.String("env", ".env", "path to .env file (optional, ignored if not exists)")
	flag.Parse()

	// Load .env file if exists (for development)
	// In production, environment variables should be set directly
	if err := godotenv.Load(*envFile); err != nil {
		// Only log if the file exists but failed to load
		if _, statErr := os.Stat(*envFile); statErr == nil {
			return fmt.Errorf("failed to load .env file: %w", err)
		}
		// .env file not found is OK - use system environment variables
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize zerolog logger (for notify module)
	zerologLevel, err := parseZerologLevel(cfg.Logger.Level)
	if err != nil {
		return fmt.Errorf("failed to parse log level: %w", err)
	}
	logger.Init(zerologLevel, cfg.Logger.Pretty)

	// Initialize slog logger (for rest of application)
	slogLevel, err := parseSlogLevel(cfg.Logger.Level)
	if err != nil {
		return fmt.Errorf("failed to parse log level: %w", err)
	}
	var slogHandler slog.Handler
	if cfg.Logger.Pretty {
		slogHandler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slogLevel})
	} else {
		slogHandler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slogLevel})
	}
	log := slog.New(slogHandler)

	log.Info("Starting remote-signer service")

	// Initialize database
	db, err := storage.NewDB(cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	log.Info("Database connected")

	// Initialize repositories
	requestRepo, err := storage.NewGormRequestRepository(db)
	if err != nil {
		return fmt.Errorf("failed to create request repository: %w", err)
	}

	ruleRepo, err := storage.NewGormRuleRepository(db)
	if err != nil {
		return fmt.Errorf("failed to create rule repository: %w", err)
	}

	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	if err != nil {
		return fmt.Errorf("failed to create apikey repository: %w", err)
	}

	// Initialize API keys from config
	apiKeyInit, err := config.NewAPIKeyInitializer(apiKeyRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create API key initializer: %w", err)
	}
	if err := apiKeyInit.SyncFromConfig(context.Background(), cfg.APIKeys); err != nil {
		return fmt.Errorf("failed to sync API keys from config: %w", err)
	}

	// Initialize template repository
	templateRepo, err := storage.NewGormTemplateRepository(db)
	if err != nil {
		return fmt.Errorf("failed to create template repository: %w", err)
	}

	// Initialize budget repository (for template instances)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	if err != nil {
		return fmt.Errorf("failed to create budget repository: %w", err)
	}

	// Initialize templates from config
	templateInit, err := config.NewTemplateInitializer(templateRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create template initializer: %w", err)
	}
	templateInit.SetConfigDir(filepath.Dir(*configPath))
	if err := templateInit.SyncFromConfig(context.Background(), cfg.Templates); err != nil {
		return fmt.Errorf("failed to sync templates from config: %w", err)
	}

	// Initialize rules from config (with template expansion)
	ruleInit, err := config.NewRuleInitializer(ruleRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create rule initializer: %w", err)
	}
	// Set config directory for resolving relative paths in rule files
	ruleInit.SetConfigDir(filepath.Dir(*configPath))
	// Expand template instance rules before syncing (type: "instance" → concrete rules)
	loadedTemplates, err := templateInit.GetLoadedTemplates(cfg.Templates)
	if err != nil {
		return fmt.Errorf("failed to get loaded templates: %w", err)
	}
	expandedRules, err := config.ExpandInstanceRules(cfg.Rules, loadedTemplates)
	if err != nil {
		return fmt.Errorf("failed to expand instance rules: %w", err)
	}
	if err := ruleInit.SyncFromConfig(context.Background(), expandedRules); err != nil {
		return fmt.Errorf("failed to sync rules from config: %w", err)
	}

	// Initialize template service
	templateService, err := service.NewTemplateService(templateRepo, ruleRepo, budgetRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create template service: %w", err)
	}

	// =========================================================================
	// RULE VALIDATION (BEFORE signer initialization to avoid password prompts)
	// =========================================================================
	// Validate Solidity expression rules FIRST, before loading signers.
	// This ensures rule errors are caught before user needs to enter keystore passwords.
	var solidityEval *evm.SolidityRuleEvaluator
	var solidityValidator *evm.SolidityRuleValidator
	if cfg.Chains.EVM != nil && cfg.Chains.EVM.Foundry.Enabled {
		solidityEval, err = evm.NewSolidityRuleEvaluator(evm.SolidityEvaluatorConfig{
			ForgePath: cfg.Chains.EVM.Foundry.ForgePath,
			CacheDir:  cfg.Chains.EVM.Foundry.CacheDir,
			TempDir:   cfg.Chains.EVM.Foundry.TempDir,
			Timeout:   cfg.Chains.EVM.Foundry.Timeout,
		}, log)
		if err != nil {
			return fmt.Errorf("failed to create Solidity rule evaluator: %w", err)
		}
		log.Info("Solidity expression evaluator created (Foundry)")

		// Create Solidity rule validator (for API rule validation)
		solidityValidator, err = evm.NewSolidityRuleValidator(solidityEval, log)
		if err != nil {
			return fmt.Errorf("failed to create Solidity rule validator: %w", err)
		}

		// Validate all Solidity expression rules at startup
		if err := validateSolidityRules(context.Background(), ruleRepo, solidityEval, log); err != nil {
			return fmt.Errorf("rule validation failed: %w", err)
		}
	}

	// =========================================================================
	// SIGNER INITIALIZATION (after rule validation)
	// =========================================================================
	auditRepo, err := storage.NewGormAuditRepository(db)
	if err != nil {
		return fmt.Errorf("failed to create audit repository: %w", err)
	}

	// Initialize chain registry
	chainRegistry := chain.NewRegistry()

	// Initialize EVM adapter and signer manager if enabled
	var evmSignerManager evm.SignerManager
	if cfg.Chains.EVM != nil && cfg.Chains.EVM.Enabled {
		evmRegistry, err := evm.NewSignerRegistry(cfg.Chains.EVM.Signers)
		if err != nil {
			return fmt.Errorf("failed to create EVM signer registry: %w", err)
		}

		evmAdapter, err := evm.NewEVMAdapter(evmRegistry)
		if err != nil {
			return fmt.Errorf("failed to create EVM adapter: %w", err)
		}

		if err := chainRegistry.Register(evmAdapter); err != nil {
			return fmt.Errorf("failed to register EVM adapter: %w", err)
		}
		log.Info("EVM adapter registered")

		// Initialize signer manager for dynamic signer creation
		keystoreDir := cfg.Chains.EVM.KeystoreDir
		if keystoreDir == "" {
			keystoreDir = "./data/keystores" // Default
		}
		evmSignerManager, err = evm.NewSignerManager(evmRegistry, keystoreDir, log)
		if err != nil {
			return fmt.Errorf("failed to create EVM signer manager: %w", err)
		}
		log.Info("EVM signer manager initialized", "keystore_dir", keystoreDir)
	}

	// Initialize state machine
	stateMachine, err := statemachine.NewStateMachine(requestRepo, auditRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create state machine: %w", err)
	}

	// Initialize rule engine (with optional budget checker for template instances)
	budgetChecker := rule.NewBudgetChecker(budgetRepo, templateRepo, log)
	ruleEngine, err := rule.NewWhitelistRuleEngine(ruleRepo, log, rule.WithBudgetChecker(budgetChecker))
	if err != nil {
		return fmt.Errorf("failed to create rule engine: %w", err)
	}

	// Register EVM rule evaluators
	ruleEngine.RegisterEvaluator(&evm.AddressListEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.ContractMethodEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.ValueLimitEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.SignerRestrictionEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.SignTypeRestrictionEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.MessagePatternEvaluator{})

	// Register Solidity expression evaluator (already created and validated above)
	if solidityEval != nil {
		ruleEngine.RegisterEvaluator(solidityEval)
		log.Info("Solidity expression evaluator registered")
	}

	// Initialize notification service
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var notifier service.Notifier
	var notifyService *notify.NotifyService // kept at function scope for audit monitor
	if notifyEnabled(&cfg.Notify) {
		notifyService, err = notify.NewNotifyService(&cfg.Notify)
		if err != nil {
			return fmt.Errorf("failed to create notify service: %w", err)
		}
		notifyService.Start(ctx)
		defer notifyService.Stop()

		notifier, err = service.NewNotifyServiceNotifier(service.NotifyServiceNotifierConfig{
			NotifyService: notifyService,
			Channels:      &cfg.NotifyChannel,
			Priority:      1,
			Sound:         "persistent",
		})
		if err != nil {
			return fmt.Errorf("failed to create notifier: %w", err)
		}
		log.Info("Notification service started")
	} else {
		notifier, err = service.NewNoopNotifier()
		if err != nil {
			return fmt.Errorf("failed to create noop notifier: %w", err)
		}
		log.Info("Notification service disabled")
	}

	// Start audit monitor (background anomaly detection)
	if cfg.AuditMonitor.Enabled && notifyService != nil {
		auditMonitor, err := audit.NewMonitor(auditRepo, notifyService, &cfg.NotifyChannel, cfg.AuditMonitor, log)
		if err != nil {
			return fmt.Errorf("failed to create audit monitor: %w", err)
		}
		auditMonitor.Start(ctx)
		defer auditMonitor.Stop()
	}

	// Initialize rule generator
	ruleGenerator, err := rule.NewDefaultRuleGenerator()
	if err != nil {
		return fmt.Errorf("failed to create rule generator: %w", err)
	}

	// Initialize approval service
	approvalService, err := service.NewApprovalService(
		ruleRepo,
		ruleGenerator,
		notifier,
		log,
	)
	if err != nil {
		return fmt.Errorf("failed to create approval service: %w", err)
	}

	// Initialize sign service
	signService, err := service.NewSignService(
		chainRegistry,
		requestRepo,
		ruleEngine,
		stateMachine,
		approvalService,
		log,
	)
	if err != nil {
		return fmt.Errorf("failed to create sign service: %w", err)
	}

	// Optional: approval guard — pauses all sign requests when too many consecutive manual-approval outcomes
	var approvalGuard *service.ManualApprovalGuard
	if cfg.Security.ApprovalGuard.Enabled {
		approvalGuard, err = service.NewManualApprovalGuard(service.ManualApprovalGuardConfig{
			Window:      cfg.Security.ApprovalGuard.Window,
			Threshold:   cfg.Security.ApprovalGuard.Threshold,
			ResumeAfter: cfg.Security.ApprovalGuard.ResumeAfter,
			NotifySvc:   notifyService,
			Channel:     &cfg.NotifyChannel,
			Logger:      log,
		})
		if err != nil {
			return fmt.Errorf("failed to create approval guard: %w", err)
		}
		signService.SetApprovalGuard(approvalGuard)
		log.Info("approval guard enabled",
			"window", cfg.Security.ApprovalGuard.Window,
			"threshold", cfg.Security.ApprovalGuard.Threshold,
			"resume_after", cfg.Security.ApprovalGuard.ResumeAfter,
		)
	}

	signService.SetManualApprovalEnabled(cfg.Security.ManualApprovalEnabled)
	if cfg.Security.ManualApprovalEnabled {
		log.Info("manual approval enabled: requests with no whitelist match will go to pending approval")
	} else {
		log.Info("manual approval disabled: requests with no whitelist match will be rejected (403)")
	}

	// Initialize nonce store for replay protection
	nonceStore, err := storage.NewInMemoryNonceStore(time.Minute)
	if err != nil {
		return fmt.Errorf("failed to create nonce store: %w", err)
	}
	defer nonceStore.Close()

	nonceRequired := true
	if cfg.Security.NonceRequired != nil {
		nonceRequired = *cfg.Security.NonceRequired
	}

	// Initialize auth verifier
	authVerifier, err := auth.NewVerifierWithNonceStore(apiKeyRepo, nonceStore, auth.Config{
		MaxRequestAge: cfg.Security.MaxRequestAge,
		NonceRequired: nonceRequired,
	})
	if err != nil {
		return fmt.Errorf("failed to create auth verifier: %w", err)
	}

	// Initialize IP whitelist
	var ipWhitelist *middleware.IPWhitelist
	if cfg.Security.IPWhitelist.Enabled {
		ipWhitelist, err = middleware.NewIPWhitelist(cfg.Security.IPWhitelist, log)
		if err != nil {
			return fmt.Errorf("failed to create IP whitelist: %w", err)
		}
		log.Info("IP whitelist enabled",
			"allowed_count", len(cfg.Security.IPWhitelist.AllowedIPs),
			"trust_proxy", cfg.Security.IPWhitelist.TrustProxy,
		)
	}

	// Initialize router
	router, err := api.NewRouter(authVerifier, signService, evmSignerManager, ruleRepo, auditRepo, log, api.RouterConfig{
		Version:           version,
		IPWhitelistConfig: ipWhitelist,
		SolidityValidator: solidityValidator,
		Template:          &api.TemplateConfig{
			TemplateRepo:    templateRepo,
			TemplateService: templateService,
		},
		ApprovalGuard: approvalGuard,
	})
	if err != nil {
		return fmt.Errorf("failed to create router: %w", err)
	}

	// Build server config
	serverConfig := api.DefaultServerConfig()
	serverConfig.Host = cfg.Server.Host
	serverConfig.Port = cfg.Server.Port

	// TLS configuration
	if cfg.Server.TLS.Enabled {
		serverConfig.TLSEnabled = true
		serverConfig.TLSCertFile = cfg.Server.TLS.CertFile
		serverConfig.TLSKeyFile = cfg.Server.TLS.KeyFile
		serverConfig.TLSCAFile = cfg.Server.TLS.CAFile
		serverConfig.TLSClientAuth = cfg.Server.TLS.ClientAuth
		log.Info("TLS enabled",
			"cert_file", cfg.Server.TLS.CertFile,
			"key_file", cfg.Server.TLS.KeyFile,
			"mtls", cfg.Server.TLS.ClientAuth,
		)
	}

	// Initialize API server
	server, err := api.NewServer(router, log, serverConfig)
	if err != nil {
		return fmt.Errorf("failed to create API server: %w", err)
	}

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		log.Info("Starting HTTP server",
			"host", cfg.Server.Host,
			"port", cfg.Server.Port,
		)
		errCh <- server.Start()
	}()

	select {
	case sig := <-sigCh:
		log.Info("Received shutdown signal", "signal", sig.String())
		if err := server.Shutdown(ctx); err != nil {
			log.Error("Server shutdown error", "error", err)
		}
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("server error: %w", err)
		}
	}

	log.Info("Service stopped")
	return nil
}

func parseZerologLevel(level string) (zerolog.Level, error) {
	switch level {
	case "debug":
		return zerolog.DebugLevel, nil
	case "info":
		return zerolog.InfoLevel, nil
	case "warn":
		return zerolog.WarnLevel, nil
	case "error":
		return zerolog.ErrorLevel, nil
	default:
		return zerolog.InfoLevel, fmt.Errorf("unknown log level: %s", level)
	}
}

func parseSlogLevel(level string) (slog.Level, error) {
	switch level {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level: %s", level)
	}
}

func notifyEnabled(cfg *notify.Config) bool {
	if cfg == nil {
		return false
	}
	if cfg.Slack != nil && cfg.Slack.Enabled {
		return true
	}
	if cfg.Pushover != nil && cfg.Pushover.Enabled {
		return true
	}
	if cfg.Webhook != nil && cfg.Webhook.Enabled {
		return true
	}
	return false
}

// validateSolidityRules validates all Solidity expression rules at startup.
// It runs the test cases defined in each rule to ensure they pass.
// If any rule fails validation, the service will not start.
func validateSolidityRules(ctx context.Context, ruleRepo storage.RuleRepository, evaluator *evm.SolidityRuleEvaluator, log *slog.Logger) error {
	// Get all Solidity expression rules
	ruleType := types.RuleTypeEVMSolidityExpression
	rules, err := ruleRepo.List(ctx, storage.RuleFilter{
		Type:        &ruleType,
		EnabledOnly: true,
	})
	if err != nil {
		return fmt.Errorf("failed to list Solidity rules: %w", err)
	}

	if len(rules) == 0 {
		log.Info("No Solidity expression rules to validate")
		return nil
	}

	log.Info("Validating Solidity expression rules", "count", len(rules))

	// Create validator
	validator, err := evm.NewSolidityRuleValidator(evaluator, log)
	if err != nil {
		return fmt.Errorf("failed to create rule validator: %w", err)
	}

	// Batch validate all rules (automatically groups by mode for optimal performance)
	batchResult, err := validator.ValidateRulesBatch(ctx, rules)
	if err != nil {
		return fmt.Errorf("rule validation failed: %w", err)
	}

	// Report results
	var failedRules []string
	for i, result := range batchResult.Results {
		rule := rules[i]
		if !result.Valid {
			// Collect failure details
			var details string
			if result.SyntaxError != nil {
				details = fmt.Sprintf("syntax error: %s", result.SyntaxError.Message)
			} else if result.FailedTestCases > 0 {
				for _, tc := range result.TestCaseResults {
					if !tc.Passed {
						details = fmt.Sprintf("test case '%s' failed: expected_pass=%v, actual_pass=%v, error=%s",
							tc.Name, tc.ExpectedPass, tc.ActualPass, tc.Error)
						break
					}
				}
			}

			log.Error("Rule validation failed",
				"rule_id", rule.ID,
				"rule_name", rule.Name,
				"details", details,
				"failed_test_cases", result.FailedTestCases,
			)
			failedRules = append(failedRules, fmt.Sprintf("%s (%s): %s", rule.Name, rule.ID, details))
		} else {
			log.Info("Rule validation passed",
				"rule_id", rule.ID,
				"rule_name", rule.Name,
				"test_cases", len(result.TestCaseResults),
			)
		}
	}

	if len(failedRules) > 0 {
		return fmt.Errorf("%d rule(s) failed validation:\n  - %s",
			len(failedRules), strings.Join(failedRules, "\n  - "))
	}

	log.Info("All Solidity expression rules validated successfully", "count", len(rules))
	return nil
}
