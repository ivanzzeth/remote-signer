package main

import (
	"context"
	"encoding/json"
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
	"github.com/ivanzzeth/remote-signer/internal/blocklist"
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
	"github.com/ivanzzeth/remote-signer/internal/ruleconfig"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

const version = "0.1.18"

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

	// Security: warn if swap is enabled (private keys could be swapped to disk)
	checkSwapEnabled(log)
	// Security: disable core dumps, lock memory pages to prevent key leakage
	hardenProcessMemory(log)

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

	auditRepo, err := storage.NewGormAuditRepository(db)
	if err != nil {
		return fmt.Errorf("failed to create audit repository: %w", err)
	}

	// Initialize audit logger early so config sync can record rule changes
	auditLogger, err := audit.NewAuditLogger(auditRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create audit logger: %w", err)
	}

	// Initialize API keys from config
	apiKeyInit, err := config.NewAPIKeyInitializer(apiKeyRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create API key initializer: %w", err)
	}
	apiKeyInit.SetAuditLogger(auditLogger)
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
	templateInit.SetAuditLogger(auditLogger)
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
	ruleInit.SetAuditLogger(auditLogger)
	ruleInit.SetTemplateRepo(templateRepo)
	ruleInit.SetBudgetRepo(budgetRepo)
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
	// Expand file-type rules so startup validation covers evm_js rules from external files.
	// SyncFromConfig already expanded them into the DB, but expandedRules still has "file" stubs.
	expandedRulesWithFiles, err := config.ExpandFileRules(expandedRules, filepath.Dir(*configPath), log)
	if err != nil {
		return fmt.Errorf("failed to expand file rules for validation: %w", err)
	}

	// Validate that all delegate_to references point to existing rule IDs.
	if err := config.ValidateDelegationTargets(expandedRulesWithFiles); err != nil {
		return fmt.Errorf("delegation target validation failed: %w", err)
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

	// Fail if config contains Solidity rules but Foundry is disabled (cannot validate them).
	if solidityEval == nil {
		for _, r := range expandedRulesWithFiles {
			if r.Type == string(types.RuleTypeEVMSolidityExpression) && r.Enabled {
				return fmt.Errorf("config contains enabled evm_solidity_expression rule %q but Foundry is disabled; enable chains.evm.foundry.enabled or remove the rule", r.Name)
			}
		}
	}

	// Validate evm_js rules at startup (same path as validate-rules; see docs/SECURITY_AUDIT_REPORT.md §4)
	if err := validateEVMJSRulesAtStartup(context.Background(), expandedRulesWithFiles, ruleRepo, solidityEval, log); err != nil {
		return fmt.Errorf("evm_js rule validation failed: %w", err)
	}

	// Validate message_pattern rules at startup (same as validate-rules; fail if any invalid or test case fails)
	if err := validateMessagePatternRulesAtStartup(context.Background(), ruleRepo, log); err != nil {
		return fmt.Errorf("message_pattern rule validation failed: %w", err)
	}

	// =========================================================================
	// SIGNER INITIALIZATION (after rule validation)
	// =========================================================================

	// Initialize chain registry
	chainRegistry := chain.NewRegistry()

	// Initialize EVM adapter and signer manager if enabled
	var evmSignerManager evm.SignerManager
	if cfg.Chains.EVM != nil && cfg.Chains.EVM.Enabled {
		// Provider-based signer initialization
		evmRegistry := evm.NewEmptySignerRegistry()

		// Check if any keystore or HD wallet requires stdin password
		hasStdinKeystores := false
		for _, ks := range cfg.Chains.EVM.Signers.Keystores {
			if ks.Enabled && ks.PasswordStdin {
				hasStdinKeystores = true
				break
			}
		}
		if !hasStdinKeystores {
			for _, hw := range cfg.Chains.EVM.Signers.HDWallets {
				if hw.Enabled && hw.PasswordStdin {
					hasStdinKeystores = true
					break
				}
			}
		}

		pwProvider, err := evm.NewCompositePasswordProvider(hasStdinKeystores)
		if err != nil {
			return fmt.Errorf("failed to create password provider: %w", err)
		}

		// Ensure keystore and HD wallet directories exist
		if err := os.MkdirAll(cfg.Chains.EVM.KeystoreDir, 0700); err != nil {
			return fmt.Errorf("failed to create keystore directory %s: %w", cfg.Chains.EVM.KeystoreDir, err)
		}
		if err := os.MkdirAll(cfg.Chains.EVM.HDWalletDir, 0700); err != nil {
			return fmt.Errorf("failed to create HD wallet directory %s: %w", cfg.Chains.EVM.HDWalletDir, err)
		}

		// 1. Load private keys
		pkProvider, err := evm.NewPrivateKeyProvider(evmRegistry, cfg.Chains.EVM.Signers.PrivateKeys)
		if err != nil {
			return fmt.Errorf("failed to create private key provider: %w", err)
		}
		evmRegistry.RegisterProvider(pkProvider)

		// 2. Load keystores
		ksProvider, err := evm.NewKeystoreProvider(evmRegistry, cfg.Chains.EVM.Signers.Keystores, cfg.Chains.EVM.KeystoreDir, pwProvider)
		if err != nil {
			return fmt.Errorf("failed to create keystore provider: %w", err)
		}
		evmRegistry.RegisterProvider(ksProvider)

		// 3. Load HD wallets
		hdProvider, err := evm.NewHDWalletProvider(evmRegistry, cfg.Chains.EVM.Signers.HDWallets, cfg.Chains.EVM.HDWalletDir, pwProvider)
		if err != nil {
			return fmt.Errorf("failed to create HD wallet provider: %w", err)
		}
		evmRegistry.RegisterProvider(hdProvider)

		defer func() {
			if err := evmRegistry.Close(); err != nil {
				log.Error("failed to close signer registry", "error", err)
			}
		}()

		// Initialize signer manager for dynamic signer creation
		signerMgrImpl, smErr := evm.NewSignerManager(evmRegistry)
		if smErr != nil {
			return fmt.Errorf("failed to create EVM signer manager: %w", smErr)
		}
		if cfg.Security.AutoLockTimeout > 0 {
			signerMgrImpl.SetAutoLockTimeout(cfg.Security.AutoLockTimeout)
			log.Info("Signer auto-lock enabled", "timeout", cfg.Security.AutoLockTimeout)
		}
		defer signerMgrImpl.StopAutoLockTimers()
		evmSignerManager = signerMgrImpl

		// Discover locked signers from disk (keystores and HD wallets not in config)
		if err := evmSignerManager.DiscoverLockedSigners(context.Background()); err != nil {
			return fmt.Errorf("failed to discover locked signers: %w", err)
		}

		if evmRegistry.SignerCount() == 0 && evmRegistry.TotalCount() == 0 {
			log.Warn("No signers configured. Add signers via TUI or API after startup.")
		}

		evmAdapter, err := evm.NewEVMAdapter(evmRegistry)
		if err != nil {
			return fmt.Errorf("failed to create EVM adapter: %w", err)
		}

		if err := chainRegistry.Register(evmAdapter); err != nil {
			return fmt.Errorf("failed to register EVM adapter: %w", err)
		}

		lockedCount := evmRegistry.TotalCount() - evmRegistry.SignerCount()
		logger.EVM().Info().Int("unlocked", evmRegistry.SignerCount()).Int("locked", lockedCount).Int("total", evmRegistry.TotalCount()).Msg("EVM adapter registered")
		if evmRegistry.SignerCount() > 0 {
			logger.EVM().Warn().Int("unlocked_count", evmRegistry.SignerCount()).Msg("signer state after startup: some signers unlocked; with empty config expect all locked")
		}
		logger.EVM().Info().Msg("EVM signer manager initialized")
	}

	// Initialize state machine
	stateMachine, err := statemachine.NewStateMachine(requestRepo, auditRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create state machine: %w", err)
	}

	// Initialize rule engine (with optional budget checker for template instances)
	budgetChecker := rule.NewBudgetChecker(budgetRepo, templateRepo, log)
	ruleEngine, err := rule.NewWhitelistRuleEngine(ruleRepo, log,
		rule.WithBudgetChecker(budgetChecker),
		rule.WithDelegationPayloadConverter(evm.DelegatePayloadToSignRequest),
	)
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

	jsEval, err := evm.NewJSRuleEvaluator(log)
	if err != nil {
		return fmt.Errorf("failed to create JS rule evaluator: %w", err)
	}
	ruleEngine.RegisterEvaluator(jsEval)
	budgetChecker.SetJSEvaluator(jsEval)

	// Register Solidity expression evaluator (already created and validated above)
	if solidityEval != nil {
		ruleEngine.RegisterEvaluator(solidityEval)
		log.Info("Solidity expression evaluator registered")
	}

	// Initialize dynamic blocklist (runtime-synced from OFAC, scam DBs, etc.)
	if cfg.DynamicBlocklist != nil && cfg.DynamicBlocklist.Enabled {
		blCfg := blocklist.Config{
			Enabled:      cfg.DynamicBlocklist.Enabled,
			SyncInterval: cfg.DynamicBlocklist.SyncInterval,
			FailMode:     cfg.DynamicBlocklist.FailMode,
			CacheFile:    cfg.DynamicBlocklist.CacheFile,
		}
		for _, src := range cfg.DynamicBlocklist.Sources {
			blCfg.Sources = append(blCfg.Sources, blocklist.SourceConfig{
				Name: src.Name, Type: src.Type, URL: src.URL, JSONPath: src.JSONPath,
			})
		}
		dynBlocklist, err := blocklist.NewDynamicBlocklist(blCfg, log)
		if err != nil {
			return fmt.Errorf("failed to create dynamic blocklist: %w", err)
		}
		syncInterval := 1 * time.Hour
		if blCfg.SyncInterval != "" {
			parsed, err := time.ParseDuration(blCfg.SyncInterval)
			if err != nil {
				return fmt.Errorf("invalid dynamic_blocklist.sync_interval: %w", err)
			}
			syncInterval = parsed
		}
		if err := dynBlocklist.Start(context.Background(), syncInterval); err != nil {
			return fmt.Errorf("failed to start dynamic blocklist: %w", err)
		}
		defer dynBlocklist.Stop()
		blEval, err := blocklist.NewEvaluator(dynBlocklist)
		if err != nil {
			return fmt.Errorf("failed to create dynamic blocklist evaluator: %w", err)
		}
		ruleEngine.RegisterEvaluator(blEval)
		log.Info("Dynamic blocklist registered", "sources", len(blCfg.Sources), "sync_interval", syncInterval, "fail_mode", blCfg.FailMode)
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

	// Wire budget alert notifications
	if notifyService != nil {
		budgetAlertNotifier := notify.NewBudgetAlertNotifier(notifyService, &cfg.NotifyChannel)
		budgetChecker.SetNotifier(budgetAlertNotifier)
		log.Info("Budget alert notifications enabled")
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

	// Log API lockdown settings
	log.Info("API lockdown settings",
		"rules_api_readonly", cfg.Security.IsRulesAPIReadonly(),
		"signers_api_readonly", cfg.Security.IsSignersAPIReadonly(),
		"api_keys_api_readonly", cfg.Security.IsAPIKeysAPIReadonly(),
	)

	// Initialize security alert service for real-time notifications
	var securityAlertService *middleware.SecurityAlertService
	if notifyService != nil {
		securityAlertService, err = middleware.NewSecurityAlertService(
			notifyService, &cfg.NotifyChannel, log, 5*time.Minute,
		)
		if err != nil {
			return fmt.Errorf("failed to create security alert service: %w", err)
		}
		stopAlertCleanup := make(chan struct{})
		securityAlertService.StartCleanupRoutine(5*time.Minute, stopAlertCleanup)
		defer close(stopAlertCleanup)
		log.Info("Security alert service enabled (real-time alerts for unauthorized access)")
	}

	// Wire alert service to IP whitelist
	if ipWhitelist != nil && securityAlertService != nil {
		ipWhitelist.SetAlertService(securityAlertService)
	}

	// Wire auto-lock notification to signer manager
	if notifyService != nil && evmSignerManager != nil {
		if impl, ok := evmSignerManager.(*evm.SignerManagerImpl); ok {
			impl.SetOnAutoLock(func(address string) {
				auditLogger.LogSignerAutoLocked(context.Background(), address)
				if securityAlertService != nil {
					securityAlertService.Alert(middleware.AlertSignerAutoLocked, address,
						fmt.Sprintf("[Remote Signer] SIGNER AUTO-LOCKED\n\nAddress: %s\nReason: unlock timeout (%s)\nTime: %s\n\nUnlock again via POST /api/v1/evm/signers/%s/unlock",
							address, cfg.Security.AutoLockTimeout, time.Now().UTC().Format(time.RFC3339), address))
				}
			})
		}
	}

	// Wire audit DB failure alerting
	if securityAlertService != nil {
		auditLogger.SetOnLogFailure(func(eventType types.AuditEventType, logErr error) {
			securityAlertService.Alert(middleware.AlertAuditDBFailure, "audit_db",
				fmt.Sprintf("[Remote Signer] AUDIT DB FAILURE\n\nEvent: %s\nError: %s\nTime: %s\n\nAudit records may be lost. Check database connectivity.",
					eventType, logErr.Error(), time.Now().UTC().Format(time.RFC3339)))
		})
	}

	signService.SetAuditLogger(auditLogger)

	// Presets dir (for preset API): resolve relative to config file directory
	var presetsDir string
	if cfg.Presets != nil && cfg.Presets.Dir != "" {
		presetsDir = cfg.Presets.Dir
		if !filepath.IsAbs(presetsDir) {
			presetsDir = filepath.Join(filepath.Dir(*configPath), presetsDir)
		}
		var errAbs error
		presetsDir, errAbs = filepath.Abs(presetsDir)
		if errAbs != nil {
			return fmt.Errorf("presets dir: %w", errAbs)
		}
	}

	// Initialize router
	routerConfig := api.RouterConfig{
		Version:                  version,
		IPWhitelistConfig:        ipWhitelist,
		IPWhitelistConfigForRead: &cfg.Security.IPWhitelist,
		IPRateLimit:              cfg.Security.IPRateLimit,
		SolidityValidator: solidityValidator,
		JSEvaluator:       jsEval,
		Template:          &api.TemplateConfig{
			TemplateRepo:    templateRepo,
			TemplateService: templateService,
		},
		ApprovalGuard:      approvalGuard,
		APIKeyRepo:         apiKeyRepo,
		BudgetRepo:         budgetRepo,
		RulesAPIReadonly:   cfg.Security.IsRulesAPIReadonly(),
		SignersAPIReadonly: cfg.Security.IsSignersAPIReadonly(),
		APIKeysAPIReadonly: cfg.Security.IsAPIKeysAPIReadonly(),
		AlertService:       securityAlertService,
		AuditLogger:        auditLogger,
		SignTimeout:        cfg.Security.SignTimeout,
		AutoLockTimeout:    cfg.Security.AutoLockTimeout,
		AuditRetentionDays: cfg.AuditMonitor.RetentionDays,
	}
	if presetsDir != "" {
		routerConfig.PresetsDir = presetsDir
		routerConfig.PresetsDB = db
	}
	router, err := api.NewRouter(authVerifier, signService, evmSignerManager, ruleRepo, auditRepo, log, routerConfig)
	if err != nil {
		return fmt.Errorf("failed to create router: %w", err)
	}

	// Build server config
	serverConfig := api.DefaultServerConfig()
	serverConfig.Host = cfg.Server.Host
	serverConfig.Port = cfg.Server.Port
	if cfg.Server.ReadTimeout > 0 {
		serverConfig.ReadTimeout = cfg.Server.ReadTimeout
	}
	if cfg.Server.WriteTimeout > 0 {
		serverConfig.WriteTimeout = cfg.Server.WriteTimeout
	}

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

	// Handle graceful shutdown and SIGHUP for config reload
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	errCh := make(chan error, 1)
	go func() {
		log.Info("Starting HTTP server",
			"host", cfg.Server.Host,
			"port", cfg.Server.Port,
		)
		errCh <- server.Start()
	}()

	for {
		select {
		case sig := <-sigCh:
			if sig == syscall.SIGHUP {
				if !cfg.Security.IsSIGHUPRulesReloadEnabled() {
					log.Warn("Received SIGHUP, ignoring (rules reload disabled by security.allow_sighup_rules_reload)")
					continue
				}
				log.Info("Received SIGHUP, reloading rules from config")
				reloadRules(*configPath, ruleInit, templateInit, auditLogger, log)
				continue
			}
			log.Info("Received shutdown signal", "signal", sig.String())
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer shutdownCancel()
			if err := server.Shutdown(shutdownCtx); err != nil {
				log.Error("Server shutdown error", "error", err)
			}
			log.Info("Service stopped")
			return nil
		case err := <-errCh:
			if err != nil {
				return fmt.Errorf("server error: %w", err)
			}
			log.Info("Service stopped")
			return nil
		}
	}
}

// reloadRules re-reads config and syncs rules to DB (triggered by SIGHUP).
// Rule engine reads from DB per-request, so no engine restart is needed.
func reloadRules(configPath string, ruleInit *config.RuleInitializer, templateInit *config.TemplateInitializer, auditLogger *audit.AuditLogger, log *slog.Logger) {
	ctx := context.Background()

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Error("SIGHUP: failed to reload config", "error", err)
		if auditLogger != nil {
			auditLogger.LogConfigReloaded(ctx, false, err.Error())
		}
		return
	}

	// Re-expand template instance rules
	loadedTemplates, err := templateInit.GetLoadedTemplates(cfg.Templates)
	if err != nil {
		log.Error("SIGHUP: failed to get loaded templates", "error", err)
		if auditLogger != nil {
			auditLogger.LogConfigReloaded(ctx, false, err.Error())
		}
		return
	}
	expandedRules, err := config.ExpandInstanceRules(cfg.Rules, loadedTemplates)
	if err != nil {
		log.Error("SIGHUP: failed to expand instance rules", "error", err)
		if auditLogger != nil {
			auditLogger.LogConfigReloaded(ctx, false, err.Error())
		}
		return
	}

	if err := ruleInit.SyncFromConfig(ctx, expandedRules); err != nil {
		log.Error("SIGHUP: failed to sync rules from config", "error", err)
		if auditLogger != nil {
			auditLogger.LogConfigReloaded(ctx, false, err.Error())
		}
		return
	}

	if auditLogger != nil {
		auditLogger.LogConfigReloaded(ctx, true, "")
	}
	log.Info("SIGHUP: rules reloaded successfully")
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
	if cfg.Telegram != nil && cfg.Telegram.Enabled {
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
	log.Info("Rule validation may take 1–3 minutes (Forge compiles and runs test cases per batch)")

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

// validateEVMJSRulesAtStartup runs evm_js test cases through the same engine path as production
// (see docs/SECURITY_AUDIT_REPORT.md §4). expandedRules must be the same list passed to SyncFromConfig
// so rule IDs and test_cases match. If any test case fails, startup fails.
func validateEVMJSRulesAtStartup(ctx context.Context, expandedRules []config.RuleConfig, ruleRepo storage.RuleRepository, solidityEval *evm.SolidityRuleEvaluator, log *slog.Logger) error {
	var toValidate []struct {
		idx  int
		cfg  config.RuleConfig
		rule *types.Rule
	}
	for i := range expandedRules {
		cfg := &expandedRules[i]
		if cfg.Type != string(types.RuleTypeEVMJS) || !cfg.Enabled {
			continue
		}
		// Fail explicitly (same as validate-rules) when test_cases are missing or insufficient.
		var pos, neg int
		for _, tc := range cfg.TestCases {
			if tc.ExpectPass {
				pos++
			} else {
				neg++
			}
		}
		if err := ruleconfig.ValidateJSRuleTestCasesRequirement(pos, neg); err != nil {
			return fmt.Errorf("rule %q: %w", cfg.Name, err)
		}
		ruleID := config.EffectiveRuleID(i, *cfg)
		rule, err := ruleRepo.Get(ctx, ruleID)
		if err != nil {
			if types.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("get rule %s: %w", ruleID, err)
		}
		toValidate = append(toValidate, struct {
			idx  int
			cfg  config.RuleConfig
			rule *types.Rule
		}{i, *cfg, rule})
	}
	if len(toValidate) == 0 {
		log.Info("No evm_js rules with test_cases to validate at startup")
		return nil
	}

	// List all rules once for building isolated engines (blocklist + delegation targets).
	const listLimit = 10000
	allRules, err := ruleRepo.List(ctx, storage.RuleFilter{EnabledOnly: false, Limit: listLimit})
	if err != nil {
		return fmt.Errorf("list rules for validation: %w", err)
	}
	allRulesMap := make(map[types.RuleID]*types.Rule, len(allRules))
	for _, r := range allRules {
		allRulesMap[r.ID] = r
	}

	jsEval, err := evm.NewJSRuleEvaluator(log)
	if err != nil {
		return fmt.Errorf("js evaluator for validation: %w", err)
	}

	var failed []string
	for _, item := range toValidate {
		cfg := item.cfg
		ruleFromDB := item.rule

		// Use template test_variables for validation so expected-fail cases (e.g. allowed_recipients set) run correctly.
		var varsToSeed map[string]interface{}
		if len(cfg.TestVariables) > 0 {
			varsToSeed = make(map[string]interface{}, len(cfg.TestVariables))
			for k, v := range cfg.TestVariables {
				varsToSeed[k] = v
			}
		} else if len(cfg.Variables) > 0 {
			varsToSeed = cfg.Variables
		}
		ruleForTest := *ruleFromDB
		ruleForTest.Variables = nil
		if len(varsToSeed) > 0 {
			variablesJSON, err := json.Marshal(varsToSeed)
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s: marshal test variables: %v", cfg.Name, err))
				continue
			}
			ruleForTest.Variables = variablesJSON
		}
		// When using template test_variables, set rule scope (ChainID, etc.) from them so the rule
		// matches the test case's chain_id and validation passes (e.g. test uses chain_id 1).
		if len(cfg.TestVariables) > 0 {
			if v, ok := cfg.TestVariables["chain_id"]; ok && v != "" {
				chainIDVal := v
				ruleForTest.ChainID = &chainIDVal
			}
		}

		// Build isolated engine (blocklist + this rule only) so expected-fail cases are not allowed by another whitelist rule.
		testEngine, err := buildIsolatedEngineForRule(ctx, allRulesMap, &ruleForTest, solidityEval, log)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: build isolated engine: %v", cfg.Name, err))
			continue
		}
		testEngine.RegisterEvaluator(jsEval)

		varsForSubst := make(map[string]string)
		if len(cfg.TestVariables) > 0 {
			for k, v := range cfg.TestVariables {
				varsForSubst[k] = v
			}
		} else {
			for k, v := range cfg.Variables {
				if v == nil {
					varsForSubst[k] = ""
				} else {
					varsForSubst[k] = fmt.Sprintf("%v", v)
				}
			}
		}
		for _, tc := range cfg.TestCases {
			inputCopy := make(map[string]interface{})
			for k, v := range tc.Input {
				inputCopy[k] = v
			}
			if len(varsForSubst) > 0 {
				jsonBytes, _ := json.Marshal(inputCopy)
				s := string(jsonBytes)
				for k, v := range varsForSubst {
					s = strings.ReplaceAll(s, "${"+k+"}", v)
				}
				if err := json.Unmarshal([]byte(s), &inputCopy); err != nil {
					failed = append(failed, fmt.Sprintf("%s test %q: variable substitution: %v", cfg.Name, tc.Name, err))
					continue
				}
			}
			req, parsed, err := evm.TestCaseInputToSignRequest(inputCopy)
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s test %q: build request: %v", cfg.Name, tc.Name, err))
				continue
			}
			evalResult, err := testEngine.EvaluateWithResult(ctx, req, parsed)
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s test %q: %v", cfg.Name, tc.Name, err))
				continue
			}
			// For blocklist rules, "pass" means "not blocked"; for whitelist, "pass" means "allowed".
			var actualPass bool
			if ruleFromDB.Mode == types.RuleModeBlocklist {
				actualPass = !evalResult.Blocked
			} else {
				actualPass = evalResult.Allowed
			}
			var actualReason string
			if evalResult.Allowed {
				actualReason = evalResult.AllowReason
			} else if evalResult.Blocked {
				actualReason = evalResult.BlockReason
			} else {
				actualReason = evalResult.NoMatchReason
			}
			if actualPass != tc.ExpectPass {
				if tc.ExpectPass {
					failed = append(failed, fmt.Sprintf("%s test %q: expected pass but got: %s", cfg.Name, tc.Name, actualReason))
				} else {
					failed = append(failed, fmt.Sprintf("%s test %q: expected fail but passed (reason: %s)", cfg.Name, tc.Name, actualReason))
				}
				continue
			}
			if tc.ExpectReason != "" && !strings.Contains(actualReason, tc.ExpectReason) {
				// In isolated engine we only have this rule (+ blocklist), so reason comes from this rule.
				isNoMatch := !evalResult.Blocked && !evalResult.Allowed
				isWhitelistRule := ruleFromDB.Mode != types.RuleModeBlocklist
				if !(isNoMatch && isWhitelistRule) {
					failed = append(failed, fmt.Sprintf("%s test %q: expected reason containing %q but got %q", cfg.Name, tc.Name, tc.ExpectReason, actualReason))
				}
			}
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d evm_js test case(s) failed:\n  - %s", len(failed), strings.Join(failed, "\n  - "))
	}
	log.Info("All evm_js rules validated at startup", "rules", len(toValidate))
	return nil
}

// buildIsolatedEngineForRule builds an engine containing only blocklist rules plus the given rule
// (and its delegation targets). Used so evm_js expected-fail test cases are not allowed by another whitelist rule.
func buildIsolatedEngineForRule(ctx context.Context, allRulesMap map[types.RuleID]*types.Rule, ruleUnderTest *types.Rule, solidityEval *evm.SolidityRuleEvaluator, log *slog.Logger) (*rule.WhitelistRuleEngine, error) {
	minimalRepo := storage.NewMemoryRuleRepository()
	for _, r := range allRulesMap {
		if r.Mode == types.RuleModeBlocklist {
			if err := minimalRepo.Create(ctx, r); err != nil {
				return nil, fmt.Errorf("add blocklist rule %s: %w", r.ID, err)
			}
		}
	}
	if ruleUnderTest.Mode != types.RuleModeBlocklist {
		if err := minimalRepo.Create(ctx, ruleUnderTest); err != nil {
			return nil, fmt.Errorf("add rule under test %s: %w", ruleUnderTest.ID, err)
		}
	}
	if err := addDelegationTargetsForValidation(ctx, ruleUnderTest, allRulesMap, minimalRepo, make(map[types.RuleID]bool), log); err != nil {
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
	if solidityEval != nil {
		eng.RegisterEvaluator(solidityEval)
	}
	return eng, nil
}

// addDelegationTargetsForValidation recursively adds delegation target rules to the minimal repo
// with Enabled=false so they are reachable via Get() but not included in List(EnabledOnly=true).
func addDelegationTargetsForValidation(ctx context.Context, r *types.Rule, allRulesMap map[types.RuleID]*types.Rule, minimalRepo *storage.MemoryRuleRepository, visited map[types.RuleID]bool, log *slog.Logger) error {
	if visited[r.ID] {
		return nil
	}
	visited[r.ID] = true
	var cfg struct {
		DelegateTo string `json:"delegate_to"`
	}
	if err := json.Unmarshal(r.Config, &cfg); err != nil {
		return fmt.Errorf("unmarshal config for rule %q: %w", r.ID, err)
	}
	if cfg.DelegateTo == "" {
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
		if err := addDelegationTargetsForValidation(ctx, target, allRulesMap, minimalRepo, visited, log); err != nil {
			return err
		}
	}
	return nil
}

// validateMessagePatternRulesAtStartup validates all message_pattern rules at startup
// (same as validate-rules: regex compile + test cases). If any fail, startup fails.
func validateMessagePatternRulesAtStartup(ctx context.Context, ruleRepo storage.RuleRepository, log *slog.Logger) error {
	ruleType := types.RuleTypeMessagePattern
	rules, err := ruleRepo.List(ctx, storage.RuleFilter{
		Type:        &ruleType,
		EnabledOnly: true,
	})
	if err != nil {
		return fmt.Errorf("list message_pattern rules: %w", err)
	}
	if len(rules) == 0 {
		log.Info("No message_pattern rules to validate at startup")
		return nil
	}

	msgValidator, err := evm.NewMessagePatternRuleValidator(log)
	if err != nil {
		return fmt.Errorf("create message_pattern validator: %w", err)
	}

	var failed []string
	for _, rule := range rules {
		result, err := msgValidator.ValidateRule(ctx, rule)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s (%s): %v", rule.Name, rule.ID, err))
			continue
		}
		if !result.Valid {
			detail := "invalid config or regex"
			if result.SyntaxError != nil {
				detail = result.SyntaxError.Message
			} else if result.FailedTestCases > 0 {
				for _, tc := range result.TestCaseResults {
					if !tc.Passed {
						detail = fmt.Sprintf("test case %q: %s", tc.Name, tc.Error)
						break
					}
				}
			}
			failed = append(failed, fmt.Sprintf("%s (%s): %s", rule.Name, rule.ID, detail))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d message_pattern rule(s) failed validation:\n  - %s",
			len(failed), strings.Join(failed, "\n  - "))
	}
	log.Info("All message_pattern rules validated at startup", "count", len(rules))
	return nil
}
