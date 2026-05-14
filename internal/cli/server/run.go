// Package server provides the daemon entrypoint for `remote-signer server start`.
// Run is the entrypoint; cmd/remote-signer wires it as a cobra subcommand.
package server

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/joho/godotenv"

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
	"github.com/ivanzzeth/remote-signer/internal/homepath"
	"github.com/ivanzzeth/remote-signer/internal/logger"
	"github.com/ivanzzeth/remote-signer/internal/notify"
	"github.com/ivanzzeth/remote-signer/internal/settings"
	"github.com/ivanzzeth/remote-signer/internal/simulation"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/ivanzzeth/remote-signer/internal/version"
)

// Run executes the server daemon with the given args (not including argv[0]).
// Returns a non-nil error on any setup or runtime failure. Blocks until the
// daemon shuts down cleanly via signal or until a fatal error occurs.
func Run(args []string) error {
	fs := flag.NewFlagSet("remote-signer server start", flag.ContinueOnError)
	configFlag := fs.String("config", "", "path to config file (default: ~/.remote-signer/config.yaml, falling back to ./config.yaml; auto-generated on first run)")
	envFile := fs.String("env", ".env", "path to .env file (optional, ignored if not exists)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	// Load .env file if exists (for development)
	// In production, environment variables should be set directly
	if err := godotenv.Load(*envFile); err != nil {
		// Only log if the file exists but failed to load
		if _, statErr := os.Stat(*envFile); statErr == nil {
			return fmt.Errorf("failed to load .env file: %w", err)
		}
		// .env file not found is OK - use system environment variables
	}

	// Ensure ~/.remote-signer exists (0700) before resolving the config path so
	// auto-generated config and bootstrap key files land in a private dir.
	if _, err := homepath.EnsureHome(); err != nil {
		return fmt.Errorf("ensure remote-signer home: %w", err)
	}

	// Resolve the config file:
	//   -config flag $REMOTE_SIGNER_CONFIG ~/.remote-signer/config.yaml ./config.yaml
	// On the first launch nothing exists yet; write a minimal default to the
	// home dir so the user has something to edit later.
	configPath, exists, err := homepath.ResolveConfigPath(*configFlag)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	if !exists {
		if err := homepath.WriteDefaultConfig(configPath); err != nil {
			return fmt.Errorf("write default config: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[INIT] wrote default config to %s\n", configPath)
	}

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// If the config left DSN empty (e.g. operator hand-trimmed the file),
	// fall back to the SQLite path under the home dir so the daemon still boots.
	if cfg.Database.DSN == "" {
		dsn, err := homepath.DefaultSQLiteDSN()
		if err != nil {
			return fmt.Errorf("compute default DSN: %w", err)
		}
		cfg.Database.DSN = dsn
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

	signerOwnershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	if err != nil {
		return fmt.Errorf("failed to create signer ownership repository: %w", err)
	}
	signerRepo, err := storage.NewGormSignerRepository(db)
	if err != nil {
		return fmt.Errorf("failed to create signer repository: %w", err)
	}

	signerAccessRepo, err := storage.NewGormSignerAccessRepository(db)
	if err != nil {
		return fmt.Errorf("failed to create signer access repository: %w", err)
	}

	// Initialize wallet repository (optional routes: /api/v1/wallets*)
	walletRepo, err := storage.NewGormWalletRepository(db)
	if err != nil {
		return fmt.Errorf("failed to create wallet repository: %w", err)
	}

	// Initialize audit logger early so config sync can record rule changes
	auditLogger, err := audit.NewAuditLogger(auditRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create audit logger: %w", err)
	}

	// Bring up the runtime-mutable settings store. PR7a wires the Manager but
	// no consumer reads from it yet — PR7b/c/d will progressively switch the
	// security middleware, notify dispatcher, and EVM subsystems to read here
	// instead of from cfg.* . The background poll keeps replicas in sync at
	// 5s cadence so admin-initiated edits propagate without restart.
	settingsStore, err := settings.NewGormStore(db)
	if err != nil {
		return fmt.Errorf("failed to create settings store: %w", err)
	}
	// One-shot seed: lift the security knobs out of cfg.Security into
	// system_settings on first launch so existing YAML-driven deployments do
	// not lose behaviour. Subsequent launches are no-ops; the row is present
	// and SeedSecurity skips the insert.
	yamlSecurity := securityYAMLView(cfg)
	seedSnapshot := settings.SecurityFromConfigValues(yamlSecurity)
	if err := settings.SeedSecurity(context.Background(), settingsStore, seedSnapshot); err != nil {
		return fmt.Errorf("failed to seed security settings: %w", err)
	}
	if err := settings.SeedNotify(context.Background(), settingsStore, notifyYAMLToSnapshot(&cfg.Notify, &cfg.NotifyChannel)); err != nil {
		return fmt.Errorf("failed to seed notify settings: %w", err)
	}
	if err := settings.SeedAuditMonitor(context.Background(), settingsStore, auditMonitorToSnapshot(cfg.AuditMonitor)); err != nil {
		return fmt.Errorf("failed to seed audit_monitor settings: %w", err)
	}
	// Web UI defaults to enabled — operators who want a headless deployment
	// flip it off with `remote-signer settings set web enabled=false`. The
	// catch-all "/" handler reads this snapshot every request, so changes
	// take effect on the next Manager refresh cycle.
	if err := settings.SeedWeb(context.Background(), settingsStore, settings.DefaultWeb()); err != nil {
		return fmt.Errorf("failed to seed web settings: %w", err)
	}
	if err := settings.SeedBlocklist(context.Background(), settingsStore, blocklistToSnapshot(cfg.DynamicBlocklist)); err != nil {
		return fmt.Errorf("failed to seed blocklist settings: %w", err)
	}
	if cfg.Chains.EVM != nil {
		if err := settings.SeedFoundry(context.Background(), settingsStore, foundryToSnapshot(cfg.Chains.EVM.Foundry)); err != nil {
			return fmt.Errorf("failed to seed foundry settings: %w", err)
		}
		if err := settings.SeedSimulation(context.Background(), settingsStore, simulationToSnapshot(cfg.Chains.EVM.Simulation)); err != nil {
			return fmt.Errorf("failed to seed simulation settings: %w", err)
		}
		if err := settings.SeedRPCGateway(context.Background(), settingsStore, rpcGatewayToSnapshot(cfg.Chains.EVM.RPCGateway)); err != nil {
			return fmt.Errorf("failed to seed rpc_gateway settings: %w", err)
		}
		if err := settings.SeedMaterialCheck(context.Background(), settingsStore, materialCheckToSnapshot(cfg.Chains.EVM.MaterialCheck)); err != nil {
			return fmt.Errorf("failed to seed material_check settings: %w", err)
		}
	}
	settingsMgr := settings.NewManager(settingsStore, log)
	if err := settingsMgr.Reload(context.Background()); err != nil {
		return fmt.Errorf("failed to load settings: %w", err)
	}
	// From here on, mgr.* groups are the source of truth. Overlay snapshots
	// back onto cfg so the existing downstream wiring (rate limiter, IP
	// whitelist, signer auto-lock, approval guard, notify service, budget
	// alerter, audit monitor, Solidity evaluator, simulator, JS RPC
	// gateway, blocklist syncer) picks up DB values without touching every
	// read site. PR7e/g will retire cfg.* in favour of mgr.* reads.
	applySecuritySnapshot(cfg, settingsMgr.Security())
	applyNotifySnapshot(&cfg.Notify, &cfg.NotifyChannel, settingsMgr.Notify())
	applyAuditMonitorSnapshot(cfg, settingsMgr.AuditMonitor())
	applyBlocklistSnapshot(cfg, settingsMgr.Blocklist())
	applyEVMSnapshots(cfg, settingsMgr.Foundry(), settingsMgr.Simulation(), settingsMgr.RPCGateway(), settingsMgr.MaterialCheck())

	// Initialize API keys from config
	apiKeyInit, err := config.NewAPIKeyInitializer(apiKeyRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create API key initializer: %w", err)
	}
	apiKeyInit.SetAuditLogger(auditLogger)
	if err := apiKeyInit.SyncFromConfig(context.Background(), cfg.APIKeys); err != nil {
		return fmt.Errorf("failed to sync API keys from config: %w", err)
	}

	// Auto-bootstrap an admin Ed25519 keypair when the api_keys table is
	// empty so the operator can use a fresh single-binary install without any
	// pre-flight steps. Subsequent launches are no-ops; the private key is
	// only written to disk, never to logs or stderr.
	adminPrivPath, adminPubPath, err := homepath.AdminKeyPaths()
	if err != nil {
		return fmt.Errorf("resolve admin key paths: %w", err)
	}
	if err := bootstrapAdminKeyIfNeeded(context.Background(), apiKeyRepo, adminPrivPath, adminPubPath, cfg.Security.RateLimitDefault, log); err != nil {
		return fmt.Errorf("bootstrap admin api key: %w", err)
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
	templateInit.SetConfigDir(filepath.Dir(configPath))
	templateInit.SetAuditLogger(auditLogger)
	// Merge in any templates discovered under templates_dir before
	// sync. The shorthand expands to a {type:file,path:...} TemplateConfig
	// per matching file so SyncFromConfig sees one unified list and
	// existing dedup/conflict semantics apply.
	allTemplates := cfg.Templates
	if cfg.TemplatesDir != "" {
		dirTemplates, dirErr := config.LoadTemplatesFromDir(cfg.TemplatesDir, filepath.Dir(configPath), log)
		if dirErr != nil {
			return fmt.Errorf("failed to enumerate templates_dir %q: %w", cfg.TemplatesDir, dirErr)
		}
		allTemplates = append(allTemplates, dirTemplates...)
		log.Info("templates_dir expanded", "dir", cfg.TemplatesDir, "count", len(dirTemplates))
	}
	if err := templateInit.SyncFromConfig(context.Background(), allTemplates); err != nil {
		return fmt.Errorf("failed to sync templates from config: %w", err)
	}

	// Run the v0.3 Registry over rules/templates and rules/presets on
	// disk. Templates land under types.RuleSourceFile so the legacy
	// initializer's Source=config prune step does not touch them, and
	// presets get a first-class DB row (the legacy path kept them on
	// disk only). The Registry's directory roots default to cfg.TemplatesDir
	// and cfg.Presets.Dir respectively, both resolved against the config
	// file directory the same way the legacy paths are. Missing roots
	// are tolerated — fresh installs without those dirs boot to an
	// empty Registry rather than failing.
	if err := syncRegistries(context.Background(), db, cfg, configPath, log); err != nil {
		return fmt.Errorf("registry sync: %w", err)
	}

	// Initialize rules from config (with template expansion)
	ruleInit, err := config.NewRuleInitializer(ruleRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create rule initializer: %w", err)
	}
	// Set config directory for resolving relative paths in rule files
	ruleInit.SetConfigDir(filepath.Dir(configPath))
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
	expandedRulesWithFiles, err := config.ExpandFileRules(expandedRules, filepath.Dir(configPath), log)
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
	var evmAdapter *evm.EVMAdapter
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

		// Sync signer ownership (assign unowned signers to first admin)
		if err := config.SyncSignerOwnership(context.Background(), evmSignerManager, signerOwnershipRepo, apiKeyRepo, log); err != nil {
			return fmt.Errorf("failed to sync signer ownership: %w", err)
		}
		if cfg.Chains.EVM.MaterialCheck.Enabled {
			checker, checkerErr := service.NewSignerMaterialChecker(
				evmSignerManager,
				signerRepo,
				cfg.Chains.EVM.KeystoreDir,
				cfg.Chains.EVM.HDWalletDir,
				cfg.Chains.EVM.MaterialCheck.Interval,
				log,
			)
			if checkerErr != nil {
				return fmt.Errorf("failed to create signer material checker: %w", checkerErr)
			}
			if cfg.Chains.EVM.MaterialCheck.StartupCheck {
				if runErr := checker.RunOnce(context.Background()); runErr != nil {
					return fmt.Errorf("startup signer material check failed: %w", runErr)
				}
			}
			checkerCtx, checkerCancel := context.WithCancel(context.Background())
			defer checkerCancel()
			go checker.Start(checkerCtx)
		}

		if evmRegistry.SignerCount() == 0 && evmRegistry.TotalCount() == 0 {
			log.Warn("No signers configured. Add signers via TUI or API after startup.")
		}

		evmAdapter, err = evm.NewEVMAdapter(evmRegistry)
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

	// Register internal transfer evaluator (requires ownership repo)
	internalTransferEval, err := evm.NewInternalTransferEvaluator(signerOwnershipRepo)
	if err != nil {
		return fmt.Errorf("failed to create internal transfer evaluator: %w", err)
	}
	ruleEngine.RegisterEvaluator(internalTransferEval)

	jsEval, err := evm.NewJSRuleEvaluator(log)
	if err != nil {
		return fmt.Errorf("failed to create JS rule evaluator: %w", err)
	}
	ruleEngine.RegisterEvaluator(jsEval)
	budgetChecker.SetJSEvaluator(jsEval)

	// Wire RPC provider for JS sandbox read-only queries, budget decimals auto-query, and broadcast
	var rpcProvider *evm.RPCProvider
	var decimalsQuerier rule.DecimalsQuerier
	if cfg.Chains.EVM != nil && cfg.Chains.EVM.RPCGateway.BaseURL != "" {
		rpcProvider, err = evm.NewRPCProvider(cfg.Chains.EVM.RPCGateway.BaseURL, cfg.Chains.EVM.RPCGateway.APIKey)
		if err != nil {
			return fmt.Errorf("failed to create RPC provider: %w", err)
		}
		cacheTTL := cfg.Chains.EVM.RPCGateway.CacheTTL
		if cacheTTL <= 0 {
			cacheTTL = 24 * time.Hour
		}
		metadataCache, err := evm.NewTokenMetadataCache(nil, rpcProvider, cacheTTL)
		if err != nil {
			return fmt.Errorf("failed to create token metadata cache: %w", err)
		}
		jsEval.SetRPCProvider(rpcProvider, metadataCache)
		// Wire RPC provider to EVM adapter for nonce auto-fetch
		if evmAdapter != nil {
			evmAdapter.SetRPCProvider(rpcProvider)
		}
		var dqErr error
		decimalsQuerier, dqErr = evm.NewDecimalsQuerierAdapter(metadataCache)
		if dqErr != nil {
			return fmt.Errorf("failed to create decimals querier: %w", dqErr)
		}
		budgetChecker.SetDecimalsQuerier(decimalsQuerier)
		log.Info("RPC provider configured for JS sandbox and budget decimals auto-query",
			"base_url", cfg.Chains.EVM.RPCGateway.BaseURL,
			"cache_ttl", cacheTTL,
		)
	}

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
		const minSyncInterval = 1 * time.Minute
		if syncInterval < minSyncInterval {
			return fmt.Errorf("dynamic_blocklist.sync_interval must be >= 1m (got %s)", syncInterval)
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

	// Seal the rule engine: no more evaluator registrations allowed after this point.
	ruleEngine.Seal()

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
			Window:                cfg.Security.ApprovalGuard.Window,
			RejectionThresholdPct: cfg.Security.ApprovalGuard.RejectionThresholdPct,
			MinSamples:            cfg.Security.ApprovalGuard.MinSamples,
			ResumeAfter:           cfg.Security.ApprovalGuard.ResumeAfter,
			NotifySvc:             notifyService,
			Channel:               &cfg.NotifyChannel,
			Logger:                log,
		})
		if err != nil {
			return fmt.Errorf("failed to create approval guard: %w", err)
		}
		signService.SetApprovalGuard(approvalGuard)
		log.Info("approval guard enabled",
			"window", cfg.Security.ApprovalGuard.Window,
			"rejection_threshold_pct", cfg.Security.ApprovalGuard.RejectionThresholdPct,
			"min_samples", cfg.Security.ApprovalGuard.MinSamples,
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

		// Wire high-risk admin operation alerting.
		// Every privileged change (signer create/unlock, rule CRUD, config reload, etc.)
		// triggers a real-time notification. If you didn't initiate it, investigate immediately.
		auditLogger.SetOnHighRiskOperation(func(eventType types.AuditEventType, apiKeyID, source, detail string) {
			alertType := auditEventToAlertType(eventType)
			who := apiKeyID
			if who == "" {
				who = "system"
			}
			securityAlertService.Alert(alertType, source,
				fmt.Sprintf("[Remote Signer] ADMIN OPERATION\n\nOperation: %s\nAPI Key: %s\nSource IP: %s\nDetail: %s\nTime: %s\n\nIf you did not initiate this, investigate immediately.",
					eventType, who, source, detail, time.Now().UTC().Format(time.RFC3339)))
		})
	}

	signService.SetAuditLogger(auditLogger)

	// Presets dir (for preset API): resolve relative to config file directory
	var presetsDir string
	if cfg.Presets != nil && cfg.Presets.Dir != "" {
		presetsDir = cfg.Presets.Dir
		if !filepath.IsAbs(presetsDir) {
			presetsDir = filepath.Join(filepath.Dir(configPath), presetsDir)
		}
		var errAbs error
		presetsDir, errAbs = filepath.Abs(presetsDir)
		if errAbs != nil {
			return fmt.Errorf("presets dir: %w", errAbs)
		}
	}

	// Initialize simulation engine (optional; eth_simulateV1 via rpc_gateway)
	var simulator simulation.Simulator
	if cfg.Chains.EVM != nil && cfg.Chains.EVM.Simulation.Enabled {
		rpcGatewayURL := cfg.Chains.EVM.RPCGateway.BaseURL
		simCfg := simulation.RPCSimulatorConfig{
			RPCGatewayURL: rpcGatewayURL,
			RPCGatewayKey: cfg.Chains.EVM.RPCGateway.APIKey,
			Timeout:       cfg.Chains.EVM.Simulation.Timeout,
		}
		sim, simErr := simulation.NewRPCSimulator(simCfg, log)
		if simErr != nil {
			return fmt.Errorf("failed to create RPC simulation engine: %w", simErr)
		}
		simulator = sim
		log.Info("simulation engine initialized (rpc/eth_simulateV1)",
			"gateway", rpcGatewayURL,
			"timeout", cfg.Chains.EVM.Simulation.Timeout,
		)

		defer func() {
			if closeErr := simulator.Close(); closeErr != nil {
				log.Error("failed to close simulation engine", "error", closeErr)
			}
		}()
	}

	// Wire simulation fallback to sign service
	if simulator != nil {
		// Hand the rule a settings-backed policy so flipping
		// auto_create_budget in the Settings UI takes effect on the
		// next sign request without restarting the daemon. The
		// adapter is local to this package to avoid pulling the
		// settings dependency into chain/evm.
		simBudgetPolicy := &settingsSimBudgetPolicy{mgr: settingsMgr}
		var signerLister evm.ManagedSignerLister
		if evmAdapter != nil {
			signerLister = evm.NewEVMAdapterSignerLister(evmAdapter)
		}
		var allowanceQuerier simulation.AllowanceQuerier
		if rpcProvider != nil {
			allowanceQuerier = evm.NewRPCAllowanceQuerier(rpcProvider)
		}
		simRule, simRuleErr := evm.NewSimulationBudgetRule(simulator, budgetRepo, simBudgetPolicy, decimalsQuerier, signerLister, allowanceQuerier, log)
		if simRuleErr != nil {
			log.Warn("failed to create simulation budget rule", "error", simRuleErr)
		} else {
			signService.SetSimulationRule(simRule)
			// Start batch accumulator if configured
			if cfg.Chains.EVM.Simulation.BatchWindow > 0 {
				simRule.SetBatchConfig(cfg.Chains.EVM.Simulation.BatchWindow, cfg.Chains.EVM.Simulation.BatchMaxSize)
				simRule.StartAccumulator()
				defer simRule.StopAccumulator()
			}
			log.Info("simulation budget rule enabled for sign service fallback")
		}
	}

	// Initialize router
	routerConfig := api.RouterConfig{
		Version:                  version.Version,
		IPWhitelistConfig:        ipWhitelist,
		IPWhitelistConfigForRead: &cfg.Security.IPWhitelist,
		IPRateLimit:              cfg.Security.IPRateLimit,
		SolidityValidator:        solidityValidator,
		JSEvaluator:              jsEval,
		Template: &api.TemplateConfig{
			TemplateRepo:    templateRepo,
			TemplateService: templateService,
		},
		ApprovalGuard:                approvalGuard,
		APIKeyRepo:                   apiKeyRepo,
		SignerRepo:                   signerRepo,
		SignerOwnershipRepo:          signerOwnershipRepo,
		SignerAccessRepo:             signerAccessRepo,
		WalletRepo:                   walletRepo,
		BudgetRepo:                   budgetRepo,
		RulesAPIReadonly:             cfg.Security.IsRulesAPIReadonly(),
		SignersAPIReadonly:           cfg.Security.IsSignersAPIReadonly(),
		APIKeysAPIReadonly:           cfg.Security.IsAPIKeysAPIReadonly(),
		MaxRulesPerAPIKey:            cfg.Security.MaxRulesPerAPIKey,
		MaxKeystoresPerKey:           cfg.Security.MaxKeystoresPerKey,
		MaxHDWalletsPerKey:           cfg.Security.MaxHDWalletsPerKey,
		RequireApprovalForAgentRules: cfg.Security.IsRequireApprovalForAgentRules(),
		AlertService:                 securityAlertService,
		AuditLogger:                  auditLogger,
		SignTimeout:                  cfg.Security.SignTimeout,
		AutoLockTimeout:              cfg.Security.AutoLockTimeout,
		AuditRetentionDays:           cfg.AuditMonitor.RetentionDays,
		Simulator:                    simulator,
		RPCProvider:                  rpcProvider,
		SettingsManager:              settingsMgr,
	}
	// Preset API: wire the DB-backed repo (populated by Registry sync at boot).
	// The legacy presetsDir is no longer used by the handler — left as a no-op
	// placeholder so the existing config field doesn't error; it can be removed
	// once we drop the legacy abs-path resolution above.
	_ = presetsDir
	if presetRepo, err := storage.NewGormPresetRepository(db); err == nil {
		routerConfig.PresetRepo = presetRepo
		routerConfig.PresetsDB = db
	} else {
		log.Warn("preset API disabled: failed to wire preset repo", "error", err)
	}
	// Wire the Registry pair for POST /api/v1/registry/refresh. Building
	// here (not at boot's syncRegistries call) keeps the handler tied to
	// the same file roots the bootstrap sync used, so a refresh always
	// picks up the same set of files regardless of working-directory
	// shenanigans at request time.
	if tmplReg, presetReg, err := buildRegistries(db, cfg, configPath, log); err == nil {
		routerConfig.TemplateRegistry = tmplReg
		routerConfig.PresetRegistry = presetReg
	} else {
		log.Warn("registry refresh endpoint disabled: failed to build registries", "error", err)
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

	// Start the settings hot-reload loop. Bound to the shutdown context below
	// so a SIGINT/SIGTERM cleanly stops the poll goroutine alongside HTTP.
	settingsCtx, settingsCancel := context.WithCancel(context.Background())
	defer settingsCancel()
	settingsMgr.Start(settingsCtx)

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
				reloadRules(configPath, ruleInit, templateInit, auditLogger, log)
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
