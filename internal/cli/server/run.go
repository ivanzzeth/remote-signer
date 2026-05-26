// Package server provides the daemon entrypoint for `remote-signer server start`.
// Run is the entrypoint; cmd/remote-signer wires it as a cobra subcommand.
package server

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/bootstrap"
	"github.com/ivanzzeth/remote-signer/internal/chain"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/statemachine"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/homepath"
	"github.com/ivanzzeth/remote-signer/internal/notify"
	"github.com/ivanzzeth/remote-signer/internal/simulation"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// Run executes the server daemon with the given args (not including argv[0]).
// Returns a non-nil error on any setup or runtime failure. Blocks until the
// daemon shuts down cleanly via signal or until a fatal error occurs.
func Run(args []string) error {
	// ---- Flag parsing ----
	fs := flag.NewFlagSet("remote-signer server start", flag.ContinueOnError)
	configFlag := fs.String("config", "", "path to config file (default: ~/.remote-signer/config.yaml, falling back to ./config.yaml; auto-generated on first run)")
	envFile := fs.String("env", ".env", "path to .env file (optional, ignored if not exists)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	// ---- Environment and config loading ----
	loadEnvFile(*envFile)
	if _, err := homepath.EnsureHome(); err != nil {
		return fmt.Errorf("ensure remote-signer home: %w", err)
	}
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
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if cfg.Database.DSN == "" {
		dsn, err := homepath.DefaultSQLiteDSN()
		if err != nil {
			return fmt.Errorf("compute default DSN: %w", err)
		}
		cfg.Database.DSN = dsn
	}

	// ---- Logger ----
	log := initLogging(cfg.Logger.Level, cfg.Logger.Pretty)
	log.Info("Starting remote-signer service")
	checkSwapEnabled(log)
	hardenProcessMemory(log)

	// ---- Database + repositories ----
	db, err := storage.NewDB(cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	log.Info("Database connected")
	repos, err := initRepositories(db, log)
	if err != nil {
		return err
	}

	// ---- Audit logger ----
	auditLogger, err := audit.NewAuditLogger(repos.auditRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create audit logger: %w", err)
	}

	// ---- Settings store ----
	settingsMgr, err := initSettingsStore(db, cfg, log)
	if err != nil {
		return err
	}

	// ---- API keys ----
	apiKeyInit, err := config.NewAPIKeyInitializer(repos.apiKeyRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create API key initializer: %w", err)
	}
	apiKeyInit.SetAuditLogger(auditLogger)
	if err := apiKeyInit.SyncFromConfig(context.Background(), cfg.APIKeys); err != nil {
		return fmt.Errorf("failed to sync API keys from config: %w", err)
	}
	adminKeystoreDir, err := homepath.APIKeysDir()
	if err != nil {
		return fmt.Errorf("resolve admin keystore dir: %w", err)
	}
	adminKeystorePath, err := homepath.AdminKeystorePath()
	if err != nil {
		return fmt.Errorf("resolve admin keystore path: %w", err)
	}
	_, adminPubPath, err := homepath.AdminKeyPaths()
	if err != nil {
		return fmt.Errorf("resolve admin key paths: %w", err)
	}
	if err := bootstrapAdminKeyIfNeeded(context.Background(), repos.apiKeyRepo, adminKeystoreDir, adminKeystorePath, adminPubPath, cfg.Security.RateLimitDefault, log); err != nil {
		return fmt.Errorf("bootstrap admin api key: %w", err)
	}
	// Closure passed to the HTTP layer so the unauthenticated
	// POST /api/v1/bootstrap/admin route can complete bootstrap when the
	// env var path is unavailable (docker without secret env, browser-only
	// users, etc.). The closure captures the resolved paths + rate limit
	// so callers only have to hand it a password. See SECURITY.md for the
	// bootstrap state machine.
	rateLimitForBootstrap := cfg.Security.RateLimitDefault
	bootstrapCreator := func(ctx context.Context, password []byte) (*bootstrap.AdminResult, error) {
		return CreateAdminKeystore(ctx, repos.apiKeyRepo, adminKeystoreDir, adminKeystorePath, adminPubPath, password, rateLimitForBootstrap, log)
	}
	// The daemon never needs the admin private key at runtime — it
	// verifies API request signatures using the public-key column on
	// api_keys. CLI / web UI / popup all read the encrypted keystore
	// directly. No plaintext PEM is ever exported.

	// Auto-bootstrap an agent Ed25519 keypair independently from the
	// admin key so agents can authenticate without an operator pre-flight.
	agentPrivPath, agentPubPath, err := homepath.AgentKeyPaths()
	if err != nil {
		return fmt.Errorf("resolve agent key paths: %w", err)
	}
	if err := bootstrapAgentKeyIfNeeded(context.Background(), repos.apiKeyRepo, agentPrivPath, agentPubPath, cfg.Security.RateLimitDefault, log); err != nil {
		return fmt.Errorf("bootstrap agent api key: %w", err)
	}

	// ---- Templates ----
	templateInit, allTemplates, err := initTemplates(cfg, configPath, repos.templateRepo, auditLogger, log)
	if err != nil {
		return err
	}

	// ---- File-based registries ----
	if err := syncRegistries(context.Background(), db, cfg, configPath, log); err != nil {
		return fmt.Errorf("registry sync: %w", err)
	}

	// Bootstrap the agent preset: on first launch, the Registry loaded
	// evm/agent preset and template into the DB. Apply the preset (create
	// rule instances owned by the agent key) if no agent rules exist yet.
	presetRepo, err := storage.NewGormPresetRepository(db)
	if err != nil {
		return fmt.Errorf("failed to create preset repository: %w", err)
	}
	if err := bootstrapAgentPresetIfNeeded(context.Background(), presetRepo, repos.templateRepo, repos.ruleRepo, repos.budgetRepo, log); err != nil {
		return fmt.Errorf("bootstrap agent preset: %w", err)
	}

	// ---- Rules ----
	ruleInit, _, expandedRulesWithFiles, err := initRules(cfg, configPath, repos.ruleRepo, repos.budgetRepo, repos.templateRepo, templateInit, allTemplates, auditLogger, log)
	if err != nil {
		return err
	}

	// ---- Template service ----
	templateService, err := service.NewTemplateService(repos.templateRepo, repos.ruleRepo, repos.budgetRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create template service: %w", err)
	}

	// ---- Rule validation (before signer init to avoid password prompts) ----
	var solidityEval *evm.SolidityRuleEvaluator
	var solidityValidator *evm.SolidityRuleValidator
	if cfg.Chains.EVM != nil && cfg.Chains.EVM.Foundry.FoundryEnabled() {
		solidityEval, err = evm.NewSolidityRuleEvaluator(evm.SolidityEvaluatorConfig{
			ForgePath: cfg.Chains.EVM.Foundry.ForgePath,
			CacheDir:  cfg.Chains.EVM.Foundry.CacheDir,
			TempDir:   cfg.Chains.EVM.Foundry.TempDir,
			Timeout:   cfg.Chains.EVM.Foundry.Timeout,
		}, log)
		if err != nil {
			// Auto-detect mode (forge_path empty): warn and disable solidity.
			// Explicit path: fatal — admin explicitly configured a bad path.
			if cfg.Chains.EVM.Foundry.ForgePath == "" {
				log.Warn("forge not found in PATH, solidity expression rules disabled", "error", err)
				solidityEval = nil
			} else {
				return fmt.Errorf("forge not found at configured path %q: %w", cfg.Chains.EVM.Foundry.ForgePath, err)
			}
		}
		if solidityEval != nil {
			log.Info("Solidity expression evaluator created (Foundry)")

			solidityValidator, err = evm.NewSolidityRuleValidator(solidityEval, log)
			if err != nil {
				return fmt.Errorf("failed to create Solidity rule validator: %w", err)
			}

			if err := validateSolidityRules(context.Background(), repos.ruleRepo, solidityEval, log); err != nil {
				return fmt.Errorf("rule validation failed: %w", err)
			}
		}
	}
	if solidityEval == nil {
		for _, r := range expandedRulesWithFiles {
			if r.Type == string(types.RuleTypeEVMSolidityExpression) && r.Enabled {
				return fmt.Errorf("config contains enabled evm_solidity_expression rule %q but Foundry is unavailable; install forge (brew install foundry / foundryup) or remove the rule", r.Name)
			}
		}
		// Warn about DB rules too — API may have created solidity rules
		// on a previous run when forge was available.
		dbRules, dbErr := repos.ruleRepo.List(context.Background(), storage.RuleFilter{Limit: -1})
		if dbErr != nil {
			log.Warn("failed to list DB rules for solidity check", "error", dbErr)
		} else {
			for _, r := range dbRules {
				if r.Type == types.RuleTypeEVMSolidityExpression && r.Enabled {
					log.Warn("evm_solidity_expression rule exists in DB but Foundry is unavailable; enable forge or disable the rule",
						"rule_id", r.ID,
						"rule_name", r.Name,
					)
				}
			}
		}
	}
	if err := validateEVMJSRulesAtStartup(context.Background(), expandedRulesWithFiles, repos.ruleRepo, solidityEval, log); err != nil {
		return fmt.Errorf("evm_js rule validation failed: %w", err)
	}
	if err := validateMessagePatternRulesAtStartup(context.Background(), repos.ruleRepo, log); err != nil {
		return fmt.Errorf("message_pattern rule validation failed: %w", err)
	}

	// ---- EVM signers ----
	chainRegistry := chain.NewRegistry()
	var evmSignerManager evm.SignerManager
	var evmAdapter *evm.EVMAdapter
	if cfg.Chains.EVM != nil && cfg.Chains.EVM.Enabled {
		esm, adapter, sErr := initEVMSigners(cfg, repos, auditLogger, log)
		if sErr != nil {
			return sErr
		}
		evmSignerManager = esm
		evmAdapter = adapter
		if err := chainRegistry.Register(evmAdapter); err != nil {
			return fmt.Errorf("failed to register EVM adapter: %w", err)
		}
	}

	// ---- State machine + rule engine ----
	stateMachine, err := statemachine.NewStateMachine(repos.requestRepo, repos.auditRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create state machine: %w", err)
	}
	budgetChecker := rule.NewBudgetChecker(repos.budgetRepo, repos.templateRepo, log)
	ruleEngine, err := rule.NewWhitelistRuleEngine(repos.ruleRepo, log,
		rule.WithBudgetChecker(budgetChecker),
		rule.WithDelegationPayloadConverter(evm.DelegatePayloadToSignRequest),
	)
	if err != nil {
		return fmt.Errorf("failed to create rule engine: %w", err)
	}
	registerEVMStandardEvaluators(ruleEngine)
	internalTransferEval, err := evm.NewInternalTransferEvaluator(repos.signerOwnershipRepo)
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

	// ---- RPC provider ----
	var rpcProvider *evm.RPCProvider
	var decimalsQuerier rule.DecimalsQuerier
	if cfg.Chains.EVM != nil && cfg.Chains.EVM.RPCGateway.BaseURL != "" {
		rpcProvider, decimalsQuerier, err = initRPCProvider(cfg, jsEval, evmAdapter, budgetChecker, log)
		if err != nil {
			return err
		}
	}

	// ---- Solidity evaluator ----
	if solidityEval != nil {
		ruleEngine.RegisterEvaluator(solidityEval)
		log.Info("Solidity expression evaluator registered")
	}

	// ---- Dynamic blocklist ----
	if cfg.DynamicBlocklist != nil && cfg.DynamicBlocklist.Enabled {
		blEval, blErr := initDynamicBlocklist(cfg, log)
		if blErr != nil {
			return blErr
		}
		ruleEngine.RegisterEvaluator(blEval)
	}
	ruleEngine.Seal()

	// ---- Notifications ----
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nr, err := initNotificationService(ctx, cfg, log)
	if err != nil {
		return err
	}
	notifyService := nr.service
	notifier := nr.notifier
	if notifyService != nil {
		defer notifyService.Stop()
	}
	if notifyService != nil {
		budgetAlertNotifier := notify.NewBudgetAlertNotifier(notifyService, &cfg.NotifyChannel)
		budgetChecker.SetNotifier(budgetAlertNotifier)
		log.Info("Budget alert notifications enabled")
	}
	if cfg.AuditMonitor.Enabled && notifyService != nil {
		auditMonitor, err := audit.NewMonitor(repos.auditRepo, notifyService, &cfg.NotifyChannel, cfg.AuditMonitor, log)
		if err != nil {
			return fmt.Errorf("failed to create audit monitor: %w", err)
		}
		auditMonitor.Start(ctx)
		defer auditMonitor.Stop()
	}

	// ---- Sign service + approval ----
	signService, approvalGuard, err := initSignService(chainRegistry, repos.ruleRepo, repos.requestRepo, ruleEngine, stateMachine, cfg, notifier, notifyService, log)
	if err != nil {
		return err
	}
	signService.SetAuditLogger(auditLogger)

	// ---- Auth + IP whitelist ----
	authVerifier, ipWhitelist, nonceStore, err := initAuthAndIPWhitelist(cfg, repos.apiKeyRepo, log)
	if err != nil {
		return err
	}
	defer nonceStore.Close()

	// ---- Security alerts ----
	securityAlertService, err := initSecurityAlerts(cfg, notifyService, auditLogger, evmSignerManager, ipWhitelist, log)
	if err != nil {
		return err
	}

	// ---- Simulation engine ----
	var simulator simulation.Simulator
	if cfg.Chains.EVM != nil && cfg.Chains.EVM.Simulation.Enabled {
		simulator, err = initSimulation(cfg, log)
		if err != nil {
			return err
		}
		defer func() {
			if closeErr := simulator.Close(); closeErr != nil {
				log.Error("failed to close simulation engine", "error", closeErr)
			}
		}()
	}
	if simulator != nil {
		simBudgetPolicy := &settingsSimBudgetPolicy{mgr: settingsMgr}
		var signerLister evm.ManagedSignerLister
		if evmAdapter != nil {
			signerLister = evm.NewEVMAdapterSignerLister(evmAdapter)
		}
		var allowanceQuerier simulation.AllowanceQuerier
		if rpcProvider != nil {
			allowanceQuerier = evm.NewRPCAllowanceQuerier(rpcProvider)
		}
		simRule, simRuleErr := evm.NewSimulationBudgetRule(simulator, repos.budgetRepo, simBudgetPolicy, decimalsQuerier, signerLister, allowanceQuerier, log)
		if simRuleErr != nil {
			log.Warn("failed to create simulation budget rule", "error", simRuleErr)
		} else {
			// Persist each evaluation's outcome so the web UI's
			// request-detail preview panel can render without
			// re-running simulation client-side. Optional —
			// disabled here means the rule still drives sign
			// approval, just no DB-backed preview.
			if simRepo, simRepoErr := storage.NewGormRequestSimulationRepository(db); simRepoErr == nil {
				simRule.SetSimulationRepo(simRepo)
			} else {
				log.Warn("simulation preview disabled: repo init failed", "error", simRepoErr)
			}
			signService.SetSimulationRule(simRule)
			if cfg.Chains.EVM.Simulation.BatchWindow > 0 {
				simRule.SetBatchConfig(cfg.Chains.EVM.Simulation.BatchWindow, cfg.Chains.EVM.Simulation.BatchMaxSize)
				simRule.StartAccumulator()
				defer simRule.StopAccumulator()
			}
			log.Info("simulation budget rule enabled for sign service fallback")
		}
	}

	// ---- Router + HTTP server ----
	rs, err := initRouterAndServer(cfg, configPath, db, repos, authVerifier, signService, evmSignerManager, approvalGuard, securityAlertService, auditLogger, settingsMgr, solidityValidator, jsEval, ipWhitelist, templateService, simulator, rpcProvider, bootstrapCreator, log)
	if err != nil {
		return fmt.Errorf("failed to create router: %w", err)
	}
	server := rs.Server

	// ---- Signal handling ----
	settingsCtx, settingsCancel := context.WithCancel(context.Background())
	defer settingsCancel()
	settingsMgr.Start(settingsCtx)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	errCh := make(chan error, 1)
	go func() {
		log.Info("Starting HTTP server", "host", cfg.Server.Host, "port", cfg.Server.Port)
		errCh <- server.Start()
	}()

	// Background receipt poller. Uses the same context the settings
	// manager uses so SIGTERM / SIGINT propagate to a clean shutdown.
	// 10s tick is the default; busy chains can tune via settings
	// once an exposed knob lands.
	if rs.TxService != nil {
		go rs.TxService.Run(settingsCtx, 10*time.Second)
	}

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
