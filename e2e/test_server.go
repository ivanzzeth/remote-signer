//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/lib/pq"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/api"
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
	"github.com/ivanzzeth/remote-signer/internal/simulation"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// TestServerConfig holds configuration for the test server
type TestServerConfig struct {
	Port             int
	SignerPrivateKey string            // Hex-encoded private key without 0x prefix
	SignerAddress    string            // Expected signer address
	APIKeyID         string            // API key ID for authentication (admin)
	APIKeyPublicKey  ed25519.PublicKey // Ed25519 public key for API auth (admin)
	// Non-admin API key
	NonAdminAPIKeyID        string            // API key ID for non-admin authentication
	NonAdminAPIKeyPublicKey ed25519.PublicKey // Ed25519 public key for non-admin API auth
	// Optional: config file path (if set, will load from config.e2e.yaml)
	ConfigPath string // Path to config.e2e.yaml (default: "config.e2e.yaml")
	// Optional: presets directory (when set, GET/POST /api/v1/presets are registered)
	PresetsDir string // Absolute path to dir containing preset YAML files
}

// TestServer manages a test instance of the remote-signer service
type TestServer struct {
	config     TestServerConfig
	server     *api.Server
	db         *gorm.DB
	cancelFunc context.CancelFunc
	baseURL    string
	tlsCerts   *tlsCerts // set by StartWithTLS for mTLS health-check
	ruleEngine *rule.WhitelistRuleEngine // exposed for dynamic evaluator registration in e2e tests
	simulator  simulation.AnvilForkManager // optional: for simulation e2e tests
}

// NewTestServer creates a new test server instance
func NewTestServer(cfg TestServerConfig) (*TestServer, error) {
	if cfg.Port <= 0 {
		cfg.Port = 8548
	}

	return &TestServer{
		config:  cfg,
		baseURL: fmt.Sprintf("http://localhost:%d", cfg.Port),
	}, nil
}

// Start initializes and starts the test server
func (ts *TestServer) Start() error {
	// Set environment variables for signer private keys (second signer for approval-guard e2e)
	os.Setenv("E2E_TEST_SIGNER_KEY", ts.config.SignerPrivateKey)
	os.Setenv("E2E_TEST_SIGNER2_KEY", testSigner2PrivateKey)

	// Create logger
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelWarn, // Reduce noise in tests
	}))

	// Load config from config.e2e.yaml if ConfigPath is set
	var cfg *config.Config
	if ts.config.ConfigPath != "" {
		// Find project root to locate config.e2e.yaml
		configPath := ts.config.ConfigPath
		if !filepath.IsAbs(configPath) {
			// Try to find project root
			wd, err := os.Getwd()
			if err == nil {
				// Go up from current directory to find project root
				for wd != "/" && wd != "" {
					testPath := filepath.Join(wd, configPath)
					if _, err := os.Stat(testPath); err == nil {
						configPath = testPath
						break
					}
					wd = filepath.Dir(wd)
				}
			}
		}

		var err error
		cfg, err = config.Load(configPath)
		if err != nil {
			log.Warn("Failed to load config.e2e.yaml, using defaults", "error", err, "path", configPath)
			cfg = nil
		} else {
			log.Info("Loaded configuration from config.e2e.yaml", "path", configPath)
		}
	}

	// Initialize in-memory SQLite database with shared cache and WAL mode
	// Using file::memory:?cache=shared ensures all connections share the same database
	// _journal_mode=WAL and _busy_timeout improve concurrent access handling
	dbDSN := "file::memory:?cache=shared&_journal_mode=WAL&_busy_timeout=5000"
	if cfg != nil && cfg.Database.DSN != "" {
		// Use config database DSN if provided (but for e2e, we prefer in-memory)
		// Only use config DSN if it's explicitly in-memory
		if cfg.Database.DSN == "file::memory:?cache=shared&_journal_mode=WAL&_busy_timeout=5000" {
			dbDSN = cfg.Database.DSN
		}
	}

	db, err := gorm.Open(sqlite.Open(dbDSN), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		return fmt.Errorf("failed to create database: %w", err)
	}

	// Single connection to avoid SQLite table lock (transaction and template reads must use same conn).
	// Rule sync pre-loads templates before the transaction so no second conn is needed.
	// Preset apply resolves templates before the transaction so it does not need a second conn.
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	ts.db = db

	// Auto-migrate tables
	if err := db.AutoMigrate(
		&types.SignRequest{},
		&types.Rule{},
		&types.APIKey{},
		&types.AuditRecord{},
		&types.RuleTemplate{},
		&types.RuleBudget{},
		&types.TokenMetadata{},
		&types.SignerOwnership{},
		&types.SignerAccess{},
	); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

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

	templateRepo, err := storage.NewGormTemplateRepository(db)
	if err != nil {
		return fmt.Errorf("failed to create template repository: %w", err)
	}

	budgetRepo, err := storage.NewGormBudgetRepository(db)
	if err != nil {
		return fmt.Errorf("failed to create budget repository: %w", err)
	}

	signerOwnershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	if err != nil {
		return fmt.Errorf("failed to create signer ownership repository: %w", err)
	}

	signerAccessRepo, err := storage.NewGormSignerAccessRepository(db)
	if err != nil {
		return fmt.Errorf("failed to create signer access repository: %w", err)
	}

	// Initialize API keys from config if available, otherwise create test keys
	if cfg != nil && len(cfg.APIKeys) > 0 {
		apiKeyInit, err := config.NewAPIKeyInitializer(apiKeyRepo, log)
		if err != nil {
			return fmt.Errorf("failed to create API key initializer: %w", err)
		}
		if err := apiKeyInit.SyncFromConfig(context.Background(), cfg.APIKeys); err != nil {
			return fmt.Errorf("failed to sync API keys from config: %w", err)
		}
		log.Info("API keys loaded from config.e2e.yaml")
	} else {
		// Create test API key (fallback to programmatic creation)
		if err := ts.createAPIKey(apiKeyRepo); err != nil {
			return fmt.Errorf("failed to create API key: %w", err)
		}
	}

	// Initialize rules from config if available, otherwise create test rules
	if cfg != nil && len(cfg.Rules) > 0 {
		ruleInit, err := config.NewRuleInitializer(ruleRepo, log)
		if err != nil {
			return fmt.Errorf("failed to create rule initializer: %w", err)
		}
		configDir := ""
		if ts.config.ConfigPath != "" {
			configDir = filepath.Dir(ts.config.ConfigPath)
			ruleInit.SetConfigDir(configDir)
		}
		ruleInit.SetTemplateRepo(templateRepo)
		ruleInit.SetBudgetRepo(budgetRepo)

		// Match main.go: sync templates (if any), expand instance rules, then sync rules
		rulesToSync := cfg.Rules
		if len(cfg.Templates) > 0 {
			templateInit, err := config.NewTemplateInitializer(templateRepo, log)
			if err != nil {
				return fmt.Errorf("failed to create template initializer: %w", err)
			}
			if configDir != "" {
				templateInit.SetConfigDir(configDir)
			}
			if err := templateInit.SyncFromConfig(context.Background(), cfg.Templates); err != nil {
				return fmt.Errorf("failed to sync templates from config: %w", err)
			}
			loadedTemplates, err := templateInit.GetLoadedTemplates(cfg.Templates)
			if err != nil {
				return fmt.Errorf("failed to get loaded templates: %w", err)
			}
			rulesToSync, err = config.ExpandInstanceRules(cfg.Rules, loadedTemplates)
			if err != nil {
				return fmt.Errorf("failed to expand instance rules: %w", err)
			}
			log.Info("Templates loaded and instance rules expanded from config.e2e.yaml")
		}
		if err := ruleInit.SyncFromConfig(context.Background(), rulesToSync); err != nil {
			return fmt.Errorf("failed to sync rules from config: %w", err)
		}
		log.Info("Rules loaded from config.e2e.yaml")
	} else {
		// Create whitelist rule to auto-approve all sign requests for testing
		if err := ts.createWhitelistRule(ruleRepo); err != nil {
			return fmt.Errorf("failed to create whitelist rule: %w", err)
		}

		// Create blocklist rule to block burn address (for testing blocklist functionality)
		// Prefer Solidity (requires forge); fallback to evm_js so e2e passes without forge
		if err := ts.createBlocklistRule(ruleRepo); err != nil {
			if jsErr := ts.createJSBlocklistRule(ruleRepo); jsErr != nil {
				log.Warn("Blocklist rule creation skipped (Solidity and JS fallback failed)", "solidity_error", err, "js_error", jsErr)
			} else {
				log.Info("Using evm_js blocklist rule (Solidity blocklist unavailable)")
			}
		}

		// Create sign type restriction rule to allow specific sign types
		if err := ts.createSignTypeRestrictionRule(ruleRepo); err != nil {
			return fmt.Errorf("failed to create sign type restriction rule: %w", err)
		}
	}

	// Initialize chain registry
	chainRegistry := chain.NewRegistry()

	// Initialize EVM adapter - use config if available, otherwise use test signer
	var evmSignerConfig evm.SignerConfig
	if cfg != nil && cfg.Chains.EVM != nil && cfg.Chains.EVM.Enabled {
		evmSignerConfig = cfg.Chains.EVM.Signers
		// Override signer key env vars for e2e (E2E_TEST_SIGNER_KEY set in Start; E2E_TEST_SIGNER2_KEY in TestMain)
		for i := range evmSignerConfig.PrivateKeys {
			if evmSignerConfig.PrivateKeys[i].Address == ts.config.SignerAddress {
				evmSignerConfig.PrivateKeys[i].KeyEnvVar = "E2E_TEST_SIGNER_KEY"
			}
			// Second signer uses E2E_TEST_SIGNER2_KEY (set in TestMain before Start)
		}
	} else {
		// Fallback to test signer configuration
		evmSignerConfig = evm.SignerConfig{
			PrivateKeys: []evm.PrivateKeyConfig{
				{
					Address:   ts.config.SignerAddress,
					KeyEnvVar: "E2E_TEST_SIGNER_KEY",
					Enabled:   true,
				},
			},
		}
	}

	// Provider-based signer initialization (matches main.go)
	evmRegistry := evm.NewEmptySignerRegistry()

	pwProvider, err := evm.NewCompositePasswordProvider(false)
	if err != nil {
		return fmt.Errorf("failed to create password provider: %w", err)
	}

	// Load private keys
	pkProvider, err := evm.NewPrivateKeyProvider(evmRegistry, evmSignerConfig.PrivateKeys)
	if err != nil {
		return fmt.Errorf("failed to create private key provider: %w", err)
	}
	evmRegistry.RegisterProvider(pkProvider)

	// Load keystores — use a fresh temp dir to avoid stale files from previous runs
	keystoreDir, cleanupKsErr := os.MkdirTemp("", "e2e-keystores-*")
	if cleanupKsErr != nil {
		return fmt.Errorf("failed to create temp keystore dir: %w", cleanupKsErr)
	}
	ksProvider, err := evm.NewKeystoreProvider(evmRegistry, evmSignerConfig.Keystores, keystoreDir, pwProvider)
	if err != nil {
		return fmt.Errorf("failed to create keystore provider: %w", err)
	}
	evmRegistry.RegisterProvider(ksProvider)

	// Load HD wallets
	hdWalletDir, cleanupErr := os.MkdirTemp("", "e2e-hd-wallets-*")
	if cleanupErr != nil {
		return fmt.Errorf("failed to create temp HD wallet dir: %w", cleanupErr)
	}
	hdProvider, err := evm.NewHDWalletProvider(evmRegistry, evmSignerConfig.HDWallets, hdWalletDir, pwProvider)
	if err != nil {
		return fmt.Errorf("failed to create HD wallet provider: %w", err)
	}
	evmRegistry.RegisterProvider(hdProvider)

	evmAdapter, err := evm.NewEVMAdapter(evmRegistry)
	if err != nil {
		return fmt.Errorf("failed to create EVM adapter: %w", err)
	}

	if err := chainRegistry.Register(evmAdapter); err != nil {
		return fmt.Errorf("failed to register EVM adapter: %w", err)
	}

	// Initialize state machine
	stateMachine, err := statemachine.NewStateMachine(requestRepo, auditRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create state machine: %w", err)
	}

	// Initialize rule engine with whitelist, budget checker (for template instances), and delegation converter for evm_js
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

	// Wire RPC provider for JS sandbox and budget decimals auto-query (if configured)
	if cfg != nil && cfg.Chains.EVM != nil && cfg.Chains.EVM.RPCGateway.BaseURL != "" {
		rpcProvider, err := evm.NewRPCProvider(cfg.Chains.EVM.RPCGateway.BaseURL, cfg.Chains.EVM.RPCGateway.APIKey)
		if err != nil {
			log.Warn("Failed to create RPC provider, decimals auto-query disabled", "error", err)
		} else {
			cacheTTL := cfg.Chains.EVM.RPCGateway.CacheTTL
			if cacheTTL <= 0 {
				cacheTTL = 24 * time.Hour
			}
			metadataCache, err := evm.NewTokenMetadataCache(db, rpcProvider, cacheTTL)
			if err != nil {
				log.Warn("Failed to create token metadata cache", "error", err)
			} else {
				jsEval.SetRPCProvider(rpcProvider, metadataCache)
				decimalsQuerier, err := evm.NewDecimalsQuerierAdapter(metadataCache)
				if err != nil {
					log.Warn("Failed to create decimals querier adapter", "error", err)
				} else {
					budgetChecker.SetDecimalsQuerier(decimalsQuerier)
					log.Info("RPC provider configured for JS sandbox and budget decimals auto-query")
				}
			}
		}
	}

	// Register Solidity expression evaluator for blocklist rules (optional - requires forge)
	// Use config if available, otherwise use defaults
	var solidityEvalConfig evm.SolidityEvaluatorConfig
	if cfg != nil && cfg.Chains.EVM != nil && cfg.Chains.EVM.Foundry.Enabled {
		solidityEvalConfig = evm.SolidityEvaluatorConfig{
			ForgePath: cfg.Chains.EVM.Foundry.ForgePath,
			CacheDir:  cfg.Chains.EVM.Foundry.CacheDir,
			TempDir:   cfg.Chains.EVM.Foundry.TempDir,
			Timeout:   cfg.Chains.EVM.Foundry.Timeout,
		}
	} else {
		solidityEvalConfig = evm.SolidityEvaluatorConfig{
			Timeout: 30 * time.Second,
		}
	}

	solidityEvaluator, err := evm.NewSolidityRuleEvaluator(solidityEvalConfig, log)
	if err != nil {
		// Solidity evaluator is optional - forge may not be installed
		log.Warn("Solidity evaluator not available (forge not installed?), skipping", "error", err)
	} else {
		ruleEngine.RegisterEvaluator(solidityEvaluator)
	}

	// Store rule engine for dynamic evaluator registration in e2e tests.
	ts.ruleEngine = ruleEngine

	// Initialize template service
	templateService, err := service.NewTemplateService(templateRepo, ruleRepo, budgetRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create template service: %w", err)
	}

	// Initialize noop notifier for tests
	notifier, err := service.NewNoopNotifier()
	if err != nil {
		return fmt.Errorf("failed to create notifier: %w", err)
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

	var approvalGuard *service.ManualApprovalGuard
	if cfg != nil && cfg.Security.ApprovalGuard.Enabled {
		approvalGuard, err = service.NewManualApprovalGuard(service.ManualApprovalGuardConfig{
			Window:                cfg.Security.ApprovalGuard.Window,
			RejectionThresholdPct: cfg.Security.ApprovalGuard.RejectionThresholdPct,
			MinSamples:            cfg.Security.ApprovalGuard.MinSamples,
			ResumeAfter:           cfg.Security.ApprovalGuard.ResumeAfter,
			NotifySvc:             nil,
			Channel:               nil,
			Logger:                log,
		})
		if err != nil {
			return fmt.Errorf("failed to create approval guard: %w", err)
		}
		signService.SetApprovalGuard(approvalGuard)
	}
	if cfg != nil {
		signService.SetManualApprovalEnabled(cfg.Security.ManualApprovalEnabled)
	}

	// Initialize auth verifier with nonce store for replay protection
	maxRequestAge := 5 * time.Minute
	if cfg != nil && cfg.Security.MaxRequestAge > 0 {
		maxRequestAge = cfg.Security.MaxRequestAge
	}
	nonceRequired := true
	if cfg != nil && cfg.Security.NonceRequired != nil {
		nonceRequired = *cfg.Security.NonceRequired
	}
	nonceStore, err := storage.NewInMemoryNonceStore(time.Minute)
	if err != nil {
		return fmt.Errorf("failed to create nonce store: %w", err)
	}
	authVerifier, err := auth.NewVerifierWithNonceStore(apiKeyRepo, nonceStore, auth.Config{
		MaxRequestAge: maxRequestAge,
		NonceRequired: nonceRequired,
	})
	if err != nil {
		return fmt.Errorf("failed to create auth verifier: %w", err)
	}

	// Initialize signer manager for dynamic signer creation
	signerManager, err := evm.NewSignerManager(evmRegistry)
	if err != nil {
		return fmt.Errorf("failed to create signer manager: %w", err)
	}

	// Discover locked signers from disk (keystores/HD wallets not in config)
	if err := signerManager.DiscoverLockedSigners(context.Background()); err != nil {
		return fmt.Errorf("failed to discover locked signers: %w", err)
	}

	// Sync signer ownership
	if err := config.SyncSignerOwnership(context.Background(), signerManager, signerOwnershipRepo, apiKeyRepo, log); err != nil {
		return fmt.Errorf("failed to sync signer ownership: %w", err)
	}

	// Grant the non-admin (strategy) key access to the primary test signer so that
	// existing e2e tests (e.g. TestAuth_NonAdminCanSubmitSignRequest, TestSigner_NonAdminCanListSigners)
	// continue to work under the new ownership model.
	if ts.config.NonAdminAPIKeyID != "" {
		nonAdminAccess := &types.SignerAccess{
			SignerAddress: ts.config.SignerAddress,
			APIKeyID:      ts.config.NonAdminAPIKeyID,
			GrantedBy:     ts.config.APIKeyID, // granted by admin
		}
		if grantErr := signerAccessRepo.Grant(context.Background(), nonAdminAccess); grantErr != nil {
			log.Warn("Failed to grant non-admin access to test signer (may already exist)", "error", grantErr)
		}
	}

	// Initialize audit logger for rule/API key CRUD audit events
	auditLogger, err := audit.NewAuditLogger(auditRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create audit logger: %w", err)
	}

	// Initialize simulation engine (optional, requires RPC gateway + anvil)
	if cfg != nil && cfg.Chains.EVM != nil && cfg.Chains.EVM.Simulation.Enabled &&
		cfg.Chains.EVM.RPCGateway.BaseURL != "" {
		simCfg := cfg.Chains.EVM.Simulation
		rpcGateway := cfg.Chains.EVM.RPCGateway
		sim, simErr := simulation.NewAnvilForkManager(simulation.AnvilForkManagerConfig{
			AnvilPath:     simCfg.AnvilPath,
			RPCGatewayURL: rpcGateway.BaseURL,
			RPCGatewayKey: rpcGateway.APIKey,
			SyncInterval:  simCfg.SyncInterval,
			Timeout:       simCfg.Timeout,
			MaxChains:     simCfg.MaxChains,
		}, log)
		if simErr != nil {
			log.Warn("Simulation engine not available, skipping", "error", simErr)
		} else {
			ts.simulator = sim
			log.Info("Simulation engine initialized for e2e tests")
		}
	}

	// Initialize router (include BudgetRepo so GET /api/v1/evm/rules/{id}/budgets works for budget e2e tests)
	routerConfig := api.RouterConfig{
		Version: "e2e-test",
		Template: &api.TemplateConfig{
			TemplateRepo:    templateRepo,
			TemplateService: templateService,
		},
		ApprovalGuard:       approvalGuard,
		APIKeyRepo:          apiKeyRepo,
		SignerOwnershipRepo: signerOwnershipRepo,
		SignerAccessRepo:    signerAccessRepo,
		BudgetRepo:          budgetRepo,
		JSEvaluator:         jsEval,
		AuditLogger:         auditLogger,
		Simulator:           ts.simulator,
	}
	if ts.config.PresetsDir != "" {
		routerConfig.PresetsDir = ts.config.PresetsDir
		routerConfig.PresetsDB = db
	}
	router, err := api.NewRouter(authVerifier, signService, signerManager, ruleRepo, auditRepo, log, routerConfig)
	if err != nil {
		return fmt.Errorf("failed to create router: %w", err)
	}

	// Bind to an available port so e2e does not fail when default port is in use
	port := ts.config.Port
	if port <= 0 {
		port = 8548
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		// Port in use or unavailable: try port 0 to get any free port
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("failed to bind listener: %w", err)
		}
		port = listener.Addr().(*net.TCPAddr).Port
		ts.baseURL = fmt.Sprintf("http://localhost:%d", port)
	}
	listener.Close()

	serverConfig := api.ServerConfig{
		Host: "127.0.0.1",
		Port: port,
	}

	server, err := api.NewServer(router, log, serverConfig)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}
	ts.server = server

	// Start server in background
	ctx, cancel := context.WithCancel(context.Background())
	ts.cancelFunc = cancel

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	// Wait for server to be ready
	if err := ts.waitForReady(ctx); err != nil {
		cancel()
		return fmt.Errorf("server failed to start: %w", err)
	}

	// Check if server errored during startup
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			cancel()
			return fmt.Errorf("server error: %w", err)
		}
	default:
		// Server is running
	}

	return nil
}

// Stop gracefully stops the test server
func (ts *TestServer) Stop() {
	if ts.cancelFunc != nil {
		ts.cancelFunc()
	}

	if ts.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ts.server.Shutdown(ctx)
	}

	// Shutdown simulation engine
	if ts.simulator != nil {
		if err := ts.simulator.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close simulation engine: %v\n", err)
		}
	}

	// Cleanup environment
	os.Unsetenv("E2E_TEST_SIGNER_KEY")
	os.Unsetenv("E2E_TEST_SIGNER2_KEY")
}

// HasSimulator returns true if the simulation engine is available.
func (ts *TestServer) HasSimulator() bool {
	return ts.simulator != nil
}

// BaseURL returns the base URL of the test server
func (ts *TestServer) BaseURL() string {
	return ts.baseURL
}

// waitForReady waits for the server to be ready to accept connections
func (ts *TestServer) waitForReady(ctx context.Context) error {
	client := &http.Client{Timeout: 1 * time.Second}
	healthURL := ts.baseURL + "/health"

	for i := 0; i < 50; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		resp, err := client.Get(healthURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}

		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("server did not become ready in time")
}

// createAPIKey creates the test API keys in the database (admin and non-admin)
func (ts *TestServer) createAPIKey(repo storage.APIKeyRepository) error {
	ctx := context.Background()

	// Create admin API key
	adminKey := &types.APIKey{
		ID:           ts.config.APIKeyID,
		Name:         "E2E Test Admin API Key",
		PublicKeyHex: hex.EncodeToString(ts.config.APIKeyPublicKey),
		RateLimit:    10000, // high limit for e2e test suite
		Role:         types.RoleAdmin,
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := repo.Create(ctx, adminKey); err != nil {
		return fmt.Errorf("failed to create admin API key: %w", err)
	}

	// Create non-admin API key if configured
	if ts.config.NonAdminAPIKeyID != "" && ts.config.NonAdminAPIKeyPublicKey != nil {
		nonAdminKey := &types.APIKey{
			ID:           ts.config.NonAdminAPIKeyID,
			Name:         "E2E Test Non-Admin API Key",
			PublicKeyHex: hex.EncodeToString(ts.config.NonAdminAPIKeyPublicKey),
			RateLimit:    1000,
			Role:         types.RoleStrategy, // strategy: can sign but cannot create/list rules or templates
			Enabled:      true,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		if err := repo.Create(ctx, nonAdminKey); err != nil {
			return fmt.Errorf("failed to create non-admin API key: %w", err)
		}
	}

	return nil
}

// createWhitelistRule creates a rule that auto-approves all sign requests
func (ts *TestServer) createWhitelistRule(repo storage.RuleRepository) error {
	ctx := context.Background()

	// Create a signer restriction rule that allows the test signer
	// This rule will match for all sign types (personal, hash, transaction, etc.)
	chainType := types.ChainTypeEVM
	config := fmt.Sprintf(`{"allowed_signers":["%s"]}`, ts.config.SignerAddress)
	rule := &types.Rule{
		ID:          "e2e-test-rule",
		Name:        "E2E Test Auto-Approve",
		Description: "Auto-approve all requests for e2e testing from test signer",
		Type:        types.RuleTypeSignerRestriction,
		Mode:        types.RuleModeWhitelist,
		Source:      types.RuleSourceConfig,
		ChainType:   &chainType,
		Config:      []byte(config),
		Enabled:     true,
		Owner:       "config",
		AppliedTo:   pq.StringArray{"*"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	return repo.Create(ctx, rule)
}

// createBlocklistRule creates a blocklist rule to block burn address (Solidity; requires forge).
func (ts *TestServer) createBlocklistRule(repo storage.RuleRepository) error {
	ctx := context.Background()

	// Create a Solidity expression blocklist rule that blocks the burn address
	// This matches the "Block known malicious addresses" rule in config.example.yaml
	chainType := types.ChainTypeEVM
	config := `{
		"expression": "require(to != 0x000000000000000000000000000000000000dEaD, \"blocked: burn address\");",
		"description": "Block transfers to burn address for e2e testing"
	}`
	rule := &types.Rule{
		ID:          "e2e-blocklist-rule",
		Name:        "E2E Test Block Burn Address",
		Description: "Block transfers to burn address (0xdEaD) for e2e testing",
		Type:        types.RuleTypeEVMSolidityExpression,
		Mode:        types.RuleModeBlocklist,
		Source:      types.RuleSourceConfig,
		ChainType:   &chainType,
		Config:      []byte(config),
		Enabled:     true,
		Owner:       "config",
		AppliedTo:   pq.StringArray{"*"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	return repo.Create(ctx, rule)
}

// createJSBlocklistRule creates an evm_js blocklist rule that blocks the burn address.
// No forge dependency; used as fallback when Solidity blocklist creation fails.
func (ts *TestServer) createJSBlocklistRule(repo storage.RuleRepository) error {
	ctx := context.Background()

	script := `function validate(input) {
	  if (input.transaction && input.transaction.to) {
	    var to = input.transaction.to;
	    if (to && (to.toLowerCase() === "0x000000000000000000000000000000000000dead" || to === "0x000000000000000000000000000000000000dEaD"))
	      return fail("blocked: burn address");
	  }
	  return ok();
	}`
	chainType := types.ChainTypeEVM
	config := fmt.Sprintf(`{"script": %q}`, script)
	rule := &types.Rule{
		ID:          "e2e-js-blocklist-rule",
		Name:        "E2E Test JS Block Burn Address",
		Description: "Block transfers to burn address (evm_js) for e2e testing",
		Type:        types.RuleTypeEVMJS,
		Mode:        types.RuleModeBlocklist,
		Source:      types.RuleSourceConfig,
		ChainType:   &chainType,
		Config:      []byte(config),
		Enabled:     true,
		Owner:       "config",
		AppliedTo:   pq.StringArray{"*"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	return repo.Create(ctx, rule)
}

// createSignTypeRestrictionRule creates a rule to allow specific sign types
func (ts *TestServer) createSignTypeRestrictionRule(repo storage.RuleRepository) error {
	ctx := context.Background()

	// Create a sign type restriction rule that allows common sign types
	chainType := types.ChainTypeEVM
	config := `{"allowed_sign_types":["personal","typed_data","transaction","hash","raw_message","eip191"]}`
	rule := &types.Rule{
		ID:          "e2e-sign-type-rule",
		Name:        "E2E Test Sign Type Restriction",
		Description: "Allow all sign types for e2e testing",
		Type:        types.RuleTypeSignTypeRestriction,
		Mode:        types.RuleModeWhitelist,
		Source:      types.RuleSourceConfig,
		ChainType:   &chainType,
		Config:      []byte(config),
		Enabled:     true,
		Owner:       "config",
		AppliedTo:   pq.StringArray{"*"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	return repo.Create(ctx, rule)
}

// RegisterDynamicBlocklistEvaluator registers a dynamic blocklist evaluator with the rule engine.
// Used by e2e tests to inject a mock blocklist at runtime.
func (ts *TestServer) RegisterDynamicBlocklistEvaluator(eval *blocklist.Evaluator) {
	if ts.ruleEngine != nil {
		ts.ruleEngine.RegisterEvaluator(eval)
	}
}
