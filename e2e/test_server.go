//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/api"
	"github.com/ivanzzeth/remote-signer/internal/chain"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/core/auth"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/statemachine"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
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
}

// TestServer manages a test instance of the remote-signer service
type TestServer struct {
	config     TestServerConfig
	server     *api.Server
	db         *gorm.DB
	cancelFunc context.CancelFunc
	baseURL    string
	tlsCerts   *tlsCerts // set by StartWithTLS for mTLS health-check
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
	// Set environment variable for signer private key
	os.Setenv("E2E_TEST_SIGNER_KEY", ts.config.SignerPrivateKey)

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

	// Ensure single connection to avoid locking issues with in-memory SQLite
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
		// Set config directory for resolving relative paths in rule files
		if ts.config.ConfigPath != "" {
			ruleInit.SetConfigDir(filepath.Dir(ts.config.ConfigPath))
		}
		if err := ruleInit.SyncFromConfig(context.Background(), cfg.Rules); err != nil {
			return fmt.Errorf("failed to sync rules from config: %w", err)
		}
		log.Info("Rules loaded from config.e2e.yaml")
	} else {
		// Create whitelist rule to auto-approve all sign requests for testing
		if err := ts.createWhitelistRule(ruleRepo); err != nil {
			return fmt.Errorf("failed to create whitelist rule: %w", err)
		}

		// Create blocklist rule to block burn address (for testing blocklist functionality)
		// This requires Solidity evaluator (forge), so skip if not available
		if err := ts.createBlocklistRule(ruleRepo); err != nil {
			// Blocklist rule is optional - requires forge
			log.Warn("Blocklist rule creation skipped (forge may not be installed)", "error", err)
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
		// Override signer key env var to use test signer
		for i := range evmSignerConfig.PrivateKeys {
			if evmSignerConfig.PrivateKeys[i].Address == ts.config.SignerAddress {
				evmSignerConfig.PrivateKeys[i].KeyEnvVar = "E2E_TEST_SIGNER_KEY"
			}
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

	evmRegistry, err := evm.NewSignerRegistry(evmSignerConfig)
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

	// Initialize state machine
	stateMachine, err := statemachine.NewStateMachine(requestRepo, auditRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create state machine: %w", err)
	}

	// Initialize rule engine with whitelist
	ruleEngine, err := rule.NewWhitelistRuleEngine(ruleRepo, log)
	if err != nil {
		return fmt.Errorf("failed to create rule engine: %w", err)
	}

	// Register EVM rule evaluators
	ruleEngine.RegisterEvaluator(&evm.AddressListEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.ContractMethodEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.ValueLimitEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.SignerRestrictionEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.SignTypeRestrictionEvaluator{})

	// Register Solidity expression evaluator for blocklist rules (optional - requires forge)
	// Use config if available, otherwise use defaults
	var solidityEvalConfig evm.SolidityEvaluatorConfig
	if cfg != nil && cfg.Chains.EVM != nil && cfg.Chains.EVM.Foundry.Enabled {
		solidityEvalConfig = evm.SolidityEvaluatorConfig{
			ForgePath: cfg.Chains.EVM.Foundry.ForgePath,
			CacheDir:  cfg.Chains.EVM.Foundry.CacheDir,
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
	// Create temp directory for e2e tests (always use temp dir for isolation)
	tempKeystoreDir, err := os.MkdirTemp("", "e2e-keystores-*")
	if err != nil {
		return fmt.Errorf("failed to create temp keystore directory: %w", err)
	}
	signerManager, err := evm.NewSignerManager(evmRegistry, tempKeystoreDir, log)
	if err != nil {
		return fmt.Errorf("failed to create signer manager: %w", err)
	}

	// Initialize router
	router, err := api.NewRouter(authVerifier, signService, signerManager, ruleRepo, auditRepo, log, api.RouterConfig{
		Version: "e2e-test",
	})
	if err != nil {
		return fmt.Errorf("failed to create router: %w", err)
	}

	// Initialize server
	serverConfig := api.ServerConfig{
		Host: "127.0.0.1",
		Port: ts.config.Port,
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

	// Cleanup environment
	os.Unsetenv("E2E_TEST_SIGNER_KEY")
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
		RateLimit:    1000,
		Admin:        true, // Admin key
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
			Admin:        false, // Non-admin key
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
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	return repo.Create(ctx, rule)
}

// createBlocklistRule creates a blocklist rule to block burn address
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
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	return repo.Create(ctx, rule)
}
