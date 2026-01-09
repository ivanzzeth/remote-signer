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
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/api"
	"github.com/ivanzzeth/remote-signer/internal/chain"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
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
	SignerPrivateKey string          // Hex-encoded private key without 0x prefix
	SignerAddress    string          // Expected signer address
	APIKeyID         string          // API key ID for authentication
	APIKeyPublicKey  ed25519.PublicKey // Ed25519 public key for API auth
}

// TestServer manages a test instance of the remote-signer service
type TestServer struct {
	config     TestServerConfig
	server     *api.Server
	db         *gorm.DB
	cancelFunc context.CancelFunc
	baseURL    string
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

	// Initialize in-memory SQLite database with shared cache and WAL mode
	// Using file::memory:?cache=shared ensures all connections share the same database
	// _journal_mode=WAL and _busy_timeout improve concurrent access handling
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared&_journal_mode=WAL&_busy_timeout=5000"), &gorm.Config{
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

	// Create test API key
	if err := ts.createAPIKey(apiKeyRepo); err != nil {
		return fmt.Errorf("failed to create API key: %w", err)
	}

	// Create whitelist rule to auto-approve all sign requests for testing
	if err := ts.createWhitelistRule(ruleRepo); err != nil {
		return fmt.Errorf("failed to create whitelist rule: %w", err)
	}

	// Initialize chain registry
	chainRegistry := chain.NewRegistry()

	// Initialize EVM adapter with test signer
	signerCfg := evm.SignerConfig{
		PrivateKeys: []evm.PrivateKeyConfig{
			{
				Address:   ts.config.SignerAddress,
				KeyEnvVar: "E2E_TEST_SIGNER_KEY",
				Enabled:   true,
			},
		},
	}

	evmRegistry, err := evm.NewSignerRegistry(signerCfg)
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

	// Initialize auth verifier
	authVerifier, err := auth.NewVerifier(apiKeyRepo, auth.Config{
		MaxRequestAge: 5 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("failed to create auth verifier: %w", err)
	}

	// Initialize router
	router, err := api.NewRouter(authVerifier, signService, log, api.RouterConfig{
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

// createAPIKey creates the test API key in the database
func (ts *TestServer) createAPIKey(repo storage.APIKeyRepository) error {
	ctx := context.Background()

	apiKey := &types.APIKey{
		ID:           ts.config.APIKeyID,
		Name:         "E2E Test API Key",
		PublicKeyHex: hex.EncodeToString(ts.config.APIKeyPublicKey),
		RateLimit:    1000,
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	return repo.Create(ctx, apiKey)
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
