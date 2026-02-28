//go:build e2e

package e2e

import (
	"fmt"
	"log/slog"
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

// newTestLogger creates a test-appropriate logger
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	}))
}

// initTestDB creates an isolated in-memory SQLite database for testing.
// Each call creates a unique database to prevent UNIQUE constraint conflicts
// when multiple TLS tests run sequentially.
func initTestDB() (*gorm.DB, error) {
	// Use a unique file name per invocation to avoid sharing state across tests.
	// The :memory: mode with cache=shared would reuse the same database for all
	// connections in the process, causing UNIQUE constraint violations on rules.
	dbDSN := fmt.Sprintf("file:tlstest_%d?mode=memory&_journal_mode=WAL&_busy_timeout=5000", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dbDSN), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	// Auto-migrate tables
	if err := db.AutoMigrate(
		&types.SignRequest{},
		&types.Rule{},
		&types.APIKey{},
		&types.AuditRecord{},
	); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return db, nil
}

// initTestRepositories creates all required repositories
func initTestRepositories(db *gorm.DB) (
	storage.RequestRepository,
	storage.RuleRepository,
	storage.APIKeyRepository,
	storage.AuditRepository,
	error,
) {
	requestRepo, err := storage.NewGormRequestRepository(db)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create request repository: %w", err)
	}

	ruleRepo, err := storage.NewGormRuleRepository(db)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create rule repository: %w", err)
	}

	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create apikey repository: %w", err)
	}

	auditRepo, err := storage.NewGormAuditRepository(db)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create audit repository: %w", err)
	}

	return requestRepo, ruleRepo, apiKeyRepo, auditRepo, nil
}

// initTestServices creates all services and returns an api.Server configured with optional TLS
func initTestServices(
	ts *TestServer,
	requestRepo storage.RequestRepository,
	ruleRepo storage.RuleRepository,
	apiKeyRepo storage.APIKeyRepository,
	auditRepo storage.AuditRepository,
	log *slog.Logger,
	tlsCertFile, tlsKeyFile, tlsCAFile string,
	tlsClientAuth bool,
) (*api.Server, error) {
	// Initialize chain registry
	chainRegistry := chain.NewRegistry()

	evmSignerConfig := evm.SignerConfig{
		PrivateKeys: []evm.PrivateKeyConfig{
			{
				Address:   ts.config.SignerAddress,
				KeyEnvVar: "E2E_TEST_SIGNER_KEY",
				Enabled:   true,
			},
		},
	}

	evmRegistry, err := evm.NewSignerRegistry(evmSignerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create EVM signer registry: %w", err)
	}

	evmAdapter, err := evm.NewEVMAdapter(evmRegistry)
	if err != nil {
		return nil, fmt.Errorf("failed to create EVM adapter: %w", err)
	}

	if err := chainRegistry.Register(evmAdapter); err != nil {
		return nil, fmt.Errorf("failed to register EVM adapter: %w", err)
	}

	// State machine
	stateMachine, err := statemachine.NewStateMachine(requestRepo, auditRepo, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create state machine: %w", err)
	}

	// Rule engine
	ruleEngine, err := rule.NewWhitelistRuleEngine(ruleRepo, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule engine: %w", err)
	}
	ruleEngine.RegisterEvaluator(&evm.AddressListEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.ContractMethodEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.ValueLimitEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.SignerRestrictionEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.SignTypeRestrictionEvaluator{})

	// Notifier (noop for tests)
	notifier, err := service.NewNoopNotifier()
	if err != nil {
		return nil, fmt.Errorf("failed to create notifier: %w", err)
	}

	// Rule generator
	ruleGenerator, err := rule.NewDefaultRuleGenerator()
	if err != nil {
		return nil, fmt.Errorf("failed to create rule generator: %w", err)
	}

	// Approval service
	approvalService, err := service.NewApprovalService(ruleRepo, ruleGenerator, notifier, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create approval service: %w", err)
	}

	// Sign service
	signService, err := service.NewSignService(chainRegistry, requestRepo, ruleEngine, stateMachine, approvalService, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create sign service: %w", err)
	}

	// Auth verifier
	nonceStore, err := storage.NewInMemoryNonceStore(time.Minute)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce store: %w", err)
	}
	authVerifier, err := auth.NewVerifierWithNonceStore(apiKeyRepo, nonceStore, auth.Config{
		MaxRequestAge: 5 * time.Minute,
		NonceRequired: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create auth verifier: %w", err)
	}

	// Signer manager
	signerManager, err := evm.NewSignerManager(evmRegistry, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer manager: %w", err)
	}

	// Router
	router, err := api.NewRouter(authVerifier, signService, signerManager, ruleRepo, auditRepo, log, api.RouterConfig{
		Version: "e2e-tls-test",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create router: %w", err)
	}

	// Server config with TLS
	serverConfig := api.ServerConfig{
		Host:         "127.0.0.1",
		Port:         ts.config.Port,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Inject TLS configuration
	if tlsCertFile != "" && tlsKeyFile != "" {
		serverConfig.TLSEnabled = true
		serverConfig.TLSCertFile = tlsCertFile
		serverConfig.TLSKeyFile = tlsKeyFile
		serverConfig.TLSCAFile = tlsCAFile
		serverConfig.TLSClientAuth = tlsClientAuth
	}

	server, err := api.NewServer(router, log, serverConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create server: %w", err)
	}

	return server, nil
}

