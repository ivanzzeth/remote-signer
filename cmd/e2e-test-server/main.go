// e2e-test-server launches a standalone test server for the extension E2E tests.
// It starts a remote-signer instance (backed by in-memory SQLite) with generated
// Ed25519 API keys and outputs the server configuration as JSON to stdout.
//
// The server stays running until SIGTERM or SIGINT.
//
// Usage:
//
//	go build -tags=e2e -o e2e-test-server ./cmd/e2e-test-server
//	E2E_API_PORT=18549 ./e2e-test-server
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/lib/pq"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/api"
	"github.com/ivanzzeth/remote-signer/internal/audit"
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

const (
	testSignerPrivateKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	testSignerAddress    = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
)

func main() {
	port := 18549
	if p := os.Getenv("E2E_API_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}

	ts, err := newTestServer(port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create test server: %v\n", err)
		os.Exit(1)
	}

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	cfg := map[string]string{
		"baseURL":              baseURL,
		"signerAddress":        testSignerAddress,
		"adminAPIKeyID":        "test-admin-key-e2e",
		"adminAPIKeyHex":       hex.EncodeToString(ts.adminPrivKey),
		"nonAdminAPIKeyID":     "test-nonadmin-key-e2e",
		"nonAdminAPIKeyHex":    hex.EncodeToString(ts.nonAdminPrivKey),
	}
	out, _ := json.Marshal(cfg)
	fmt.Println(string(out))

	fmt.Fprintf(os.Stderr, "[e2e-test-server] Ready at %s\n", baseURL)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Fprintf(os.Stderr, "[e2e-test-server] Shutting down...\n")
	ts.Stop()
}

type testServer struct {
	server         *api.Server
	db             *gorm.DB
	cancelFunc     context.CancelFunc
	adminPrivKey   ed25519.PrivateKey
	nonAdminPrivKey ed25519.PrivateKey
}

func newTestServer(port int) (*testServer, error) {
	ts := &testServer{}

	// Generate Ed25519 API keys
	adminPubKey, adminPrivKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generate admin key: %w", err)
	}
	ts.adminPrivKey = adminPrivKey
	adminAPIKeyID := "test-admin-key-e2e"

	nonAdminPubKey, nonAdminPrivKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generate non-admin key: %w", err)
	}
	ts.nonAdminPrivKey = nonAdminPrivKey
	nonAdminAPIKeyID := "test-nonadmin-key-e2e"

	os.Setenv("E2E_TEST_SIGNER_KEY", testSignerPrivateKey)

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	}))

	// Load config.e2e.yaml
	var cfg *config.Config
	configPath := findConfig("config.e2e.yaml")
	if configPath != "" {
		var loadErr error
		cfg, loadErr = config.Load(configPath)
		if loadErr != nil {
			log.Warn("Failed to load config.e2e.yaml, using programmatic setup", "error", loadErr)
			cfg = nil
		} else {
			log.Info("Loaded config.e2e.yaml", "path", configPath)
		}
	}

	// In-memory SQLite
	dbDSN := "file::memory:?cache=shared&_journal_mode=WAL&_busy_timeout=5000"
	db, err := gorm.Open(sqlite.Open(dbDSN), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("create database: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	ts.db = db

	if err := db.AutoMigrate(
		&types.SignRequest{}, &types.Rule{}, &types.APIKey{}, &types.AuditRecord{},
		&types.RuleTemplate{}, &types.RulePreset{}, &types.RuleBudget{},
		&types.TokenMetadata{}, &types.SignerOwnership{}, &types.SignerAccess{},
		&types.Wallet{}, &types.WalletMember{},
	); err != nil {
		return nil, fmt.Errorf("migrate database: %w", err)
	}

	// Repositories
	requestRepo, _ := storage.NewGormRequestRepository(db)
	ruleRepo, _ := storage.NewGormRuleRepository(db)
	apiKeyRepo, _ := storage.NewGormAPIKeyRepository(db)
	auditRepo, _ := storage.NewGormAuditRepository(db)
	templateRepo, _ := storage.NewGormTemplateRepository(db)
	budgetRepo, _ := storage.NewGormBudgetRepository(db)
	signerOwnershipRepo, _ := storage.NewGormSignerOwnershipRepository(db)
	signerRepo, _ := storage.NewGormSignerRepository(db)
	signerAccessRepo, _ := storage.NewGormSignerAccessRepository(db)
	walletRepo, _ := storage.NewGormWalletRepository(db)

	// Create API keys
	if cfg != nil && len(cfg.APIKeys) > 0 {
		apiKeyInit, err := config.NewAPIKeyInitializer(apiKeyRepo, log)
		if err != nil {
			return nil, fmt.Errorf("create API key initializer: %w", err)
		}
		if err := apiKeyInit.SyncFromConfig(context.Background(), cfg.APIKeys); err != nil {
			return nil, fmt.Errorf("sync API keys: %w", err)
		}
	} else {
		createTestAPIKey(apiKeyRepo, adminAPIKeyID, "Admin", hex.EncodeToString(adminPubKey), types.RoleAdmin, 10000)
		createTestAPIKey(apiKeyRepo, nonAdminAPIKeyID, "NonAdmin", hex.EncodeToString(nonAdminPubKey), types.RoleStrategy, 1000)
	}

	// Create whitelist rule
	if cfg != nil && len(cfg.Rules) > 0 {
		ruleInit, _ := config.NewRuleInitializer(ruleRepo, log)
		ruleInit.SetTemplateRepo(templateRepo)
		ruleInit.SetBudgetRepo(budgetRepo)

		rulesToSync := cfg.Rules
		if len(cfg.Templates) > 0 {
			templateInit, _ := config.NewTemplateInitializer(templateRepo, log)
			if dir := filepath.Dir(configPath); dir != "" {
				templateInit.SetConfigDir(dir)
			}
			templateInit.SyncFromConfig(context.Background(), cfg.Templates)
			loaded, _ := templateInit.GetLoadedTemplates(cfg.Templates)
			rulesToSync, _ = config.ExpandInstanceRules(cfg.Rules, loaded)
		}
		ruleInit.SyncFromConfig(context.Background(), rulesToSync)
	} else {
		createWhitelistRule(ruleRepo, testSignerAddress)
		createSignTypeRule(ruleRepo)
	}

	// Chain registry + EVM adapter
	chainRegistry := chain.NewRegistry()
	evmRegistry := evm.NewEmptySignerRegistry()

	pkProvider, _ := evm.NewPrivateKeyProvider(evmRegistry, []evm.PrivateKeyConfig{
		{Address: testSignerAddress, KeyEnvVar: "E2E_TEST_SIGNER_KEY", Enabled: true},
	})
	evmRegistry.RegisterProvider(pkProvider)

	evmAdapter, err := evm.NewEVMAdapter(evmRegistry)
	if err != nil {
		return nil, fmt.Errorf("create EVM adapter: %w", err)
	}
	chainRegistry.Register(evmAdapter)

	// State machine
	stateMachine, err := statemachine.NewStateMachine(requestRepo, auditRepo, log)
	if err != nil {
		return nil, fmt.Errorf("create state machine: %w", err)
	}

	// Rule engine
	budgetChecker := rule.NewBudgetChecker(budgetRepo, templateRepo, log)
	ruleEngine, err := rule.NewWhitelistRuleEngine(ruleRepo, log,
		rule.WithBudgetChecker(budgetChecker),
		rule.WithDelegationPayloadConverter(evm.DelegatePayloadToSignRequest),
	)
	if err != nil {
		return nil, fmt.Errorf("create rule engine: %w", err)
	}

	ruleEngine.RegisterEvaluator(&evm.AddressListEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.ContractMethodEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.ValueLimitEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.SignerRestrictionEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.SignTypeRestrictionEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.MessagePatternEvaluator{})

	jsEval, _ := evm.NewJSRuleEvaluator(log)
	ruleEngine.RegisterEvaluator(jsEval)
	budgetChecker.SetJSEvaluator(jsEval)

	// Services
	templateService, _ := service.NewTemplateService(templateRepo, ruleRepo, budgetRepo, log)
	notifier, _ := service.NewNoopNotifier()
	ruleGenerator, _ := rule.NewDefaultRuleGenerator()

	approvalService, _ := service.NewApprovalService(ruleRepo, ruleGenerator, notifier, log)
	signService, _ := service.NewSignService(chainRegistry, requestRepo, ruleEngine, stateMachine, approvalService, log)
	signerManager, _ := evm.NewSignerManager(evmRegistry)

	// Auth with nonce store
	nonceStore, _ := storage.NewInMemoryNonceStore(time.Minute)
	authVerifier, _ := auth.NewVerifierWithNonceStore(apiKeyRepo, nonceStore, auth.Config{
		MaxRequestAge: 5 * time.Minute,
		NonceRequired: true,
	})

	// Audit logger
	auditLogger, _ := audit.NewAuditLogger(auditRepo, log)

	router, err := api.NewRouter(authVerifier, signService, signerManager, ruleRepo, auditRepo, log, api.RouterConfig{
		Version:             "e2e-test",
		APIKeyRepo:          apiKeyRepo,
		SignerRepo:          signerRepo,
		SignerOwnershipRepo: signerOwnershipRepo,
		SignerAccessRepo:    signerAccessRepo,
		BudgetRepo:          budgetRepo,
		JSEvaluator:         jsEval,
		AuditLogger:         auditLogger,
		WalletRepo:          walletRepo,
		Template: &api.TemplateConfig{
			TemplateRepo:    templateRepo,
			TemplateService: templateService,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create router: %w", err)
	}

	server, err := api.NewServer(router, log, api.ServerConfig{
		Host: "127.0.0.1",
		Port: port,
	})
	if err != nil {
		return nil, fmt.Errorf("create server: %w", err)
	}
	ts.server = server

	ctx, cancel := context.WithCancel(context.Background())
	ts.cancelFunc = cancel

	errCh := make(chan error, 1)
	go func() { errCh <- server.Start() }()

	// Wait for server ready
	if !waitForServer(ctx, port) {
		cancel()
		return nil, fmt.Errorf("server did not become ready")
	}

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			cancel()
			return nil, fmt.Errorf("server error: %w", err)
		}
	default:
	}

	return ts, nil
}

func (ts *testServer) Stop() {
	if ts.cancelFunc != nil {
		ts.cancelFunc()
	}
	if ts.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ts.server.Shutdown(ctx)
	}
	os.Unsetenv("E2E_TEST_SIGNER_KEY")
}

func waitForServer(ctx context.Context, port int) bool {
	url := fmt.Sprintf("http://127.0.0.1:%d/health", port)
	client := &http.Client{Timeout: 1 * time.Second}
	for i := 0; i < 50; i++ {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func findConfig(filename string) string {
	wd, _ := os.Getwd()
	for wd != "/" && wd != "" {
		p := filepath.Join(wd, filename)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		wd = filepath.Dir(wd)
	}
	return ""
}

func createTestAPIKey(repo storage.APIKeyRepository, id, name, pubKeyHex string, role types.APIKeyRole, rateLimit int) {
	ctx := context.Background()
	key := &types.APIKey{
		ID:           id,
		Name:         "E2E " + name,
		PublicKeyHex: pubKeyHex,
		RateLimit:    rateLimit,
		Role:         role,
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	repo.Create(ctx, key)
}

func createWhitelistRule(repo storage.RuleRepository, signerAddress string) {
	ctx := context.Background()
	chainType := types.ChainTypeEVM
	cfg := fmt.Sprintf(`{"allowed_signers":["%s"]}`, signerAddress)
	rule := &types.Rule{
		ID:          "e2e-test-rule",
		Name:        "E2E Auto-Approve",
		Type:        types.RuleTypeSignerRestriction,
		Mode:        types.RuleModeWhitelist,
		Source:      types.RuleSourceConfig,
		ChainType:   &chainType,
		Config:      []byte(cfg),
		Enabled:     true,
		Owner:       "config",
		AppliedTo:   pq.StringArray{"*"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	repo.Create(ctx, rule)
}

func createSignTypeRule(repo storage.RuleRepository) {
	ctx := context.Background()
	chainType := types.ChainTypeEVM
	cfg := `{"allowed_sign_types":["personal","typed_data","transaction","hash","raw_message","eip191"]}`
	rule := &types.Rule{
		ID:          "e2e-sign-type-rule",
		Name:        "E2E Sign Type Restriction",
		Type:        types.RuleTypeSignTypeRestriction,
		Mode:        types.RuleModeWhitelist,
		Source:      types.RuleSourceConfig,
		ChainType:   &chainType,
		Config:      []byte(cfg),
		Enabled:     true,
		Owner:       "config",
		AppliedTo:   pq.StringArray{"*"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	repo.Create(ctx, rule)
}
