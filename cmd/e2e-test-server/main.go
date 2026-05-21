//go:build e2e

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// ServerInfo is printed to stdout as JSON so the Playwright harness can parse it.
type ServerInfo struct {
	BaseURL           string `json:"base_url"`
	AdminAPIKeyID     string `json:"admin_api_key_id"`
	AdminAPIKeyHex    string `json:"admin_api_key_hex"`
	NonAdminAPIKeyID  string `json:"non_admin_api_key_id"`
	NonAdminAPIKeyHex string `json:"non_admin_api_key_hex"`
	SignerAddress     string `json:"signer_address"`
	// Second pre-unlocked signer for multi-account routing tests.
	// Specs that only need one signer keep using signer_address.
	SignerAddress2 string `json:"signer_address_2"`
}

const (
	// Anvil / Hardhat well-known account #0.
	testSignerPrivateKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	testSignerAddress    = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	// Anvil account #3 — the *second* unlocked signer in the fixture.
	// Lets multi-account-routing tests prove the EIP1193 provider
	// routes by request address rather than by the popup's "active"
	// signer index. Picked #3 specifically because TEST_ACCOUNTS in
	// helpers.ts already claims anvil #0 (signer), #1 (recipient),
	// and #2 (treasury) — using one of those here would turn a
	// "definitely-not-a-signer" recipient into a valid signer and
	// break specs that rely on the rejection path.
	testSignerPrivateKey2 = "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"
	testSignerAddress2    = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// Generate Ed25519 API keys (admin + non-admin).
	adminPubKey, adminPrivKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		fatal("generate admin key: %v", err)
	}
	adminAPIKeyID := "test-admin-key-e2e"
	adminAPIKeyHex := hex.EncodeToString(adminPrivKey)

	nonAdminPubKey, nonAdminPrivKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		fatal("generate non-admin key: %v", err)
	}
	nonAdminAPIKeyID := "test-nonadmin-key-e2e"
	nonAdminAPIKeyHex := hex.EncodeToString(nonAdminPrivKey)

	// Set env vars for sign keys.
	os.Setenv("E2E_TEST_SIGNER_KEY", testSignerPrivateKey)
	os.Setenv("E2E_TEST_SIGNER_KEY_2", testSignerPrivateKey2)

	// Create in-memory SQLite DB.
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared&_journal_mode=WAL&_busy_timeout=5000"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		fatal("open db: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	if err := db.AutoMigrate(
		&types.SignRequest{},
		&types.Transaction{},
		&types.RequestSimulation{},
		&types.Rule{},
		&types.APIKey{},
		&types.AuditRecord{},
		&types.RuleTemplate{},
		&types.RulePreset{},
		&types.RuleBudget{},
		&types.TokenMetadata{},
		&types.SignerOwnership{},
		&types.SignerAccess{},
		&types.Wallet{},
		&types.WalletMember{},
	); err != nil {
		fatal("migrate: %v", err)
	}

	// Repositories.
	requestRepo, _ := storage.NewGormRequestRepository(db)
	ruleRepo, _ := storage.NewGormRuleRepository(db)
	apiKeyRepo, _ := storage.NewGormAPIKeyRepository(db)
	auditRepo, _ := storage.NewGormAuditRepository(db)
	templateRepo, _ := storage.NewGormTemplateRepository(db)
	budgetRepo, _ := storage.NewGormBudgetRepository(db)
	signerRepo, _ := storage.NewGormSignerRepository(db)
	signerOwnershipRepo, _ := storage.NewGormSignerOwnershipRepository(db)
	signerAccessRepo, _ := storage.NewGormSignerAccessRepository(db)
	walletRepo, _ := storage.NewGormWalletRepository(db)

	// Seed API keys.
	ctx := context.Background()
	apiKeyRepo.Create(ctx, &types.APIKey{
		ID:           adminAPIKeyID,
		Name:         "E2E Test Admin API Key",
		PublicKeyHex: hex.EncodeToString(adminPubKey),
		RateLimit:    10000,
		Role:         types.RoleAdmin,
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})
	apiKeyRepo.Create(ctx, &types.APIKey{
		ID:           nonAdminAPIKeyID,
		Name:         "E2E Test Non-Admin API Key",
		PublicKeyHex: hex.EncodeToString(nonAdminPubKey),
		RateLimit:    1000,
		Role:         types.RoleStrategy,
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})

	// Chain registry.
	chainRegistry := chain.NewRegistry()
	evmRegistry := evm.NewEmptySignerRegistry()
	pwProvider, _ := evm.NewCompositePasswordProvider(false)
	pkProvider, _ := evm.NewPrivateKeyProvider(evmRegistry, []evm.PrivateKeyConfig{
		{Address: testSignerAddress, KeyEnvVar: "E2E_TEST_SIGNER_KEY", Enabled: true},
		{Address: testSignerAddress2, KeyEnvVar: "E2E_TEST_SIGNER_KEY_2", Enabled: true},
	})
	evmRegistry.RegisterProvider(pkProvider)

	keystoreDir, _ := os.MkdirTemp("", "e2e-keystores-*")
	ksProvider, _ := evm.NewKeystoreProvider(evmRegistry, nil, keystoreDir, pwProvider)
	evmRegistry.RegisterProvider(ksProvider)

	hdWalletDir, _ := os.MkdirTemp("", "e2e-hd-wallets-*")
	hdProvider, _ := evm.NewHDWalletProvider(evmRegistry, nil, hdWalletDir, pwProvider)
	evmRegistry.RegisterProvider(hdProvider)

	evmAdapter, _ := evm.NewEVMAdapter(evmRegistry)
	chainRegistry.Register(evmAdapter)

	// State machine.
	stateMachine, _ := statemachine.NewStateMachine(requestRepo, auditRepo, log)

	// Rule engine.
	budgetChecker := rule.NewBudgetChecker(budgetRepo, templateRepo, log)
	ruleEngine, _ := rule.NewWhitelistRuleEngine(ruleRepo, log,
		rule.WithBudgetChecker(budgetChecker),
		rule.WithDelegationPayloadConverter(evm.DelegatePayloadToSignRequest),
	)
	ruleEngine.RegisterEvaluator(&evm.AddressListEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.ContractMethodEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.ValueLimitEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.SignerRestrictionEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.SignTypeRestrictionEvaluator{})
	ruleEngine.RegisterEvaluator(&evm.MessagePatternEvaluator{})
	internalTransferEval, _ := evm.NewInternalTransferEvaluator(signerOwnershipRepo)
	ruleEngine.RegisterEvaluator(internalTransferEval)
	jsEval, _ := evm.NewJSRuleEvaluator(log)
	ruleEngine.RegisterEvaluator(jsEval)
	budgetChecker.SetJSEvaluator(jsEval)

	// Seed a whitelist rule for the test signer.
	chainType := types.ChainTypeEVM
	if ruleCreateErr := ruleRepo.Create(ctx, &types.Rule{
		ID:          "e2e-test-rule",
		Name:        "E2E Test Auto-Approve",
		Description: "Auto-approve all requests for e2e testing",
		Type:        types.RuleTypeSignerRestriction,
		Mode:        types.RuleModeWhitelist,
		Source:      types.RuleSourceConfig,
		ChainType:   &chainType,
		Config:      []byte(`{"allowed_signers":["` + testSignerAddress + `","` + testSignerAddress2 + `"]}`),
		Enabled:     true,
		// AppliedTo must be set explicitly — the rules.applied_to column is
		// NOT NULL and Gorm wasn't auto-defaulting; an unset value made the
		// seed insert silently fail (when the error was swallowed) which in
		// turn caused every signing request to land in "no matching rule".
		AppliedTo: []string{"*"},
		Status:    types.RuleStatusActive,
		Owner:     "config",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}); ruleCreateErr != nil {
		fatal("seed whitelist rule: %v", ruleCreateErr)
	}

	// Auth verifier.
	nonceStore, _ := storage.NewInMemoryNonceStore(time.Minute)
	authVerifier, _ := auth.NewVerifierWithNonceStore(apiKeyRepo, nonceStore, auth.Config{
		MaxRequestAge: 5 * time.Minute,
		NonceRequired: true,
	})

	// Signer manager.
	signerManager, _ := evm.NewSignerManager(evmRegistry)
	signerManager.DiscoverLockedSigners(ctx)
	config.SyncSignerOwnership(ctx, signerManager, signerOwnershipRepo, apiKeyRepo, log)

	// Grant non-admin access to every seeded signer (mirrors the admin's
	// view so popup tests can switch keys without rebooting fixtures).
	signerAccessRepo.Grant(ctx, &types.SignerAccess{
		SignerAddress: testSignerAddress,
		APIKeyID:      nonAdminAPIKeyID,
		GrantedBy:     adminAPIKeyID,
	})
	signerAccessRepo.Grant(ctx, &types.SignerAccess{
		SignerAddress: testSignerAddress2,
		APIKeyID:      nonAdminAPIKeyID,
		GrantedBy:     adminAPIKeyID,
	})

	// Services.
	templateService, _ := service.NewTemplateService(templateRepo, ruleRepo, budgetRepo, log)
	notifier, _ := service.NewNoopNotifier()
	ruleGenerator, _ := rule.NewDefaultRuleGenerator()
	approvalService, _ := service.NewApprovalService(ruleRepo, ruleGenerator, notifier, log)
	signService, _ := service.NewSignService(chainRegistry, requestRepo, ruleEngine, stateMachine, approvalService, log)
	// Mirror prod's default and let unmatched requests land in the
	// manual-approval queue (instead of failing immediately). Required for
	// the pending-approval-window e2e to exercise the queue path.
	signService.SetManualApprovalEnabled(true)

	// Optional RPC proxy backend pointing at the test fixture's anvil
	// instance. Anvil serves at root (no chain-prefixed path); the
	// daemon's RPCProvider expects baseURL/{chainID}, so we stand up
	// a tiny path-stripping reverse proxy and point RPCProvider at it.
	// Without this the wallet RPC proxy route doesn't register and
	// eth_sendTransaction broadcast specs fail with 404.
	var rpcProvider *evm.RPCProvider
	anvilURL := strings.TrimSpace(os.Getenv("E2E_ANVIL_URL"))
	if anvilURL != "" {
		stripPrefix := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Forward body to anvil at /, dropping the /{chainID} prefix.
			body, _ := io.ReadAll(r.Body)
			req, perr := http.NewRequestWithContext(r.Context(), r.Method, anvilURL, strings.NewReader(string(body)))
			if perr != nil {
				http.Error(w, perr.Error(), http.StatusBadGateway)
				return
			}
			req.Header = r.Header.Clone()
			resp, ferr := http.DefaultClient.Do(req)
			if ferr != nil {
				http.Error(w, ferr.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			for k, vs := range resp.Header {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
		}))
		var prErr error
		rpcProvider, prErr = evm.NewRPCProvider(stripPrefix.URL, "")
		if prErr != nil {
			fatal("init e2e rpc provider: %v", prErr)
		}
	}

	// Transaction tracking — wired if rpcProvider is too, so the e2e
	// specs that drive eth_sendTransaction exercise the same path the
	// production daemon does (proxy → record broadcast → poller +
	// read API).
	var txService *service.TransactionService
	var txRepo *storage.GormTransactionRepository
	if rpcProvider != nil {
		var txErr error
		txRepo, txErr = storage.NewGormTransactionRepository(db)
		if txErr != nil {
			fatal("init e2e transaction repo: %v", txErr)
		}
		txService, err = service.NewTransactionService(txRepo, requestRepo, rpcProvider, log)
		if err != nil {
			fatal("init e2e transaction service: %v", err)
		}
		// Faster grace period for the dropped-tx detector — keeps
		// dropped-path specs short. Pollers in the real daemon use
		// the 10-minute default; tests don't have minutes to spare.
		txService.WithGracePeriod(30 * time.Second)
		// Launch the receipt poller on a tight 250ms tick so anvil's
		// instant-mining mode flips rows to mined fast enough for
		// the e2e to assert in single-digit seconds.
		go txService.Run(ctx, 250*time.Millisecond)
	}

	// Router.
	router, err := api.NewRouter(authVerifier, signService, signerManager, ruleRepo, auditRepo, log, api.RouterConfig{
		Version:             "e2e-test",
		APIKeyRepo:          apiKeyRepo,
		SignerRepo:          signerRepo,
		SignerOwnershipRepo: signerOwnershipRepo,
		SignerAccessRepo:    signerAccessRepo,
		BudgetRepo:          budgetRepo,
		JSEvaluator:         jsEval,
		WalletRepo:          walletRepo,
		RPCProvider:         rpcProvider,
		TransactionService:  txService,
		TransactionRepo:     txRepo,
		Template: &api.TemplateConfig{
			TemplateRepo:    templateRepo,
			TemplateService: templateService,
		},
	})
	if err != nil {
		fatal("router: %v", err)
	}

	// Find a free port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatal("listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	baseURL := fmt.Sprintf("http://localhost:%d", port)

	server, err := api.NewServer(router, log, api.ServerConfig{Host: "127.0.0.1", Port: port})
	if err != nil {
		fatal("server: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	// Wait for readiness.
	client := &http.Client{Timeout: 1 * time.Second}
	ready := false
	for i := 0; i < 50; i++ {
		resp, err := client.Get(baseURL + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		server.Shutdown(context.Background())
		fatal("server did not become ready")
	}

	info := ServerInfo{
		BaseURL:           baseURL,
		AdminAPIKeyID:     adminAPIKeyID,
		AdminAPIKeyHex:    adminAPIKeyHex,
		NonAdminAPIKeyID:  nonAdminAPIKeyID,
		NonAdminAPIKeyHex: nonAdminAPIKeyHex,
		SignerAddress:     testSignerAddress,
		SignerAddress2:    testSignerAddress2,
	}
	out, _ := json.Marshal(info)
	fmt.Println(string(out))

	log.Info("e2e-test-server ready", "url", baseURL)

	// Wait for signal.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
}

func fatal(format string, args ...interface{}) {
	err := fmt.Sprintf(format, args...)
	out, _ := json.Marshal(map[string]string{"error": err})
	fmt.Fprintln(os.Stderr, string(out))
	os.Exit(1)
}
