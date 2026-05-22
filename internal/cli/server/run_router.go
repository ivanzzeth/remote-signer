// Package server provides the daemon entrypoint for `remote-signer server start`.
// run_router.go contains the router initialization extracted from Run().
package server

import (
	"log/slog"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/api"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/bootstrap"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/core/auth"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/settings"
	"github.com/ivanzzeth/remote-signer/internal/simulation"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/ivanzzeth/remote-signer/internal/version"
)

// RouterAndServer bundles the router and server created in Run().
type RouterAndServer struct {
	Router *api.Router
	Server *api.Server
	// TxService is the on-chain transaction tracker. Exposed so the
	// daemon's main loop can launch its background receipt poller
	// alongside the HTTP server. Nil when transaction tracking
	// wasn't wired (no RPCProvider, repo failure).
	TxService *service.TransactionService
}

// initRouterAndServer builds the RouterConfig, registers presets and registries,
// and creates the API Router and HTTP Server.
func initRouterAndServer(
	cfg *config.Config,
	configPath string,
	db *gorm.DB,
	repos *repoBundle,
	authVerifier *auth.Verifier,
	signService *service.SignService,
	evmSignerManager evm.SignerManager,
	approvalGuard *service.ManualApprovalGuard,
	securityAlertService *middleware.SecurityAlertService,
	auditLogger *audit.AuditLogger,
	settingsMgr *settings.Manager,
	solidityValidator *evm.SolidityRuleValidator,
	jsEval *evm.JSRuleEvaluator,
	ipWhitelist *middleware.IPWhitelist,
	templateService *service.TemplateService,
	simulator simulation.Simulator,
	rpcProvider *evm.RPCProvider,
	bootstrapCreator bootstrap.AdminCreator,
	log *slog.Logger,
) (*RouterAndServer, error) {
	routerConfig := api.RouterConfig{
		Version:                  version.Version,
		IPWhitelistConfig:        ipWhitelist,
		IPWhitelistConfigForRead: &cfg.Security.IPWhitelist,
		IPRateLimit:              cfg.Security.IPRateLimit,
		SolidityValidator:        solidityValidator,
		JSEvaluator:              jsEval,
		Template: &api.TemplateConfig{
			TemplateRepo:    repos.templateRepo,
			TemplateService: templateService,
		},
		ApprovalGuard:                approvalGuard,
		APIKeyRepo:                   repos.apiKeyRepo,
		SignerRepo:                   repos.signerRepo,
		SignerOwnershipRepo:          repos.signerOwnershipRepo,
		SignerAccessRepo:             repos.signerAccessRepo,
		WalletRepo:                   repos.walletRepo,
		BudgetRepo:                   repos.budgetRepo,
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
		RequestRepo:                  repos.requestRepo,
		BootstrapCreator:             bootstrapCreator,
	}
	// Simulation preview: the request-detail UI's preview panel
	// reads this repo. Optional — without it the GET /requests/
	// {id}/simulation route simply doesn't register and the panel
	// shows "evaluating" forever.
	if simRepo, simRepoErr := storage.NewGormRequestSimulationRepository(db); simRepoErr == nil {
		routerConfig.RequestSimulationRepo = simRepo
	} else {
		log.Warn("simulation preview API disabled: repo init failed", "error", simRepoErr)
	}
	// Wire the on-chain transaction tracker if we have an RPC + the
	// repos it needs. Best-effort: a build that omits these still
	// runs, the wallet proxy + sign endpoints just stop populating
	// the transactions table.
	var txService *service.TransactionService
	if rpcProvider != nil {
		if txRepo, txErr := storage.NewGormTransactionRepository(db); txErr == nil {
			routerConfig.TransactionRepo = txRepo
			if txSvc, sErr := service.NewTransactionService(txRepo, repos.requestRepo, rpcProvider, log); sErr == nil {
				routerConfig.TransactionService = txSvc
				txService = txSvc
			} else {
				log.Warn("transaction tracking disabled: service init failed", "error", sErr)
			}
		} else {
			log.Warn("transaction tracking disabled: repo init failed", "error", txErr)
		}
	}
	_ = resolveLegacyPresetsDir(cfg, configPath)
	if presetRepo, err := storage.NewGormPresetRepository(db); err == nil {
		routerConfig.PresetRepo = presetRepo
		routerConfig.PresetsDB = db
	} else {
		log.Warn("preset API disabled: failed to wire preset repo", "error", err)
	}
	if tmplReg, presetReg, err := buildRegistries(db, cfg, configPath, log); err == nil {
		routerConfig.TemplateRegistry = tmplReg
		routerConfig.PresetRegistry = presetReg
	} else {
		log.Warn("registry refresh endpoint disabled: failed to build registries", "error", err)
	}
	router, err := api.NewRouter(authVerifier, signService, evmSignerManager, repos.ruleRepo, repos.auditRepo, log, routerConfig)
	if err != nil {
		return nil, err
	}

	serverConfig := api.DefaultServerConfig()
	serverConfig.Host = cfg.Server.Host
	serverConfig.Port = cfg.Server.Port
	if cfg.Server.ReadTimeout > 0 {
		serverConfig.ReadTimeout = cfg.Server.ReadTimeout
	}
	if cfg.Server.WriteTimeout > 0 {
		serverConfig.WriteTimeout = cfg.Server.WriteTimeout
	}
	if cfg.Server.TLS.Enabled {
		serverConfig.TLSEnabled = true
		serverConfig.TLSCertFile = cfg.Server.TLS.CertFile
		serverConfig.TLSKeyFile = cfg.Server.TLS.KeyFile
		serverConfig.TLSCAFile = cfg.Server.TLS.CAFile
		serverConfig.TLSClientAuth = cfg.Server.TLS.ClientAuth
		log.Info("TLS enabled", "cert_file", cfg.Server.TLS.CertFile, "key_file", cfg.Server.TLS.KeyFile, "mtls", cfg.Server.TLS.ClientAuth)
	}
	server, err := api.NewServer(router, log, serverConfig)
	if err != nil {
		return nil, err
	}
	return &RouterAndServer{Router: router, Server: server, TxService: txService}, nil
}
