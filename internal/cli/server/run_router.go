// Package server provides the daemon entrypoint for `remote-signer server start`.
// run_router.go contains the router initialization extracted from Run().
package server

import (
	"log/slog"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/api"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
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
	return &RouterAndServer{Router: router, Server: server}, nil
}
