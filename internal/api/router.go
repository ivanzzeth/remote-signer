package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/bootstrap"
	evmhandler "github.com/ivanzzeth/remote-signer/internal/api/handler/evm"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/core/auth"
	"github.com/ivanzzeth/remote-signer/internal/core/registry"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/metrics"
	"github.com/ivanzzeth/remote-signer/internal/settings"
	"github.com/ivanzzeth/remote-signer/internal/simulation"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/ivanzzeth/remote-signer/internal/web"
)

// TemplateConfig contains template-related dependencies for the router
type TemplateConfig struct {
	TemplateRepo    storage.TemplateRepository
	TemplateService *service.TemplateService
}

// RouterConfig contains configuration for the router
type RouterConfig struct {
	Version                      string
	IPWhitelistConfig            *middleware.IPWhitelist
	IPWhitelistConfigForRead     *config.IPWhitelistConfig // optional: for GET /api/v1/acls/ip-whitelist (admin, read-only)
	IPRateLimit                  int                       // requests per minute per IP (pre-auth); 0 = use default (200)
	SolidityValidator            *evm.SolidityRuleValidator
	JSEvaluator                  *evm.JSRuleEvaluator
	Template                     *TemplateConfig
	ApprovalGuard                *service.ManualApprovalGuard      // optional: for admin resume endpoint
	APIKeyRepo                   storage.APIKeyRepository          // optional: for signer access visibility and API key management
	SignerOwnershipRepo          storage.SignerOwnershipRepository // for signer ownership tracking
	SignerAccessRepo             storage.SignerAccessRepository    // for signer access grants
	SignerRepo                   storage.SignerRepository          // DB signer inventory/material status
	RulesAPIReadonly             bool                              // block rule/template mutations via API
	SignersAPIReadonly           bool                              // block signer/HD-wallet creation via API
	APIKeysAPIReadonly           bool                              // block API key management via API
	AlertService                 *middleware.SecurityAlertService  // optional: real-time security alerts
	AuditLogger                  *audit.AuditLogger                // optional: persistent audit logging
	SignTimeout                  time.Duration                     // context timeout for sign operations (default: 30s)
	AutoLockTimeout              time.Duration                     // signer auto-lock timeout (for health endpoint)
	AuditRetentionDays           int                               // audit log retention days (for health endpoint)
	BudgetRepo                   storage.BudgetRepository          // optional: for GET /api/v1/evm/rules/{id}/budgets
	MaxRulesPerAPIKey            int                               // per-key rule count limit (0 = no limit, default 50)
	RequireApprovalForAgentRules bool                              // require admin approval for agent whitelist rules
	// Preset API (admin-only). Presets live in the DB after v0.3 Registry
	// sync; the handler reads them from PresetRepo and writes apply
	// results in PresetsDB transactions. Both are required to register
	// the /api/v1/presets routes.
	PresetRepo storage.PresetRepository // DB-backed preset catalogue
	PresetsDB  *gorm.DB                 // txn handle for preset apply
	// Registry refresh endpoint (admin-only). Re-runs the template +
	// preset Registry sync without restart, so an operator can edit YAML
	// on disk and reload via `POST /api/v1/registry/refresh` instead of
	// kicking the daemon. Both fields must be set for the route to
	// register; nil disables the endpoint.
	TemplateRegistry *registry.TemplateRegistry
	PresetRegistry   *registry.PresetRegistry
	// Wallets
	WalletRepo storage.WalletRepository // optional: for wallet CRUD

	// SettingsManager backs /api/v1/admin/settings/:group and is read by the
	// daemon for runtime-mutable knobs (security/foundry/simulation/...).
	// When nil, the admin settings endpoints are not registered.
	SettingsManager *settings.Manager

	// Resource limits
	MaxKeystoresPerKey int // max keystores per API key (0 = no limit, default 5)
	MaxHDWalletsPerKey int // max HD wallets per API key (0 = no limit, default 3)
	// Simulation engine (optional). When set, POST /api/v1/evm/simulate, /simulate/batch, and /sign/batch are registered.
	Simulator simulation.Simulator
	// SimulationRule is the built-in simulation budget fallback rule (optional).
	// When set together with Simulator, the batch sign endpoint uses it for transactions
	// that don't match any user-defined whitelist rule.
	SimulationRule *evm.SimulationBudgetRule
	// RuleEngine is required for batch sign to evaluate rules per-tx before signing.
	RuleEngine rule.RuleEngine
	// RPCProvider is the optional RPC provider for broadcast endpoint.
	RPCProvider *evm.RPCProvider
	// TransactionService records eth_sendRawTransaction broadcasts +
	// hosts the receipt poller. Optional — installations without it
	// keep the proxy working (broadcasts still go to upstream), they
	// just lose the per-tx audit row + status tracking.
	TransactionService evmhandler.TransactionRecorder
	// TransactionRepo backs the /api/v1/evm/transactions read API.
	// Optional in the same sense as TransactionService — the routes
	// register only when set, so a build without tracking simply
	// omits the listing surface.
	TransactionRepo storage.TransactionRepository
	// RequestSimulationRepo backs the per-request simulation
	// preview endpoint. Optional — without it the route doesn't
	// register and the web UI's preview panel just shows
	// "evaluating" forever.
	RequestSimulationRepo storage.RequestSimulationRepository
	// RequestRepo backs handlers that need a direct repo handle
	// for cross-handler joins (e.g. the simulation handler joins
	// sign_request.api_key_id for visibility scoping). Optional —
	// handlers that need it gate their own registration on it.
	RequestRepo storage.RequestRepository

	// BootstrapCreator wires the POST /api/v1/bootstrap/admin handler.
	// Closure that, given a password, creates the admin keystore and
	// inserts the matching api_keys row. Supplied by run.go using the
	// daemon's resolved home paths so the HTTP layer doesn't need to
	// know where on disk anything lives. Nil → the bootstrap routes
	// don't register (useful in test harnesses that pre-seed admin
	// out of band).
	BootstrapCreator bootstrap.AdminCreator
}

// Router handles HTTP routing
type Router struct {
	mux           *http.ServeMux
	authVerifier  *auth.Verifier
	signService   *service.SignService
	signerManager evm.SignerManager
	ruleRepo      storage.RuleRepository
	auditRepo     storage.AuditRepository
	rateLimiter   *middleware.RateLimiter
	ipWhitelist   *middleware.IPWhitelist
	logger        *slog.Logger
	config        RouterConfig
}

// NewRouter creates a new router
func NewRouter(
	authVerifier *auth.Verifier,
	signService *service.SignService,
	signerManager evm.SignerManager,
	ruleRepo storage.RuleRepository,
	auditRepo storage.AuditRepository,
	logger *slog.Logger,
	config RouterConfig,
) (*Router, error) {
	r := &Router{
		mux:           http.NewServeMux(),
		authVerifier:  authVerifier,
		signService:   signService,
		signerManager: signerManager,
		ruleRepo:      ruleRepo,
		auditRepo:     auditRepo,
		rateLimiter:   middleware.NewRateLimiter(logger),
		ipWhitelist:   config.IPWhitelistConfig,
		logger:        logger,
		config:        config,
	}

	if err := r.setupRoutes(); err != nil {
		return nil, err
	}

	return r, nil
}

func (r *Router) setupRoutes() error {
	// Health check (no auth required, but with security headers)
	healthHandler := handler.NewHealthHandler(r.config.Version)
	healthHandler.SetSecurityConfig(r.config.AutoLockTimeout, r.config.SignTimeout, r.config.AuditRetentionDays)
	r.mux.Handle("/health", middleware.SecurityHeadersMiddleware()(healthHandler))

	// Prometheus metrics (no auth; same port as API)
	r.mux.Handle("/metrics", middleware.SecurityHeadersMiddleware()(metrics.Handler()))

	// First-run bootstrap (no auth). On an empty api_keys table the daemon
	// has no public key to verify a signed request against, so requiring
	// auth here would be a deadlock. The handler enforces single-shot
	// semantics: once the first POST succeeds, subsequent ones return
	// 410 Gone. Wiring is gated on a non-nil BootstrapCreator so a daemon
	// built without the cli/server import (test harness, embedded use)
	// can opt out cleanly.
	if r.config.BootstrapCreator != nil && r.config.APIKeyRepo != nil {
		bootstrapHandler := handler.NewBootstrapHandler(r.config.APIKeyRepo, r.config.BootstrapCreator, r.logger)
		r.mux.Handle("/api/v1/bootstrap/status", middleware.SecurityHeadersMiddleware()(http.HandlerFunc(bootstrapHandler.ServeStatus)))
		r.mux.Handle("/api/v1/bootstrap/admin", middleware.SecurityHeadersMiddleware()(http.HandlerFunc(bootstrapHandler.ServeAdmin)))
	}

	// Create SignerAccessService
	var accessService *service.SignerAccessService
	if r.config.SignerOwnershipRepo != nil && r.config.SignerAccessRepo != nil && r.config.APIKeyRepo != nil {
		hdWalletMgrFn := func() (service.HDWalletParentResolver, error) {
			if r.signerManager == nil {
				return nil, fmt.Errorf("no signer manager")
			}
			return r.signerManager.HDWalletManager()
		}
		var svcErr error
		accessService, svcErr = service.NewSignerAccessService(
			r.config.SignerOwnershipRepo,
			r.config.SignerAccessRepo,
			r.config.APIKeyRepo,
			hdWalletMgrFn,
			r.logger,
		)
		if svcErr != nil {
			return fmt.Errorf("failed to create signer access service: %w", svcErr)
		}
	}

	// EVM handlers
	signHandler, err := evmhandler.NewSignHandler(r.signService, r.signerManager, accessService, r.logger)
	if err != nil {
		return err
	}
	if r.config.SignerRepo != nil {
		signHandler.SetSignerRepo(r.config.SignerRepo)
	}
	if r.config.AlertService != nil {
		signHandler.SetAlertService(r.config.AlertService)
	}
	if r.config.SignTimeout > 0 {
		signHandler.SetSignTimeout(r.config.SignTimeout)
	}

	requestHandler, err := evmhandler.NewRequestHandler(r.signService, r.ruleRepo, r.logger)
	if err != nil {
		return err
	}

	listHandler, err := evmhandler.NewListHandler(r.signService, r.ruleRepo, r.logger)
	if err != nil {
		return err
	}

	approvalHandler, err := evmhandler.NewApprovalHandler(r.signService, accessService, r.logger, r.config.RulesAPIReadonly)
	if err != nil {
		return err
	}

	previewRuleHandler, err := evmhandler.NewPreviewRuleHandler(r.signService, r.logger)
	if err != nil {
		return err
	}

	var ruleHandlerOpts []evmhandler.RuleHandlerOption
	if r.config.SolidityValidator != nil {
		ruleHandlerOpts = append(ruleHandlerOpts, evmhandler.WithSolidityValidator(r.config.SolidityValidator))
	}
	if r.config.JSEvaluator != nil {
		ruleHandlerOpts = append(ruleHandlerOpts, evmhandler.WithJSEvaluator(r.config.JSEvaluator))
	}
	if r.config.AuditLogger != nil {
		ruleHandlerOpts = append(ruleHandlerOpts, evmhandler.WithAuditLogger(r.config.AuditLogger))
	}
	if r.config.BudgetRepo != nil {
		ruleHandlerOpts = append(ruleHandlerOpts, evmhandler.WithBudgetRepo(r.config.BudgetRepo))
	}
	if r.config.RulesAPIReadonly {
		ruleHandlerOpts = append(ruleHandlerOpts, evmhandler.WithReadOnly())
	}
	if r.config.APIKeyRepo != nil {
		ruleHandlerOpts = append(ruleHandlerOpts, evmhandler.WithAPIKeyRepo(r.config.APIKeyRepo))
	}
	if r.config.MaxRulesPerAPIKey > 0 {
		ruleHandlerOpts = append(ruleHandlerOpts, evmhandler.WithMaxRulesPerKey(r.config.MaxRulesPerAPIKey))
	}
	ruleHandlerOpts = append(ruleHandlerOpts, evmhandler.WithRequireApproval(r.config.RequireApprovalForAgentRules))
	ruleHandler, err := evmhandler.NewRuleHandler(r.ruleRepo, r.logger, ruleHandlerOpts...)
	if err != nil {
		return err
	}

	signerHandler, err := evmhandler.NewSignerHandler(r.signerManager, accessService, r.logger, r.config.SignersAPIReadonly)
	if err != nil {
		return err
	}
	if r.config.SignerRepo != nil {
		signerHandler.SetSignerRepo(r.config.SignerRepo)
	}
	if r.config.WalletRepo != nil {
		signerHandler.SetWalletRepo(r.config.WalletRepo)
	}
	if r.config.AuditLogger != nil {
		signerHandler.SetAuditLogger(r.config.AuditLogger)
	}
	if r.config.MaxKeystoresPerKey > 0 {
		signerHandler.SetMaxKeystoresPerKey(r.config.MaxKeystoresPerKey)
	}

	hdWalletHandler, err := evmhandler.NewHDWalletHandler(r.signerManager, accessService, r.logger, r.config.SignersAPIReadonly)
	if err != nil {
		return err
	}
	if r.config.AuditLogger != nil {
		hdWalletHandler.SetAuditLogger(r.config.AuditLogger)
	}
	if r.config.MaxHDWalletsPerKey > 0 {
		hdWalletHandler.SetMaxHDWalletsPerKey(r.config.MaxHDWalletsPerKey)
	}

	// Audit handler
	auditHandler, err := handler.NewAuditHandler(r.auditRepo, r.logger)
	if err != nil {
		return err
	}

	// EVM routes (with auth)
	r.mux.Handle("/api/v1/evm/sign", r.withAuthAndPerm(middleware.PermSignRequest, signHandler))
	r.mux.Handle("/api/v1/evm/requests", r.withAuthAndPerm(middleware.PermListOwnRequests, listHandler))
	var requestSimHandler *evmhandler.RequestSimulationHandler
	if r.config.RequestSimulationRepo != nil && r.config.RequestRepo != nil {
		var rsErr error
		requestSimHandler, rsErr = evmhandler.NewRequestSimulationHandler(
			r.config.RequestSimulationRepo, r.config.RequestRepo, r.logger,
		)
		if rsErr != nil {
			return fmt.Errorf("failed to create request simulation handler: %w", rsErr)
		}
	}
	r.mux.Handle("/api/v1/evm/requests/", r.withAuth(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Route to approval handler if path ends with /approve (admin only)
		if strings.HasSuffix(req.URL.Path, "/approve") {
			middleware.RequirePermission(middleware.PermApproveRequest, r.logger, r.config.AlertService)(approvalHandler).ServeHTTP(w, req)
			return
		}
		// Route to preview-rule handler if path ends with /preview-rule (admin only)
		if strings.HasSuffix(req.URL.Path, "/preview-rule") {
			middleware.RequirePermission(middleware.PermApproveRequest, r.logger, r.config.AlertService)(previewRuleHandler).ServeHTTP(w, req)
			return
		}
		// Route to simulation handler if path ends with /simulation.
		// Visibility is enforced inside the handler (non-admin only
		// sees own); 404 on parent-not-found prevents id-pattern
		// enumeration by foreign callers.
		if strings.HasSuffix(req.URL.Path, "/simulation") {
			if requestSimHandler == nil {
				http.NotFound(w, req)
				return
			}
			requestSimHandler.ServeHTTP(w, req)
			return
		}
		// Otherwise, route to request handler (any authenticated user can view own requests)
		requestHandler.ServeHTTP(w, req)
	})))

	// Rule management routes (RBAC: PermListRules covers GET for admin/dev/agent)
	r.mux.Handle("/api/v1/evm/rules", r.withAuthAndPerm(middleware.PermListRules, ruleHandler))
	r.mux.Handle("/api/v1/evm/rules/", r.withAuthAndPerm(middleware.PermListRules, ruleHandler))

	// Budget routes:
	//   GET    /api/v1/evm/budgets         list (PermReadBudgets)
	//   POST   /api/v1/evm/budgets         create (PermManageBudgets, in-handler)
	//   GET    /api/v1/evm/budgets/{id}    detail (PermReadBudgets)
	//   PATCH  /api/v1/evm/budgets/{id}    update (PermManageBudgets, in-handler)
	//   DELETE /api/v1/evm/budgets/{id}    delete (PermManageBudgets, in-handler)
	//   POST   /api/v1/evm/budgets/{id}/reset reset (PermManageBudgets, in-handler)
	//
	// The list view exists because synthetic simulation budgets
	// (rule_id "sim:*") have no row in the rules table, so a UI that
	// fans out over rules.list() can never see them.
	if r.config.BudgetRepo != nil {
		budgetListHandler, blErr := evmhandler.NewBudgetListHandler(r.config.BudgetRepo, r.ruleRepo, r.logger)
		if blErr != nil {
			return fmt.Errorf("failed to create budget list handler: %w", blErr)
		}
		budgetItemHandler, biErr := evmhandler.NewBudgetItemHandler(r.config.BudgetRepo, r.ruleRepo, r.logger)
		if biErr != nil {
			return fmt.Errorf("failed to create budget item handler: %w", biErr)
		}
		if r.config.AuditLogger != nil {
			budgetListHandler.SetAuditLogger(r.config.AuditLogger)
			budgetItemHandler.SetAuditLogger(r.config.AuditLogger)
		}
		// Gate at the perm "read"; the handler itself escalates to
		// PermManageBudgets for mutating method/path combos.
		r.mux.Handle("/api/v1/evm/budgets", r.withAuthAndPerm(middleware.PermReadBudgets, budgetListHandler))
		r.mux.Handle("/api/v1/evm/budgets/", r.withAuthAndPerm(middleware.PermReadBudgets, budgetItemHandler))
	}

	// Approval guard resume (admin only)
	if r.config.ApprovalGuard != nil {
		r.mux.Handle("/api/v1/evm/guard/resume", r.withAuthAndPerm(middleware.PermResumeGuard, http.HandlerFunc(r.handleGuardResume)))
	}

	// Signer management routes
	// GET: PermReadSigners (all roles); POST: PermCreateSigners checked in handler
	r.mux.Handle("/api/v1/evm/signers", r.withAuthAndPerm(middleware.PermReadSigners, signerHandler))
	// Signer action routes: /api/v1/evm/signers/{address}/unlock, /lock (admin only via PermUnlockSigner in handler)
	r.mux.Handle("/api/v1/evm/signers/", r.withAuthAndPerm(middleware.PermReadSigners, http.HandlerFunc(signerHandler.HandleSignerAction)))

	// HD wallet management routes
	r.mux.Handle("/api/v1/evm/hd-wallets", r.withAuth(hdWalletHandler))
	r.mux.Handle("/api/v1/evm/hd-wallets/", r.withAuth(hdWalletHandler))

	// Simulation routes (optional, requires simulation engine)
	if r.config.Simulator != nil {
		simulateHandler, simErr := evmhandler.NewSimulateHandler(r.config.Simulator, r.logger)
		if simErr != nil {
			return fmt.Errorf("failed to create simulate handler: %w", simErr)
		}
		r.mux.Handle("/api/v1/evm/simulate", r.withAuthAndPerm(middleware.PermSignRequest, simulateHandler))
		r.mux.Handle("/api/v1/evm/simulate/batch", r.withAuthAndPerm(middleware.PermSignRequest, http.HandlerFunc(simulateHandler.ServeBatchHTTP)))
		r.mux.Handle("/api/v1/evm/simulate/status", r.withAuthAndPerm(middleware.PermSignRequest, http.HandlerFunc(simulateHandler.ServeStatusHTTP)))
	}

	// Broadcast route (optional, requires RPC provider)
	if r.config.RPCProvider != nil {
		broadcastHandler, bcErr := evmhandler.NewBroadcastHandler(r.config.RPCProvider, r.logger)
		if bcErr != nil {
			return fmt.Errorf("failed to create broadcast handler: %w", bcErr)
		}
		r.mux.Handle("/api/v1/evm/broadcast", r.withAuthAndPerm(middleware.PermSignRequest, broadcastHandler))

		// Wallet RPC proxy: browser-extension EIP1193Provider routes
		// every read method + signed-tx broadcast through here so the
		// extension doesn't have to ship a list of public RPC URLs.
		// withAuth (no admin perm) — the handler's allowlist gates
		// what actually goes upstream, sign methods are explicitly
		// excluded so a non-admin key can't bypass /sign.
		rpcProxyHandler, rpErr := evmhandler.NewRPCProxyHandler(r.config.RPCProvider, r.config.TransactionService, r.logger)
		if rpErr != nil {
			return fmt.Errorf("failed to create rpc proxy handler: %w", rpErr)
		}
		r.mux.Handle("/api/v1/evm/rpc/", r.withAuth(rpcProxyHandler))
	}

	// On-chain transactions read API. Registered independently of
	// the proxy: even an operator who doesn't broadcast through the
	// daemon may want to see legacy rows (e.g. ones recorded by an
	// older build). withAuth — visibility is enforced inside the
	// handler by joining sign_request.api_key_id against the caller.
	if r.config.TransactionRepo != nil {
		txHandler, txErr := evmhandler.NewTransactionsHandler(r.config.TransactionRepo, r.logger)
		if txErr != nil {
			return fmt.Errorf("failed to create transactions handler: %w", txErr)
		}
		r.mux.Handle("/api/v1/evm/transactions", r.withAuth(txHandler))
		r.mux.Handle("/api/v1/evm/transactions/", r.withAuth(txHandler))
	}

	// Batch sign route (optional, requires rule engine; simulation rule is optional)
	if r.config.RuleEngine != nil && accessService != nil {
		batchSignHandler, bsErr := evmhandler.NewBatchSignHandler(evmhandler.BatchSignHandlerConfig{
			SignService:    r.signService,
			SignerManager:  r.signerManager,
			AccessService:  accessService,
			SimulationRule: r.config.SimulationRule,
			RuleEngine:     r.config.RuleEngine,
			Logger:         r.logger,
		})
		if bsErr != nil {
			return fmt.Errorf("failed to create batch sign handler: %w", bsErr)
		}
		if r.config.AlertService != nil {
			batchSignHandler.SetAlertService(r.config.AlertService)
		}
		if r.config.SignTimeout > 0 {
			batchSignHandler.SetSignTimeout(r.config.SignTimeout)
		}
		r.mux.Handle("/api/v1/evm/sign/batch", r.withAuthAndPerm(middleware.PermSignRequest, batchSignHandler))
	}

	// Audit routes
	r.mux.Handle("/api/v1/audit", r.withAuthAndPerm(middleware.PermReadAudit, auditHandler))
	r.mux.Handle("/api/v1/audit/requests/", r.withAuthAndPerm(middleware.PermReadAudit, http.HandlerFunc(auditHandler.ServeRequestHTTP)))

	// Set rule repo on access service for cascade cleanup
	if accessService != nil {
		accessService.SetRuleRepo(r.ruleRepo)
		if r.config.WalletRepo != nil {
			accessService.SetWalletRepo(r.config.WalletRepo)
		}
	}

	// API key management routes (admin only)
	if r.config.APIKeyRepo != nil {
		apiKeyHandler, err := handler.NewAPIKeyHandler(r.config.APIKeyRepo, r.logger, r.config.APIKeysAPIReadonly)
		if err != nil {
			return err
		}
		if r.config.AuditLogger != nil {
			apiKeyHandler.SetAuditLogger(r.config.AuditLogger)
		}
		if accessService != nil {
			apiKeyHandler.SetAccessService(accessService)
		}
		// /names is the lightweight read-only projection any
		// authenticated key may pull (id + name + role + enabled). Must
		// land BEFORE the /api/v1/api-keys/ prefix so the standard mux's
		// longest-match wins and we don't accidentally route through
		// ServeKeyHTTP (which would treat "names" as an id and 404).
		r.mux.Handle("/api/v1/api-keys/names", r.withAuth(http.HandlerFunc(apiKeyHandler.ListAPIKeyNames)))
		r.mux.Handle("/api/v1/api-keys", r.withAuthAndPerm(middleware.PermManageAPIKeys, apiKeyHandler))
		r.mux.Handle("/api/v1/api-keys/", r.withAuthAndPerm(middleware.PermManageAPIKeys, http.HandlerFunc(apiKeyHandler.ServeKeyHTTP)))
	}

	// Wallet routes (all authenticated users can manage their own wallets)
	if r.config.WalletRepo != nil {
		walletHandler, collErr := handler.NewWalletHandler(r.config.WalletRepo, r.config.SignerOwnershipRepo, r.config.SignerAccessRepo, r.logger)
		if collErr != nil {
			return fmt.Errorf("failed to create wallet handler: %w", collErr)
		}
		r.mux.Handle("/api/v1/wallets", r.withAuthAndPerm(middleware.PermManageWallets, walletHandler))
		r.mux.Handle("/api/v1/wallets/", r.withAuthAndPerm(middleware.PermManageWallets, http.HandlerFunc(walletHandler.ServeWalletHTTP)))
	}

	// ACLs read-only routes (admin only): IP whitelist config
	if r.config.IPWhitelistConfigForRead != nil {
		aclHandler := handler.NewACLHandler(r.config.IPWhitelistConfigForRead)
		r.mux.Handle("/api/v1/acls/ip-whitelist", r.withAuthAndPerm(middleware.PermReadACLs, aclHandler))
	}

	// Runtime-mutable settings (admin only). PUT against /api/v1/admin/settings/security
	// persists into system_settings and refreshes the local snapshot; PR7c/d
	// add the other groups as they become DB-backed.
	if r.config.SettingsManager != nil {
		settingsHandler := handler.NewSettingsHandler(r.config.SettingsManager, r.logger)
		if r.config.AuditLogger != nil {
			settingsHandler.SetAuditLogger(r.config.AuditLogger)
		}
		r.mux.Handle("/api/v1/admin/settings/", r.withAuthAndPerm(middleware.PermManageSettings, settingsHandler))
	}

	// Template routes (read: PermReadTemplates; mutate: PermInstantiateTemplate checked in handler)
	if r.config.Template != nil && r.config.Template.TemplateRepo != nil && r.config.Template.TemplateService != nil {
		templateHandler, err := handler.NewTemplateHandler(
			r.config.Template.TemplateRepo,
			r.config.Template.TemplateService,
			r.logger,
			r.config.RulesAPIReadonly,
			handler.WithTemplateRequireApproval(r.config.RequireApprovalForAgentRules),
			handler.WithTemplateAPIKeyRepo(r.config.APIKeyRepo),
		)
		if err != nil {
			return err
		}

		r.mux.Handle("/api/v1/templates", r.withAuthAndPerm(middleware.PermReadTemplates, templateHandler))
		r.mux.Handle("/api/v1/templates/", r.withAuthAndPerm(middleware.PermReadTemplates, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// Route to instance handler if path starts with /instances/
			if strings.HasPrefix(req.URL.Path, "/api/v1/templates/instances/") {
				templateHandler.ServeInstanceHTTP(w, req)
				return
			}
			// Otherwise, route to template handler
			templateHandler.ServeHTTP(w, req)
		})))
	}

	// Preset API (read: PermReadPresets; apply: PermApplyPreset checked in handler)
	if r.config.PresetRepo != nil && r.config.Template != nil && r.config.Template.TemplateRepo != nil {
		presetHandler, err := handler.NewPresetHandler(
			r.config.PresetRepo,
			r.config.Template.TemplateRepo,
			r.config.PresetsDB,
			r.config.Template.TemplateService,
			r.config.RulesAPIReadonly,
			r.logger,
			handler.WithPresetRequireApproval(r.config.RequireApprovalForAgentRules),
			handler.WithPresetAPIKeyRepo(r.config.APIKeyRepo),
		)
		if err != nil {
			return err
		}
		if r.config.AuditLogger != nil {
			presetHandler.SetAuditLogger(r.config.AuditLogger)
		}
		r.mux.Handle("/api/v1/presets", r.withAuthAndPerm(middleware.PermReadPresets, presetHandler))
		r.mux.Handle("/api/v1/presets/", r.withAuthAndPerm(middleware.PermReadPresets, http.HandlerFunc(presetHandler.ServeHTTP)))
	}

	// Registry refresh endpoint — re-runs Template + Preset Registry
	// sync without a daemon restart. Both registries must be wired
	// (run.go's buildRegistries provides them at boot). Gated by the
	// apply_preset permission since refresh can prune catalogue rows.
	if r.config.TemplateRegistry != nil && r.config.PresetRegistry != nil {
		refreshHandler, err := handler.NewRegistryRefreshHandler(
			r.config.TemplateRegistry,
			r.config.PresetRegistry,
			r.logger,
		)
		if err != nil {
			return err
		}
		r.mux.Handle("/api/v1/registry/refresh", r.withAuthAndPerm(middleware.PermApplyPreset, refreshHandler))
	}

	// Web UI catch-all. Must be registered LAST so every explicit
	// /api/v1/* and /health-style route wins ServeMux's longest-prefix
	// match. The handler internally short-circuits when
	// settings.web.enabled is false, so this registration is unconditional
	// — flipping the setting at runtime is enough to disable the UI.
	if r.config.SettingsManager != nil {
		webHandler := web.NewHandler(r.config.SettingsManager, r.logger)
		r.mux.Handle("/", webHandler)
	}

	return nil
}

// withAuth wraps a handler with authentication middleware
func (r *Router) withAuth(h http.Handler) http.Handler {
	middlewares := []func(http.Handler) http.Handler{
		middleware.SecurityHeadersMiddleware(),
		middleware.RecoveryMiddleware(r.logger),
		middleware.ClientIPMiddleware(r.ipWhitelist),
		middleware.LoggingMiddleware(r.logger, r.config.AuditLogger),
		middleware.IPRateLimitMiddleware(r.rateLimiter, r.ipWhitelist, r.config.IPRateLimit, r.config.AlertService),
		middleware.AuthMiddleware(r.authVerifier, r.logger, r.config.AuditLogger, r.config.AlertService),
		middleware.RateLimitMiddleware(r.rateLimiter, r.config.AuditLogger, r.config.AlertService),
		middleware.ContentTypeMiddleware(),
	}
	// Add IP whitelist as outermost middleware (checked first)
	if r.ipWhitelist != nil {
		middlewares = append(middlewares, middleware.IPWhitelistMiddleware(r.ipWhitelist))
	}
	return r.chain(h, middlewares...)
}

// withAuthAndPerm wraps a handler with authentication + RBAC permission middleware.
func (r *Router) withAuthAndPerm(perm middleware.Permission, h http.Handler) http.Handler {
	middlewares := []func(http.Handler) http.Handler{
		middleware.SecurityHeadersMiddleware(),
		middleware.RecoveryMiddleware(r.logger),
		middleware.ClientIPMiddleware(r.ipWhitelist),
		middleware.LoggingMiddleware(r.logger, r.config.AuditLogger),
		middleware.IPRateLimitMiddleware(r.rateLimiter, r.ipWhitelist, r.config.IPRateLimit, r.config.AlertService),
		middleware.AuthMiddleware(r.authVerifier, r.logger, r.config.AuditLogger, r.config.AlertService),
		middleware.RequirePermission(perm, r.logger, r.config.AlertService),
		middleware.RateLimitMiddleware(r.rateLimiter, r.config.AuditLogger, r.config.AlertService),
		middleware.ContentTypeMiddleware(),
	}
	if r.ipWhitelist != nil {
		middlewares = append(middlewares, middleware.IPWhitelistMiddleware(r.ipWhitelist))
	}
	return r.chain(h, middlewares...)
}

// chain applies middlewares in reverse order
func (r *Router) chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

// handleGuardResume resumes the approval guard (admin only). POST only.
func (r *Router) handleGuardResume(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.config.ApprovalGuard == nil {
		http.Error(w, "approval guard not configured", http.StatusNotImplemented)
		return
	}
	r.config.ApprovalGuard.Resume()
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write([]byte(`{"ok":true,"message":"approval guard resumed"}`)); err != nil {
		r.logger.Error("failed to write guard resume response", "error", err)
	}
}

// Handler returns the HTTP handler
func (r *Router) Handler() http.Handler {
	return r.mux
}

// StartRateLimitCleanup starts the rate limit cleanup routine
func (r *Router) StartRateLimitCleanup(stop <-chan struct{}) {
	r.rateLimiter.StartCleanupRoutine(5*time.Minute, stop) // every 5 minutes
}
