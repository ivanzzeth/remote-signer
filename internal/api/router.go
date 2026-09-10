package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	evmhandler "github.com/ivanzzeth/remote-signer/internal/api/handler/evm"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/api/respond"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/auth"
	"github.com/ivanzzeth/remote-signer/internal/core/ports"
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
	// Modules are feature slices built by the composition root, each holding its
	// own dependencies and registering its own routes.
	//
	// ⭐ New features belong here, not in a new field below. Every field in this
	// struct is a dependency the router must know about in order to decide
	// whether a route exists — which is why reading setupRoutes cannot tell you
	// what a daemon serves. A module answers that itself; see module.go.
	Modules []Module

	Version                  string
	IPWhitelistConfig        *middleware.IPWhitelist
	IPWhitelistConfigForRead *ports.IPWhitelist // optional: for GET /api/v1/acls/ip-whitelist (admin, read-only)
	SolidityValidator        *evm.SolidityRuleValidator
	JSEvaluator              *evm.JSRuleEvaluator
	Template                 *TemplateConfig
	ApprovalGuard            *service.ManualApprovalGuard      // optional: for admin resume endpoint
	APIKeyRepo               storage.APIKeyRepository          // optional: for signer access visibility and API key management
	SignerOwnershipRepo      storage.SignerOwnershipRepository // for signer ownership tracking
	SignerAccessRepo         storage.SignerAccessRepository    // for signer access grants
	SignerRepo               storage.SignerRepository          // DB signer inventory/material status
	AlertService             *middleware.SecurityAlertService  // optional: real-time security alerts
	AuditLogger              *audit.AuditLogger                // optional: persistent audit logging
	AuditRetentionDays       int                               // audit log retention days (for health endpoint)
	BudgetRepo               storage.BudgetRepository          // optional: for GET /api/v1/evm/rules/{id}/budgets
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
}

// Router handles HTTP routing
type Router struct {
	modules []string
	// routeAuth records what every registered pattern declared about
	// authorization — a permission, or an explicit exemption carrying the reason
	// it has none. Written only by handle, only during setupRoutes, and read
	// afterwards by Handler's deny-by-default guard; see route_auth.go.
	//
	// ⚠️ It replaced routePerms, which recorded only the ~26 patterns that went
	// through handlePerm. A table that describes half the surface answers "is
	// there a route nobody decided about?" with silence.
	routeAuth     map[string]RouteAuth
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
	healthHandler *handler.HealthHandler
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
		routeAuth:     map[string]RouteAuth{},
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
	r.healthHandler = handler.NewHealthHandler(r.config.Version)
	r.healthHandler.SetSecurityConfig(r.config.AuditRetentionDays)
	r.healthHandler.SetSettingsManager(r.config.SettingsManager)
	r.syncApprovalGuard()
	r.handle("GET /health", Public(
		"liveness/readiness: scraped by orchestrators and by `remote-signer server status` before any API key exists, "+
			"so requiring one would make the check useless exactly when it matters. "+
			"⚠️ It answers with more than liveness — version plus a security summary "+
			"(sign/auto-lock timeouts, audit retention, approval-guard state; handler/health.go:19-33). "+
			"That is a disclosure question for whoever owns the endpoint, not something this exemption decides."),
		r.healthHandler)

	// Prometheus metrics (no auth; same port as API)
	r.handle("/metrics", Public(
		"Prometheus scrape. Unauthenticated on purpose and documented as such (docs/sdk-cli-matrix.md:30, "+
			"\"CLI uses raw GET /metrics (no auth)\"), and the TUI metrics view scrapes it the same way. "+
			"⚠️ middleware.PermReadMetrics exists and is granted to admin+dev (middleware/rbac.go:64) while being "+
			"referenced by no route — so either that permission or this exemption is dead. Recorded, not resolved: "+
			"putting a permission here would silently break every scraper."),
		metrics.Handler())

	// First-run bootstrap (no auth). On an empty api_keys table the daemon
	// has no public key to verify a signed request against, so requiring
	// auth here would be a deadlock. The handler enforces single-shot
	// semantics: once the first POST succeeds, subsequent ones return
	// 410 Gone. Wiring is gated on a non-nil BootstrapCreator so a daemon
	// built without the cli/server import (test harness, embedded use)
	// can opt out cleanly.
	r.mountModules(r.config.Modules...)

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
	signHandler.SetSignTimeout(
		r.liveDuration(func(s *settings.SecuritySnapshot) time.Duration { return s.SignTimeout }))

	requestHandler, err := evmhandler.NewRequestHandler(r.signService, r.ruleRepo, r.logger)
	if err != nil {
		return err
	}

	listHandler, err := evmhandler.NewListHandler(r.signService, r.ruleRepo, r.logger)
	if err != nil {
		return err
	}

	approvalHandler, err := evmhandler.NewApprovalHandler(r.signService, accessService, r.logger, r.liveReadOnly(func(s *settings.SecuritySnapshot) bool { return s.RulesAPIReadonly }))
	if err != nil {
		return err
	}

	batchApprovalHandler, err := evmhandler.NewBatchApprovalHandler(r.signService, accessService, r.logger)
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
	if r.config.Template != nil && r.config.Template.TemplateRepo != nil {
		ruleHandlerOpts = append(ruleHandlerOpts, evmhandler.WithTemplateRepo(r.config.Template.TemplateRepo))
	}
	ruleHandlerOpts = append(ruleHandlerOpts, evmhandler.WithReadOnly(
		r.liveReadOnly(func(s *settings.SecuritySnapshot) bool { return s.RulesAPIReadonly })))
	if r.config.APIKeyRepo != nil {
		ruleHandlerOpts = append(ruleHandlerOpts, evmhandler.WithAPIKeyRepo(r.config.APIKeyRepo))
	}
	ruleHandlerOpts = append(ruleHandlerOpts, evmhandler.WithMaxRulesPerKey(
		r.liveInt(func(s *settings.SecuritySnapshot) int { return s.MaxRulesPerAPIKey })))
	ruleHandlerOpts = append(ruleHandlerOpts, evmhandler.WithRequireApproval(r.liveReadOnly(func(s *settings.SecuritySnapshot) bool { return s.RequireApprovalForAgentRules })))
	if r.signService != nil {
		ruleHandlerOpts = append(ruleHandlerOpts, evmhandler.WithRuleActivatedCallback(func(callerName string) {
			r.signService.ReevaluatePending(context.Background(), callerName)
		}))
	}
	ruleHandler, err := evmhandler.NewRuleHandler(r.ruleRepo, r.logger, ruleHandlerOpts...)
	if err != nil {
		return err
	}

	signerHandler, err := evmhandler.NewSignerHandler(r.signerManager, accessService, r.logger, r.liveReadOnly(func(s *settings.SecuritySnapshot) bool { return s.SignersAPIReadonly }))
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
	signerHandler.SetMaxKeystoresPerKey(
		r.liveInt(func(s *settings.SecuritySnapshot) int { return s.MaxKeystoresPerKey }))

	hdWalletHandler, err := evmhandler.NewHDWalletHandler(r.signerManager, accessService, r.logger, r.liveReadOnly(func(s *settings.SecuritySnapshot) bool { return s.SignersAPIReadonly }))
	if err != nil {
		return err
	}
	if r.config.AuditLogger != nil {
		hdWalletHandler.SetAuditLogger(r.config.AuditLogger)
	}
	hdWalletHandler.SetMaxHDWalletsPerKey(
		r.liveInt(func(s *settings.SecuritySnapshot) int { return s.MaxHDWalletsPerKey }))

	// Audit handler
	auditHandler, err := handler.NewAuditHandler(r.auditRepo, r.logger)
	if err != nil {
		return err
	}

	// EVM routes (with auth)
	r.handle("POST /api/v1/evm/sign", Permitted(middleware.PermSignRequest), signHandler)
	r.handle("/api/v1/evm/requests", Permitted(middleware.PermListOwnRequests), listHandler)
	r.handle("POST /api/v1/evm/requests/batch-approve", Permitted(middleware.PermApproveRequest), batchApprovalHandler)
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
	r.handle("/api/v1/evm/requests/", AuthenticatedOnly(
		"one prefix, four sub-paths with different permissions: the closure below installs "+
			"PermApproveRequest for .../approve and PermPreviewRule for .../preview-rule itself. "+
			"The two remaining branches carry none by design — .../simulation and the default "+
			"\"read one request\" are scoped to the caller's own rows inside the handler, and answer 404 "+
			"rather than 403 for a foreign id so the id space cannot be enumerated. "+
			"⚠️ This is the KNOWN LIMIT in route_auth.go made concrete: a prefix can declare one permission, "+
			"so this one declares none and the four real endpoints are invisible to the route table until "+
			"the closure is decomposed into four patterns (proposal S7)."),
		http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// Route to approval handler if path ends with /approve (admin only)
			if strings.HasSuffix(req.URL.Path, "/approve") {
				middleware.RequirePermission(middleware.PermApproveRequest, r.logger, r.config.AlertService)(approvalHandler).ServeHTTP(w, req)
				return
			}
			// Route to preview-rule handler if path ends with /preview-rule
			if strings.HasSuffix(req.URL.Path, "/preview-rule") {
				middleware.RequirePermission(middleware.PermPreviewRule, r.logger, r.config.AlertService)(previewRuleHandler).ServeHTTP(w, req)
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
		}))

	// Rule management routes (RBAC: PermListRules covers GET for admin/dev/agent)
	r.handle("/api/v1/evm/rules", Permitted(middleware.PermListRules), ruleHandler)
	r.handle("/api/v1/evm/rules/", Permitted(middleware.PermListRules), ruleHandler)
	// /rules/{id}/budgets/reset changes budgets, so it is gated on
	// PermManageBudgets rather than reached on PermListRules and re-checked
	// inside the handler. Registered after the prefix pattern above; Go's mux
	// prefers the more specific one.
	r.handle("POST /api/v1/evm/rules/{id}/budgets/reset", Permitted(middleware.PermManageBudgets), ruleHandler)

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
		// ⚠️ Method-scoped, so the permission is declared with the route rather
		// than escalated inside the handler. It used to register the read
		// permission for every method and have each mutating branch re-check
		// PermManageBudgets itself — five checks in one file, and forgetting one
		// is a permission bypass that nothing reports. Here a route with no
		// registration simply has no permission, which is the failure direction
		// worth having.
		//
		// The trailing-slash patterns cover the sub-paths: POST reaches
		// /budgets/{id}/reset, DELETE reaches both /budgets/{id} and
		// /budgets/by-rule/{ruleID}.
		r.handle("GET /api/v1/evm/budgets", Permitted(middleware.PermReadBudgets), budgetListHandler)
		r.handle("POST /api/v1/evm/budgets", Permitted(middleware.PermManageBudgets), budgetListHandler)
		r.handle("GET /api/v1/evm/budgets/", Permitted(middleware.PermReadBudgets), budgetItemHandler)
		r.handle("POST /api/v1/evm/budgets/", Permitted(middleware.PermManageBudgets), budgetItemHandler)
		r.handle("PATCH /api/v1/evm/budgets/", Permitted(middleware.PermManageBudgets), budgetItemHandler)
		r.handle("DELETE /api/v1/evm/budgets/", Permitted(middleware.PermManageBudgets), budgetItemHandler)
	}

	// Approval guard resume (admin only). Route is always registered; handler
	// returns 501 when security.approval_guard.enabled is false.
	r.handle("/api/v1/evm/guard/resume", Permitted(middleware.PermResumeGuard), http.HandlerFunc(r.handleGuardResume))

	// Signer management routes
	//
	// ⚠️ The eleven patterns and their permissions live in module_signers.go
	// now, and every permission is byte-for-byte the one that stood here. What
	// changed is that the method-less `/api/v1/evm/signers/` prefix became the
	// five endpoints it was hiding — item DELETE/PATCH, access list/grant/revoke
	// — so a verb no endpoint serves is refused by the mux instead of being read
	// out of the path by the handler and performed (6d30ba1). See
	// signersModule.Routes for the measured before/after table.
	signersMod, signersModErr := NewSignersModule(signerHandler)
	if signersModErr != nil {
		return fmt.Errorf("failed to create signers module: %w", signersModErr)
	}
	r.mountModules(signersMod)

	// HD wallet management routes
	//
	// ⚠️ The four patterns, their AuthenticatedOnly exemption and the written
	// reason behind it live in module_hdwallets.go now, and the reason is
	// byte-for-byte the one that stood here. What changed is that the two
	// wildcard patterns became the four endpoints they were hiding; the known
	// RBAC gap they declare is unchanged and deliberately still open — see
	// hdWalletGap.
	hdWalletsMod, hdModErr := NewHDWalletsModule(hdWalletHandler)
	if hdModErr != nil {
		return fmt.Errorf("failed to create hd wallet module: %w", hdModErr)
	}
	r.mountModules(hdWalletsMod)

	// Simulation routes (optional, requires simulation engine)
	if r.config.Simulator != nil {
		simulateHandler, simErr := evmhandler.NewSimulateHandler(r.config.Simulator, r.logger)
		if simErr != nil {
			return fmt.Errorf("failed to create simulate handler: %w", simErr)
		}
		r.handle("POST /api/v1/evm/simulate", Permitted(middleware.PermSignRequest), simulateHandler)
		r.handle("POST /api/v1/evm/simulate/batch", Permitted(middleware.PermSignRequest), http.HandlerFunc(simulateHandler.ServeBatchHTTP))
		r.handle("GET /api/v1/evm/simulate/status", Permitted(middleware.PermSignRequest), http.HandlerFunc(simulateHandler.ServeStatusHTTP))
	}

	// Simulation history (persisted snapshots from the sign pipeline).
	if r.config.RequestSimulationRepo != nil {
		simHistHandler, shErr := evmhandler.NewSimulationHistoryHandler(r.config.RequestSimulationRepo, r.logger)
		if shErr != nil {
			return fmt.Errorf("failed to create simulation history handler: %w", shErr)
		}
		r.handle("/api/v1/evm/simulations", Permitted(middleware.PermSignRequest), simHistHandler)
	}

	// Broadcast route (optional, requires RPC provider)
	if r.config.RPCProvider != nil {
		broadcastHandler, bcErr := evmhandler.NewBroadcastHandler(r.config.RPCProvider, r.logger)
		if bcErr != nil {
			return fmt.Errorf("failed to create broadcast handler: %w", bcErr)
		}
		r.handle("POST /api/v1/evm/broadcast", Permitted(middleware.PermSignRequest), broadcastHandler)

		// Wallet RPC proxy: browser-extension EIP1193Provider routes
		// every read method + signed-tx broadcast through here so the
		// extension doesn't have to ship a list of public RPC URLs.
		rpcProxyHandler, rpErr := evmhandler.NewRPCProxyHandler(r.config.RPCProvider, r.config.TransactionService, r.logger)
		if rpErr != nil {
			return fmt.Errorf("failed to create rpc proxy handler: %w", rpErr)
		}
		r.handle("POST /api/v1/evm/rpc/", AuthenticatedOnly(
			"JSON-RPC envelope, not a REST resource: what the caller may do is decided by the method name inside "+
				"the body, which a route cannot see. The handler's allowlist is the gate — every eth_sign* method is "+
				"excluded there, so a non-admin key cannot use this to bypass POST /api/v1/evm/sign."),
			rpcProxyHandler)
	}

	// On-chain transactions read API. Registered independently of
	// the proxy: even an operator who doesn't broadcast through the
	// daemon may want to see legacy rows (e.g. ones recorded by an
	// older build). withAuth — visibility is enforced inside the
	// handler by joining sign_request.api_key_id against the caller.

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
		batchSignHandler.SetSignTimeout(
			r.liveDuration(func(s *settings.SecuritySnapshot) time.Duration { return s.SignTimeout }))
		r.handle("POST /api/v1/evm/sign/batch", Permitted(middleware.PermSignRequest), batchSignHandler)
	}

	// Audit routes
	// ⚠️ Method-scoped registrations. Go's ServeMux answers 405 itself when a
	// pattern matches the path but not the method, so the handler no longer
	// hand-rolls `if r.Method != …`. Thirty-five of those checks existed and
	// forgetting one means a GET reaching a write path — a mistake the mux
	// cannot make.
	r.handle("GET /api/v1/audit", Permitted(middleware.PermReadAudit), auditHandler)
	r.handle("GET /api/v1/audit/requests/", Permitted(middleware.PermReadAudit), http.HandlerFunc(auditHandler.ServeRequestHTTP))

	// Set rule repo on access service for cascade cleanup
	if accessService != nil {
		accessService.SetRuleRepo(r.ruleRepo)
		if r.config.WalletRepo != nil {
			accessService.SetWalletRepo(r.config.WalletRepo)
		}
	}

	// API key management routes (admin only)
	if r.config.APIKeyRepo != nil {
		apiKeyHandler, err := handler.NewAPIKeyHandler(r.config.APIKeyRepo, r.logger, r.liveReadOnly(func(s *settings.SecuritySnapshot) bool { return s.APIKeysAPIReadonly }))
		if err != nil {
			return err
		}
		if r.config.AuditLogger != nil {
			apiKeyHandler.SetAuditLogger(r.config.AuditLogger)
		}
		if accessService != nil {
			apiKeyHandler.SetAccessService(accessService)
		}
		// ⚠️ The six patterns, their permissions and the /names exemption's
		// written reason live in module_apikeys.go now, and the reason is
		// byte-for-byte the one that stood here. What changed is that the two
		// method-less prefixes became the five endpoints they were hiding.
		apiKeysMod, akModErr := NewAPIKeysModule(apiKeyHandler)
		if akModErr != nil {
			return fmt.Errorf("failed to create api key module: %w", akModErr)
		}
		r.mountModules(apiKeysMod)
	}

	// Wallet routes (all authenticated users can manage their own wallets).
	// ⚠️ The patterns and their permission live in module_wallets.go now, and
	// they are byte-for-byte the two that were here. The move is what lets the
	// wallet handler tests route through the production registration instead of
	// a copy of it; see the comment on walletsModule.
	if r.config.WalletRepo != nil {
		walletsMod, collErr := NewWalletsModule(r.config.WalletRepo, r.config.SignerOwnershipRepo, r.config.SignerAccessRepo, r.logger)
		if collErr != nil {
			return fmt.Errorf("failed to create wallet handler: %w", collErr)
		}
		r.mountModules(walletsMod)
	}

	// ACLs read-only routes (admin only): IP whitelist config
	if r.config.IPWhitelistConfigForRead != nil {
		aclHandler := handler.NewACLHandler(r.config.IPWhitelistConfigForRead)
		r.handle("GET /api/v1/acls/ip-whitelist", Permitted(middleware.PermReadACLs), aclHandler)
	}

	// Runtime-mutable settings (admin only). PUT against /api/v1/admin/settings/security
	// persists into system_settings and refreshes the local snapshot.
	//
	// ⚠️ The eighteen patterns and their permission live in module_settings.go
	// now, and the permission is byte-for-byte the PermManageSettings the one
	// method-less prefix declared for all of them. What changed is that the
	// prefix — behind which the request body type varied with a path segment,
	// the one shape OpenAPI cannot describe — became one route per group per
	// method, each with a concrete body type. See settingsModule.Routes.
	if r.config.SettingsManager != nil {
		settingsHandler := handler.NewSettingsHandler(r.config.SettingsManager, r.logger)
		if r.config.AuditLogger != nil {
			settingsHandler.SetAuditLogger(r.config.AuditLogger)
		}
		settingsHandler.SetOnSecurityUpdated(r.syncApprovalGuard)
		settingsMod, sModErr := NewSettingsModule(settingsHandler)
		if sModErr != nil {
			return fmt.Errorf("failed to create settings module: %w", sModErr)
		}
		r.mountModules(settingsMod)
	}

	// Template routes (read: PermReadTemplates; mutate: PermInstantiateTemplate checked in handler)
	if r.config.Template != nil && r.config.Template.TemplateRepo != nil && r.config.Template.TemplateService != nil {
		templateHandler, err := handler.NewTemplateHandler(
			r.config.Template.TemplateRepo,
			r.config.Template.TemplateService,
			r.logger,
			r.liveReadOnly(func(s *settings.SecuritySnapshot) bool { return s.RulesAPIReadonly }),
			handler.WithTemplateRequireApproval(r.liveReadOnly(func(s *settings.SecuritySnapshot) bool { return s.RequireApprovalForAgentRules })),
			handler.WithTemplateAPIKeyRepo(r.config.APIKeyRepo),
			handler.WithTemplateJSEvaluator(r.config.JSEvaluator),
			handler.WithTemplateSolidityValidator(r.config.SolidityValidator),
		)
		if err != nil {
			return err
		}

		r.handle("/api/v1/templates", Permitted(middleware.PermReadTemplates), templateHandler)
		r.handle("/api/v1/templates/", Permitted(middleware.PermReadTemplates), http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// Route to instance handler if path starts with /instances/
			if strings.HasPrefix(req.URL.Path, "/api/v1/templates/instances/") {
				templateHandler.ServeInstanceHTTP(w, req)
				return
			}
			// Otherwise, route to template handler
			templateHandler.ServeHTTP(w, req)
		}))
	}

	// Preset API (read: PermReadPresets; apply: PermApplyPreset checked in handler)
	if r.config.PresetRepo != nil && r.config.Template != nil && r.config.Template.TemplateRepo != nil {
		presetHandler, err := handler.NewPresetHandler(
			r.config.PresetRepo,
			r.config.Template.TemplateRepo,
			r.config.PresetsDB,
			r.config.Template.TemplateService,
			r.liveReadOnly(func(s *settings.SecuritySnapshot) bool { return s.RulesAPIReadonly }),
			r.logger,
			handler.WithPresetRequireApproval(r.liveReadOnly(func(s *settings.SecuritySnapshot) bool { return s.RequireApprovalForAgentRules })),
			handler.WithPresetAPIKeyRepo(r.config.APIKeyRepo),
			handler.WithPresetJSEvaluator(r.config.JSEvaluator),
			handler.WithPresetSolidityValidator(r.config.SolidityValidator),
		)
		if err != nil {
			return err
		}
		if r.config.AuditLogger != nil {
			presetHandler.SetAuditLogger(r.config.AuditLogger)
		}
		r.handle("/api/v1/presets", Permitted(middleware.PermReadPresets), presetHandler)
		// /presets/{id}/apply and /presets/{id}/validate are POSTs that change
		// the catalogue, so they carry PermApplyPreset at the route instead of
		// being reached on the read permission and re-checked inside apply().
		r.handle("GET /api/v1/presets/", Permitted(middleware.PermReadPresets), http.HandlerFunc(presetHandler.ServeHTTP))
		r.handle("POST /api/v1/presets/", Permitted(middleware.PermApplyPreset), http.HandlerFunc(presetHandler.ServeHTTP))
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
		r.handle("POST /api/v1/registry/refresh", Permitted(middleware.PermApplyPreset), refreshHandler)
	}

	// ⭐ The net under the whole API namespace. Registered before the SPA
	// catch-all below, which is what it exists to keep API clients out of.
	r.registerAPIFallback()

	// Web UI catch-all. Must be registered LAST so every explicit
	// /api/v1/* and /health-style route wins ServeMux's longest-prefix
	// match. The handler internally short-circuits when
	// settings.web.enabled is false, so this registration is unconditional
	// — flipping the setting at runtime is enough to disable the UI.
	if r.config.SettingsManager != nil {
		webHandler := web.NewHandler(r.config.SettingsManager, r.logger)
		r.handle("/", PublicUnwrapped(
			"the SPA itself: HTML, JS and assets a browser fetches before it has any credential, so there is "+
				"nobody to authenticate. It is PublicUnwrapped rather than Public because "+
				"SecurityHeadersMiddleware sets `Content-Security-Policy: default-src 'none'`, which is right for "+
				"an API and would blank the page here. The handler short-circuits when settings.web.enabled is "+
				"false, so the switch — not the registration — is what turns the UI off. "+
				"⚠️ It is also the catch-all: every path no /api/v1 pattern claims lands here, which is why the "+
				"deny-by-default guard in Handler() cannot be phrased as \"unmatched means denied\"."),
			webHandler)
	}

	return nil
}

// registerAPIFallback installs the least-specific route under /api/v1/, whose
// only job is to answer JSON where the SPA catch-all would answer HTML.
//
// # What it is for (proposal §2.3, row 1)
//
// `/api/v1/evm/rules/` is a prefix pattern, so a deep path like
// /api/v1/evm/rules/a/b/c/d reaches handler/evm/rule.go today and comes back as
// 400 {"error":"invalid rule_id format"}. Once that handler is decomposed into
// method+wildcard patterns (proposal S3–S8) such a path matches nothing under
// /api/v1/ and falls through to `/` — the SPA — which serves text/html with a
// 200 to a client that is parsing JSON. That is a client-visible regression
// whose error message would have nothing to do with its cause, so the net goes
// in *before* the decomposition can trip it, not with it.
//
// # Why it shadows nothing
//
// Go's ServeMux prefers the more specific pattern, and "more specific" means
// "matches a strict subset". Every other /api/v1 pattern — literal, method
// scoped, wildcard, or a longer prefix — is a strict subset of "/api/v1/", so
// each of them still wins and no pair overlaps without one containing the
// other (which is the shape that would panic at NewRouter; proposal §2.2).
// ⚠️ In particular /api/v1/evm/rules/ keeps answering its own 400: this route
// only ever sees paths that no other pattern claims. Pinned by
// TestAPIFallback_DoesNotShadowRegisteredRoutes and
// TestAPIFallback_RulesPrefixStillAnswersItsOwn400.
//
// ⚠️ One thing it does change, and it is not the 404: a request whose path
// matches a method-scoped route with the wrong method (GET on
// POST /api/v1/evm/simulate). The mux answers 405 only when *nothing* matches;
// this pattern matches, so such a request now gets 404 here. ⛔ In a daemon
// that is not a change — the SPA catch-all already matched those requests and
// returned HTML 200, so there was no 405 to lose. It differs only in a Router
// built without a SettingsManager, i.e. in tests. Proposal §2.3's "405 语义不变"
// is true of the decomposition itself and stops being true once this net
// exists; that trade is deliberate and is the cheaper of the two.
func (r *Router) registerAPIFallback() {
	// ⚠️ AuthenticatedOnly, not Public, and the difference is what an
	// unauthenticated caller learns.
	//
	// Today an unauthenticated request to an unknown /api/v1 path is served by
	// the SPA catch-all: HTML, 200, no credential required. So *neither*
	// constructor would widen anything relative to today. What separates them
	// is what survives when the SPA is disabled (settings.web.enabled=false) or
	// absent (SettingsManager nil — the route below is not registered at all):
	// Public would leave a credential-free oracle over the entire API
	// namespace, answering 404 for a path that has no route and 401 for one
	// that does, which is a map of the route table for anyone who can reach the
	// port. AuthenticatedOnly makes both answer 401, and the authenticated
	// client — the only kind with business under /api/v1 — still gets the JSON
	// 404 this route was added to give it.
	//
	// It carries no permission because there is nothing behind it to hold a
	// permission over: every middleware.Perm* names something a caller may do,
	// and reaching this route means the caller may do nothing, on any of them.
	// ⛔ That is the honest reason, not "internal endpoint".
	r.handle("/api/v1/", AuthenticatedOnly(
		"the least-specific /api/v1/ pattern, and it is not a resource: it answers JSON 404 for API paths no other "+
			"pattern claims, so a client that parses JSON stops receiving the SPA's text/html when a path stops "+
			"matching (proposal §2.3 row 1). No permission, because there is nothing behind it to hold one over — "+
			"a caller who reaches this route may do nothing at all. ⚠️ AuthenticatedOnly rather than Public: today "+
			"these paths are served unauthenticated by the `/` catch-all, so neither choice widens anything, but "+
			"Public would leave an unauthenticated oracle over the whole namespace (404 = no such route, 401 = there "+
			"is one) for daemons whose Web UI is off or absent. Requiring a key makes both 401."),
		http.HandlerFunc(r.apiNotFound))
}

// apiNotFound is the fallback's body: the repo's standard error envelope
// ({"error": ...}, respond.Error), the same one every handler under /api/v1
// already writes, so a client needs no second parser for it.
//
// ⚠️ It deliberately does not echo the requested path. The message is a
// constant: an unmatched path is attacker-controlled input and reflecting it
// buys the caller nothing it did not already type.
func (r *Router) apiNotFound(w http.ResponseWriter, _ *http.Request) {
	respond.Error(w, "not found: no such API endpoint", http.StatusNotFound, r.logger)
}

// withAuth wraps a handler with authentication middleware
func (r *Router) withAuth(h http.Handler) http.Handler {
	middlewares := []func(http.Handler) http.Handler{
		middleware.SecurityHeadersMiddleware(),
		middleware.RecoveryMiddleware(r.logger),
		middleware.ClientIPMiddleware(r.ipWhitelist),
		middleware.LoggingMiddleware(r.logger, r.config.AuditLogger),
		middleware.IPRateLimitMiddleware(r.rateLimiter, r.ipWhitelist, r.liveInt(func(s *settings.SecuritySnapshot) int { return s.IPRateLimit }), r.config.AlertService),
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

// withAuthAndPerm wraps a handler with authentication + RBAC permission
// middleware. ⛔ Reachable only through handle (route_auth.go); calling it and
// handing the result to the mux yourself is what the archcheck `route-auth`
// gate exists to catch, because a route registered that way is absent from the
// authorization table and therefore invisible to everything that reads it.
func (r *Router) withAuthAndPerm(perm middleware.Permission, h http.Handler) http.Handler {
	middlewares := []func(http.Handler) http.Handler{
		middleware.SecurityHeadersMiddleware(),
		middleware.RecoveryMiddleware(r.logger),
		middleware.ClientIPMiddleware(r.ipWhitelist),
		middleware.LoggingMiddleware(r.logger, r.config.AuditLogger),
		middleware.IPRateLimitMiddleware(r.rateLimiter, r.ipWhitelist, r.liveInt(func(s *settings.SecuritySnapshot) int { return s.IPRateLimit }), r.config.AlertService),
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
	if r.config.SettingsManager == nil || !r.config.SettingsManager.Security().ApprovalGuard.Enabled {
		http.Error(w, "approval guard is disabled in runtime settings", http.StatusNotImplemented)
		return
	}
	if r.config.ApprovalGuard == nil {
		r.syncApprovalGuard()
	}
	if r.config.ApprovalGuard == nil {
		http.Error(w, "approval guard failed to start; check daemon logs", http.StatusServiceUnavailable)
		return
	}
	r.config.ApprovalGuard.Resume()
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write([]byte(`{"ok":true,"message":"approval guard resumed"}`)); err != nil {
		r.logger.Error("failed to write guard resume response", "error", err)
	}
}

// syncApprovalGuard wires the live ManualApprovalGuard from runtime security
// settings. Called at startup and after PUT /api/v1/admin/settings/security.
func (r *Router) syncApprovalGuard() {
	if r.config.SettingsManager == nil {
		return
	}
	ag := r.config.SettingsManager.Security().ApprovalGuard
	if !ag.Enabled {
		r.config.ApprovalGuard = nil
		r.signService.SetApprovalGuard(nil)
		if r.healthHandler != nil {
			r.healthHandler.SetApprovalGuard(nil)
		}
		return
	}
	if r.config.ApprovalGuard == nil {
		guard, err := service.NewManualApprovalGuard(service.ManualApprovalGuardConfig{
			Window:                ag.Window,
			RejectionThresholdPct: ag.RejectionThresholdPct,
			MinSamples:            ag.MinSamples,
			ResumeAfter:           ag.ResumeAfter,
			Logger:                r.logger,
		})
		if err != nil {
			r.logger.Error("failed to create approval guard from runtime settings", "error", err)
			return
		}
		r.config.ApprovalGuard = guard
		r.logger.Info("approval guard enabled from runtime settings",
			"window", ag.Window,
			"rejection_threshold_pct", ag.RejectionThresholdPct,
			"min_samples", ag.MinSamples,
			"resume_after", ag.ResumeAfter,
		)
	}
	r.signService.SetApprovalGuard(r.config.ApprovalGuard)
	if r.healthHandler != nil {
		r.healthHandler.SetApprovalGuard(r.config.ApprovalGuard)
	}
}

// Handler returns the HTTP handler.
//
// ⚠️ It is the mux behind the deny-by-default guard, never the bare mux: a
// pattern that reached the mux without going through handle is refused here.
// See the Layer 3 note in route_auth.go for what was there before (nothing) and
// why an unmatched request is deliberately left alone.
func (r *Router) Handler() http.Handler {
	return r.denyUndeclared(r.mux)
}

// StartRateLimitCleanup starts the rate limit cleanup routine
func (r *Router) StartRateLimitCleanup(stop <-chan struct{}) {
	r.rateLimiter.StartCleanupRoutine(5*time.Minute, stop) // every 5 minutes
}

// liveReadOnly returns a closure reading one of the *_api_readonly switches
// from the runtime settings snapshot on every call.
//
// ⚠️ Returning the value instead of the closure is the bug this replaces:
// settings.SecuritySnapshot is reloaded from the database, so a bool captured
// here freezes at boot. internal/settings/model.go promises these become
// "effective without a daemon restart"; before 2026-09-10 flipping
// rules_api_readonly in the Web UI changed the database, changed the snapshot,
// and changed no behaviour at all.
//
// nil when there is no settings manager — the handlers read that as "never
// read-only". Only tests construct a Router without one; the daemon always has
// one (initSettingsStore) and so does the e2e harness.
func (r *Router) liveReadOnly(pick func(*settings.SecuritySnapshot) bool) func() bool {
	if r.config.SettingsManager == nil {
		return nil
	}
	mgr := r.config.SettingsManager
	return func() bool {
		snap := mgr.Security()
		if snap == nil {
			return false
		}
		return pick(snap)
	}
}

// liveInt and liveDuration are liveReadOnly for the knobs that are not bools.
//
// Same reason, same shape: settings.SecuritySnapshot is reloaded from the
// database, so a value read here at wiring time freezes at boot. The zero
// value returned when there is no settings manager means "no limit" /
// "use the handler default", which is what these fields meant when unset.
func (r *Router) liveInt(pick func(*settings.SecuritySnapshot) int) func() int {
	if r.config.SettingsManager == nil {
		return nil
	}
	mgr := r.config.SettingsManager
	return func() int {
		snap := mgr.Security()
		if snap == nil {
			return 0
		}
		return pick(snap)
	}
}

func (r *Router) liveDuration(pick func(*settings.SecuritySnapshot) time.Duration) func() time.Duration {
	if r.config.SettingsManager == nil {
		return nil
	}
	mgr := r.config.SettingsManager
	return func() time.Duration {
		snap := mgr.Security()
		if snap == nil {
			return 0
		}
		return pick(snap)
	}
}
