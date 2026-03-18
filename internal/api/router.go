package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	evmhandler "github.com/ivanzzeth/remote-signer/internal/api/handler/evm"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/core/auth"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/metrics"
	"github.com/ivanzzeth/remote-signer/internal/simulation"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// TemplateConfig contains template-related dependencies for the router
type TemplateConfig struct {
	TemplateRepo    storage.TemplateRepository
	TemplateService *service.TemplateService
}

// RouterConfig contains configuration for the router
type RouterConfig struct {
	Version                  string
	IPWhitelistConfig        *middleware.IPWhitelist
	IPWhitelistConfigForRead *config.IPWhitelistConfig // optional: for GET /api/v1/acls/ip-whitelist (admin, read-only)
	IPRateLimit              int                       // requests per minute per IP (pre-auth); 0 = use default (200)
	SolidityValidator        *evm.SolidityRuleValidator
	JSEvaluator              *evm.JSRuleEvaluator
	Template                 *TemplateConfig
	ApprovalGuard            *service.ManualApprovalGuard     // optional: for admin resume endpoint
	APIKeyRepo               storage.APIKeyRepository         // optional: for signer access visibility and API key management
	SignerOwnershipRepo      storage.SignerOwnershipRepository // for signer ownership tracking
	SignerAccessRepo         storage.SignerAccessRepository    // for signer access grants
	RulesAPIReadonly         bool                             // block rule/template mutations via API
	SignersAPIReadonly       bool                             // block signer/HD-wallet creation via API
	APIKeysAPIReadonly       bool                             // block API key management via API
	AlertService             *middleware.SecurityAlertService // optional: real-time security alerts
	AuditLogger              *audit.AuditLogger               // optional: persistent audit logging
	SignTimeout              time.Duration                    // context timeout for sign operations (default: 30s)
	AutoLockTimeout          time.Duration                    // signer auto-lock timeout (for health endpoint)
	AuditRetentionDays       int                              // audit log retention days (for health endpoint)
	BudgetRepo                    storage.BudgetRepository         // optional: for GET /api/v1/evm/rules/{id}/budgets
	MaxRulesPerAPIKey             int                              // per-key rule count limit (0 = no limit, default 50)
	RequireApprovalForAgentRules  bool                             // require admin approval for agent whitelist rules
	// Preset API (admin-only). When PresetsDir is non-empty, GET/POST /api/v1/presets are registered.
	PresetsDir string   // directory containing preset YAML files (resolved absolute path)
	PresetsDB  *gorm.DB // optional: for preset apply transaction; required when PresetsDir is set and template service is used
	// Resource limits
	MaxKeystoresPerKey int // max keystores per API key (0 = no limit, default 5)
	MaxHDWalletsPerKey int // max HD wallets per API key (0 = no limit, default 3)
	// Simulation engine (optional). When set, POST /api/v1/evm/simulate, /simulate/batch, and /sign/batch are registered.
	Simulator simulation.AnvilForkManager
	// SimulationRule is the built-in simulation budget fallback rule (optional).
	// When set together with Simulator, the batch sign endpoint uses it for transactions
	// that don't match any user-defined whitelist rule.
	SimulationRule *evm.SimulationBudgetRule
	// RuleEngine is required for batch sign to evaluate rules per-tx before signing.
	RuleEngine rule.RuleEngine
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

	approvalHandler, err := evmhandler.NewApprovalHandler(r.signService, r.logger, r.config.RulesAPIReadonly)
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
		// Otherwise, route to request handler (any authenticated user can view own requests)
		requestHandler.ServeHTTP(w, req)
	})))

	// Rule management routes (RBAC: PermListRules covers GET for admin/dev/agent)
	r.mux.Handle("/api/v1/evm/rules", r.withAuthAndPerm(middleware.PermListRules, ruleHandler))
	r.mux.Handle("/api/v1/evm/rules/", r.withAuthAndPerm(middleware.PermListRules, ruleHandler))

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
		r.mux.Handle("/api/v1/api-keys", r.withAuthAndPerm(middleware.PermManageAPIKeys, apiKeyHandler))
		r.mux.Handle("/api/v1/api-keys/", r.withAuthAndPerm(middleware.PermManageAPIKeys, http.HandlerFunc(apiKeyHandler.ServeKeyHTTP)))
	}

	// ACLs read-only routes (admin only): IP whitelist config
	if r.config.IPWhitelistConfigForRead != nil {
		aclHandler := handler.NewACLHandler(r.config.IPWhitelistConfigForRead)
		r.mux.Handle("/api/v1/acls/ip-whitelist", r.withAuthAndPerm(middleware.PermReadACLs, aclHandler))
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
	if r.config.PresetsDir != "" {
		var templateSvc *service.TemplateService
		if r.config.Template != nil {
			templateSvc = r.config.Template.TemplateService
		}
		presetHandler, err := handler.NewPresetHandler(
			r.config.PresetsDir,
			r.config.PresetsDB,
			templateSvc,
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
