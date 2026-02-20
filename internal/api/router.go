package api

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	evmhandler "github.com/ivanzzeth/remote-signer/internal/api/handler/evm"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/auth"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// RouterConfig contains configuration for the router
type RouterConfig struct {
	Version            string
	IPWhitelistConfig  *middleware.IPWhitelist
	SolidityValidator  *evm.SolidityRuleValidator
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
	r.mux.Handle("/health", middleware.SecurityHeadersMiddleware()(healthHandler))

	// EVM handlers
	signHandler, err := evmhandler.NewSignHandler(r.signService, r.logger)
	if err != nil {
		return err
	}

	requestHandler, err := evmhandler.NewRequestHandler(r.signService, r.logger)
	if err != nil {
		return err
	}

	listHandler, err := evmhandler.NewListHandler(r.signService, r.logger)
	if err != nil {
		return err
	}

	approvalHandler, err := evmhandler.NewApprovalHandler(r.signService, r.logger)
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
	ruleHandler, err := evmhandler.NewRuleHandler(r.ruleRepo, r.logger, ruleHandlerOpts...)
	if err != nil {
		return err
	}

	signerHandler, err := evmhandler.NewSignerHandler(r.signerManager, r.logger)
	if err != nil {
		return err
	}

	// Audit handler
	auditHandler, err := handler.NewAuditHandler(r.auditRepo, r.logger)
	if err != nil {
		return err
	}

	// EVM routes (with auth)
	r.mux.Handle("/api/v1/evm/sign", r.withAuth(signHandler))
	r.mux.Handle("/api/v1/evm/requests", r.withAuth(listHandler))
	r.mux.Handle("/api/v1/evm/requests/", r.withAuth(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Route to approval handler if path ends with /approve (admin only)
		if strings.HasSuffix(req.URL.Path, "/approve") {
			r.requireAdmin(approvalHandler).ServeHTTP(w, req)
			return
		}
		// Route to preview-rule handler if path ends with /preview-rule (admin only)
		if strings.HasSuffix(req.URL.Path, "/preview-rule") {
			r.requireAdmin(previewRuleHandler).ServeHTTP(w, req)
			return
		}
		// Otherwise, route to request handler
		requestHandler.ServeHTTP(w, req)
	})))

	// Rule management routes (with auth + admin required for all operations)
	r.mux.Handle("/api/v1/evm/rules", r.withAuthAndAdmin(ruleHandler))
	r.mux.Handle("/api/v1/evm/rules/", r.withAuthAndAdmin(ruleHandler))

	// Signer management routes (GET with auth, POST with auth + admin)
	r.mux.Handle("/api/v1/evm/signers", r.withAuth(signerHandler))

	// Audit routes (with auth + admin required — audit logs contain sensitive data)
	r.mux.Handle("/api/v1/audit", r.withAuthAndAdmin(auditHandler))

	return nil
}

// withAuth wraps a handler with authentication middleware
func (r *Router) withAuth(h http.Handler) http.Handler {
	middlewares := []func(http.Handler) http.Handler{
		middleware.SecurityHeadersMiddleware(),
		middleware.RecoveryMiddleware(r.logger),
		middleware.LoggingMiddleware(r.logger),
		middleware.AuthMiddleware(r.authVerifier, r.logger),
		middleware.RateLimitMiddleware(r.rateLimiter),
	}
	// Add IP whitelist as outermost middleware (checked first)
	if r.ipWhitelist != nil {
		middlewares = append(middlewares, middleware.IPWhitelistMiddleware(r.ipWhitelist))
	}
	return r.chain(h, middlewares...)
}

// requireAdmin wraps a handler with admin middleware (must be used after auth)
func (r *Router) requireAdmin(h http.Handler) http.Handler {
	return middleware.AdminMiddleware(r.logger)(h)
}

// withAuthAndAdmin wraps a handler with authentication and admin middleware
func (r *Router) withAuthAndAdmin(h http.Handler) http.Handler {
	middlewares := []func(http.Handler) http.Handler{
		middleware.SecurityHeadersMiddleware(),
		middleware.RecoveryMiddleware(r.logger),
		middleware.LoggingMiddleware(r.logger),
		middleware.AuthMiddleware(r.authVerifier, r.logger),
		middleware.AdminMiddleware(r.logger),
		middleware.RateLimitMiddleware(r.rateLimiter),
	}
	// Add IP whitelist as outermost middleware (checked first)
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

// Handler returns the HTTP handler
func (r *Router) Handler() http.Handler {
	return r.mux
}

// StartRateLimitCleanup starts the rate limit cleanup routine
func (r *Router) StartRateLimitCleanup(stop <-chan struct{}) {
	r.rateLimiter.StartCleanupRoutine(5*time.Minute, stop) // every 5 minutes
}
