package api

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/api/handler/evm"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/auth"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
)

// RouterConfig contains configuration for the router
type RouterConfig struct {
	Version string
}

// Router handles HTTP routing
type Router struct {
	mux          *http.ServeMux
	authVerifier *auth.Verifier
	signService  *service.SignService
	rateLimiter  *middleware.RateLimiter
	logger       *slog.Logger
	config       RouterConfig
}

// NewRouter creates a new router
func NewRouter(
	authVerifier *auth.Verifier,
	signService *service.SignService,
	logger *slog.Logger,
	config RouterConfig,
) (*Router, error) {
	r := &Router{
		mux:          http.NewServeMux(),
		authVerifier: authVerifier,
		signService:  signService,
		rateLimiter:  middleware.NewRateLimiter(logger),
		logger:       logger,
		config:       config,
	}

	if err := r.setupRoutes(); err != nil {
		return nil, err
	}

	return r, nil
}

func (r *Router) setupRoutes() error {
	// Health check (no auth required)
	healthHandler := handler.NewHealthHandler(r.config.Version)
	r.mux.Handle("/health", healthHandler)

	// EVM handlers
	signHandler, err := evm.NewSignHandler(r.signService, r.logger)
	if err != nil {
		return err
	}

	requestHandler, err := evm.NewRequestHandler(r.signService, r.logger)
	if err != nil {
		return err
	}

	listHandler, err := evm.NewListHandler(r.signService, r.logger)
	if err != nil {
		return err
	}

	approvalHandler, err := evm.NewApprovalHandler(r.signService, r.logger)
	if err != nil {
		return err
	}

	previewRuleHandler, err := evm.NewPreviewRuleHandler(r.signService, r.logger)
	if err != nil {
		return err
	}

	// EVM routes (with auth)
	r.mux.Handle("/api/v1/evm/sign", r.withAuth(signHandler))
	r.mux.Handle("/api/v1/evm/requests", r.withAuth(listHandler))
	r.mux.Handle("/api/v1/evm/requests/", r.withAuth(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Route to approval handler if path ends with /approve
		if strings.HasSuffix(req.URL.Path, "/approve") {
			approvalHandler.ServeHTTP(w, req)
			return
		}
		// Route to preview-rule handler if path ends with /preview-rule
		if strings.HasSuffix(req.URL.Path, "/preview-rule") {
			previewRuleHandler.ServeHTTP(w, req)
			return
		}
		// Otherwise, route to request handler
		requestHandler.ServeHTTP(w, req)
	})))

	return nil
}

// withAuth wraps a handler with authentication middleware
func (r *Router) withAuth(h http.Handler) http.Handler {
	return r.chain(
		h,
		middleware.RecoveryMiddleware(r.logger),
		middleware.LoggingMiddleware(r.logger),
		middleware.AuthMiddleware(r.authVerifier, r.logger),
		middleware.RateLimitMiddleware(r.rateLimiter),
	)
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
	r.rateLimiter.StartCleanupRoutine(5*60*1000, stop) // every 5 minutes
}
