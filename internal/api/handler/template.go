package handler

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// TemplateHandler handles template management and instance creation endpoints
type TemplateHandler struct {
	templateRepo    storage.TemplateRepository
	templateService *service.TemplateService
	readOnly        bool // when true, block all template mutations via API
	logger          *slog.Logger
	requireApproval bool
	apiKeyRepo      storage.APIKeyRepository
}

// TemplateHandlerOption is a functional option for TemplateHandler.
type TemplateHandlerOption func(*TemplateHandler)

// WithTemplateRequireApproval enables admin approval for agent whitelist rules created via template instantiation.
func WithTemplateRequireApproval(v bool) TemplateHandlerOption {
	return func(h *TemplateHandler) {
		h.requireApproval = v
	}
}

// WithTemplateAPIKeyRepo sets the API key repository for applied_to validation.
func WithTemplateAPIKeyRepo(repo storage.APIKeyRepository) TemplateHandlerOption {
	return func(h *TemplateHandler) {
		h.apiKeyRepo = repo
	}
}

// NewTemplateHandler creates a new template handler
func NewTemplateHandler(
	templateRepo storage.TemplateRepository,
	templateService *service.TemplateService,
	logger *slog.Logger,
	readOnly bool,
	opts ...TemplateHandlerOption,
) (*TemplateHandler, error) {
	if templateRepo == nil {
		return nil, fmt.Errorf("template repository is required")
	}
	if templateService == nil {
		return nil, fmt.Errorf("template service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	h := &TemplateHandler{
		templateRepo:    templateRepo,
		templateService: templateService,
		readOnly:        readOnly,
		logger:          logger,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h, nil
}

// ServeHTTP handles /api/v1/templates and /api/v1/templates/{id}
func (h *TemplateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get API key from context (for audit)
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Path: /api/v1/templates or /api/v1/templates/{id} or /api/v1/templates/{id}/instantiate.
	// EscapedPath instead of Path so file-stem IDs containing '/'
	// (v0.3 Registry: "evm/erc20") round-trip through the SDK's
	// encodeURIComponent unchanged.
	rawPath := strings.TrimPrefix(r.URL.EscapedPath(), "/api/v1/templates")
	rawPath = strings.TrimPrefix(rawPath, "/")

	if rawPath == "" {
		switch r.Method {
		case http.MethodGet:
			h.listTemplates(w, r)
		case http.MethodPost:
			h.createTemplate(w, r)
		default:
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	encodedID := rawPath
	sub := ""
	if strings.HasSuffix(rawPath, "/instantiate") {
		encodedID = strings.TrimSuffix(rawPath, "/instantiate")
		sub = "instantiate"
	}
	templateID, err := url.PathUnescape(encodedID)
	if err != nil {
		h.writeError(w, "invalid template id", http.StatusBadRequest)
		return
	}

	if sub == "instantiate" {
		if r.Method == http.MethodPost {
			h.instantiateTemplate(w, r, templateID)
		} else {
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getTemplate(w, r, templateID)
	case http.MethodDelete:
		h.deleteTemplate(w, r, templateID)
	case http.MethodPatch:
		h.updateTemplate(w, r, templateID)
	default:
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ServeInstanceHTTP handles /api/v1/templates/instances/{ruleID}/revoke
func (h *TemplateHandler) ServeInstanceHTTP(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Path: /api/v1/templates/instances/{ruleID}/revoke
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/templates/instances/")

	if strings.HasSuffix(path, "/revoke") {
		ruleID := strings.TrimSuffix(path, "/revoke")
		if r.Method == http.MethodPost {
			h.revokeInstance(w, r, ruleID)
		} else {
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	h.writeError(w, "not found", http.StatusNotFound)
}
