package evm

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/api/respond"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

// ApprovalHandler handles manual approval requests
type ApprovalHandler struct {
	signService   service.SignServiceAPI
	accessService *service.SignerAccessService
	rulesReadOnly func() bool // when true, block auto-rule creation during approval
	logger        *slog.Logger
}

// NewApprovalHandler creates a new approval handler
func NewApprovalHandler(signService service.SignServiceAPI, accessService *service.SignerAccessService, logger *slog.Logger, rulesReadOnly func() bool) (*ApprovalHandler, error) {
	if signService == nil {
		return nil, fmt.Errorf("sign service is required")
	}
	if accessService == nil {
		return nil, fmt.Errorf("access service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &ApprovalHandler{
		signService:   signService,
		accessService: accessService,
		rulesReadOnly: rulesReadOnly,
		logger:        logger,
	}, nil
}

// ApprovalAPIRequest represents the request body for approval
type ApprovalAPIRequest struct {
	Approved bool   `json:"approved"`
	RuleType string `json:"rule_type,omitempty"` // evm_address_list, evm_contract_method, evm_value_limit
	RuleMode string `json:"rule_mode,omitempty"` // whitelist, blocklist
	RuleName string `json:"rule_name,omitempty"`
	MaxValue string `json:"max_value,omitempty"` // Required for evm_value_limit
}

// ApprovalAPIResponse represents the response for an approval request
type ApprovalAPIResponse struct {
	RequestID     string      `json:"request_id"`
	Status        string      `json:"status"`
	Signature     string      `json:"signature,omitempty"`
	SignedData    string      `json:"signed_data,omitempty"`
	Message       string      `json:"message,omitempty"`
	GeneratedRule *types.Rule `json:"generated_rule,omitempty"`
}

// PreviewRuleAPIRequest represents the request body for rule preview
type PreviewRuleAPIRequest struct {
	RuleType string `json:"rule_type"` // Required
	RuleMode string `json:"rule_mode"` // Required
	RuleName string `json:"rule_name,omitempty"`
	MaxValue string `json:"max_value,omitempty"` // Required for evm_value_limit
}

// ServeHTTP serves POST /api/v1/evm/requests/{id}/approve — one endpoint, one
// route (internal/api/module_requests.go).
//
// ⛔ It used to sit behind the method-less "/api/v1/evm/requests/" prefix and a
// closure that picked it by strings.HasSuffix(path, "/approve"), so it read
// parts[len-2] as the id. That accepted *any* depth, and unlike the wrong-verb
// shapes it was not refused: measured before the change,
// POST /api/v1/evm/requests/a/b/approve approved request "b" and
// POST /api/v1/evm/requests/a/b/c/d/approve approved request "d" — a mutation
// whose path named a different resource than the row it changed. {id} is exactly
// one segment, so that is unrepresentable now.
func (h *ApprovalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get API key from context
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}

	requestID := r.PathValue("id")

	// Parse request body — log details internally, return generic error to client
	var req ApprovalAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("failed to decode approval request", "error", err, "pattern", r.Pattern)
		respond.Error(w, "invalid request body", http.StatusBadRequest, h.logger)
		return
	}

	// First, verify the request exists and belongs to this API key
	signReq, err := h.signService.GetRequest(r.Context(), types.SignRequestID(requestID))
	if err != nil {
		if types.IsNotFound(err) {
			respond.Error(w, "request not found", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("failed to get request", "error", err)
		respond.Error(w, "failed to get request", http.StatusInternalServerError, h.logger)
		return
	}

	ownership, err := h.accessService.GetOwnership(r.Context(), signReq.SignerAddress)
	if err != nil {
		h.logger.Error("failed to get signer ownership", "signer", signReq.SignerAddress, "error", err)
		respond.Error(w, "failed to verify signer ownership", http.StatusInternalServerError, h.logger)
		return
	}

	// Authorization for manual approval:
	// - Admin (PermApproveRequest) may approve any authorizing request — the
	//   typical ops path when an agent-owned signer submits a request.
	// - Other roles cannot reach this handler (RBAC middleware); the owner
	//   check remains as defense-in-depth if that ever changes.
	if !middleware.HasPermission(apiKey.Role, middleware.PermApproveRequest) {
		if ownership.OwnerID != apiKey.ID {
			h.logger.Warn("approval denied: caller is not signer owner",
				"request_id", requestID,
				"caller_api_key", apiKey.ID,
				"signer_owner", ownership.OwnerID,
				"signer_address", signReq.SignerAddress,
			)
			respond.Error(w, "not authorized: only the signer owner can approve requests", http.StatusForbidden, h.logger)
			return
		}
	}

	// Block auto-rule creation when rules API is readonly
	if req.RuleType != "" && h.isReadOnly() {
		respond.Error(w, "auto-rule creation during approval is disabled (security.rules_api_readonly)", http.StatusForbidden, h.logger)
		return
	}

	// Build rule options if rule generation is requested
	var ruleOpts *rule.RuleGenerateOptions
	if req.RuleType != "" {
		if !validate.IsValidRuleType(req.RuleType) {
			respond.Error(w, "invalid rule_type", http.StatusBadRequest, h.logger)
			return
		}
		if req.RuleMode != "" {
			if err := validate.ValidateRuleMode(req.RuleMode); err != nil {
				respond.Error(w, err.Error(), http.StatusBadRequest, h.logger)
				return
			}
		}
		if len(req.RuleName) > 255 {
			respond.Error(w, "rule_name must be at most 255 characters", http.StatusBadRequest, h.logger)
			return
		}
		if req.MaxValue != "" && !validate.IsValidWeiDecimal(req.MaxValue) {
			respond.Error(w, "max_value must be a non-empty decimal string", http.StatusBadRequest, h.logger)
			return
		}
		ruleOpts = &rule.RuleGenerateOptions{
			RuleType: types.RuleType(req.RuleType),
			RuleMode: types.RuleMode(req.RuleMode),
			RuleName: req.RuleName,
		}
		if req.MaxValue != "" {
			ruleOpts.MaxValue = &req.MaxValue
		}
	}

	// Process approval
	approvalReq := &service.ApprovalRequest{
		Approved:   req.Approved,
		ApprovedBy: apiKey.ID,
		RuleOpts:   ruleOpts,
	}

	resp, err := h.signService.ProcessApproval(r.Context(), types.SignRequestID(requestID), approvalReq)
	if err != nil {
		h.logger.Error("failed to process approval", "error", err, "request_id", requestID)
		if errors.Is(err, service.ErrApprovalConflict) {
			respond.Error(w, err.Error(), http.StatusConflict, h.logger)
			return
		}
		// A locked signer is an operator-actionable state, not an internal
		// fault — surface 423 with the underlying reason so the UI can
		// prompt the user to unlock before retrying. Any wording containing
		// "is locked" comes from chain adapters' GetSigner path.
		if strings.Contains(err.Error(), "is locked") {
			respond.Error(w, "signer is locked — unlock it before approving", http.StatusLocked, h.logger)
			return
		}
		respond.Error(w, "failed to process approval", http.StatusInternalServerError, h.logger)
		return
	}

	// Build response
	approvalResp := ApprovalAPIResponse{
		RequestID:     string(resp.SignResponse.RequestID),
		Status:        string(resp.SignResponse.Status),
		Message:       resp.SignResponse.Message,
		GeneratedRule: resp.GeneratedRule,
	}
	if len(resp.SignResponse.Signature) > 0 {
		approvalResp.Signature = fmt.Sprintf("0x%x", resp.SignResponse.Signature)
	}
	if len(resp.SignResponse.SignedData) > 0 {
		approvalResp.SignedData = fmt.Sprintf("0x%x", resp.SignResponse.SignedData)
	}

	respond.JSON(w, approvalResp, http.StatusOK, h.logger)
}

// PreviewRuleHandler handles POST /api/v1/evm/requests/{id}/preview-rule
type PreviewRuleHandler struct {
	signService service.SignServiceAPI
	logger      *slog.Logger
}

// NewPreviewRuleHandler creates a new preview rule handler
func NewPreviewRuleHandler(signService service.SignServiceAPI, logger *slog.Logger) (*PreviewRuleHandler, error) {
	if signService == nil {
		return nil, fmt.Errorf("sign service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &PreviewRuleHandler{
		signService: signService,
		logger:      logger,
	}, nil
}

// ServeHTTP serves POST /api/v1/evm/requests/{id}/preview-rule — one endpoint,
// one route (internal/api/module_requests.go).
//
// ⚠️ Same shape as ApprovalHandler above and the same depth swallow: the closure
// picked it by strings.HasSuffix(path, "/preview-rule") and it read parts[len-2],
// so POST /api/v1/evm/requests/a/b/preview-rule previewed a rule for request "b"
// (measured). This one only reads, so it was a wrong-answer bug rather than a
// wrong-mutation one; {id} is one segment and neither is possible now.
func (h *PreviewRuleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get API key from context
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}

	requestID := r.PathValue("id")

	// Parse request body — log details internally, return generic error to client
	var req PreviewRuleAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("failed to decode preview-rule request", "error", err, "pattern", r.Pattern)
		respond.Error(w, "invalid request body", http.StatusBadRequest, h.logger)
		return
	}

	// Validate required fields and formats
	if req.RuleType == "" {
		respond.Error(w, "rule_type is required", http.StatusBadRequest, h.logger)
		return
	}
	if !validate.IsValidRuleType(req.RuleType) {
		respond.Error(w, "invalid rule_type", http.StatusBadRequest, h.logger)
		return
	}
	if req.RuleMode == "" {
		respond.Error(w, "rule_mode is required", http.StatusBadRequest, h.logger)
		return
	}
	if err := validate.ValidateRuleMode(req.RuleMode); err != nil {
		respond.Error(w, err.Error(), http.StatusBadRequest, h.logger)
		return
	}
	if len(req.RuleName) > 255 {
		respond.Error(w, "rule_name must be at most 255 characters", http.StatusBadRequest, h.logger)
		return
	}
	if req.MaxValue != "" && !validate.IsValidWeiDecimal(req.MaxValue) {
		respond.Error(w, "max_value must be a non-empty decimal string", http.StatusBadRequest, h.logger)
		return
	}

	// First, verify the request exists and belongs to this API key
	signReq, err := h.signService.GetRequest(r.Context(), types.SignRequestID(requestID))
	if err != nil {
		if types.IsNotFound(err) {
			respond.Error(w, "request not found", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("failed to get request", "error", err)
		respond.Error(w, "failed to get request", http.StatusInternalServerError, h.logger)
		return
	}

	// Authorization for preview:
	// - Admin may preview any request (same queue they approve in the UI).
	// - Everyone else may preview only requests they submitted.
	if !middleware.HasPermission(apiKey.Role, middleware.PermApproveRequest) &&
		signReq.APIKeyID != apiKey.ID {
		respond.Error(w, "not authorized to preview rule for this request", http.StatusForbidden, h.logger)
		return
	}

	// Build rule options
	ruleOpts := &rule.RuleGenerateOptions{
		RuleType: types.RuleType(req.RuleType),
		RuleMode: types.RuleMode(req.RuleMode),
		RuleName: req.RuleName,
	}
	if req.MaxValue != "" {
		ruleOpts.MaxValue = &req.MaxValue
	}

	// Generate preview
	preview, err := h.signService.PreviewRuleForRequest(r.Context(), types.SignRequestID(requestID), ruleOpts)
	if err != nil {
		h.logger.Error("failed to preview rule", "error", err, "request_id", requestID)
		respond.Error(w, previewRuleClientError(err), http.StatusBadRequest, h.logger)
		return
	}

	respond.JSON(w, preview, http.StatusOK, h.logger)
}

// previewRuleClientError maps generator/service failures to operator-facing text.
// Auth and validation errors are returned verbatim earlier in the handler.
func previewRuleClientError(err error) string {
	if err == nil {
		return "failed to preview rule"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not pending approval"):
		return "request is not awaiting approval"
	case strings.Contains(msg, "cannot generate address list rule"):
		return "cannot generate address list rule: transaction requests need a recipient (to) address"
	case strings.Contains(msg, "cannot generate contract method rule"):
		return "cannot generate contract method rule: transaction requests need contract calldata"
	case strings.Contains(msg, "max_value is required"):
		return "max_value is required for evm_value_limit rule type"
	default:
		return "failed to preview rule"
	}
}

// readOnly reports whether write operations are blocked right now.
//
// It is a function, not a bool, because the setting behind it is runtime
// mutable: settings.SecuritySnapshot is reloaded from the database, and a
// value copied into this struct at construction would freeze at boot. That
// was the actual behaviour until 2026-09-10 — internal/settings/model.go
// promises settings become "effective without a daemon restart", and for this
// one, flipping it in the Web UI changed the database, changed the snapshot,
// and changed nothing else.
//
// nil means "never read-only", which is the permissive direction; the router
// only leaves it nil when there is no settings manager at all (tests).
func (h *ApprovalHandler) isReadOnly() bool {
	if h.rulesReadOnly == nil {
		return false
	}
	return h.rulesReadOnly()
}
