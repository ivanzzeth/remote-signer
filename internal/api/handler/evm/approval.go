package evm

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

// ApprovalHandler handles manual approval requests
type ApprovalHandler struct {
	signService    service.SignServiceAPI
	accessService  *service.SignerAccessService
	rulesReadOnly  bool // when true, block auto-rule creation during approval
	logger         *slog.Logger
}

// NewApprovalHandler creates a new approval handler
func NewApprovalHandler(signService service.SignServiceAPI, accessService *service.SignerAccessService, logger *slog.Logger, rulesReadOnly bool) (*ApprovalHandler, error) {
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
	RequestID     string     `json:"request_id"`
	Status        string     `json:"status"`
	Signature     string     `json:"signature,omitempty"`
	SignedData    string     `json:"signed_data,omitempty"`
	Message       string     `json:"message,omitempty"`
	GeneratedRule *types.Rule `json:"generated_rule,omitempty"`
}

// PreviewRuleAPIRequest represents the request body for rule preview
type PreviewRuleAPIRequest struct {
	RuleType string `json:"rule_type"` // Required
	RuleMode string `json:"rule_mode"` // Required
	RuleName string `json:"rule_name,omitempty"`
	MaxValue string `json:"max_value,omitempty"` // Required for evm_value_limit
}

// ServeHTTP handles POST /api/v1/evm/requests/{id}/approve
func (h *ApprovalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get API key from context
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract request ID from path
	// Expected: /api/v1/evm/requests/{id}/approve
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 6 {
		h.writeError(w, "invalid path", http.StatusBadRequest)
		return
	}
	requestID := parts[len(parts)-2] // {id} is second to last

	// Parse request body — log details internally, return generic error to client
	var req ApprovalAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("failed to decode approval request", "error", err, "path", r.URL.Path)
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// First, verify the request exists and belongs to this API key
	signReq, err := h.signService.GetRequest(r.Context(), types.SignRequestID(requestID))
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "request not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to get request", "error", err)
		h.writeError(w, "failed to get request", http.StatusInternalServerError)
		return
	}

	// Authorization: only the signer's owner can approve requests.
	// This prevents a compromised agent API key from self-approving transactions
	// on signers it doesn't own. If agent key A submits a request for a signer
	// owned by admin key B, only B can approve it.
	ownership, err := h.accessService.GetOwnership(r.Context(), signReq.SignerAddress)
	if err != nil {
		h.logger.Error("failed to get signer ownership", "signer", signReq.SignerAddress, "error", err)
		h.writeError(w, "failed to verify signer ownership", http.StatusInternalServerError)
		return
	}
	if ownership.OwnerID != apiKey.ID {
		h.logger.Warn("approval denied: caller is not signer owner",
			"request_id", requestID,
			"caller_api_key", apiKey.ID,
			"signer_owner", ownership.OwnerID,
			"signer_address", signReq.SignerAddress,
		)
		h.writeError(w, "not authorized: only the signer owner can approve requests", http.StatusForbidden)
		return
	}

	// Block auto-rule creation when rules API is readonly
	if req.RuleType != "" && h.rulesReadOnly {
		h.writeError(w, "auto-rule creation during approval is disabled (security.rules_api_readonly)", http.StatusForbidden)
		return
	}

	// Build rule options if rule generation is requested
	var ruleOpts *rule.RuleGenerateOptions
	if req.RuleType != "" {
		if !validate.IsValidRuleType(req.RuleType) {
			h.writeError(w, "invalid rule_type", http.StatusBadRequest)
			return
		}
		if req.RuleMode != "" {
			if err := validate.ValidateRuleMode(req.RuleMode); err != nil {
				h.writeError(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if len(req.RuleName) > 255 {
			h.writeError(w, "rule_name must be at most 255 characters", http.StatusBadRequest)
			return
		}
		if req.MaxValue != "" && !validate.IsValidWeiDecimal(req.MaxValue) {
			h.writeError(w, "max_value must be a non-empty decimal string", http.StatusBadRequest)
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
		h.writeError(w, "failed to process approval", http.StatusInternalServerError)
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

	h.writeJSON(w, approvalResp, http.StatusOK)
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

// ServeHTTP handles POST /api/v1/evm/requests/{id}/preview-rule
func (h *PreviewRuleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get API key from context
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract request ID from path
	// Expected: /api/v1/evm/requests/{id}/preview-rule
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 6 {
		h.writeError(w, "invalid path", http.StatusBadRequest)
		return
	}
	requestID := parts[len(parts)-2] // {id} is second to last

	// Parse request body — log details internally, return generic error to client
	var req PreviewRuleAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("failed to decode preview-rule request", "error", err, "path", r.URL.Path)
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields and formats
	if req.RuleType == "" {
		h.writeError(w, "rule_type is required", http.StatusBadRequest)
		return
	}
	if !validate.IsValidRuleType(req.RuleType) {
		h.writeError(w, "invalid rule_type", http.StatusBadRequest)
		return
	}
	if req.RuleMode == "" {
		h.writeError(w, "rule_mode is required", http.StatusBadRequest)
		return
	}
	if err := validate.ValidateRuleMode(req.RuleMode); err != nil {
		h.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.RuleName) > 255 {
		h.writeError(w, "rule_name must be at most 255 characters", http.StatusBadRequest)
		return
	}
	if req.MaxValue != "" && !validate.IsValidWeiDecimal(req.MaxValue) {
		h.writeError(w, "max_value must be a non-empty decimal string", http.StatusBadRequest)
		return
	}

	// First, verify the request exists and belongs to this API key
	signReq, err := h.signService.GetRequest(r.Context(), types.SignRequestID(requestID))
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "request not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to get request", "error", err)
		h.writeError(w, "failed to get request", http.StatusInternalServerError)
		return
	}

	// Check if the API key owns this request
	if signReq.APIKeyID != apiKey.ID {
		h.writeError(w, "not authorized to preview rule for this request", http.StatusForbidden)
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
		h.writeError(w, "failed to preview rule", http.StatusBadRequest)
		return
	}

	h.writeJSON(w, preview, http.StatusOK)
}

func (h *PreviewRuleHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

func (h *PreviewRuleHandler) writeError(w http.ResponseWriter, message string, status int) {
	h.writeJSON(w, ErrorResponse{Error: message}, status)
}

func (h *ApprovalHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

func (h *ApprovalHandler) writeError(w http.ResponseWriter, message string, status int) {
	h.writeJSON(w, ErrorResponse{Error: message}, status)
}
