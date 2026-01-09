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
)

// ApprovalHandler handles manual approval requests
type ApprovalHandler struct {
	signService *service.SignService
	logger      *slog.Logger
}

// NewApprovalHandler creates a new approval handler
func NewApprovalHandler(signService *service.SignService, logger *slog.Logger) (*ApprovalHandler, error) {
	if signService == nil {
		return nil, fmt.Errorf("sign service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &ApprovalHandler{
		signService: signService,
		logger:      logger,
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

	// Parse request body
	var req ApprovalAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
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
		h.writeError(w, "not authorized to approve this request", http.StatusForbidden)
		return
	}

	// Build rule options if rule generation is requested
	var ruleOpts *rule.RuleGenerateOptions
	if req.RuleType != "" {
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
		h.writeError(w, fmt.Sprintf("failed to process approval: %v", err), http.StatusInternalServerError)
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
	signService *service.SignService
	logger      *slog.Logger
}

// NewPreviewRuleHandler creates a new preview rule handler
func NewPreviewRuleHandler(signService *service.SignService, logger *slog.Logger) (*PreviewRuleHandler, error) {
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

	// Parse request body
	var req PreviewRuleAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.RuleType == "" {
		h.writeError(w, "rule_type is required", http.StatusBadRequest)
		return
	}
	if req.RuleMode == "" {
		h.writeError(w, "rule_mode is required", http.StatusBadRequest)
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
		h.writeError(w, fmt.Sprintf("failed to preview rule: %v", err), http.StatusBadRequest)
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
