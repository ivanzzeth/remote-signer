package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ApproveRequest represents a request to approve a signing request.
type ApproveRequest struct {
	Approved bool   `json:"approved"`            // true for approve, false for reject
	RuleType string `json:"rule_type,omitempty"` // evm_address_list, evm_contract_method, evm_value_limit (if set, generates rule)
	RuleMode string `json:"rule_mode,omitempty"` // whitelist, blocklist
	RuleName string `json:"rule_name,omitempty"` // Name for the generated rule
	MaxValue string `json:"max_value,omitempty"` // Required for evm_value_limit
}

// PreviewRuleRequest represents a request to preview a rule for approval.
type PreviewRuleRequest struct {
	RuleType string `json:"rule_type"` // evm_address_list, evm_contract_method, evm_value_limit
	RuleMode string `json:"rule_mode"` // whitelist, blocklist
	RuleName string `json:"rule_name,omitempty"`
	MaxValue string `json:"max_value,omitempty"` // Required for evm_value_limit
}

// ApproveResponse represents the response from an approval request.
type ApproveResponse struct {
	RequestID     string `json:"request_id"`
	Status        string `json:"status"`
	Signature     string `json:"signature,omitempty"`
	SignedData    string `json:"signed_data,omitempty"`
	Message       string `json:"message,omitempty"`
	GeneratedRule *Rule  `json:"generated_rule,omitempty"`
}

// PreviewRuleResponse represents a rule preview for an approval.
type PreviewRuleResponse struct {
	Rule Rule `json:"rule"`
}

// Rule represents an authorization rule.
type Rule struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Description   string     `json:"description,omitempty"`
	Type          string     `json:"type"`
	Mode          string     `json:"mode"`
	Source        string     `json:"source"`
	ChainType     *string    `json:"chain_type,omitempty"`
	ChainID       *string    `json:"chain_id,omitempty"`
	APIKeyID      *string    `json:"api_key_id,omitempty"`
	SignerAddress *string    `json:"signer_address,omitempty"`
	Config        RuleConfig `json:"config,omitempty"`
	Enabled       bool       `json:"enabled"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	MatchCount    uint64     `json:"match_count"`
	LastMatchedAt *time.Time `json:"last_matched_at,omitempty"`
}

// RuleConfig represents the configuration for a rule.
// The actual structure depends on the rule type.
type RuleConfig json.RawMessage

// MarshalJSON implements json.Marshaler.
func (r RuleConfig) MarshalJSON() ([]byte, error) {
	return json.RawMessage(r).MarshalJSON()
}

// UnmarshalJSON implements json.Unmarshaler.
func (r *RuleConfig) UnmarshalJSON(data []byte) error {
	*r = RuleConfig(data)
	return nil
}

// ListRulesResponse represents the response from listing rules.
type ListRulesResponse struct {
	Rules []Rule `json:"rules"`
	Total int    `json:"total"`
}

// AuditRecord represents an audit log entry.
type AuditRecord struct {
	ID            string     `json:"id"`
	EventType     string     `json:"event_type"`
	Severity      string     `json:"severity"`
	Timestamp     time.Time  `json:"timestamp"`
	APIKeyID      string     `json:"api_key_id,omitempty"`
	ActorAddress  string     `json:"actor_address,omitempty"`
	SignRequestID *string    `json:"sign_request_id,omitempty"`
	SignerAddress *string    `json:"signer_address,omitempty"`
	ChainType     *string    `json:"chain_type,omitempty"`
	ChainID       *string    `json:"chain_id,omitempty"`
	RuleID        *string    `json:"rule_id,omitempty"`
	Details       RuleConfig `json:"details,omitempty"` // JSON details
	ErrorMessage  string     `json:"error_message,omitempty"`
	RequestMethod string     `json:"request_method,omitempty"`
	RequestPath   string     `json:"request_path,omitempty"`
}

// ListAuditResponse represents the response from listing audit records.
type ListAuditResponse struct {
	Records      []AuditRecord `json:"records"`
	Total        int           `json:"total"`
	NextCursor   *string       `json:"next_cursor,omitempty"`
	NextCursorID *string       `json:"next_cursor_id,omitempty"`
	HasMore      bool          `json:"has_more"`
}

// ApproveSignRequest approves or rejects a pending signing request.
func (c *Client) ApproveSignRequest(ctx context.Context, requestID string, req *ApproveRequest) (*ApproveResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	path := fmt.Sprintf("/api/v1/evm/requests/%s/approve", requestID)
	httpReq, err := c.newSignedRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp)
	}

	var approveResp ApproveResponse
	if err := json.NewDecoder(resp.Body).Decode(&approveResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &approveResp, nil
}

// PreviewRule previews the rule that would be generated for a pending request.
func (c *Client) PreviewRule(ctx context.Context, requestID string, req *PreviewRuleRequest) (*PreviewRuleResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	path := fmt.Sprintf("/api/v1/evm/requests/%s/preview-rule", requestID)
	httpReq, err := c.newSignedRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp)
	}

	var previewResp PreviewRuleResponse
	if err := json.NewDecoder(resp.Body).Decode(&previewResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &previewResp, nil
}

// ListRulesFilter contains filter options for listing rules.
type ListRulesFilter struct {
	ChainType     string
	SignerAddress string
	APIKeyID      string
	Type          string
	Mode          string
	Enabled       *bool
	Limit         int
	Offset        int
}

// ListRules lists authorization rules with optional filters.
func (c *Client) ListRules(ctx context.Context, filter *ListRulesFilter) (*ListRulesResponse, error) {
	path := "/api/v1/evm/rules"
	params := make([]string, 0)

	if filter != nil {
		if filter.ChainType != "" {
			params = append(params, fmt.Sprintf("chain_type=%s", filter.ChainType))
		}
		if filter.SignerAddress != "" {
			params = append(params, fmt.Sprintf("signer_address=%s", filter.SignerAddress))
		}
		if filter.APIKeyID != "" {
			params = append(params, fmt.Sprintf("api_key_id=%s", filter.APIKeyID))
		}
		if filter.Type != "" {
			params = append(params, fmt.Sprintf("type=%s", filter.Type))
		}
		if filter.Mode != "" {
			params = append(params, fmt.Sprintf("mode=%s", filter.Mode))
		}
		if filter.Enabled != nil {
			params = append(params, fmt.Sprintf("enabled=%t", *filter.Enabled))
		}
		if filter.Limit > 0 {
			params = append(params, fmt.Sprintf("limit=%d", filter.Limit))
		}
		if filter.Offset > 0 {
			params = append(params, fmt.Sprintf("offset=%d", filter.Offset))
		}
	}

	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}

	httpReq, err := c.newSignedRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp)
	}

	var listResp ListRulesResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &listResp, nil
}

// GetRule retrieves a specific rule by ID.
func (c *Client) GetRule(ctx context.Context, ruleID string) (*Rule, error) {
	path := fmt.Sprintf("/api/v1/evm/rules/%s", ruleID)
	httpReq, err := c.newSignedRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp)
	}

	var rule Rule
	if err := json.NewDecoder(resp.Body).Decode(&rule); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &rule, nil
}

// ListAuditFilter contains filter options for listing audit records.
type ListAuditFilter struct {
	EventType     string
	Severity      string
	APIKeyID      string
	SignerAddress string
	ChainType     string
	ChainID       string
	StartTime     *time.Time
	EndTime       *time.Time
	Limit         int
	// Cursor-based pagination
	Cursor   *string
	CursorID *string
}

// ListAuditRecords lists audit records with optional filters.
func (c *Client) ListAuditRecords(ctx context.Context, filter *ListAuditFilter) (*ListAuditResponse, error) {
	path := "/api/v1/audit"
	params := make([]string, 0)

	if filter != nil {
		if filter.EventType != "" {
			params = append(params, fmt.Sprintf("event_type=%s", filter.EventType))
		}
		if filter.Severity != "" {
			params = append(params, fmt.Sprintf("severity=%s", filter.Severity))
		}
		if filter.APIKeyID != "" {
			params = append(params, fmt.Sprintf("api_key_id=%s", filter.APIKeyID))
		}
		if filter.SignerAddress != "" {
			params = append(params, fmt.Sprintf("signer_address=%s", filter.SignerAddress))
		}
		if filter.ChainType != "" {
			params = append(params, fmt.Sprintf("chain_type=%s", filter.ChainType))
		}
		if filter.ChainID != "" {
			params = append(params, fmt.Sprintf("chain_id=%s", filter.ChainID))
		}
		if filter.StartTime != nil {
			params = append(params, fmt.Sprintf("start_time=%s", filter.StartTime.Format(time.RFC3339)))
		}
		if filter.EndTime != nil {
			params = append(params, fmt.Sprintf("end_time=%s", filter.EndTime.Format(time.RFC3339)))
		}
		if filter.Limit > 0 {
			params = append(params, fmt.Sprintf("limit=%d", filter.Limit))
		}
		if filter.Cursor != nil {
			params = append(params, fmt.Sprintf("cursor=%s", url.QueryEscape(*filter.Cursor)))
		}
		if filter.CursorID != nil {
			params = append(params, fmt.Sprintf("cursor_id=%s", url.QueryEscape(*filter.CursorID)))
		}
	}

	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}

	httpReq, err := c.newSignedRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp)
	}

	var listResp ListAuditResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &listResp, nil
}

// CreateRuleRequest represents a request to create a new rule.
type CreateRuleRequest struct {
	Name          string                 `json:"name"`
	Description   string                 `json:"description,omitempty"`
	Type          string                 `json:"type"`
	Mode          string                 `json:"mode"`
	ChainType     *string                `json:"chain_type,omitempty"`
	ChainID       *string                `json:"chain_id,omitempty"`
	APIKeyID      *string                `json:"api_key_id,omitempty"`
	SignerAddress *string                `json:"signer_address,omitempty"`
	Config        map[string]interface{} `json:"config"`
	Enabled       bool                   `json:"enabled"`
}

// UpdateRuleRequest represents a request to update an existing rule.
type UpdateRuleRequest struct {
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Enabled     bool                   `json:"enabled"`
}

// CreateRule creates a new authorization rule.
func (c *Client) CreateRule(ctx context.Context, req *CreateRuleRequest) (*Rule, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	path := "/api/v1/evm/rules"
	httpReq, err := c.newSignedRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, c.parseErrorResponse(resp)
	}

	var rule Rule
	if err := json.NewDecoder(resp.Body).Decode(&rule); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &rule, nil
}

// UpdateRule updates an existing authorization rule.
func (c *Client) UpdateRule(ctx context.Context, ruleID string, req *UpdateRuleRequest) (*Rule, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	path := fmt.Sprintf("/api/v1/evm/rules/%s", ruleID)
	httpReq, err := c.newSignedRequest(ctx, http.MethodPatch, path, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp)
	}

	var rule Rule
	if err := json.NewDecoder(resp.Body).Decode(&rule); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &rule, nil
}

// DeleteRule deletes a rule by ID.
func (c *Client) DeleteRule(ctx context.Context, ruleID string) error {
	path := fmt.Sprintf("/api/v1/evm/rules/%s", ruleID)
	httpReq, err := c.newSignedRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.parseErrorResponse(resp)
	}

	return nil
}

// ToggleRule enables or disables a rule.
func (c *Client) ToggleRule(ctx context.Context, ruleID string, enabled bool) (*Rule, error) {
	body, err := json.Marshal(map[string]bool{"enabled": enabled})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	path := fmt.Sprintf("/api/v1/evm/rules/%s", ruleID)
	httpReq, err := c.newSignedRequest(ctx, http.MethodPatch, path, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp)
	}

	var rule Rule
	if err := json.NewDecoder(resp.Body).Decode(&rule); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &rule, nil
}

// Signer represents a signer configuration.
type Signer struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
}

// ListSignersResponse represents the response from listing signers.
type ListSignersResponse struct {
	Signers []Signer `json:"signers"`
	Total   int      `json:"total"`
	HasMore bool     `json:"has_more"`
}

// CreateSignerRequest represents a request to create a new signer.
type CreateSignerRequest struct {
	Type     string                 `json:"type"`
	Keystore *CreateKeystoreParams  `json:"keystore,omitempty"`
}

// CreateKeystoreParams contains parameters for creating a keystore signer.
type CreateKeystoreParams struct {
	Password string `json:"password"`
}

// ListSignersFilter contains filter options for listing signers.
type ListSignersFilter struct {
	Type   string
	Offset int
	Limit  int
}

// ListSigners lists available signers with optional filters.
func (c *Client) ListSigners(ctx context.Context, filter *ListSignersFilter) (*ListSignersResponse, error) {
	path := "/api/v1/evm/signers"
	params := make([]string, 0)

	if filter != nil {
		if filter.Type != "" {
			params = append(params, fmt.Sprintf("type=%s", filter.Type))
		}
		if filter.Limit > 0 {
			params = append(params, fmt.Sprintf("limit=%d", filter.Limit))
		}
		if filter.Offset > 0 {
			params = append(params, fmt.Sprintf("offset=%d", filter.Offset))
		}
	}

	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}

	httpReq, err := c.newSignedRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp)
	}

	var listResp ListSignersResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &listResp, nil
}

// CreateSigner creates a new signer (admin only).
func (c *Client) CreateSigner(ctx context.Context, req *CreateSignerRequest) (*Signer, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	path := "/api/v1/evm/signers"
	httpReq, err := c.newSignedRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, c.parseErrorResponse(resp)
	}

	var signer Signer
	if err := json.NewDecoder(resp.Body).Decode(&signer); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &signer, nil
}
