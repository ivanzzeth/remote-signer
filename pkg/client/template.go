package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Template represents a rule template.
type Template struct {
	ID             string             `json:"id"`
	Name           string             `json:"name"`
	Description    string             `json:"description,omitempty"`
	Type           string             `json:"type"`
	Mode           string             `json:"mode"`
	Source         string             `json:"source"`
	Variables      []TemplateVariable `json:"variables,omitempty"`
	Config         RuleConfig         `json:"config,omitempty"`
	BudgetMetering RuleConfig         `json:"budget_metering,omitempty"`
	Enabled        bool               `json:"enabled"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
}

// TemplateVariable describes a variable in a rule template.
type TemplateVariable struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"`
}

// ListTemplatesResponse represents the response from listing templates.
type ListTemplatesResponse struct {
	Templates []Template `json:"templates"`
	Total     int        `json:"total"`
}

// ListTemplatesFilter contains filter options for listing templates.
type ListTemplatesFilter struct {
	Type    string
	Source  string
	Enabled *bool
	Limit   int
	Offset  int
}

// CreateTemplateRequest represents a request to create a new template.
type CreateTemplateRequest struct {
	Name           string                 `json:"name"`
	Description    string                 `json:"description,omitempty"`
	Type           string                 `json:"type"`
	Mode           string                 `json:"mode"`
	Variables      []TemplateVariable     `json:"variables,omitempty"`
	Config         map[string]interface{} `json:"config"`
	BudgetMetering map[string]interface{} `json:"budget_metering,omitempty"`
	TestVariables  map[string]string      `json:"test_variables,omitempty"`
	Enabled        bool                   `json:"enabled"`
}

// UpdateTemplateRequest represents a request to update a template.
type UpdateTemplateRequest struct {
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Enabled     *bool                  `json:"enabled,omitempty"`
}

// InstantiateTemplateRequest represents a request to create a rule instance from a template.
type InstantiateTemplateRequest struct {
	TemplateName  string            `json:"template_name,omitempty"`
	Name          string            `json:"name,omitempty"`
	Variables     map[string]string `json:"variables"`
	ChainType     *string           `json:"chain_type,omitempty"`
	ChainID       *string           `json:"chain_id,omitempty"`
	APIKeyID      *string           `json:"api_key_id,omitempty"`
	SignerAddress *string           `json:"signer_address,omitempty"`
	ExpiresAt     *time.Time        `json:"expires_at,omitempty"`
	ExpiresIn     *string           `json:"expires_in,omitempty"`
	Budget        *BudgetConfig     `json:"budget,omitempty"`
	Schedule      *ScheduleConfig   `json:"schedule,omitempty"`
}

// BudgetConfig defines budget limits for an instance.
type BudgetConfig struct {
	MaxTotal   string `json:"max_total"`
	MaxPerTx   string `json:"max_per_tx"`
	MaxTxCount int    `json:"max_tx_count,omitempty"`
	AlertPct   int    `json:"alert_pct,omitempty"`
}

// ScheduleConfig defines periodic budget renewal.
type ScheduleConfig struct {
	Period  string     `json:"period"`
	StartAt *time.Time `json:"start_at,omitempty"`
}

// InstantiateTemplateResponse represents the response from creating a rule instance.
type InstantiateTemplateResponse struct {
	Rule   json.RawMessage `json:"rule"`
	Budget json.RawMessage `json:"budget,omitempty"`
}

// RevokeInstanceResponse represents the response from revoking an instance.
type RevokeInstanceResponse struct {
	Status string `json:"status"`
	RuleID string `json:"rule_id"`
}

// ListTemplates lists rule templates with optional filters.
func (c *Client) ListTemplates(ctx context.Context, filter *ListTemplatesFilter) (*ListTemplatesResponse, error) {
	path := "/api/v1/templates"
	params := make([]string, 0)

	if filter != nil {
		if filter.Type != "" {
			params = append(params, fmt.Sprintf("type=%s", filter.Type))
		}
		if filter.Source != "" {
			params = append(params, fmt.Sprintf("source=%s", filter.Source))
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

	var listResp ListTemplatesResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &listResp, nil
}

// GetTemplate retrieves a specific template by ID.
func (c *Client) GetTemplate(ctx context.Context, templateID string) (*Template, error) {
	path := fmt.Sprintf("/api/v1/templates/%s", templateID)
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

	var tmpl Template
	if err := json.NewDecoder(resp.Body).Decode(&tmpl); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tmpl, nil
}

// CreateTemplate creates a new rule template (admin only).
func (c *Client) CreateTemplate(ctx context.Context, req *CreateTemplateRequest) (*Template, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	path := "/api/v1/templates"
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

	var tmpl Template
	if err := json.NewDecoder(resp.Body).Decode(&tmpl); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tmpl, nil
}

// UpdateTemplate updates an existing template (admin only).
func (c *Client) UpdateTemplate(ctx context.Context, templateID string, req *UpdateTemplateRequest) (*Template, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	path := fmt.Sprintf("/api/v1/templates/%s", templateID)
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

	var tmpl Template
	if err := json.NewDecoder(resp.Body).Decode(&tmpl); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tmpl, nil
}

// DeleteTemplate deletes a template by ID (admin only).
func (c *Client) DeleteTemplate(ctx context.Context, templateID string) error {
	path := fmt.Sprintf("/api/v1/templates/%s", templateID)
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

// InstantiateTemplate creates a rule instance from a template (admin only).
func (c *Client) InstantiateTemplate(ctx context.Context, templateID string, req *InstantiateTemplateRequest) (*InstantiateTemplateResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	path := fmt.Sprintf("/api/v1/templates/%s/instantiate", templateID)
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

	var instResp InstantiateTemplateResponse
	if err := json.NewDecoder(resp.Body).Decode(&instResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &instResp, nil
}

// RevokeInstance revokes (disables) a rule instance created from a template (admin only).
func (c *Client) RevokeInstance(ctx context.Context, ruleID string) (*RevokeInstanceResponse, error) {
	path := fmt.Sprintf("/api/v1/templates/instances/%s/revoke", ruleID)
	httpReq, err := c.newSignedRequest(ctx, http.MethodPost, path, nil)
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

	var revokeResp RevokeInstanceResponse
	if err := json.NewDecoder(resp.Body).Decode(&revokeResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &revokeResp, nil
}
