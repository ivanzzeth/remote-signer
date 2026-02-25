//go:build e2e
package e2e

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
)

func TestTemplate_AdminCanCreateTemplate(t *testing.T) {
	ctx := context.Background()

	req := &client.CreateTemplateRequest{
		Name:        "Test Template - Address Whitelist",
		Description: "Template for whitelisting addresses with variables",
		Type:        "evm_address_list",
		Mode:        "whitelist",
		Variables: []client.TemplateVariable{
			{
				Name:        "allowed_address",
				Type:        "address",
				Description: "The address to whitelist",
				Required:    true,
			},
		},
		Config: map[string]interface{}{
			"addresses": []string{"${allowed_address}"},
		},
		Enabled: true,
	}

	created, err := adminClient.CreateTemplate(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.NotEmpty(t, created.ID)
	assert.Equal(t, req.Name, created.Name)
	assert.Equal(t, req.Description, created.Description)
	assert.Equal(t, req.Type, created.Type)
	assert.Equal(t, req.Mode, created.Mode)
	assert.True(t, created.Enabled)

	// Cleanup
	err = adminClient.DeleteTemplate(ctx, created.ID)
	require.NoError(t, err)
}

// TestTemplate_ConfigLoadedTemplatesAndInstanceRules verifies that the server loads
// templates from config and expands instance rules at startup (same flow as main.go).
// config.e2e.yaml defines one file template (E2E Minimal Template) and one instance
// rule; the expanded rule "E2E From Template Instance" must appear in the rules list.
func TestTemplate_ConfigLoadedTemplatesAndInstanceRules(t *testing.T) {
	ctx := context.Background()

	resp, err := adminClient.ListRules(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	var found bool
	for _, r := range resp.Rules {
		if r.Name == "E2E From Template Instance" {
			found = true
			assert.Equal(t, "evm_address_whitelist", string(r.Type))
			assert.True(t, r.Enabled)
			break
		}
	}
	assert.True(t, found, "rule 'E2E From Template Instance' (from config template instance) should be loaded at startup")
}

func TestTemplate_AdminCanListTemplates(t *testing.T) {
	ctx := context.Background()

	// Get initial count
	initialResp, err := adminClient.ListTemplates(ctx, nil)
	require.NoError(t, err)
	initialCount := initialResp.Total

	// Create a template
	req := &client.CreateTemplateRequest{
		Name:    "Test Template - List",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
		Enabled: true,
	}

	created, err := adminClient.CreateTemplate(ctx, req)
	require.NoError(t, err)

	// List again and verify count increased
	resp, err := adminClient.ListTemplates(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, initialCount+1, resp.Total)

	// Cleanup
	err = adminClient.DeleteTemplate(ctx, created.ID)
	require.NoError(t, err)
}

func TestTemplate_AdminCanGetTemplate(t *testing.T) {
	ctx := context.Background()

	// Create a template
	req := &client.CreateTemplateRequest{
		Name:        "Test Template - Get",
		Description: "A template for get testing",
		Type:        "evm_value_limit",
		Mode:        "whitelist",
		Config:      map[string]interface{}{"max_value": "1000000000000000000"},
		Enabled:     true,
	}

	created, err := adminClient.CreateTemplate(ctx, req)
	require.NoError(t, err)

	// Get the template by ID
	tmpl, err := adminClient.GetTemplate(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, tmpl.ID)
	assert.Equal(t, created.Name, tmpl.Name)
	assert.Equal(t, created.Description, tmpl.Description)
	assert.Equal(t, created.Type, tmpl.Type)
	assert.Equal(t, created.Mode, tmpl.Mode)
	assert.Equal(t, created.Enabled, tmpl.Enabled)

	// Cleanup
	err = adminClient.DeleteTemplate(ctx, created.ID)
	require.NoError(t, err)
}

func TestTemplate_AdminCanUpdateTemplate(t *testing.T) {
	ctx := context.Background()

	// Create a template
	req := &client.CreateTemplateRequest{
		Name:        "Test Template - Update Original",
		Description: "Original description",
		Type:        "evm_value_limit",
		Mode:        "whitelist",
		Config:      map[string]interface{}{"max_value": "1000000000000000000"},
		Enabled:     true,
	}

	created, err := adminClient.CreateTemplate(ctx, req)
	require.NoError(t, err)

	// Update the template
	updateReq := &client.UpdateTemplateRequest{
		Name:        "Test Template - Update Modified",
		Description: "Modified description",
	}

	updated, err := adminClient.UpdateTemplate(ctx, created.ID, updateReq)
	require.NoError(t, err)
	assert.Equal(t, "Test Template - Update Modified", updated.Name)
	assert.Equal(t, "Modified description", updated.Description)

	// Cleanup
	err = adminClient.DeleteTemplate(ctx, created.ID)
	require.NoError(t, err)
}

func TestTemplate_AdminCanDeleteTemplate(t *testing.T) {
	ctx := context.Background()

	// Create a template
	req := &client.CreateTemplateRequest{
		Name:    "Test Template - Delete",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
		Enabled: true,
	}

	created, err := adminClient.CreateTemplate(ctx, req)
	require.NoError(t, err)

	// Delete the template
	err = adminClient.DeleteTemplate(ctx, created.ID)
	require.NoError(t, err)

	// Verify it's deleted
	_, err = adminClient.GetTemplate(ctx, created.ID)
	require.Error(t, err)
}

func TestTemplate_AdminCanInstantiateTemplate(t *testing.T) {
	ctx := context.Background()

	// Create a template with a variable
	createReq := &client.CreateTemplateRequest{
		Name:        "Test Template - Instantiate",
		Description: "Address whitelist template for instantiation",
		Type:        "evm_address_list",
		Mode:        "whitelist",
		Variables: []client.TemplateVariable{
			{
				Name:        "allowed_address",
				Type:        "address",
				Description: "The address to whitelist",
				Required:    true,
			},
		},
		Config: map[string]interface{}{
			"addresses": []string{"${allowed_address}"},
		},
		Enabled: true,
	}

	created, err := adminClient.CreateTemplate(ctx, createReq)
	require.NoError(t, err)

	// Instantiate the template with concrete variable values
	instReq := &client.InstantiateTemplateRequest{
		Variables: map[string]string{
			"allowed_address": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		},
	}

	instResp, err := adminClient.InstantiateTemplate(ctx, created.ID, instReq)
	require.NoError(t, err)
	require.NotNil(t, instResp)
	assert.NotNil(t, instResp.Rule, "Instantiate response should contain a rule")

	// Cleanup: delete template
	err = adminClient.DeleteTemplate(ctx, created.ID)
	require.NoError(t, err)
}

// TestTemplate_InstanceWithBudget_CreateAndSign verifies that an instance with budget
// can be created and that one matching sign request succeeds (budget is deducted).
// Full budget-exhaustion behavior is covered by unit tests (whitelist + BudgetChecker).
func TestTemplate_InstanceWithBudget_CreateAndSign(t *testing.T) {
	ctx := context.Background()

	createReq := &client.CreateTemplateRequest{
		Name:        "E2E Budget Template",
		Description: "Template with budget metering for e2e",
		Type:        "signer_restriction",
		Mode:        "whitelist",
		Variables: []client.TemplateVariable{
			{Name: "allowed_signer", Type: "address", Description: "Allowed signer", Required: true},
		},
		Config: map[string]interface{}{
			"allowed_signers": []string{"${allowed_signer}"},
		},
		BudgetMetering: map[string]interface{}{
			"method": "count_only",
			"unit":   "count",
		},
		Enabled: true,
	}

	created, err := adminClient.CreateTemplate(ctx, createReq)
	require.NoError(t, err)
	require.NotNil(t, created)
	defer func() { _ = adminClient.DeleteTemplate(ctx, created.ID) }()

	instReq := &client.InstantiateTemplateRequest{
		Variables: map[string]string{
			"allowed_signer": signerAddress,
		},
		Budget: &client.BudgetConfig{
			MaxTotal:   "10",
			MaxPerTx:   "1",
			MaxTxCount: 5,
			AlertPct:   80,
		},
	}

	instResp, err := adminClient.InstantiateTemplate(ctx, created.ID, instReq)
	require.NoError(t, err)
	require.NotNil(t, instResp)
	require.NotNil(t, instResp.Rule, "instantiate response should contain rule")
	require.NotNil(t, instResp.Budget, "instantiate response should contain budget when budget requested")

	// One matching sign request should succeed (budget deducted)
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)
	_, err = signer.PersonalSign("E2E budget instance sign")
	require.NoError(t, err, "first sign with budget instance should succeed")

	// Revoke instance so config is clean for other tests
	var ruleData struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(instResp.Rule, &ruleData))
	revokeResp, err := adminClient.RevokeInstance(ctx, ruleData.ID)
	require.NoError(t, err)
	require.Equal(t, "revoked", revokeResp.Status)
}

func TestTemplate_AdminCanRevokeInstance(t *testing.T) {
	ctx := context.Background()

	// Create a template with a variable
	createReq := &client.CreateTemplateRequest{
		Name:        "Test Template - Revoke Instance",
		Description: "Template for revoke testing",
		Type:        "evm_address_list",
		Mode:        "whitelist",
		Variables: []client.TemplateVariable{
			{
				Name:        "allowed_address",
				Type:        "address",
				Description: "The address to whitelist",
				Required:    true,
			},
		},
		Config: map[string]interface{}{
			"addresses": []string{"${allowed_address}"},
		},
		Enabled: true,
	}

	created, err := adminClient.CreateTemplate(ctx, createReq)
	require.NoError(t, err)

	// Instantiate the template
	instReq := &client.InstantiateTemplateRequest{
		Variables: map[string]string{
			"allowed_address": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
		},
	}

	instResp, err := adminClient.InstantiateTemplate(ctx, created.ID, instReq)
	require.NoError(t, err)
	require.NotNil(t, instResp)

	// Extract rule ID from the instantiate response
	var ruleData struct {
		ID string `json:"id"`
	}
	err = json.Unmarshal(instResp.Rule, &ruleData)
	require.NoError(t, err)
	require.NotEmpty(t, ruleData.ID)

	// Revoke the instance
	revokeResp, err := adminClient.RevokeInstance(ctx, ruleData.ID)
	require.NoError(t, err)
	require.NotNil(t, revokeResp)
	assert.Equal(t, "revoked", revokeResp.Status)
	assert.Equal(t, ruleData.ID, revokeResp.RuleID)

	// Cleanup: delete template
	err = adminClient.DeleteTemplate(ctx, created.ID)
	require.NoError(t, err)
}

func TestTemplate_NonAdminCannotCreateTemplate(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	req := &client.CreateTemplateRequest{
		Name:    "Test Template - Non-Admin Create",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
		Enabled: true,
	}

	_, err := nonAdminClient.CreateTemplate(ctx, req)
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode)
}

func TestTemplate_NonAdminCannotListTemplates(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	_, err := nonAdminClient.ListTemplates(ctx, nil)
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode)
}
