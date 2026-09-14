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
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/pkg/client/templates"
)

func TestTemplate_AdminCanCreateTemplate(t *testing.T) {
	ensureGuardResumed(t)
	ctx := context.Background()

	req := &templates.CreateRequest{
		Name:        "Test Template - Address Whitelist",
		Description: "Template for whitelisting addresses with variables",
		Type:        "evm_address_list",
		Mode:        "whitelist",
		Variables: []templates.TemplateVariable{
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

	created, err := adminClient.Templates.Create(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.NotEmpty(t, created.ID)
	assert.Equal(t, req.Name, created.Name)
	assert.Equal(t, req.Description, created.Description)
	assert.Equal(t, req.Type, created.Type)
	assert.Equal(t, req.Mode, created.Mode)
	assert.True(t, created.Enabled)

	// Cleanup
	err = adminClient.Templates.Delete(ctx, created.ID)
	require.NoError(t, err)
}

// TestTemplate_ConfigLoadedTemplatesAndInstanceRules verifies that the server loads
// templates from config and expands instance rules at startup (same flow as main.go).
// config.e2e.yaml defines one file template (Minimal Template) and one instance
// rule; the expanded rule "From Template Instance" must appear in the rules list.
func TestTemplate_ConfigLoadedTemplatesAndInstanceRules(t *testing.T) {
	ensureGuardResumed(t)
	ctx := context.Background()

	resp, err := adminClient.EVM.Rules.List(ctx, &evm.ListRulesFilter{Limit: 1000})
	require.NoError(t, err)
	require.NotNil(t, resp)

	var found bool
	for _, r := range resp.Rules {
		if r.Name == "From Template Instance" {
			found = true
			assert.Equal(t, "evm_address_list", string(r.Type))
			assert.True(t, r.Enabled)
			break
		}
	}
	assert.True(t, found, "rule 'From Template Instance' (from config template instance) should be loaded at startup")
}

func TestTemplate_AdminCanListTemplates(t *testing.T) {
	ensureGuardResumed(t)
	ctx := context.Background()

	// Get initial count
	initialResp, err := adminClient.Templates.List(ctx, nil)
	require.NoError(t, err)
	initialCount := initialResp.Total

	// Create a template
	req := &templates.CreateRequest{
		Name:    "Test Template - List",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
		Enabled: true,
	}

	created, err := adminClient.Templates.Create(ctx, req)
	require.NoError(t, err)

	// List again and verify count increased
	resp, err := adminClient.Templates.List(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, initialCount+1, resp.Total)

	// Cleanup
	err = adminClient.Templates.Delete(ctx, created.ID)
	require.NoError(t, err)
}

func TestTemplate_AdminCanGetTemplate(t *testing.T) {
	ensureGuardResumed(t)
	ctx := context.Background()

	// Create a template
	req := &templates.CreateRequest{
		Name:        "Test Template - Get",
		Description: "A template for get testing",
		Type:        "evm_value_limit",
		Mode:        "whitelist",
		Config:      map[string]interface{}{"max_value": "1000000000000000000"},
		Enabled:     true,
	}

	created, err := adminClient.Templates.Create(ctx, req)
	require.NoError(t, err)

	// Get the template by ID
	tmpl, err := adminClient.Templates.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, tmpl.ID)
	assert.Equal(t, created.Name, tmpl.Name)
	assert.Equal(t, created.Description, tmpl.Description)
	assert.Equal(t, created.Type, tmpl.Type)
	assert.Equal(t, created.Mode, tmpl.Mode)
	assert.Equal(t, created.Enabled, tmpl.Enabled)

	// Cleanup
	err = adminClient.Templates.Delete(ctx, created.ID)
	require.NoError(t, err)
}

func TestTemplate_AdminCanUpdateTemplate(t *testing.T) {
	ensureGuardResumed(t)
	ctx := context.Background()

	// Create a template
	req := &templates.CreateRequest{
		Name:        "Test Template - Update Original",
		Description: "Original description",
		Type:        "evm_value_limit",
		Mode:        "whitelist",
		Config:      map[string]interface{}{"max_value": "1000000000000000000"},
		Enabled:     true,
	}

	created, err := adminClient.Templates.Create(ctx, req)
	require.NoError(t, err)

	// Update the template
	updateReq := &templates.UpdateRequest{
		Name:        "Test Template - Update Modified",
		Description: "Modified description",
	}

	updated, err := adminClient.Templates.Update(ctx, created.ID, updateReq)
	require.NoError(t, err)
	assert.Equal(t, "Test Template - Update Modified", updated.Name)
	assert.Equal(t, "Modified description", updated.Description)

	// Cleanup
	err = adminClient.Templates.Delete(ctx, created.ID)
	require.NoError(t, err)
}

func TestTemplate_AdminCanDeleteTemplate(t *testing.T) {
	ensureGuardResumed(t)
	ctx := context.Background()

	// Create a template
	req := &templates.CreateRequest{
		Name:    "Test Template - Delete",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
		Enabled: true,
	}

	created, err := adminClient.Templates.Create(ctx, req)
	require.NoError(t, err)

	// Delete the template
	err = adminClient.Templates.Delete(ctx, created.ID)
	require.NoError(t, err)

	// Verify it's deleted
	_, err = adminClient.Templates.Get(ctx, created.ID)
	require.Error(t, err)
}

func TestTemplate_AdminCanInstantiateTemplate(t *testing.T) {
	ensureGuardResumed(t)
	ctx := context.Background()

	// Create a template with a variable
	createReq := &templates.CreateRequest{
		Name:        "Test Template - Instantiate",
		Description: "Address whitelist template for instantiation",
		Type:        "evm_address_list",
		Mode:        "whitelist",
		Variables: []templates.TemplateVariable{
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

	created, err := adminClient.Templates.Create(ctx, createReq)
	require.NoError(t, err)

	// Instantiate the template with concrete variable values
	instReq := &templates.InstantiateRequest{
		Variables: map[string]string{
			"allowed_address": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		},
	}

	instResp, err := adminClient.Templates.Instantiate(ctx, created.ID, instReq)
	require.NoError(t, err)
	require.NotNil(t, instResp)
	assert.NotNil(t, instResp.Rule, "Instantiate response should contain a rule")

	// Cleanup: delete template
	err = adminClient.Templates.Delete(ctx, created.ID)
	require.NoError(t, err)
}

// TestTemplate_InstanceWithBudget_CreateAndSign verifies that an instance with budget
// can be created and that one matching sign request succeeds (budget is deducted).
// Full budget-exhaustion behavior is covered by unit tests (whitelist + BudgetChecker).
func TestTemplate_InstanceWithBudget_CreateAndSign(t *testing.T) {
	ensureGuardResumed(t)
	ctx := context.Background()

	createReq := &templates.CreateRequest{
		Name:        "E2E Budget Template",
		Description: "Template with budget metering for e2e",
		Type:        "signer_restriction",
		Mode:        "whitelist",
		Variables: []templates.TemplateVariable{
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

	created, err := adminClient.Templates.Create(ctx, createReq)
	require.NoError(t, err)
	require.NotNil(t, created)
	defer func() { _ = adminClient.Templates.Delete(ctx, created.ID) }()

	instReq := &templates.InstantiateRequest{
		Variables: map[string]string{
			"allowed_signer": signerAddress,
		},
		Budget: &templates.BudgetConfig{
			MaxTotal:   "10",
			MaxPerTx:   "1",
			MaxTxCount: 5,
			AlertPct:   80,
		},
	}

	instResp, err := adminClient.Templates.Instantiate(ctx, created.ID, instReq)
	require.NoError(t, err)
	require.NotNil(t, instResp)
	require.NotNil(t, instResp.Rule, "instantiate response should contain rule")
	require.NotNil(t, instResp.Budget, "instantiate response should contain budget when budget requested")

	// One matching sign request should succeed (budget deducted)
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	_, err = signer.PersonalSign("E2E budget instance sign")
	require.NoError(t, err, "first sign with budget instance should succeed")

	// Revoke instance so config is clean for other tests
	var ruleData struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(instResp.Rule, &ruleData))
	revokeResp, err := adminClient.Templates.RevokeInstance(ctx, ruleData.ID)
	require.NoError(t, err)
	require.Equal(t, "revoked", revokeResp.Status)
}

func TestTemplate_AdminCanRevokeInstance(t *testing.T) {
	ensureGuardResumed(t)
	ctx := context.Background()

	// Create a template with a variable
	createReq := &templates.CreateRequest{
		Name:        "Test Template - Revoke Instance",
		Description: "Template for revoke testing",
		Type:        "evm_address_list",
		Mode:        "whitelist",
		Variables: []templates.TemplateVariable{
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

	created, err := adminClient.Templates.Create(ctx, createReq)
	require.NoError(t, err)

	// Instantiate the template
	instReq := &templates.InstantiateRequest{
		Variables: map[string]string{
			"allowed_address": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
		},
	}

	instResp, err := adminClient.Templates.Instantiate(ctx, created.ID, instReq)
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
	revokeResp, err := adminClient.Templates.RevokeInstance(ctx, ruleData.ID)
	require.NoError(t, err)
	require.NotNil(t, revokeResp)
	assert.Equal(t, "revoked", revokeResp.Status)
	assert.Equal(t, ruleData.ID, revokeResp.RuleID)

	// Cleanup: delete template
	err = adminClient.Templates.Delete(ctx, created.ID)
	require.NoError(t, err)
}

func TestTemplate_NonAdminCannotCreateTemplate(t *testing.T) {
	ensureGuardResumed(t)
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	req := &templates.CreateRequest{
		Name:    "Test Template - Non-Admin Create",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
		Enabled: true,
	}

	_, err := nonAdminClient.Templates.Create(ctx, req)
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode)
}

func TestTemplate_NonAdminCannotListTemplates(t *testing.T) {
	ensureGuardResumed(t)
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	_, err := nonAdminClient.Templates.List(ctx, nil)
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode)
}

// TestTemplate_DevKeyCannotMutateTemplates is the negative verification for the
// slice that gave the four template mutations PermInstantiateTemplate.
//
// ⛔ It asserts by EFFECT, not by status code. A 403 alone would also be
// produced by a broken key, a rate limit, or read-only mode, so after every
// refusal the admin key reads the resource back and the assertion is that
// nothing moved: no template row appeared, the name did not change, the
// template still exists, no instance rule was minted, the instance is still
// enabled. The status code is checked too, but it is the weaker half.
//
// # Why `dev` is the right key for this
//
// read_templates is held by admin, dev and agent; instantiate_template by admin
// and agent only. ⭐ So `dev` is exactly "a key holding only the old, weaker
// permission" — it still passes the route guard on every template *read*, which
// is what the control arm at the top proves. Without that arm a green run would
// also be satisfied by a key that cannot reach the template surface at all.
func TestTemplate_DevKeyCannotMutateTemplates(t *testing.T) {
	ensureGuardResumed(t)
	ctx := context.Background()

	devClient := createRoleClient(t, "dev", "e2e-tmpl-perm-dev")

	// ---------- control arm: dev still holds read_templates ----------
	//
	// ⛔ Do not delete this. It is the only thing separating "the permission
	// narrowed" from "this key cannot talk to the daemon at all".
	if _, err := devClient.Templates.List(ctx, nil); err != nil {
		t.Fatalf("premise of this test: a dev key still holds read_templates and can list. "+
			"It could not (%v), so every 403 below proves nothing", err)
	}

	// ---------- create ----------
	const devTmplName = "Test Template - dev must not create"
	_, err := devClient.Templates.Create(ctx, &templates.CreateRequest{
		Name:    devTmplName,
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Config:  map[string]interface{}{"addresses": []string{"0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}},
		Enabled: true,
	})
	expectAPIError(t, err, 403, "dev holds read_templates but not instantiate_template: create must be refused")

	listed, err := adminClient.Templates.List(ctx, nil)
	require.NoError(t, err)
	for _, tmpl := range listed.Templates {
		assert.NotEqual(t, devTmplName, tmpl.Name,
			"⛔ the 403 was cosmetic: the template row exists anyway (id=%s)", tmpl.ID)
	}

	// ---------- a real template to aim the rest at ----------
	created, err := adminClient.Templates.Create(ctx, &templates.CreateRequest{
		Name:        "Test Template - dev perm fixture",
		Description: "original description",
		Type:        "evm_address_list",
		Mode:        "whitelist",
		Variables: []templates.TemplateVariable{
			{Name: "allowed_address", Type: "address", Description: "addr", Required: true},
		},
		Config:  map[string]interface{}{"addresses": []string{"${allowed_address}"}},
		Enabled: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = adminClient.Templates.Delete(context.Background(), created.ID) })

	// ---------- update ----------
	_, err = devClient.Templates.Update(ctx, created.ID, &templates.UpdateRequest{
		Description: "dev must not be able to write this",
	})
	expectAPIError(t, err, 403, "dev must not update a template")

	after, err := adminClient.Templates.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "original description", after.Description,
		"⛔ the 403 was cosmetic: the description was written anyway")

	// ---------- instantiate ----------
	_, err = devClient.Templates.Instantiate(ctx, created.ID, &templates.InstantiateRequest{
		Variables: map[string]string{"allowed_address": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"},
	})
	expectAPIError(t, err, 403, "dev must not instantiate a template")

	rules, err := adminClient.EVM.Rules.List(ctx, &evm.ListRulesFilter{Limit: 1000})
	require.NoError(t, err)
	for _, rule := range rules.Rules {
		if rule.TemplateID != nil && *rule.TemplateID == created.ID {
			t.Fatalf("⛔ the 403 was cosmetic: an instance of %s exists anyway (rule %s)", created.ID, rule.ID)
		}
	}

	// ---------- revoke an instance the admin made ----------
	inst, err := adminClient.Templates.Instantiate(ctx, created.ID, &templates.InstantiateRequest{
		Variables: map[string]string{"allowed_address": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"},
	})
	require.NoError(t, err)
	var instRule evm.Rule
	require.NoError(t, json.Unmarshal(inst.Rule, &instRule))
	t.Cleanup(func() { _ = adminClient.EVM.Rules.Delete(context.Background(), instRule.ID) })

	_, err = devClient.Templates.RevokeInstance(ctx, instRule.ID)
	expectAPIError(t, err, 403, "dev must not revoke a template instance")

	stillThere, err := adminClient.EVM.Rules.Get(ctx, instRule.ID)
	require.NoError(t, err)
	assert.True(t, stillThere.Enabled,
		"⛔ the 403 was cosmetic: the instance was disabled anyway")

	// ---------- delete ----------
	err = devClient.Templates.Delete(ctx, created.ID)
	expectAPIError(t, err, 403, "dev must not delete a template")

	_, err = adminClient.Templates.Get(ctx, created.ID)
	require.NoError(t, err, "⛔ the 403 was cosmetic: the template was deleted anyway")
}
