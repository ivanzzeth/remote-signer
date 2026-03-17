//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/templates"
)

// skipIfPresetAPIDisabled calls GET /api/v1/presets; if 404, skips the test (preset API not enabled).
func skipIfPresetAPIDisabled(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	_, err := adminClient.Presets.List(ctx)
	if err != nil {
		if apiErr, ok := err.(*client.APIError); ok && apiErr.StatusCode == 404 {
			t.Skip("preset API not enabled (presets.dir not set or route not registered)")
		}
		require.NoError(t, err)
	}
}

func TestPreset_List(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	resp, err := adminClient.Presets.List(ctx)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotNil(t, resp.Presets)
	// We created e2e_minimal.preset.yaml in TestMain
	var found bool
	for _, p := range resp.Presets {
		if p.ID == "e2e_minimal.preset.yaml" {
			found = true
			assert.Contains(t, p.TemplateNames, "E2E Preset Template")
			break
		}
	}
	assert.True(t, found, "e2e_minimal.preset.yaml should appear in list")
}

func TestPreset_Vars(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	resp, err := adminClient.Presets.Vars(ctx, "e2e_minimal.preset.yaml")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Contains(t, resp.OverrideHints, "allowed_address")
}

func TestPreset_Vars_NotFound(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	_, err := adminClient.Presets.Vars(ctx, "nonexistent-preset-12345.yaml")
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok)
	assert.Equal(t, 404, apiErr.StatusCode)
}

func TestPreset_Vars_PathTraversal(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	// Id with .. is invalid. Server may return 400/404, or 401 if path normalization causes signature mismatch.
	_, err := adminClient.Presets.Vars(ctx, "../../../etc/passwd")
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok)
	assert.True(t, apiErr.StatusCode == 400 || apiErr.StatusCode == 404 || apiErr.StatusCode == 401,
		"path traversal should be rejected (400/404/401), got %d", apiErr.StatusCode)
}

func TestPreset_Apply_Success(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	// Create the template that the preset references (E2E Preset Template)
	tmplReq := &templates.CreateRequest{
		Name:        "E2E Preset Template",
		Description: "Template for e2e preset apply",
		Type:        "evm_address_list",
		Mode:        "whitelist",
		Variables: []templates.TemplateVariable{
			{Name: "allowed_address", Type: "address", Description: "Allowed address", Required: true},
		},
		Config:  map[string]interface{}{"addresses": []string{"${allowed_address}"}},
		Enabled: true,
	}
	createdTmpl, err := adminClient.Templates.Create(ctx, tmplReq)
	require.NoError(t, err)
	defer func() {
		if err := adminClient.Templates.Delete(ctx, createdTmpl.ID); err != nil {
			t.Logf("warning: failed to delete e2e preset template: %v", err)
		}
	}()

	// Apply preset (uses variables from preset file; can override via body)
	applyResp, err := adminClient.Presets.ApplyWithVariables(ctx, "e2e_minimal.preset.yaml", nil)
	require.NoError(t, err)
	require.NotNil(t, applyResp)
	require.Len(t, applyResp.Results, 1)
	assert.NotEmpty(t, applyResp.Results[0].Rule)

	// Cleanup: revoke the created instance rules
	cleanupApplyResults(t, applyResp.Results)
}

func TestPreset_Matrix_Apply_MultiChain(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	// Create the template that the matrix preset references
	tmplReq := &templates.CreateRequest{
		Name:        "E2E Preset Template",
		Description: "Template for e2e matrix preset",
		Type:        "evm_address_list",
		Mode:        "whitelist",
		Variables: []templates.TemplateVariable{
			{Name: "allowed_address", Type: "address", Description: "Allowed address", Required: true},
		},
		Config:  map[string]interface{}{"addresses": []string{"${allowed_address}"}},
		Enabled: true,
	}
	createdTmpl, err := adminClient.Templates.Create(ctx, tmplReq)
	require.NoError(t, err)
	defer func() {
		if err := adminClient.Templates.Delete(ctx, createdTmpl.ID); err != nil {
			t.Logf("warning: failed to delete e2e preset template: %v", err)
		}
	}()

	// Apply matrix preset — should produce 3 rules (one per chain)
	applyResp, err := adminClient.Presets.ApplyWithVariables(ctx, "e2e_matrix.preset.yaml", nil)
	require.NoError(t, err)
	require.NotNil(t, applyResp)
	require.Len(t, applyResp.Results, 3, "matrix preset should produce 3 rules (one per chain)")

	// Cleanup: revoke the created instance rules
	cleanupApplyResults(t, applyResp.Results)

	// Verify each rule has correct chain_id scope
	chainIDs := make(map[string]bool)
	for _, result := range applyResp.Results {
		assert.NotEmpty(t, result.Rule)
		var ruleMap map[string]interface{}
		if err := json.Unmarshal(result.Rule, &ruleMap); err == nil {
			if cid, ok := ruleMap["chain_id"].(string); ok {
				chainIDs[cid] = true
			}
		}
	}
	assert.True(t, chainIDs["1"], "should have rule for chain 1")
	assert.True(t, chainIDs["137"], "should have rule for chain 137")
	assert.True(t, chainIDs["42161"], "should have rule for chain 42161")
}

func TestPreset_Matrix_List_Shows_Template(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	resp, err := adminClient.Presets.List(ctx)
	require.NoError(t, err)

	var found bool
	for _, p := range resp.Presets {
		if p.ID == "e2e_matrix.preset.yaml" {
			found = true
			assert.Contains(t, p.TemplateNames, "E2E Preset Template")
			break
		}
	}
	assert.True(t, found, "e2e_matrix.preset.yaml should appear in preset list")
}

func TestPreset_Apply_Forbidden_NonAdmin(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)
	if nonAdminClient == nil {
		t.Skip("non-admin client not configured")
	}

	_, err := nonAdminClient.Presets.Apply(ctx, "e2e_minimal.preset.yaml", nil)
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok)
	assert.Equal(t, 403, apiErr.StatusCode)
}
