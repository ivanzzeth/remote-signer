//go:build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
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

// decodeRuleConfig decodes a config field from a Rule fetched via the API.
// The API stores config as a base64-encoded JSON string, so we need to
// first extract the base64 string, decode it, then JSON-unmarshal.
func decodeRuleConfig(t *testing.T, rule evm.Rule) map[string]interface{} {
	t.Helper()
	var cfg map[string]interface{}
	if len(rule.Config) == 0 {
		return cfg
	}
	var b64 string
	if err := json.Unmarshal(rule.Config, &b64); err != nil {
		return cfg
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Logf("warning: config is not base64: %v", err)
		return cfg
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Logf("warning: config json decode: %v", err)
	}
	return cfg
}

func TestPreset_List(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	resp, err := adminClient.Presets.List(ctx)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotNil(t, resp.Presets)
	// We seeded e2e_minimal.preset in TestMain.
	var found bool
	for _, p := range resp.Presets {
		if p.ID == "e2e_minimal.preset" {
			found = true
			// Post-migration: presets carry stable template IDs (file-derived,
			// e.g. "evm/e2e_preset"), not human-readable display names.
			assert.Contains(t, p.TemplateIDs, "evm/e2e_preset")
			break
		}
	}
	assert.True(t, found, "e2e_minimal.preset should appear in list")
}

func TestPreset_Vars(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	resp, err := adminClient.Presets.Get(ctx, "e2e_minimal.preset")
	require.NoError(t, err)
	require.NotNil(t, resp)
	// Modernised SDK: variable overrides live in resp.Variables (with
	// per-variable detail), not the flat OverrideHints map.
	var names []string
	for _, v := range resp.Variables {
		names = append(names, v.Name)
	}
	assert.Contains(t, names, "allowed_address")
}

func TestPreset_Vars_NotFound(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	_, err := adminClient.Presets.Get(ctx, "nonexistent-preset-12345.yaml")
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok)
	assert.Equal(t, 404, apiErr.StatusCode)
}

func TestPreset_Vars_PathTraversal(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	// Id with .. is invalid. Server may return 400/404, or 401 if path normalization causes signature mismatch.
	_, err := adminClient.Presets.Get(ctx, "../../../etc/passwd")
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
	applyResp, err := adminClient.Presets.ApplyWithVariables(ctx, "e2e_minimal.preset", nil)
	require.NoError(t, err)
	require.NotNil(t, applyResp)
	require.Len(t, applyResp.Results, 1)
	assert.NotEmpty(t, applyResp.Results[0].Rule)

	// Cleanup: revoke the created instance rules
	cleanupApplyResults(t, applyResp.Results)
}

func TestPreset_Matrix_Apply_MultiChain(t *testing.T) {
	// Matrix preset expansion (one rule per chain entry) is not part of
	// the post-migration preset schema — the current presetYAML struct
	// has no `matrix:` field, so the YAML is parsed but the chain list
	// is silently dropped. Skip until matrix support is re-added (or
	// retire the test if matrix is gone for good).
	t.Skip("matrix preset support removed in commit f5bbe96; re-enable when reinstated or delete this test")
}

func TestPreset_Matrix_List_Shows_Template(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	resp, err := adminClient.Presets.List(ctx)
	require.NoError(t, err)

	var found bool
	for _, p := range resp.Presets {
		if p.ID == "e2e_matrix.preset" {
			found = true
			assert.Contains(t, p.TemplateIDs, "evm/e2e_preset")
			break
		}
	}
	assert.True(t, found, "e2e_matrix.preset should appear in preset list")
}

func TestPreset_Apply_CrossTemplateDelegate(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	// The delegate preset references evm/e2e_bundle_target (bundle with
	// sub-rules "e2e-target" and "e2e-extra") and evm/e2e_delegator
	// (single rule with delegate_to: "${delegate_to}").
	// This test verifies that cross-template delegate_to references are
	// resolved from raw sub-rule IDs (e.g. "e2e-target") to inst_<hash>
	// format in Phase 2 of commitInstances.

	snapshotRules(t)

	resp, err := adminClient.Presets.ApplyWithVariables(ctx, "e2e_delegate.preset", nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Results, 3, "expected 3 rules (2 bundle sub-rules + 1 delegator)")

	// Decode each result into an SDK Rule and collect configs.
	type ruleEntry struct {
		rule   evm.Rule
		config map[string]interface{}
	}
	createdRules := make(map[string]*ruleEntry)

	for _, result := range resp.Results {
		var r evm.Rule
		require.NoError(t, json.Unmarshal(result.Rule, &r))
		require.NotEmpty(t, r.ID, "apply result rule should have an id")
		createdRules[r.ID] = &ruleEntry{rule: r, config: decodeRuleConfig(t, r)}
	}

	// Locate the delegator rule (the one with delegate_to in config)
	var delegatorEntry *ruleEntry
	var delegatorRuleID string
	for id, entry := range createdRules {
		if entry.config != nil {
			if _, ok := entry.config["delegate_to"]; ok {
				delegatorEntry = entry
				delegatorRuleID = id
				break
			}
		}
	}
	require.NotNil(t, delegatorEntry, "delegator rule with delegate_to should exist")
	require.NotEmpty(t, delegatorRuleID)

	// Verify delegate_to is resolved to inst_<hash> format
	delegateTo, _ := delegatorEntry.config["delegate_to"].(string)
	require.NotEmpty(t, delegateTo, "delegate_to should not be empty")
	assert.True(t, strings.HasPrefix(delegateTo, "inst_"),
		"delegate_to should be resolved to inst_<hash> format, got %q", delegateTo)

	// Verify the delegated-to rule actually exists among the created rules
	_, ok := createdRules[delegateTo]
	require.True(t, ok, "delegated rule %q should exist in apply results", delegateTo)
	t.Logf("Cross-template delegate resolved: %s -> %s (target name: %s)",
		delegatorRuleID, delegateTo, createdRules[delegateTo].rule.Name)

	// Also verify via the API that the delegated rule exists
	fetched, err := adminClient.EVM.Rules.Get(ctx, delegateTo)
	require.NoError(t, err, "delegated rule should be fetchable via API")
	fetchedCfg := decodeRuleConfig(t, *fetched)
	// The target rule should NOT have delegate_to (it's the bundle sub-rule, not the delegator)
	_, hasDelegate := fetchedCfg["delegate_to"]
	assert.False(t, hasDelegate, "bundle sub-rule should not have delegate_to in config")

	// Verify the second bundle sub-rule (e2e-extra) also exists as inst_<hash>
	var extraRuleID string
	for id := range createdRules {
		if strings.HasPrefix(id, "inst_") && id != delegateTo {
			extraRuleID = id
			break
		}
	}
	require.NotEmpty(t, extraRuleID, "second bundle sub-rule (e2e-extra) should exist as inst_<hash>")
	_, err = adminClient.EVM.Rules.Get(ctx, extraRuleID)
	require.NoError(t, err, "second bundle sub-rule should be fetchable via API")
	t.Logf("Second bundle sub-rule: %s", extraRuleID)

	// Verify the delegator rule itself is fetchable
	_, err = adminClient.EVM.Rules.Get(ctx, delegatorRuleID)
	require.NoError(t, err, "delegator rule should be fetchable via API")
}

func TestPreset_Apply_Forbidden_NonAdmin(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)
	if nonAdminClient == nil {
		t.Skip("non-admin client not configured")
	}

	_, err := nonAdminClient.Presets.Apply(ctx, "e2e_minimal.preset", nil)
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok)
	assert.Equal(t, 403, apiErr.StatusCode)
}
