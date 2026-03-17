//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/apikeys"
	"github.com/ivanzzeth/remote-signer/pkg/client/audit"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// =============================================================================
// Helper: create a client with a specific role
// =============================================================================

func createRoleClient(t *testing.T, role, keyID string) *client.Client {
	t.Helper()
	ctx := context.Background()

	pubKey, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	created, err := adminClient.APIKeys.Create(ctx, &apikeys.CreateRequest{
		ID:              keyID,
		Name:            fmt.Sprintf("E2E %s key", role),
		PublicKey:       hex.EncodeToString(pubKey),
		Role:            role,
		RateLimit:       500,
		AllowAllSigners: true,
	})
	if err != nil {
		apiErr, ok := err.(*client.APIError)
		if ok && apiErr.StatusCode == 403 {
			t.Skip("Skipping: API key management is readonly")
		}
		require.NoError(t, err)
	}
	require.NotNil(t, created)

	t.Cleanup(func() {
		if delErr := adminClient.APIKeys.Delete(context.Background(), keyID); delErr != nil {
			t.Logf("Warning: failed to clean up %s key %s: %v", role, keyID, delErr)
		}
	})

	c, err := client.NewClient(client.Config{
		BaseURL:       baseURL,
		APIKeyID:      keyID,
		PrivateKeyHex: hex.EncodeToString(privKey),
		PollInterval:  adminClient.EVM.Sign.PollInterval,
		PollTimeout:   adminClient.EVM.Sign.PollTimeout,
	})
	require.NoError(t, err)
	return c
}

// expectAPIError asserts that err is an APIError with the given status code.
func expectAPIError(t *testing.T, err error, statusCode int, msg string) {
	t.Helper()
	require.Error(t, err, msg)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T: %v", err, err)
	assert.Equal(t, statusCode, apiErr.StatusCode, msg)
}

// createTestAddressListRule creates a simple evm_address_list rule via the given client.
func createTestAddressListRule(t *testing.T, c *client.Client, name string) *evm.Rule {
	t.Helper()
	ctx := context.Background()
	chainType := "evm"
	rule, err := c.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:      name,
		Type:      "evm_address_list",
		Mode:      "whitelist",
		ChainType: &chainType,
		Config: map[string]interface{}{
			"addresses": []string{"0x0000000000000000000000000000000000000001"},
		},
		Enabled: true,
	})
	require.NoError(t, err, "failed to create rule %s", name)
	t.Cleanup(func() {
		// Try delete with admin as fallback
		if delErr := adminClient.EVM.Rules.Delete(context.Background(), rule.ID); delErr != nil {
			t.Logf("Warning: failed to clean up rule %s: %v", rule.ID, delErr)
		}
	})
	return rule
}

// =============================================================================
// Group A: Role Permission Boundaries
// =============================================================================

func TestRBAC_A1_Admin(t *testing.T) {
	ctx := context.Background()
	// Use existing adminClient

	t.Run("A1.2_create_rule_applied_to_star", func(t *testing.T) {
		chainType := "evm"
		rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "RBAC-A1.2 admin global rule",
			Type:      "evm_address_list",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
			Enabled:   true,
			AppliedTo: []string{"*"},
		})
		require.NoError(t, err)
		assert.Contains(t, rule.AppliedTo, "*")
		t.Cleanup(func() { adminClient.EVM.Rules.Delete(context.Background(), rule.ID) })
	})

	t.Run("A1.5_modify_any_rule", func(t *testing.T) {
		chainType := "evm"
		rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "RBAC-A1.5 to modify",
			Type:      "evm_address_list",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
			Enabled:   true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { adminClient.EVM.Rules.Delete(context.Background(), rule.ID) })

		updated, err := adminClient.EVM.Rules.Update(ctx, rule.ID, &evm.UpdateRuleRequest{
			Name:    "RBAC-A1.5 modified",
			Enabled: true,
		})
		require.NoError(t, err)
		assert.Equal(t, "RBAC-A1.5 modified", updated.Name)
	})

	t.Run("A1.6_delete_any_rule", func(t *testing.T) {
		chainType := "evm"
		rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "RBAC-A1.6 to delete",
			Type:      "evm_address_list",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
			Enabled:   true,
		})
		require.NoError(t, err)
		err = adminClient.EVM.Rules.Delete(ctx, rule.ID)
		require.NoError(t, err)
	})

	t.Run("A1.9_list_all_rules", func(t *testing.T) {
		resp, err := adminClient.EVM.Rules.List(ctx, nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, resp.Total, 1)
	})

	t.Run("A1.10_list_all_api_keys", func(t *testing.T) {
		resp, err := adminClient.APIKeys.List(ctx, nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, resp.Total, 1)
	})
}

func TestRBAC_A2_Dev(t *testing.T) {
	ctx := context.Background()
	devClient := createRoleClient(t, "dev", "e2e-rbac-dev")

	t.Run("A2.2_create_rule_self", func(t *testing.T) {
		rule := createTestAddressListRule(t, devClient, "RBAC-A2.2 dev self rule")
		assert.Equal(t, "active", rule.Status)
	})

	t.Run("A2.4_create_rule_star_forced_self", func(t *testing.T) {
		// Dev sends applied_to=["*"] but server silently forces it to ["self"]
		chainType := "evm"
		rule, err := devClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "RBAC-A2.4 dev star",
			Type:      "evm_address_list",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
			Enabled:   true,
			AppliedTo: []string{"*"},
		})
		require.NoError(t, err)
		t.Cleanup(func() { adminClient.EVM.Rules.Delete(context.Background(), rule.ID) })
		assert.Contains(t, rule.AppliedTo, "self", "dev applied_to should be forced to [self]")
		assert.NotContains(t, rule.AppliedTo, "*", "dev applied_to should NOT contain *")
	})

	t.Run("A2.6_modify_own_rule", func(t *testing.T) {
		rule := createTestAddressListRule(t, devClient, "RBAC-A2.6 dev own")
		updated, err := devClient.EVM.Rules.Update(ctx, rule.ID, &evm.UpdateRuleRequest{
			Name:    "RBAC-A2.6 modified",
			Enabled: true,
		})
		require.NoError(t, err)
		assert.Equal(t, "RBAC-A2.6 modified", updated.Name)
	})

	t.Run("A2.7_cannot_modify_others_rule", func(t *testing.T) {
		// Admin creates a rule
		chainType := "evm"
		adminRule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "RBAC-A2.7 admin rule",
			Type:      "evm_address_list",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
			Enabled:   true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { adminClient.EVM.Rules.Delete(context.Background(), adminRule.ID) })

		_, err = devClient.EVM.Rules.Update(ctx, adminRule.ID, &evm.UpdateRuleRequest{
			Name:    "dev should not modify",
			Enabled: true,
		})
		expectAPIError(t, err, 403, "dev CANNOT modify other's rule")
	})

	t.Run("A2.8_delete_own_rule", func(t *testing.T) {
		rule := createTestAddressListRule(t, devClient, "RBAC-A2.8 dev delete")
		err := devClient.EVM.Rules.Delete(ctx, rule.ID)
		require.NoError(t, err)
	})

	t.Run("A2.10_list_all_rules", func(t *testing.T) {
		resp, err := devClient.EVM.Rules.List(ctx, nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, resp.Total, 1)
	})

	t.Run("A2.11_cannot_approve_rules", func(t *testing.T) {
		// Create a pending rule from admin (we'd need approval flow config)
		// For now, just test the endpoint returns 403 for dev
		_, err := devClient.EVM.Rules.Approve(ctx, "nonexistent-rule")
		expectAPIError(t, err, 403, "dev CANNOT approve rules")
	})

	t.Run("A2.12_cannot_manage_api_keys", func(t *testing.T) {
		_, err := devClient.APIKeys.List(ctx, nil)
		expectAPIError(t, err, 403, "dev CANNOT manage API keys")
	})

	t.Run("A2.14_read_budgets", func(t *testing.T) {
		rule := createTestAddressListRule(t, devClient, "RBAC-A2.14 budgets")
		budgets, err := devClient.EVM.Rules.ListBudgets(ctx, rule.ID)
		require.NoError(t, err)
		assert.NotNil(t, budgets)
	})

	t.Run("A2.16_cannot_create_signer_restriction", func(t *testing.T) {
		chainType := "evm"
		_, err := devClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "RBAC-A2.16 signer restriction",
			Type:      "signer_restriction",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"allowed_signers": []string{signerAddress}},
			Enabled:   true,
		})
		expectAPIError(t, err, 403, "dev CANNOT create signer_restriction rule")
	})
}

func TestRBAC_A3_Agent(t *testing.T) {
	ctx := context.Background()
	agentClient := createRoleClient(t, "agent", "e2e-rbac-agent")

	t.Run("A3.2_create_declarative_rule", func(t *testing.T) {
		rule := createTestAddressListRule(t, agentClient, "RBAC-A3.2 agent declarative")
		assert.NotEmpty(t, rule.ID)
	})

	t.Run("A3.3_cannot_create_evm_js", func(t *testing.T) {
		chainType := "evm"
		_, err := agentClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "RBAC-A3.3 agent js",
			Type:      "evm_js",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config: map[string]interface{}{
				"script": "function validate(input) { return ok(); }",
			},
			Enabled: true,
		})
		expectAPIError(t, err, 403, "agent CANNOT create evm_js rule")
	})

	t.Run("A3.4_cannot_create_solidity_expression", func(t *testing.T) {
		chainType := "evm"
		_, err := agentClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "RBAC-A3.4 agent solidity",
			Type:      "evm_solidity_expression",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"expression": "require(true);"},
			Enabled:   true,
		})
		expectAPIError(t, err, 403, "agent CANNOT create evm_solidity_expression rule")
	})

	t.Run("A3.5_cannot_create_signer_restriction", func(t *testing.T) {
		chainType := "evm"
		_, err := agentClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "RBAC-A3.5 agent signer",
			Type:      "signer_restriction",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"allowed_signers": []string{signerAddress}},
			Enabled:   true,
		})
		expectAPIError(t, err, 403, "agent CANNOT create signer_restriction rule")
	})

	t.Run("A3.6_cannot_create_rule_star", func(t *testing.T) {
		chainType := "evm"
		_, err := agentClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "RBAC-A3.6 agent star",
			Type:      "evm_address_list",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
			Enabled:   true,
			AppliedTo: []string{"*"},
		})
		// Agent's applied_to is forced to ["self"] — no error, just override
		// OR it returns 403. Check which behavior the server implements.
		if err != nil {
			expectAPIError(t, err, 403, "agent CANNOT create rule with applied_to=[*]")
		}
		// If no error, the rule was created but applied_to should be forced to ["self"]
	})

	t.Run("A3.8_applied_to_forced_self", func(t *testing.T) {
		chainType := "evm"
		rule, err := agentClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "RBAC-A3.8 force self",
			Type:      "evm_address_list",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
			Enabled:   true,
			AppliedTo: []string{"*"}, // Should be overridden to ["self"]
		})
		if err == nil {
			t.Cleanup(func() { adminClient.EVM.Rules.Delete(context.Background(), rule.ID) })
			assert.Contains(t, rule.AppliedTo, "self", "agent applied_to should be forced to [self]")
			assert.NotContains(t, rule.AppliedTo, "*", "agent applied_to should NOT contain *")
		}
		// If error, A3.6 already covers the 403 case
	})

	t.Run("A3.9_owner_auto_set", func(t *testing.T) {
		rule := createTestAddressListRule(t, agentClient, "RBAC-A3.9 owner auto")
		assert.NotNil(t, rule.Owner)
		if rule.Owner != nil {
			assert.Equal(t, "e2e-rbac-agent", *rule.Owner, "owner should be agent's key ID")
		}
	})

	t.Run("A3.10_modify_own_declarative", func(t *testing.T) {
		rule := createTestAddressListRule(t, agentClient, "RBAC-A3.10 agent modify")
		updated, err := agentClient.EVM.Rules.Update(ctx, rule.ID, &evm.UpdateRuleRequest{
			Name:    "RBAC-A3.10 modified",
			Enabled: true,
		})
		require.NoError(t, err)
		assert.Equal(t, "RBAC-A3.10 modified", updated.Name)
	})

	t.Run("A3.12_cannot_modify_admin_rule", func(t *testing.T) {
		chainType := "evm"
		adminRule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "RBAC-A3.12 admin rule",
			Type:      "evm_address_list",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
			Enabled:   true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { adminClient.EVM.Rules.Delete(context.Background(), adminRule.ID) })

		_, err = agentClient.EVM.Rules.Update(ctx, adminRule.ID, &evm.UpdateRuleRequest{
			Name:    "agent should not modify",
			Enabled: true,
		})
		expectAPIError(t, err, 403, "agent CANNOT modify admin's rule")
	})

	t.Run("A3.14_delete_own_rule", func(t *testing.T) {
		rule := createTestAddressListRule(t, agentClient, "RBAC-A3.14 agent delete")
		err := agentClient.EVM.Rules.Delete(ctx, rule.ID)
		require.NoError(t, err)
	})

	t.Run("A3.15_cannot_delete_admin_rule", func(t *testing.T) {
		chainType := "evm"
		adminRule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "RBAC-A3.15 admin rule",
			Type:      "evm_address_list",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
			Enabled:   true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { adminClient.EVM.Rules.Delete(context.Background(), adminRule.ID) })

		err = agentClient.EVM.Rules.Delete(ctx, adminRule.ID)
		expectAPIError(t, err, 403, "agent CANNOT delete admin's rule")
	})

	t.Run("A3.23_cannot_manage_api_keys", func(t *testing.T) {
		_, err := agentClient.APIKeys.List(ctx, nil)
		expectAPIError(t, err, 403, "agent CANNOT manage API keys")
	})

	t.Run("A3.24_cannot_approve_rules", func(t *testing.T) {
		_, err := agentClient.EVM.Rules.Approve(ctx, "nonexistent")
		expectAPIError(t, err, 403, "agent CANNOT approve rules")
	})
}

func TestRBAC_A4_Strategy(t *testing.T) {
	ctx := context.Background()
	stratClient := createRoleClient(t, "strategy", "e2e-rbac-strategy")

	t.Run("A4.3_cannot_list_rules", func(t *testing.T) {
		_, err := stratClient.EVM.Rules.List(ctx, nil)
		expectAPIError(t, err, 403, "strategy CANNOT list rules")
	})

	t.Run("A4.4_cannot_read_single_rule", func(t *testing.T) {
		_, err := stratClient.EVM.Rules.Get(ctx, "any-rule-id")
		expectAPIError(t, err, 403, "strategy CANNOT read single rule")
	})

	t.Run("A4.5_cannot_create_rules", func(t *testing.T) {
		chainType := "evm"
		_, err := stratClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "strategy should not create",
			Type:      "evm_address_list",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
			Enabled:   true,
		})
		expectAPIError(t, err, 403, "strategy CANNOT create rules")
	})

	t.Run("A4.8_cannot_read_budgets", func(t *testing.T) {
		_, err := stratClient.EVM.Rules.ListBudgets(ctx, "any-rule")
		expectAPIError(t, err, 403, "strategy CANNOT read budgets")
	})

	t.Run("A4.11_cannot_manage_api_keys", func(t *testing.T) {
		_, err := stratClient.APIKeys.List(ctx, nil)
		expectAPIError(t, err, 403, "strategy CANNOT manage API keys")
	})

	t.Run("A4.13_cannot_read_audit", func(t *testing.T) {
		_, err := stratClient.Audit.List(ctx, nil)
		expectAPIError(t, err, 403, "strategy CANNOT read audit logs")
	})
}

// =============================================================================
// Group B: Rule Ownership & Scoping
// =============================================================================

func TestRBAC_B1_OwnerAutoSet(t *testing.T) {
	ctx := context.Background()

	t.Run("B1.1_agent_owner", func(t *testing.T) {
		agentClient := createRoleClient(t, "agent", "e2e-rbac-b1-agent")
		rule := createTestAddressListRule(t, agentClient, "RBAC-B1.1 agent owner")
		require.NotNil(t, rule.Owner)
		assert.Equal(t, "e2e-rbac-b1-agent", *rule.Owner)
	})

	t.Run("B1.2_admin_owner", func(t *testing.T) {
		chainType := "evm"
		rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "RBAC-B1.2 admin owner",
			Type:      "evm_address_list",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
			Enabled:   true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { adminClient.EVM.Rules.Delete(context.Background(), rule.ID) })
		require.NotNil(t, rule.Owner)
		assert.Equal(t, adminAPIKeyID, *rule.Owner)
	})

	t.Run("B1.3_config_sourced_owner", func(t *testing.T) {
		// Config-sourced rules should have owner="config"
		resp, err := adminClient.EVM.Rules.List(ctx, nil)
		require.NoError(t, err)
		var configRule *evm.Rule
		for i, r := range resp.Rules {
			if r.Source == "config" {
				configRule = &resp.Rules[i]
				break
			}
		}
		if configRule == nil {
			t.Skip("no config-sourced rules found")
		}
		require.NotNil(t, configRule.Owner)
		assert.Equal(t, "config", *configRule.Owner)
	})
}

func TestRBAC_B2_AppliedToEnforcement(t *testing.T) {
	ctx := context.Background()

	t.Run("B2.1_agent_forced_self", func(t *testing.T) {
		agentClient := createRoleClient(t, "agent", "e2e-rbac-b2-agent")
		chainType := "evm"
		rule, err := agentClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "RBAC-B2.1 agent forced self",
			Type:      "evm_address_list",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
			Enabled:   true,
			AppliedTo: []string{"*"}, // Should be overridden
		})
		if err == nil {
			t.Cleanup(func() { adminClient.EVM.Rules.Delete(context.Background(), rule.ID) })
			assert.Contains(t, rule.AppliedTo, "self")
		}
	})

	t.Run("B2.2_admin_star", func(t *testing.T) {
		chainType := "evm"
		rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "RBAC-B2.2 admin star",
			Type:      "evm_address_list",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
			Enabled:   true,
			AppliedTo: []string{"*"},
		})
		require.NoError(t, err)
		t.Cleanup(func() { adminClient.EVM.Rules.Delete(context.Background(), rule.ID) })
		assert.Contains(t, rule.AppliedTo, "*")
	})

	t.Run("B2.4_admin_nonexistent_key", func(t *testing.T) {
		chainType := "evm"
		_, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "RBAC-B2.4 nonexistent key",
			Type:      "evm_address_list",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
			Enabled:   true,
			AppliedTo: []string{"nonexistent-key-12345"},
		})
		expectAPIError(t, err, 400, "admin should get 400 for nonexistent applied_to key ID")
	})

	t.Run("B2.5_dev_forced_self", func(t *testing.T) {
		devClient := createRoleClient(t, "dev", "e2e-rbac-b2-dev")
		rule := createTestAddressListRule(t, devClient, "RBAC-B2.5 dev forced self")
		assert.Contains(t, rule.AppliedTo, "self")
	})
}

// =============================================================================
// Group C: Rule Lifecycle
// =============================================================================

func TestRBAC_C1_ImmediateActivation(t *testing.T) {
	agentClient := createRoleClient(t, "agent", "e2e-rbac-c1-agent")
	rule := createTestAddressListRule(t, agentClient, "RBAC-C1.1 immediate active")
	assert.Equal(t, "active", rule.Status)
}

func TestRBAC_C4_Deletion(t *testing.T) {
	ctx := context.Background()

	t.Run("C4.1_agent_delete_own_active", func(t *testing.T) {
		agentClient := createRoleClient(t, "agent", "e2e-rbac-c4-agent")
		rule := createTestAddressListRule(t, agentClient, "RBAC-C4.1 to delete")
		err := agentClient.EVM.Rules.Delete(ctx, rule.ID)
		require.NoError(t, err)
	})

	t.Run("C4.3_agent_cannot_delete_config_rule", func(t *testing.T) {
		agentClient := createRoleClient(t, "agent", "e2e-rbac-c4-agent2")
		resp, err := adminClient.EVM.Rules.List(ctx, nil)
		require.NoError(t, err)
		var configRuleID string
		for _, r := range resp.Rules {
			if r.Source == "config" {
				configRuleID = r.ID
				break
			}
		}
		if configRuleID == "" {
			t.Skip("no config-sourced rules found")
		}
		err = agentClient.EVM.Rules.Delete(ctx, configRuleID)
		expectAPIError(t, err, 403, "agent CANNOT delete config-sourced rule")
	})
}

func TestRBAC_C5_Immutable(t *testing.T) {
	ctx := context.Background()

	t.Run("C5.1_admin_create_immutable", func(t *testing.T) {
		chainType := "evm"
		rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "RBAC-C5.1 immutable",
			Type:      "evm_address_list",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
			Enabled:   true,
			Immutable: true,
		})
		require.NoError(t, err)
		assert.True(t, rule.Immutable)
		t.Cleanup(func() {
			// Immutable rules can't be deleted via API — leave for server cleanup
		})

		t.Run("C5.2_cannot_modify_immutable", func(t *testing.T) {
			_, err := adminClient.EVM.Rules.Update(ctx, rule.ID, &evm.UpdateRuleRequest{
				Name:    "should not modify",
				Enabled: true,
			})
			expectAPIError(t, err, 403, "admin CANNOT modify immutable rule")
		})

		t.Run("C5.3_cannot_delete_immutable", func(t *testing.T) {
			err := adminClient.EVM.Rules.Delete(ctx, rule.ID)
			expectAPIError(t, err, 403, "admin CANNOT delete immutable rule")
		})
	})
}

// =============================================================================
// Group D: Safety Limits
// =============================================================================

func TestRBAC_D2_BlockedRuleTypes(t *testing.T) {
	ctx := context.Background()
	agentClient := createRoleClient(t, "agent", "e2e-rbac-d2-agent")
	devClient := createRoleClient(t, "dev", "e2e-rbac-d2-dev")

	chainType := "evm"

	t.Run("D2.1_agent_cannot_evm_js", func(t *testing.T) {
		_, err := agentClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "D2.1",
			Type:      "evm_js",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"script": "function validate(input) { return ok(); }"},
			Enabled:   true,
		})
		expectAPIError(t, err, 403, "agent CANNOT create evm_js")
	})

	t.Run("D2.2_agent_cannot_signer_restriction", func(t *testing.T) {
		_, err := agentClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "D2.2",
			Type:      "signer_restriction",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"allowed_signers": []string{signerAddress}},
			Enabled:   true,
		})
		expectAPIError(t, err, 403, "agent CANNOT create signer_restriction")
	})

	t.Run("D2.3_agent_cannot_solidity", func(t *testing.T) {
		_, err := agentClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "D2.3",
			Type:      "evm_solidity_expression",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"expression": "require(true);"},
			Enabled:   true,
		})
		expectAPIError(t, err, 403, "agent CANNOT create evm_solidity_expression")
	})

	t.Run("D2.4_agent_can_address_list", func(t *testing.T) {
		rule := createTestAddressListRule(t, agentClient, "D2.4 address list")
		assert.NotEmpty(t, rule.ID)
	})

	t.Run("D2.5_agent_can_contract_method", func(t *testing.T) {
		rule, err := agentClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "D2.5 contract method",
			Type:      "evm_contract_method",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"method_sigs": []string{"0xa9059cbb"}},
			Enabled:   true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { adminClient.EVM.Rules.Delete(context.Background(), rule.ID) })
		assert.NotEmpty(t, rule.ID)
	})

	t.Run("D2.6_agent_can_value_limit", func(t *testing.T) {
		rule, err := agentClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "D2.6 value limit",
			Type:      "evm_value_limit",
			Mode:      "blocklist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"max_value": "1000000000000000000"},
			Enabled:   true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { adminClient.EVM.Rules.Delete(context.Background(), rule.ID) })
		assert.NotEmpty(t, rule.ID)
	})

	t.Run("D2.9_dev_cannot_signer_restriction", func(t *testing.T) {
		_, err := devClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "D2.9 dev signer restriction",
			Type:      "signer_restriction",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"allowed_signers": []string{signerAddress}},
			Enabled:   true,
		})
		expectAPIError(t, err, 403, "dev CANNOT create signer_restriction")
	})

	t.Run("D2.10_dev_can_evm_js", func(t *testing.T) {
		rule, err := devClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "D2.10 dev evm_js",
			Type:      "evm_js",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config: map[string]interface{}{
				"script": "function validate(input) { if (input.chain_id === 999) return fail('chain 999 blocked'); return ok(); }",
			},
			Enabled: true,
			TestCases: []evm.JSRuleTestCase{
				{
					Name:       "positive: chain 1 allowed",
					Input:      map[string]interface{}{"sign_type": "personal", "chain_id": 1, "signer": signerAddress, "personal_sign": map[string]interface{}{"message": "hi"}},
					ExpectPass: true,
				},
				{
					Name:         "negative: chain 999 blocked",
					Input:        map[string]interface{}{"sign_type": "personal", "chain_id": 999, "signer": signerAddress, "personal_sign": map[string]interface{}{"message": "hi"}},
					ExpectPass:   false,
					ExpectReason: "chain 999 blocked",
				},
			},
		})
		require.NoError(t, err)
		t.Cleanup(func() { adminClient.EVM.Rules.Delete(context.Background(), rule.ID) })
		assert.NotEmpty(t, rule.ID)
	})

	t.Run("D2.11_admin_can_any_type", func(t *testing.T) {
		rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
			Name:      "D2.11 admin signer restriction",
			Type:      "signer_restriction",
			Mode:      "whitelist",
			ChainType: &chainType,
			Config:    map[string]interface{}{"allowed_signers": []string{signerAddress}},
			Enabled:   true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { adminClient.EVM.Rules.Delete(context.Background(), rule.ID) })
		assert.NotEmpty(t, rule.ID)
	})
}

// =============================================================================
// Group E: Config-Sourced Rules
// =============================================================================

func TestRBAC_E_ConfigSourcedRules(t *testing.T) {
	ctx := context.Background()

	t.Run("E1_E2_config_rules_have_star_and_config_owner", func(t *testing.T) {
		resp, err := adminClient.EVM.Rules.List(ctx, nil)
		require.NoError(t, err)

		var configRuleFound bool
		for _, r := range resp.Rules {
			if r.Source == "config" {
				configRuleFound = true
				assert.Contains(t, r.AppliedTo, "*", "config rules should have applied_to=[*]")
				require.NotNil(t, r.Owner)
				assert.Equal(t, "config", *r.Owner, "config rules should have owner=config")
			}
		}
		if !configRuleFound {
			t.Skip("no config-sourced rules found")
		}
	})
}

// =============================================================================
// Group F: Audit
// =============================================================================

func TestRBAC_F_Audit(t *testing.T) {
	ctx := context.Background()

	t.Run("F1_agent_create_rule_audit", func(t *testing.T) {
		agentClient := createRoleClient(t, "agent", "e2e-rbac-f1-agent")
		rule := createTestAddressListRule(t, agentClient, "RBAC-F1 audit")

		// Check audit logs via admin, filtering by event type and API key
		resp, err := adminClient.Audit.List(ctx, &audit.ListFilter{
			EventType: "rule_created",
			APIKeyID:  "e2e-rbac-f1-agent",
			Limit:     50,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)

		// Look for entry related to this rule
		var found bool
		for _, entry := range resp.Records {
			if entry.RuleID != nil && *entry.RuleID == rule.ID {
				found = true
				break
			}
		}
		assert.True(t, found, "audit log should contain rule_created entry for rule %s (got %d records)", rule.ID, len(resp.Records))
	})

	t.Run("F6_agent_can_read_audit", func(t *testing.T) {
		agentClient := createRoleClient(t, "agent", "e2e-rbac-f6-agent")
		// Agent should NOT be able to read audit (no PermReadAudit for agent role)
		_, err := agentClient.Audit.List(ctx, nil)
		// Agent does NOT have read_audit permission in the RBAC matrix
		expectAPIError(t, err, 403, "agent CANNOT read audit logs")
	})

	t.Run("F7_strategy_cannot_read_audit", func(t *testing.T) {
		stratClient := createRoleClient(t, "strategy", "e2e-rbac-f7-strat")
		_, err := stratClient.Audit.List(ctx, nil)
		expectAPIError(t, err, 403, "strategy CANNOT read audit logs")
	})
}

// =============================================================================
// Group G: Multi-Agent Isolation
// =============================================================================

func TestRBAC_G_MultiAgentIsolation(t *testing.T) {
	ctx := context.Background()

	agentAClient := createRoleClient(t, "agent", "e2e-rbac-g-agent-a")
	agentBClient := createRoleClient(t, "agent", "e2e-rbac-g-agent-b")

	// Agent-A creates a rule
	ruleA := createTestAddressListRule(t, agentAClient, "RBAC-G agent-A rule")

	t.Run("G4_agentA_cannot_see_agentB_rules", func(t *testing.T) {
		// Agent-B creates a rule
		ruleB := createTestAddressListRule(t, agentBClient, "RBAC-G agent-B rule")

		// Agent-A lists rules — should NOT see agent-B's rule
		respA, err := agentAClient.EVM.Rules.List(ctx, nil)
		require.NoError(t, err)

		for _, r := range respA.Rules {
			assert.NotEqual(t, ruleB.ID, r.ID, "agent-A should NOT see agent-B's rule in list")
		}
	})

	t.Run("G5_agentA_cannot_read_agentB_rule_by_id", func(t *testing.T) {
		ruleB := createTestAddressListRule(t, agentBClient, "RBAC-G5 agent-B rule")
		_, err := agentAClient.EVM.Rules.Get(ctx, ruleB.ID)
		// Should be 403 or 404 (rule not visible to agent-A)
		require.Error(t, err, "agent-A should NOT be able to read agent-B's rule by ID")
	})

	t.Run("G1_agentA_sees_own_rule", func(t *testing.T) {
		respA, err := agentAClient.EVM.Rules.List(ctx, nil)
		require.NoError(t, err)
		var found bool
		for _, r := range respA.Rules {
			if r.ID == ruleA.ID {
				found = true
				break
			}
		}
		assert.True(t, found, "agent-A should see its own rule")
	})
}
