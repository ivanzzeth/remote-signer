//go:build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// personalSignReq creates a personal sign request for the given signer address.
func personalSignReq(signerAddr string) *evm.SignRequest {
	return &evm.SignRequest{
		ChainID:      chainID,
		SignerAddress: signerAddr,
		SignType:     evm.SignTypePersonal,
		Payload:      []byte(`{"message":"access-test"}`),
	}
}

// TestSignerAccess_GrantRevokeSignScope tests the full grant/revoke/sign flow.
// Uses the pre-configured test signer (which already has a whitelist rule) so the
// rule engine permits signing when the access check passes.
func TestSignerAccess_GrantRevokeSignScope(t *testing.T) {
	ensureGuardResumed(t)
	ctx := context.Background()

	// Use the existing test signer that has a whitelist rule in config.e2e.yaml
	addr := signerAddress

	// Create an agent client
	agentClient := createRoleClient(t, "agent", "e2e-access-agent")

	// Agent cannot sign with this signer (no access)
	_, signErr := agentClient.EVM.Sign.Execute(ctx, personalSignReq(addr))
	require.Error(t, signErr, "agent should not be able to sign without access")
	assert.Contains(t, signErr.Error(), "403")

	// Admin grants access to agent
	err := adminClient.EVM.Signers.GrantAccess(ctx, addr, &evm.GrantAccessRequest{
		APIKeyID: "e2e-access-agent",
	})
	require.NoError(t, err)
	// Clean up access grant on test end
	t.Cleanup(func() {
		adminClient.EVM.Signers.RevokeAccess(context.Background(), addr, "e2e-access-agent")
	})

	// Agent can now sign
	result, signErr := agentClient.EVM.Sign.Execute(ctx, personalSignReq(addr))
	require.NoError(t, signErr)
	assert.NotEmpty(t, result.Signature)

	// Admin lists access
	accesses, err := adminClient.EVM.Signers.ListAccess(ctx, addr)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(accesses), 1, "should have at least one access grant")
	found := false
	for _, a := range accesses {
		if a.APIKeyID == "e2e-access-agent" {
			found = true
			break
		}
	}
	assert.True(t, found, "access list should contain e2e-access-agent")

	// Admin revokes access
	err = adminClient.EVM.Signers.RevokeAccess(ctx, addr, "e2e-access-agent")
	require.NoError(t, err)

	// Agent can no longer sign
	_, signErr = agentClient.EVM.Sign.Execute(ctx, personalSignReq(addr))
	require.Error(t, signErr, "agent should not be able to sign after revoke")
	assert.Contains(t, signErr.Error(), "403")
}

// TestSignerAccess_OwnerSeesSignerInList tests that only accessible signers appear in list.
func TestSignerAccess_OwnerSeesSignerInList(t *testing.T) {
	ctx := context.Background()

	// Create a signer
	signer, err := adminClient.EVM.Signers.Create(ctx, &evm.CreateSignerRequest{
		Type: "keystore",
		Keystore: &evm.CreateKeystoreParams{
			Password: "list-test-pass-1234",
		},
	})
	require.NoError(t, err)
	addr := signer.Address

	// Admin sees it
	adminSigners, err := adminClient.EVM.Signers.List(ctx, nil)
	require.NoError(t, err)
	found := false
	for _, s := range adminSigners.Signers {
		if s.Address == addr {
			found = true
			assert.NotEmpty(t, s.OwnerID)
			break
		}
	}
	assert.True(t, found, "admin should see the signer in list")

	// Strategy client without access should not see it
	stratClient := createRoleClient(t, "strategy", "e2e-access-strat")
	stratSigners, err := stratClient.EVM.Signers.List(ctx, nil)
	require.NoError(t, err)
	for _, s := range stratSigners.Signers {
		assert.NotEqual(t, addr, s.Address, "strategy should not see signer without access")
	}
}

// TestSignerAccess_NonOwnerCannotGrant tests that non-owners cannot grant access.
func TestSignerAccess_NonOwnerCannotGrant(t *testing.T) {
	ctx := context.Background()

	// Use the test signer (admin owns it from startup)
	signers, err := adminClient.EVM.Signers.List(ctx, nil)
	require.NoError(t, err)
	require.True(t, len(signers.Signers) > 0, "need at least one signer")
	addr := signers.Signers[0].Address

	// Create a dev client and grant access so dev can see the signer
	devClient := createRoleClient(t, "dev", "e2e-access-dev")

	// Dev tries to grant access to itself (should fail — not owner)
	err = devClient.EVM.Signers.GrantAccess(ctx, addr, &evm.GrantAccessRequest{
		APIKeyID: "e2e-access-dev",
	})
	require.Error(t, err, "non-owner should not be able to grant access")
}

// TestSignerAccess_PendingApproval tests that non-admin created signers are pending.
func TestSignerAccess_PendingApproval(t *testing.T) {
	ctx := context.Background()

	// Create an agent client with create permission
	agentClient := createRoleClient(t, "agent", "e2e-access-pending")

	// Agent creates a signer (should be pending_approval)
	signer, err := agentClient.EVM.Signers.Create(ctx, &evm.CreateSignerRequest{
		Type: "keystore",
		Keystore: &evm.CreateKeystoreParams{
			Password: "pending-pass-1234567",
		},
	})
	require.NoError(t, err)
	addr := signer.Address

	// Agent can list it (owns it, even if pending)
	// But access check should fail because status is pending
	_, signErr := agentClient.EVM.Sign.Execute(ctx, personalSignReq(addr))
	require.Error(t, signErr, "pending signer should not be accessible for signing")

	// Admin approves
	err = adminClient.EVM.Signers.ApproveSigner(ctx, addr)
	require.NoError(t, err)

	// After approval, agent sees it in list as active
	agentSigners, err := agentClient.EVM.Signers.List(ctx, nil)
	require.NoError(t, err)
	found := false
	for _, s := range agentSigners.Signers {
		if s.Address == addr {
			found = true
			assert.Equal(t, "active", s.Status)
			break
		}
	}
	assert.True(t, found, "agent should see approved signer")
}
