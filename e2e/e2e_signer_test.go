//go:build e2e
package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

func TestSigner_ListSigners(t *testing.T) {
	ctx := context.Background()

	// List signers (should include the test signer)
	resp, err := adminClient.EVM.Signers.List(ctx, &evm.ListSignersFilter{
		Limit: 100,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.GreaterOrEqual(t, resp.Total, 1, "Should have at least the test signer")

	// Verify the test signer is in the list
	found := false
	for _, signer := range resp.Signers {
		if signer.Address == signerAddress {
			found = true
			assert.True(t, signer.Enabled, "Test signer should be enabled")
			assert.Equal(t, "private_key", signer.Type)
			break
		}
	}
	assert.True(t, found, "Test signer should be in the list")
}

func TestSigner_ListSignersWithTypeFilter(t *testing.T) {
	ctx := context.Background()

	// Filter by private_key type
	resp, err := adminClient.EVM.Signers.List(ctx, &evm.ListSignersFilter{
		Type:  "private_key",
		Limit: 10,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// All returned signers should be private_key type
	for _, signer := range resp.Signers {
		assert.Equal(t, "private_key", signer.Type)
	}

	// Filter by keystore type (should be empty initially)
	resp, err = adminClient.EVM.Signers.List(ctx, &evm.ListSignersFilter{
		Type:  "keystore",
		Limit: 10,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	// May or may not have keystore signers depending on test order
}

func TestSigner_ListSignersPagination(t *testing.T) {
	ctx := context.Background()

	// Test pagination with small limit
	resp, err := adminClient.EVM.Signers.List(ctx, &evm.ListSignersFilter{
		Limit: 1,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.LessOrEqual(t, len(resp.Signers), 1)

	// If there are more signers, HasMore should be true
	if resp.Total > 1 {
		assert.True(t, resp.HasMore, "HasMore should be true when more signers exist")

		// Get next page
		resp2, err := adminClient.EVM.Signers.List(ctx, &evm.ListSignersFilter{
			Offset: 1,
			Limit:  1,
		})
		require.NoError(t, err)
		require.NotNil(t, resp2)

		// Should have different signers
		if len(resp.Signers) > 0 && len(resp2.Signers) > 0 {
			assert.NotEqual(t, resp.Signers[0].Address, resp2.Signers[0].Address,
				"Page 2 should have different signers than page 1")
		}
	}
}

func TestSigner_CreateKeystoreSigner(t *testing.T) {
	if useExternalServer {
		t.Skip("Skipping: keystore creation test not supported with external server")
	}

	ctx := context.Background()

	// Create a new keystore signer
	req := &evm.CreateSignerRequest{
		Type: "keystore",
		Keystore: &evm.CreateKeystoreParams{
			Password: "test-password-e2e-123",
		},
	}

	signer, err := adminClient.EVM.Signers.Create(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, signer)

	assert.NotEmpty(t, signer.Address, "Created signer should have an address")
	assert.Equal(t, "keystore", signer.Type)
	assert.True(t, signer.Enabled, "Created signer should be enabled")

	// Verify the new signer appears in the list
	resp, err := adminClient.EVM.Signers.List(ctx, &evm.ListSignersFilter{
		Limit: 100,
	})
	require.NoError(t, err)

	found := false
	for _, s := range resp.Signers {
		if s.Address == signer.Address {
			found = true
			assert.Equal(t, "keystore", s.Type)
			break
		}
	}
	assert.True(t, found, "Newly created signer should appear in the list")
}

func TestSigner_CreateSignerValidationErrors(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		req         *evm.CreateSignerRequest
		expectError bool
	}{
		{
			name:        "missing type",
			req:         &evm.CreateSignerRequest{},
			expectError: true,
		},
		{
			name: "missing keystore params",
			req: &evm.CreateSignerRequest{
				Type: "keystore",
			},
			expectError: true,
		},
		{
			name: "empty password",
			req: &evm.CreateSignerRequest{
				Type: "keystore",
				Keystore: &evm.CreateKeystoreParams{
					Password: "",
				},
			},
			expectError: true,
		},
		{
			name: "unsupported type",
			req: &evm.CreateSignerRequest{
				Type: "aws_kms",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := adminClient.EVM.Signers.Create(ctx, tt.req)
			if tt.expectError {
				require.Error(t, err, "Expected error for %s", tt.name)
			} else {
				require.NoError(t, err, "Expected no error for %s", tt.name)
			}
		})
	}
}

func TestSigner_NonAdminCanListSigners(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	// Non-admin should be able to list signers (GET is public)
	resp, err := nonAdminClient.EVM.Signers.List(ctx, &evm.ListSignersFilter{
		Limit: 10,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.GreaterOrEqual(t, resp.Total, 1)
}

func TestSigner_NonAdminCannotCreateSigner(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	// Non-admin should NOT be able to create signers
	req := &evm.CreateSignerRequest{
		Type: "keystore",
		Keystore: &evm.CreateKeystoreParams{
			Password: "test-password",
		},
	}

	_, err := nonAdminClient.EVM.Signers.Create(ctx, req)
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode, "Non-admin should get 403 Forbidden")
}

// =============================================================================
// Template Management Tests
// =============================================================================
