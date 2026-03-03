package evm

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestSignerManager_CreateSigner_Keystore(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "signer-manager-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	registry := NewEmptySignerRegistry()

	// Register a private key provider with a test key
	_, err = NewPrivateKeyProvider(registry, []PrivateKeyConfig{
		{
			Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
			KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
			Enabled:   true,
		},
	})
	require.NoError(t, err)

	// Register a keystore provider (needed for dynamic creation)
	pwProvider, err := NewEnvPasswordProvider()
	require.NoError(t, err)
	ksProvider, err := NewKeystoreProvider(registry, nil, tempDir, pwProvider)
	require.NoError(t, err)
	registry.RegisterProvider(ksProvider)

	manager, err := NewSignerManager(registry)
	require.NoError(t, err)

	// Create a new keystore signer
	req := types.CreateSignerRequest{
		Type: types.SignerTypeKeystore,
		Keystore: &types.CreateKeystoreParams{
			Password: "test-password-123",
		},
	}

	signerInfo, err := manager.CreateSigner(context.Background(), req)
	require.NoError(t, err)

	assert.NotEmpty(t, signerInfo.Address)
	assert.Equal(t, string(types.SignerTypeKeystore), signerInfo.Type)
	assert.True(t, signerInfo.Enabled)

	// Verify the signer is registered and can sign
	assert.True(t, registry.HasSigner(signerInfo.Address))

	// List should now include the new signer
	result := registry.ListSignersWithFilter(types.SignerFilter{Limit: 10})
	assert.Equal(t, 2, result.Total) // Original + new keystore
}

func TestSignerManager_CreateSigner_ValidationErrors(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "signer-manager-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	registry := NewEmptySignerRegistry()

	_, err = NewPrivateKeyProvider(registry, []PrivateKeyConfig{
		{
			Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
			KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
			Enabled:   true,
		},
	})
	require.NoError(t, err)

	pwProvider, err := NewEnvPasswordProvider()
	require.NoError(t, err)
	ksProvider, err := NewKeystoreProvider(registry, nil, tempDir, pwProvider)
	require.NoError(t, err)
	registry.RegisterProvider(ksProvider)

	manager, err := NewSignerManager(registry)
	require.NoError(t, err)

	tests := []struct {
		name        string
		req         types.CreateSignerRequest
		expectError error
	}{
		{
			name:        "missing type",
			req:         types.CreateSignerRequest{},
			expectError: types.ErrMissingSignerType,
		},
		{
			name: "missing keystore params",
			req: types.CreateSignerRequest{
				Type: types.SignerTypeKeystore,
			},
			expectError: types.ErrMissingKeystoreParams,
		},
		{
			name: "empty password",
			req: types.CreateSignerRequest{
				Type: types.SignerTypeKeystore,
				Keystore: &types.CreateKeystoreParams{
					Password: "",
				},
			},
			expectError: types.ErrEmptyPassword,
		},
		{
			name: "private key creation not supported",
			req: types.CreateSignerRequest{
				Type: types.SignerTypePrivateKey,
			},
			expectError: types.ErrPrivateKeyCreationNotSupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := manager.CreateSigner(context.Background(), tt.req)
			assert.ErrorIs(t, err, tt.expectError)
		})
	}
}

func TestSignerManager_ListSigners(t *testing.T) {
	registry := NewEmptySignerRegistry()

	_, err := NewPrivateKeyProvider(registry, []PrivateKeyConfig{
		{
			Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
			KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
			Enabled:   true,
		},
	})
	require.NoError(t, err)

	manager, err := NewSignerManager(registry)
	require.NoError(t, err)

	result, err := manager.ListSigners(context.Background(), types.SignerFilter{Limit: 10})
	require.NoError(t, err)

	assert.Equal(t, 1, result.Total)
	assert.Len(t, result.Signers, 1)
	assert.Equal(t, string(types.SignerTypePrivateKey), result.Signers[0].Type)
}

func TestNewSignerManager_Validation(t *testing.T) {
	_, err := NewSignerManager(nil)
	assert.Error(t, err)
}

func TestSignerManager_HDWalletManager_NotConfigured(t *testing.T) {
	registry := NewEmptySignerRegistry()

	manager, err := NewSignerManager(registry)
	require.NoError(t, err)

	_, err = manager.HDWalletManager()
	assert.ErrorIs(t, err, types.ErrHDWalletNotConfigured)
}

func TestSignerManager_HDWalletManager_Configured(t *testing.T) {
	registry := NewEmptySignerRegistry()

	pwProvider, err := NewEnvPasswordProvider()
	require.NoError(t, err)

	hdProvider, err := NewHDWalletProvider(registry, nil, t.TempDir(), pwProvider)
	require.NoError(t, err)
	registry.RegisterProvider(hdProvider)

	manager, err := NewSignerManager(registry)
	require.NoError(t, err)

	mgr, err := manager.HDWalletManager()
	require.NoError(t, err)
	assert.NotNil(t, mgr)
}
