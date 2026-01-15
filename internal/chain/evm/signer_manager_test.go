package evm

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestSignerManager_CreateSigner_Keystore(t *testing.T) {
	// Create a temp directory for keystores
	tempDir, err := os.MkdirTemp("", "signer-manager-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a registry with a test signer
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}

	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	manager, err := NewSignerManager(registry, tempDir, logger)
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

	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}

	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	manager, err := NewSignerManager(registry, tempDir, logger)
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
			name: "unsupported type",
			req: types.CreateSignerRequest{
				Type: types.SignerType("aws_kms"),
			},
			expectError: types.ErrUnsupportedSignerType,
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
	tempDir, err := os.MkdirTemp("", "signer-manager-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}

	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	manager, err := NewSignerManager(registry, tempDir, logger)
	require.NoError(t, err)

	result, err := manager.ListSigners(context.Background(), types.SignerFilter{Limit: 10})
	require.NoError(t, err)

	assert.Equal(t, 1, result.Total)
	assert.Len(t, result.Signers, 1)
	assert.Equal(t, string(types.SignerTypePrivateKey), result.Signers[0].Type)
}

func TestNewSignerManager_Validation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}

	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)

	t.Run("nil registry", func(t *testing.T) {
		_, err := NewSignerManager(nil, "/tmp", logger)
		assert.Error(t, err)
	})

	t.Run("empty keystore dir", func(t *testing.T) {
		_, err := NewSignerManager(registry, "", logger)
		assert.Error(t, err)
	})

	t.Run("nil logger", func(t *testing.T) {
		_, err := NewSignerManager(registry, "/tmp", nil)
		assert.Error(t, err)
	})
}
