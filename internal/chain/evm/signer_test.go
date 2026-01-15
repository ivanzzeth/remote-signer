package evm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestSignerRegistry_ListSignersWithFilter(t *testing.T) {
	// Create a registry with test signers using private keys
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
			{
				Address:   "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
				KeyEnvVar: "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
				Enabled:   true,
			},
		},
	}

	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)

	t.Run("list all signers", func(t *testing.T) {
		result := registry.ListSignersWithFilter(types.SignerFilter{
			Limit: 10,
		})
		assert.Equal(t, 2, result.Total)
		assert.Len(t, result.Signers, 2)
		assert.False(t, result.HasMore)
	})

	t.Run("filter by type - private_key", func(t *testing.T) {
		signerType := types.SignerTypePrivateKey
		result := registry.ListSignersWithFilter(types.SignerFilter{
			Type:  &signerType,
			Limit: 10,
		})
		assert.Equal(t, 2, result.Total)
		for _, s := range result.Signers {
			assert.Equal(t, string(types.SignerTypePrivateKey), s.Type)
		}
	})

	t.Run("filter by type - keystore (none)", func(t *testing.T) {
		signerType := types.SignerTypeKeystore
		result := registry.ListSignersWithFilter(types.SignerFilter{
			Type:  &signerType,
			Limit: 10,
		})
		assert.Equal(t, 0, result.Total)
		assert.Len(t, result.Signers, 0)
	})

	t.Run("pagination - offset", func(t *testing.T) {
		result := registry.ListSignersWithFilter(types.SignerFilter{
			Offset: 1,
			Limit:  10,
		})
		assert.Equal(t, 2, result.Total)
		assert.Len(t, result.Signers, 1)
		assert.False(t, result.HasMore)
	})

	t.Run("pagination - limit", func(t *testing.T) {
		result := registry.ListSignersWithFilter(types.SignerFilter{
			Offset: 0,
			Limit:  1,
		})
		assert.Equal(t, 2, result.Total)
		assert.Len(t, result.Signers, 1)
		assert.True(t, result.HasMore)
	})

	t.Run("pagination - offset beyond total", func(t *testing.T) {
		result := registry.ListSignersWithFilter(types.SignerFilter{
			Offset: 10,
			Limit:  10,
		})
		assert.Equal(t, 2, result.Total)
		assert.Len(t, result.Signers, 0)
		assert.False(t, result.HasMore)
	})

	t.Run("no limit returns all", func(t *testing.T) {
		result := registry.ListSignersWithFilter(types.SignerFilter{
			Offset: 0,
			Limit:  0, // No limit
		})
		assert.Equal(t, 2, result.Total)
		assert.Len(t, result.Signers, 2)
		assert.False(t, result.HasMore)
	})
}

func TestSignerRegistry_RegisterKeystore_AlreadyExists(t *testing.T) {
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

	// Try to register a keystore with an existing address
	err = registry.RegisterKeystore(
		"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		"/nonexistent/path",
		[]byte("password"),
	)
	assert.ErrorIs(t, err, types.ErrAlreadyExists)
}
