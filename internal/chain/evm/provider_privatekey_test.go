package evm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// Well-known Hardhat test private key and its corresponding address.
const (
	testPrivateKeyHex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	testAddress       = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
)

func TestPrivateKeyProvider_LoadSigner(t *testing.T) {
	registry := NewEmptySignerRegistry()

	configs := []PrivateKeyConfig{
		{
			Address:   testAddress,
			KeyEnvVar: testPrivateKeyHex, // resolvePrivateKey treats 64-hex-char strings as direct values
			Enabled:   true,
		},
	}

	provider, err := NewPrivateKeyProvider(registry, configs)
	require.NoError(t, err)
	defer provider.Close()

	// Verify the signer is registered in the registry
	assert.True(t, registry.HasSigner(testAddress))
	assert.Equal(t, 1, registry.SignerCount())

	// Verify we can retrieve the signer and it has the correct address
	signer, err := registry.GetSigner(testAddress)
	require.NoError(t, err)
	assert.NotNil(t, signer)
}

func TestPrivateKeyProvider_AddressMismatch(t *testing.T) {
	registry := NewEmptySignerRegistry()

	// Use the correct private key but a wrong expected address
	wrongAddress := "0x0000000000000000000000000000000000000001"
	configs := []PrivateKeyConfig{
		{
			Address:   wrongAddress,
			KeyEnvVar: testPrivateKeyHex,
			Enabled:   true,
		},
	}

	_, err := NewPrivateKeyProvider(registry, configs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "address mismatch")
}

func TestPrivateKeyProvider_EmptyKey(t *testing.T) {
	registry := NewEmptySignerRegistry()

	// Use an env var name that does not exist, so resolvePrivateKey returns ""
	configs := []PrivateKeyConfig{
		{
			Address:   testAddress,
			KeyEnvVar: "NON_EXISTENT_ENV_VAR_FOR_TEST_12345",
			Enabled:   true,
		},
	}

	_, err := NewPrivateKeyProvider(registry, configs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "private key is empty")
}

func TestPrivateKeyProvider_DisabledSkipped(t *testing.T) {
	registry := NewEmptySignerRegistry()

	configs := []PrivateKeyConfig{
		{
			Address:   testAddress,
			KeyEnvVar: testPrivateKeyHex,
			Enabled:   false, // disabled
		},
	}

	provider, err := NewPrivateKeyProvider(registry, configs)
	require.NoError(t, err)
	defer provider.Close()

	// No signer should be registered because the config is disabled
	assert.Equal(t, 0, registry.SignerCount())
	assert.False(t, registry.HasSigner(testAddress))
}

func TestPrivateKeyProvider_Type(t *testing.T) {
	registry := NewEmptySignerRegistry()

	provider, err := NewPrivateKeyProvider(registry, nil)
	require.NoError(t, err)

	assert.Equal(t, types.SignerTypePrivateKey, provider.Type())
}

func TestPrivateKeyProvider_NilRegistry(t *testing.T) {
	configs := []PrivateKeyConfig{
		{
			Address:   testAddress,
			KeyEnvVar: testPrivateKeyHex,
			Enabled:   true,
		},
	}

	_, err := NewPrivateKeyProvider(nil, configs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registry is required")
}
