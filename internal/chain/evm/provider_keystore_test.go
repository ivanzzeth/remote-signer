package evm

import (
	"context"
	"os"
	"testing"

	"github.com/ivanzzeth/ethsig/keystore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// =============================================================================
// NewKeystoreProvider constructor tests
// =============================================================================

func TestNewKeystoreProvider_NilRegistry(t *testing.T) {
	pwProvider, err := NewCompositePasswordProvider(false)
	require.NoError(t, err)

	_, err = NewKeystoreProvider(nil, nil, t.TempDir(), pwProvider)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registry is required")
}

func TestNewKeystoreProvider_NilPasswordProvider(t *testing.T) {
	registry := NewEmptySignerRegistry()

	_, err := NewKeystoreProvider(registry, nil, t.TempDir(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "password provider is required")
}

func TestNewKeystoreProvider_EmptyConfigs(t *testing.T) {
	registry := NewEmptySignerRegistry()
	pwProvider, err := NewCompositePasswordProvider(false)
	require.NoError(t, err)

	provider, err := NewKeystoreProvider(registry, nil, t.TempDir(), pwProvider)
	require.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, 0, registry.SignerCount())
}

func TestNewKeystoreProvider_DisabledConfigSkipped(t *testing.T) {
	registry := NewEmptySignerRegistry()
	pwProvider, err := NewCompositePasswordProvider(false)
	require.NoError(t, err)

	configs := []KeystoreConfig{
		{
			Address:     "0x0000000000000000000000000000000000000001",
			Path:        "/non/existent/keystore.json",
			PasswordEnv: "TEST_KS_PASSWORD",
			Enabled:     false,
		},
	}

	provider, err := NewKeystoreProvider(registry, configs, t.TempDir(), pwProvider)
	require.NoError(t, err)
	assert.Equal(t, 0, registry.SignerCount())
	assert.NotNil(t, provider)
}

func TestNewKeystoreProvider_LoadFromConfig(t *testing.T) {
	ksDir := t.TempDir()
	password := []byte("test-ks-config-load")

	// Create a keystore file
	address, keystorePath, err := keystore.CreateKeystore(ksDir, password)
	require.NoError(t, err)
	require.NotEmpty(t, address)

	registry := NewEmptySignerRegistry()
	configs := []KeystoreConfig{
		{
			Address:     address,
			Path:        keystorePath,
			PasswordEnv: "TEST_KS_PASSWORD",
			Enabled:     true,
		},
	}

	pwProvider := &mockPasswordProvider{password: password}
	provider, err := NewKeystoreProvider(registry, configs, ksDir, pwProvider)
	require.NoError(t, err)
	defer provider.Close()

	// Keystore signer should be registered
	assert.Equal(t, 1, registry.SignerCount())
	assert.True(t, registry.HasSigner(address))

	// Verify the signer can sign
	signer, err := registry.GetSigner(address)
	require.NoError(t, err)
	sig, err := signer.PersonalSign("hello keystore")
	require.NoError(t, err)
	assert.Len(t, sig, 65)
}

func TestNewKeystoreProvider_PasswordError(t *testing.T) {
	ksDir := t.TempDir()
	password := []byte("temp-password")

	address, keystorePath, err := keystore.CreateKeystore(ksDir, password)
	require.NoError(t, err)

	registry := NewEmptySignerRegistry()
	configs := []KeystoreConfig{
		{
			Address:     address,
			Path:        keystorePath,
			PasswordEnv: "TEST_KS_PASSWORD",
			Enabled:     true,
		},
	}

	pwProvider := &mockPasswordProvider{err: assert.AnError}
	_, err = NewKeystoreProvider(registry, configs, ksDir, pwProvider)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get password")
}

func TestNewKeystoreProvider_WrongPassword(t *testing.T) {
	ksDir := t.TempDir()
	password := []byte("correct-password")

	address, keystorePath, err := keystore.CreateKeystore(ksDir, password)
	require.NoError(t, err)

	registry := NewEmptySignerRegistry()
	configs := []KeystoreConfig{
		{
			Address:     address,
			Path:        keystorePath,
			PasswordEnv: "TEST_KS_PASSWORD",
			Enabled:     true,
		},
	}

	pwProvider := &mockPasswordProvider{password: []byte("wrong-password")}
	_, err = NewKeystoreProvider(registry, configs, ksDir, pwProvider)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load keystore")
}

func TestNewKeystoreProvider_MultipleKeystores(t *testing.T) {
	ksDir := t.TempDir()
	password := []byte("multi-ks-password")

	// Create two keystores
	addr1, path1, err := keystore.CreateKeystore(ksDir, password)
	require.NoError(t, err)
	addr2, path2, err := keystore.CreateKeystore(ksDir, password)
	require.NoError(t, err)

	registry := NewEmptySignerRegistry()
	configs := []KeystoreConfig{
		{Address: addr1, Path: path1, PasswordEnv: "PW", Enabled: true},
		{Address: addr2, Path: path2, PasswordEnv: "PW", Enabled: true},
	}

	// Use copyMockPasswordProvider because SecureZeroize zeroes the returned slice;
	// the non-copy mock would return a zeroed password on the second call.
	pwProvider := &copyMockPasswordProvider{password: password}
	provider, err := NewKeystoreProvider(registry, configs, ksDir, pwProvider)
	require.NoError(t, err)
	defer provider.Close()

	assert.Equal(t, 2, registry.SignerCount())
	assert.True(t, registry.HasSigner(addr1))
	assert.True(t, registry.HasSigner(addr2))
}

// =============================================================================
// CreateSigner tests
// =============================================================================

func TestKeystoreProvider_CreateSigner(t *testing.T) {
	tempDir := t.TempDir()
	registry := NewEmptySignerRegistry()

	pwProvider, err := NewCompositePasswordProvider(false)
	require.NoError(t, err)

	provider, err := NewKeystoreProvider(registry, nil, tempDir, pwProvider)
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()

	signerInfo, err := provider.CreateSigner(ctx, &types.CreateKeystoreParams{
		Password: "test-password-123",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, signerInfo.Address)
	assert.Equal(t, string(types.SignerTypeKeystore), signerInfo.Type)
	assert.True(t, signerInfo.Enabled)

	// Verify the signer is registered in the registry
	assert.True(t, registry.HasSigner(signerInfo.Address))
	assert.Equal(t, 1, registry.SignerCount())

	// Verify the signer can be retrieved and sign
	signer, err := registry.GetSigner(signerInfo.Address)
	require.NoError(t, err)
	assert.NotNil(t, signer)

	sig, err := signer.PersonalSign("test message")
	require.NoError(t, err)
	assert.Len(t, sig, 65)
}

func TestKeystoreProvider_CreateSignerInvalidParams(t *testing.T) {
	tempDir := t.TempDir()
	registry := NewEmptySignerRegistry()
	pwProvider, err := NewCompositePasswordProvider(false)
	require.NoError(t, err)

	provider, err := NewKeystoreProvider(registry, nil, tempDir, pwProvider)
	require.NoError(t, err)

	ctx := context.Background()

	// Wrong type
	_, err = provider.CreateSigner(ctx, "not-keystore-params")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid params type")

	// Nil params
	_, err = provider.CreateSigner(ctx, (*types.CreateKeystoreParams)(nil))
	require.Error(t, err)
	assert.ErrorIs(t, err, types.ErrMissingKeystoreParams)
}

func TestKeystoreProvider_CreateSignerEmptyPassword(t *testing.T) {
	tempDir := t.TempDir()
	registry := NewEmptySignerRegistry()
	pwProvider, err := NewCompositePasswordProvider(false)
	require.NoError(t, err)

	provider, err := NewKeystoreProvider(registry, nil, tempDir, pwProvider)
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()

	// Empty password should fail during keystore creation
	_, err = provider.CreateSigner(ctx, &types.CreateKeystoreParams{
		Password: "",
	})
	require.Error(t, err)
}

// =============================================================================
// Type and Close tests
// =============================================================================

func TestKeystoreProvider_Type(t *testing.T) {
	registry := NewEmptySignerRegistry()
	pwProvider, err := NewCompositePasswordProvider(false)
	require.NoError(t, err)

	provider, err := NewKeystoreProvider(registry, nil, t.TempDir(), pwProvider)
	require.NoError(t, err)

	assert.Equal(t, types.SignerTypeKeystore, provider.Type())
}

func TestKeystoreProvider_Close(t *testing.T) {
	registry := NewEmptySignerRegistry()
	pwProvider, err := NewCompositePasswordProvider(false)
	require.NoError(t, err)

	provider, err := NewKeystoreProvider(registry, nil, t.TempDir(), pwProvider)
	require.NoError(t, err)

	err = provider.Close()
	assert.NoError(t, err)
}

// =============================================================================
// EnvPasswordProvider tests
// =============================================================================

func TestEnvPasswordProvider_Success(t *testing.T) {
	provider, err := NewEnvPasswordProvider()
	require.NoError(t, err)

	const envVar = "TEST_ENV_PW_PROVIDER_12345"
	t.Setenv(envVar, "my-secret-password")

	pw, err := provider.GetPassword("0xABC", KeystoreConfig{PasswordEnv: envVar})
	require.NoError(t, err)
	assert.Equal(t, []byte("my-secret-password"), pw)
}

func TestEnvPasswordProvider_EmptyEnvVar(t *testing.T) {
	provider, err := NewEnvPasswordProvider()
	require.NoError(t, err)

	_, err = provider.GetPassword("0xABC", KeystoreConfig{PasswordEnv: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "password_env not configured")
}

func TestEnvPasswordProvider_UnsetEnvVar(t *testing.T) {
	provider, err := NewEnvPasswordProvider()
	require.NoError(t, err)

	// Ensure env var is unset
	os.Unsetenv("NONEXISTENT_PW_VAR_FOR_TEST_xyz")

	_, err = provider.GetPassword("0xABC", KeystoreConfig{PasswordEnv: "NONEXISTENT_PW_VAR_FOR_TEST_xyz"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is empty")
}

func TestCompositePasswordProvider_EnvMode(t *testing.T) {
	const envVar = "TEST_COMPOSITE_PW_12345"
	t.Setenv(envVar, "composite-password")

	cp, err := NewCompositePasswordProvider(false)
	require.NoError(t, err)

	pw, err := cp.GetPassword("0xABC", KeystoreConfig{PasswordEnv: envVar})
	require.NoError(t, err)
	assert.Equal(t, []byte("composite-password"), pw)
}

func TestCompositePasswordProvider_StdinWithoutInit(t *testing.T) {
	// Stdin provider not initialized (hasStdinKeystores=false)
	cp, err := NewCompositePasswordProvider(false)
	require.NoError(t, err)

	// Requesting stdin password should fail
	_, err = cp.GetPassword("0xABC", KeystoreConfig{PasswordStdin: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stdin password provider not initialized")
}
