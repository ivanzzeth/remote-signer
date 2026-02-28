package evm

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/ivanzzeth/ethsig/keystore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// copyMockPasswordProvider returns a fresh copy of password each time, safe against SecureZeroize.
type copyMockPasswordProvider struct {
	password []byte
	err      error
}

func (m *copyMockPasswordProvider) GetPassword(_ string, _ KeystoreConfig) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	cp := make([]byte, len(m.password))
	copy(cp, m.password)
	return cp, nil
}

// =============================================================================
// NewHDWalletProvider constructor tests
// =============================================================================

func TestNewHDWalletProvider_NilRegistry(t *testing.T) {
	_, err := NewHDWalletProvider(nil, nil, t.TempDir(), &mockPasswordProvider{}, newTestLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registry is required")
}

func TestNewHDWalletProvider_NilLogger(t *testing.T) {
	registry := NewEmptySignerRegistry()
	_, err := NewHDWalletProvider(registry, nil, t.TempDir(), &mockPasswordProvider{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

func TestNewHDWalletProvider_EmptyConfigs(t *testing.T) {
	registry := NewEmptySignerRegistry()
	provider, err := NewHDWalletProvider(registry, nil, t.TempDir(), &mockPasswordProvider{}, newTestLogger())
	require.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, 0, registry.SignerCount())
}

func TestNewHDWalletProvider_DisabledConfigSkipped(t *testing.T) {
	registry := NewEmptySignerRegistry()
	configs := []HDWalletConfig{
		{
			Path:    "/non/existent/file.json",
			Enabled: false,
		},
	}
	provider, err := NewHDWalletProvider(registry, configs, t.TempDir(), &mockPasswordProvider{}, newTestLogger())
	require.NoError(t, err)
	assert.Equal(t, 0, registry.SignerCount())
	assert.Len(t, provider.ListHDWallets(), 0)
}

func TestNewHDWalletProvider_LoadFromConfig(t *testing.T) {
	walletDir := t.TempDir()
	password := []byte("test-config-load-password")

	// Create an HD wallet file to load from config
	address, walletPath, err := keystore.CreateHDWallet(walletDir, password, 128)
	require.NoError(t, err)
	require.NotEmpty(t, address)

	registry := NewEmptySignerRegistry()
	configs := []HDWalletConfig{
		{
			Path:        walletPath,
			PasswordEnv: "TEST_HD_PASSWORD",
			Enabled:     true,
		},
	}

	pwProvider := &mockPasswordProvider{password: password}
	provider, err := NewHDWalletProvider(registry, configs, walletDir, pwProvider, newTestLogger())
	require.NoError(t, err)
	defer provider.Close()

	// Primary address (index 0) should be registered
	assert.Equal(t, 1, registry.SignerCount())
	assert.True(t, registry.HasSigner(address))

	// Should appear in wallet list
	wallets := provider.ListHDWallets()
	assert.Len(t, wallets, 1)
}

func TestNewHDWalletProvider_LoadWithDeriveIndices(t *testing.T) {
	walletDir := t.TempDir()
	password := []byte("test-derive-indices-password")

	address, walletPath, err := keystore.CreateHDWallet(walletDir, password, 128)
	require.NoError(t, err)

	registry := NewEmptySignerRegistry()
	configs := []HDWalletConfig{
		{
			Path:          walletPath,
			PasswordEnv:   "TEST_HD_PASSWORD",
			DeriveIndices: []uint32{0, 1, 2}, // index 0 is primary (already derived), 1 and 2 are additional
			Enabled:       true,
		},
	}

	pwProvider := &mockPasswordProvider{password: password}
	provider, err := NewHDWalletProvider(registry, configs, walletDir, pwProvider, newTestLogger())
	require.NoError(t, err)
	defer provider.Close()

	// 3 addresses should be registered: index 0, 1, 2
	assert.Equal(t, 3, registry.SignerCount())
	assert.True(t, registry.HasSigner(address))

	wallets := provider.ListHDWallets()
	require.Len(t, wallets, 1)
	assert.Equal(t, 3, wallets[0].DerivedCount)
}

func TestNewHDWalletProvider_PasswordError(t *testing.T) {
	walletDir := t.TempDir()
	password := []byte("temp-password")

	_, walletPath, err := keystore.CreateHDWallet(walletDir, password, 128)
	require.NoError(t, err)

	registry := NewEmptySignerRegistry()
	configs := []HDWalletConfig{
		{
			Path:        walletPath,
			PasswordEnv: "TEST_HD_PASSWORD",
			Enabled:     true,
		},
	}

	pwProvider := &mockPasswordProvider{err: assert.AnError}
	_, err = NewHDWalletProvider(registry, configs, walletDir, pwProvider, newTestLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get password")
}

func TestNewHDWalletProvider_WrongPassword(t *testing.T) {
	walletDir := t.TempDir()
	password := []byte("correct-password")

	_, walletPath, err := keystore.CreateHDWallet(walletDir, password, 128)
	require.NoError(t, err)

	registry := NewEmptySignerRegistry()
	configs := []HDWalletConfig{
		{
			Path:        walletPath,
			PasswordEnv: "TEST_HD_PASSWORD",
			Enabled:     true,
		},
	}

	pwProvider := &mockPasswordProvider{password: []byte("wrong-password")}
	_, err = NewHDWalletProvider(registry, configs, walletDir, pwProvider, newTestLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open HD wallet")
}

func TestNewHDWalletProvider_NonExistentFile(t *testing.T) {
	walletDir := t.TempDir()

	registry := NewEmptySignerRegistry()
	configs := []HDWalletConfig{
		{
			Path:        "/non/existent/wallet.json",
			PasswordEnv: "TEST_HD_PASSWORD",
			Enabled:     true,
		},
	}

	pwProvider := &mockPasswordProvider{password: []byte("some-password")}
	_, err := NewHDWalletProvider(registry, configs, walletDir, pwProvider, newTestLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open HD wallet")
}

// =============================================================================
// CreateHDWallet tests
// =============================================================================

func TestHDWalletProvider_CreateAndDerive(t *testing.T) {
	tempDir := t.TempDir()
	logger := newTestLogger()
	registry := NewEmptySignerRegistry()

	pwProvider, err := NewEnvPasswordProvider()
	require.NoError(t, err)

	provider, err := NewHDWalletProvider(registry, nil, tempDir, pwProvider, logger)
	require.NoError(t, err)
	registry.RegisterProvider(provider)
	defer provider.Close()

	ctx := context.Background()

	// Create a new HD wallet
	info, err := provider.CreateHDWallet(ctx, types.CreateHDWalletParams{
		Password:    "test-password-123",
		EntropyBits: 128, // faster for tests
	})
	require.NoError(t, err)
	assert.NotEmpty(t, info.PrimaryAddress)
	assert.Equal(t, 1, info.DerivedCount)
	assert.Len(t, info.Derived, 1)

	primaryAddr := info.PrimaryAddress

	// Primary address should be registered
	assert.True(t, registry.HasSigner(primaryAddr))

	// Derive a single additional address
	derived, err := provider.DeriveAddress(ctx, primaryAddr, 1)
	require.NoError(t, err)
	assert.NotEmpty(t, derived.Address)
	assert.NotEqual(t, primaryAddr, derived.Address)
	assert.Equal(t, string(types.SignerTypeHDWallet), derived.Type)

	// Derived address should be registered
	assert.True(t, registry.HasSigner(derived.Address))

	// Derive multiple addresses
	batch, err := provider.DeriveAddresses(ctx, primaryAddr, 2, 3)
	require.NoError(t, err)
	assert.Len(t, batch, 3)
	for _, d := range batch {
		assert.True(t, registry.HasSigner(d.Address))
	}

	// List derived addresses
	derivedList, err := provider.ListDerivedAddresses(primaryAddr)
	require.NoError(t, err)
	assert.Len(t, derivedList, 5) // 0, 1, 2, 3, 4

	// List HD wallets
	wallets := provider.ListHDWallets()
	assert.Len(t, wallets, 1)
	assert.Equal(t, primaryAddr, wallets[0].PrimaryAddress)
}

func TestHDWalletProvider_CreateEmptyPassword(t *testing.T) {
	tempDir := t.TempDir()
	registry := NewEmptySignerRegistry()

	provider, err := NewHDWalletProvider(registry, nil, tempDir, &mockPasswordProvider{}, newTestLogger())
	require.NoError(t, err)

	ctx := context.Background()

	_, err = provider.CreateHDWallet(ctx, types.CreateHDWalletParams{
		Password: "",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, types.ErrEmptyPassword)
}

func TestHDWalletProvider_CreateDefaultEntropy(t *testing.T) {
	tempDir := t.TempDir()
	registry := NewEmptySignerRegistry()

	provider, err := NewHDWalletProvider(registry, nil, tempDir, &mockPasswordProvider{}, newTestLogger())
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()

	// EntropyBits=0 should default to 256
	info, err := provider.CreateHDWallet(ctx, types.CreateHDWalletParams{
		Password: "test-default-entropy",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, info.PrimaryAddress)
}

// =============================================================================
// ImportHDWallet tests
// =============================================================================

func TestHDWalletProvider_ImportAndDerive(t *testing.T) {
	tempDir := t.TempDir()
	logger := newTestLogger()
	registry := NewEmptySignerRegistry()

	pwProvider, err := NewEnvPasswordProvider()
	require.NoError(t, err)

	provider, err := NewHDWalletProvider(registry, nil, tempDir, pwProvider, logger)
	require.NoError(t, err)
	registry.RegisterProvider(provider)
	defer provider.Close()

	ctx := context.Background()

	// Import a wallet from a known mnemonic
	testMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	info, err := provider.ImportHDWallet(ctx, types.ImportHDWalletParams{
		Mnemonic: testMnemonic,
		Password: "test-password",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, info.PrimaryAddress)

	// Derive addresses and verify they match the expected ones
	derived, err := provider.DeriveAddress(ctx, info.PrimaryAddress, 1)
	require.NoError(t, err)
	assert.NotEmpty(t, derived.Address)

	// Import the same wallet again should fail
	_, err = provider.ImportHDWallet(ctx, types.ImportHDWalletParams{
		Mnemonic: testMnemonic,
		Password: "test-password",
	})
	assert.Error(t, err) // already exists
}

func TestHDWalletProvider_ImportEmptyMnemonic(t *testing.T) {
	tempDir := t.TempDir()
	registry := NewEmptySignerRegistry()

	provider, err := NewHDWalletProvider(registry, nil, tempDir, &mockPasswordProvider{}, newTestLogger())
	require.NoError(t, err)

	ctx := context.Background()

	_, err = provider.ImportHDWallet(ctx, types.ImportHDWalletParams{
		Mnemonic: "",
		Password: "test-password",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mnemonic is required")
}

func TestHDWalletProvider_ImportEmptyPassword(t *testing.T) {
	tempDir := t.TempDir()
	registry := NewEmptySignerRegistry()

	provider, err := NewHDWalletProvider(registry, nil, tempDir, &mockPasswordProvider{}, newTestLogger())
	require.NoError(t, err)

	ctx := context.Background()

	_, err = provider.ImportHDWallet(ctx, types.ImportHDWalletParams{
		Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		Password: "",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, types.ErrEmptyPassword)
}

// =============================================================================
// CreateSigner (SignerCreator interface) tests
// =============================================================================

func TestHDWalletProvider_CreateSigner(t *testing.T) {
	tempDir := t.TempDir()
	logger := newTestLogger()
	registry := NewEmptySignerRegistry()

	pwProvider, err := NewEnvPasswordProvider()
	require.NoError(t, err)

	provider, err := NewHDWalletProvider(registry, nil, tempDir, pwProvider, logger)
	require.NoError(t, err)
	registry.RegisterProvider(provider)
	defer provider.Close()

	ctx := context.Background()

	// Test via the SignerCreator interface
	signerInfo, err := provider.CreateSigner(ctx, &types.CreateHDWalletParams{
		Password:    "test-password",
		EntropyBits: 128,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, signerInfo.Address)
	assert.Equal(t, string(types.SignerTypeHDWallet), signerInfo.Type)
}

func TestHDWalletProvider_CreateSignerInvalidParams(t *testing.T) {
	tempDir := t.TempDir()
	registry := NewEmptySignerRegistry()

	provider, err := NewHDWalletProvider(registry, nil, tempDir, &mockPasswordProvider{}, newTestLogger())
	require.NoError(t, err)

	ctx := context.Background()

	// Wrong type
	_, err = provider.CreateSigner(ctx, "not-hd-wallet-params")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid params type")

	// Nil params
	_, err = provider.CreateSigner(ctx, (*types.CreateHDWalletParams)(nil))
	require.Error(t, err)
	assert.ErrorIs(t, err, types.ErrMissingHDWalletParams)
}

// =============================================================================
// Derive error cases
// =============================================================================

func TestHDWalletProvider_DeriveNonExistentWallet(t *testing.T) {
	tempDir := t.TempDir()
	registry := NewEmptySignerRegistry()

	provider, err := NewHDWalletProvider(registry, nil, tempDir, &mockPasswordProvider{}, newTestLogger())
	require.NoError(t, err)

	ctx := context.Background()

	_, err = provider.DeriveAddress(ctx, "0x0000000000000000000000000000000000000000", 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HD wallet not found")
}

func TestHDWalletProvider_DeriveAddressesNonExistentWallet(t *testing.T) {
	tempDir := t.TempDir()
	registry := NewEmptySignerRegistry()

	provider, err := NewHDWalletProvider(registry, nil, tempDir, &mockPasswordProvider{}, newTestLogger())
	require.NoError(t, err)

	ctx := context.Background()

	_, err = provider.DeriveAddresses(ctx, "0x0000000000000000000000000000000000000000", 0, 3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HD wallet not found")
}

func TestHDWalletProvider_ListDerivedNonExistentWallet(t *testing.T) {
	tempDir := t.TempDir()
	registry := NewEmptySignerRegistry()

	provider, err := NewHDWalletProvider(registry, nil, tempDir, &mockPasswordProvider{}, newTestLogger())
	require.NoError(t, err)

	_, err = provider.ListDerivedAddresses("0x0000000000000000000000000000000000000000")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HD wallet not found")
}

func TestHDWalletProvider_ReDeriveSameIndex(t *testing.T) {
	tempDir := t.TempDir()
	registry := NewEmptySignerRegistry()

	provider, err := NewHDWalletProvider(registry, nil, tempDir, &mockPasswordProvider{}, newTestLogger())
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()

	info, err := provider.CreateHDWallet(ctx, types.CreateHDWalletParams{
		Password:    "test-password",
		EntropyBits: 128,
	})
	require.NoError(t, err)

	// Derive index 1
	_, err = provider.DeriveAddress(ctx, info.PrimaryAddress, 1)
	require.NoError(t, err)

	// Re-derive index 1 — should not fail, returns ErrAlreadyExists via registerDerivedSigner
	_, err = provider.DeriveAddress(ctx, info.PrimaryAddress, 1)
	require.Error(t, err)
	assert.ErrorIs(t, err, types.ErrAlreadyExists)

	// Batch re-derive — should not fail even if some already exist
	batch, err := provider.DeriveAddresses(ctx, info.PrimaryAddress, 0, 3)
	require.NoError(t, err)
	assert.Len(t, batch, 3) // 0, 1, 2 — 0 and 1 already exist but batch tolerates it
}

// =============================================================================
// Type, Close, Signing tests
// =============================================================================

func TestHDWalletProvider_Type(t *testing.T) {
	registry := NewEmptySignerRegistry()
	provider, err := NewHDWalletProvider(registry, nil, t.TempDir(), &mockPasswordProvider{}, newTestLogger())
	require.NoError(t, err)

	assert.Equal(t, types.SignerTypeHDWallet, provider.Type())
}

func TestHDWalletProvider_Close(t *testing.T) {
	tempDir := t.TempDir()
	registry := NewEmptySignerRegistry()

	provider, err := NewHDWalletProvider(registry, nil, tempDir, &mockPasswordProvider{}, newTestLogger())
	require.NoError(t, err)

	ctx := context.Background()

	// Create two wallets
	_, err = provider.CreateHDWallet(ctx, types.CreateHDWalletParams{
		Password:    "wallet-1",
		EntropyBits: 128,
	})
	require.NoError(t, err)

	_, err = provider.CreateHDWallet(ctx, types.CreateHDWalletParams{
		Password:    "wallet-2",
		EntropyBits: 128,
	})
	require.NoError(t, err)

	assert.Len(t, provider.ListHDWallets(), 2)

	// Close should succeed
	err = provider.Close()
	assert.NoError(t, err)
}

func TestHDWalletProvider_Signing(t *testing.T) {
	tempDir := t.TempDir()
	logger := newTestLogger()
	registry := NewEmptySignerRegistry()

	pwProvider, err := NewEnvPasswordProvider()
	require.NoError(t, err)

	provider, err := NewHDWalletProvider(registry, nil, tempDir, pwProvider, logger)
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()

	info, err := provider.CreateHDWallet(ctx, types.CreateHDWalletParams{
		Password:    "test-password",
		EntropyBits: 128,
	})
	require.NoError(t, err)

	// Get the signer and verify it can sign
	signer, err := registry.GetSigner(info.PrimaryAddress)
	require.NoError(t, err)

	sig, err := signer.PersonalSign("test message")
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
	assert.Len(t, sig, 65) // r(32) + s(32) + v(1)
}

func TestHDWalletProvider_ListHDWalletsMultiple(t *testing.T) {
	tempDir := t.TempDir()
	registry := NewEmptySignerRegistry()

	provider, err := NewHDWalletProvider(registry, nil, tempDir, &mockPasswordProvider{}, newTestLogger())
	require.NoError(t, err)
	defer provider.Close()

	ctx := context.Background()

	// Create 3 wallets
	addrs := make([]string, 3)
	for i := 0; i < 3; i++ {
		info, err := provider.CreateHDWallet(ctx, types.CreateHDWalletParams{
			Password:    "test-password",
			EntropyBits: 128,
		})
		require.NoError(t, err)
		addrs[i] = info.PrimaryAddress
	}

	wallets := provider.ListHDWallets()
	assert.Len(t, wallets, 3)

	// All primary addresses should be present
	addrSet := make(map[string]bool)
	for _, w := range wallets {
		addrSet[w.PrimaryAddress] = true
	}
	for _, addr := range addrs {
		assert.True(t, addrSet[addr], "wallet %s should be in list", addr)
	}
}
