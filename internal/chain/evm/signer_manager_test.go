package evm

import (
	"context"
	"testing"

	"github.com/ivanzzeth/ethsig/keystore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetHDHierarchy_EmptyWhenNoWallets(t *testing.T) {
	registry := NewEmptySignerRegistry()
	tmpDir := t.TempDir()

	derivStore, err := NewDerivationStateStore(tmpDir)
	require.NoError(t, err)

	hdProvider := &HDWalletProvider{
		registry:   registry,
		wallets:    make(map[string]*hdWalletState),
		derivStore: derivStore,
	}

	registry.RegisterProvider(hdProvider)

	manager := &SignerManagerImpl{
		registry: registry,
	}

	hierarchy := manager.buildHDHierarchy()
	assert.Empty(t, hierarchy, "hierarchy should be empty when no wallets loaded")
}

func TestGetHDHierarchy_UnlockedWallet(t *testing.T) {
	registry := NewEmptySignerRegistry()
	walletDir := t.TempDir()
	password := []byte("test-hierarchy-password")

	// Create HD wallet
	primaryAddr, walletPath, err := keystore.CreateHDWallet(walletDir, password, 128)
	require.NoError(t, err)

	// Create HD wallet provider
	pwProvider := &copyMockPasswordProvider{password: password}
	configs := []HDWalletConfig{
		{
			Path:    walletPath,
			Enabled: true,
		},
	}

	hdProvider, err := NewHDWalletProvider(registry, configs, walletDir, pwProvider)
	require.NoError(t, err)
	defer hdProvider.Close()
	registry.RegisterProvider(hdProvider)

	// Index 0 is registered when the wallet loads; derive indices 1 and 2 for two more signers.
	ctx := context.Background()
	derivedAddrs := []string{primaryAddr}
	for i := uint32(1); i < 3; i++ {
		signer, err := hdProvider.DeriveAddress(ctx, primaryAddr, i)
		require.NoError(t, err)
		derivedAddrs = append(derivedAddrs, signer.Address)
	}

	manager := &SignerManagerImpl{
		registry: registry,
	}

	// Build hierarchy
	hierarchy := manager.buildHDHierarchy()

	// Should have 3 derived addresses
	assert.Len(t, hierarchy, 3, "should have 3 derived addresses in hierarchy")

	// Verify each derived address has correct parent and index
	for i, addr := range derivedAddrs {
		info, exists := hierarchy[normalizeAddress(addr)]
		assert.True(t, exists, "derived address %s should exist in hierarchy", addr)
		assert.Equal(t, primaryAddr, info.ParentAddress, "parent address should match for %s", addr)
		assert.Equal(t, uint32(i), info.DerivationIndex, "derivation index should be %d for %s", i, addr)
	}
}

func TestGetHDHierarchy_CacheInvalidation(t *testing.T) {
	registry := NewEmptySignerRegistry()
	walletDir := t.TempDir()
	password := []byte("test-cache-password")

	primaryAddr, walletPath, err := keystore.CreateHDWallet(walletDir, password, 128)
	require.NoError(t, err)

	pwProvider := &copyMockPasswordProvider{password: password}
	configs := []HDWalletConfig{
		{
			Path:    walletPath,
			Enabled: true,
		},
	}

	hdProvider, err := NewHDWalletProvider(registry, configs, walletDir, pwProvider)
	require.NoError(t, err)
	defer hdProvider.Close()
	registry.RegisterProvider(hdProvider)

	ctx := context.Background()

	manager := &SignerManagerImpl{
		registry: registry,
	}

	// Wallet load already persists index 0; first snapshot has one derived entry.
	hierarchy1 := manager.GetHDHierarchy()
	cacheTime1 := manager.hdHierarchyCacheTime
	assert.Len(t, hierarchy1, 1)

	// Derive index 1 (index 0 is already the loaded primary).
	_, err = hdProvider.DeriveAddress(ctx, primaryAddr, 1)
	require.NoError(t, err)

	// Second call within 5 minutes - uses stale cache
	hierarchy2 := manager.GetHDHierarchy()
	cacheTime2 := manager.hdHierarchyCacheTime
	assert.Equal(t, cacheTime1, cacheTime2, "cache time should not change on second call")
	assert.Len(t, hierarchy2, 1, "hierarchy should use stale cache (still 1 address)")

	// Invalidate cache explicitly
	manager.hdHierarchyCacheMu.Lock()
	manager.hdHierarchyCache = nil
	manager.hdHierarchyCacheMu.Unlock()

	// Third call - rebuilds cache
	hierarchy3 := manager.GetHDHierarchy()
	assert.Len(t, hierarchy3, 2, "hierarchy should be rebuilt with 2 addresses")
}

func TestGetHDHierarchy_ConcurrentAccess(t *testing.T) {
	registry := NewEmptySignerRegistry()
	walletDir := t.TempDir()

	derivStore, err := NewDerivationStateStore(walletDir)
	require.NoError(t, err)

	hdProvider := &HDWalletProvider{
		registry:   registry,
		wallets:    make(map[string]*hdWalletState),
		derivStore: derivStore,
	}

	registry.RegisterProvider(hdProvider)

	manager := &SignerManagerImpl{
		registry: registry,
	}

	// Test concurrent access to GetHDHierarchy
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()
			hierarchy := manager.GetHDHierarchy()
			_ = hierarchy
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
