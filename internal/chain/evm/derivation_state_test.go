package evm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDerivationStateStore_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDerivationStateStore(dir)
	require.NoError(t, err)

	// Save indices for a wallet
	err = store.Save("0x1234567890abcdef1234567890abcdef12345678", []uint32{0, 1, 2, 5})
	require.NoError(t, err)

	// Load them back
	indices := store.Load("0x1234567890abcdef1234567890abcdef12345678")
	assert.Equal(t, []uint32{0, 1, 2, 5}, indices)

	// Unknown address returns nil
	indices = store.Load("0xunknown")
	assert.Nil(t, indices)
}

func TestDerivationStateStore_PersistsAcrossNewStore(t *testing.T) {
	dir := t.TempDir()

	store1, err := NewDerivationStateStore(dir)
	require.NoError(t, err)
	err = store1.Save("0xaaa", []uint32{0, 1, 2})
	require.NoError(t, err)

	// Create new store instance (simulates restart)
	store2, err := NewDerivationStateStore(dir)
	require.NoError(t, err)

	indices := store2.Load("0xaaa")
	assert.Equal(t, []uint32{0, 1, 2}, indices)
}

func TestDerivationStateStore_DedupeAndSort(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDerivationStateStore(dir)
	require.NoError(t, err)

	// Save with duplicates and unsorted
	err = store.Save("0xbbb", []uint32{5, 2, 0, 2, 1, 0})
	require.NoError(t, err)

	indices := store.Load("0xbbb")
	assert.Equal(t, []uint32{0, 1, 2, 5}, indices)
}

func TestDerivationStateStore_EmptyDirFails(t *testing.T) {
	_, err := NewDerivationStateStore("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wallet directory is required")
}

func TestDerivationStateStore_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDerivationStateStore(dir)
	require.NoError(t, err)

	err = store.Save("0xccc", []uint32{0, 1})
	require.NoError(t, err)

	err = store.Save("0xccc", []uint32{0, 1, 2, 3})
	require.NoError(t, err)

	indices := store.Load("0xccc")
	assert.Equal(t, []uint32{0, 1, 2, 3}, indices)
}

func TestDerivationStateStore_FileCreated(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDerivationStateStore(dir)
	require.NoError(t, err)

	err = store.Save("0xddd", []uint32{0})
	require.NoError(t, err)

	path := filepath.Join(dir, derivationStateFilename)
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.False(t, info.IsDir())
}
