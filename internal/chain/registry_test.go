package chain

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

type mockAdapter struct {
	chainType types.ChainType
}

func (m *mockAdapter) Type() types.ChainType { return m.chainType }

func (m *mockAdapter) ValidateBasicRequest(chainID, signerAddress, signType string, payload []byte) error {
	return nil
}

func (m *mockAdapter) ValidatePayload(ctx context.Context, signType string, payload []byte) error {
	return nil
}

func (m *mockAdapter) Sign(ctx context.Context, signerAddress string, signType string, chainID string, payload []byte) (*types.SignResult, error) {
	return &types.SignResult{Signature: []byte("sig")}, nil
}

func (m *mockAdapter) ParsePayload(ctx context.Context, signType string, payload []byte) (*types.ParsedPayload, error) {
	return &types.ParsedPayload{}, nil
}

func (m *mockAdapter) ListSigners(ctx context.Context) ([]types.SignerInfo, error) {
	return nil, nil
}

func (m *mockAdapter) HasSigner(ctx context.Context, address string) bool {
	return false
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	require.NotNil(t, r)
	assert.NotNil(t, r.adapters)

	chains := r.SupportedChains()
	assert.Empty(t, chains)
}

func TestRegistryRegisterAndGet(t *testing.T) {
	r := NewRegistry()
	adapter := &mockAdapter{chainType: types.ChainTypeEVM}

	err := r.Register(adapter)
	require.NoError(t, err)

	got, err := r.Get(types.ChainTypeEVM)
	require.NoError(t, err)
	assert.Equal(t, adapter, got)
}

func TestRegistryRegisterNil(t *testing.T) {
	r := NewRegistry()
	err := r.Register(nil)
	assert.ErrorContains(t, err, "adapter cannot be nil")
}

func TestRegistryRegisterDuplicate(t *testing.T) {
	r := NewRegistry()
	err := r.Register(&mockAdapter{chainType: types.ChainTypeEVM})
	require.NoError(t, err)

	err = r.Register(&mockAdapter{chainType: types.ChainTypeEVM})
	assert.ErrorContains(t, err, "already registered")
}

func TestRegistryGetNotFound(t *testing.T) {
	r := NewRegistry()
	_, err := r.Get(types.ChainTypeEVM)
	assert.ErrorContains(t, err, "no adapter registered")
}

func TestRegistrySupportedChains(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(&mockAdapter{chainType: types.ChainTypeEVM}))

	chains := r.SupportedChains()
	assert.Len(t, chains, 1)
	assert.Equal(t, types.ChainTypeEVM, chains[0])
}

func TestRegistrySupportedChainsMultiple(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(&mockAdapter{chainType: types.ChainTypeEVM}))
	require.NoError(t, r.Register(&mockAdapter{chainType: types.ChainType("solana")}))

	chains := r.SupportedChains()
	assert.Len(t, chains, 2)
	assert.Contains(t, chains, types.ChainTypeEVM)
	assert.Contains(t, chains, types.ChainType("solana"))
}

func TestRegistryHas(t *testing.T) {
	r := NewRegistry()
	assert.False(t, r.Has(types.ChainTypeEVM))

	require.NoError(t, r.Register(&mockAdapter{chainType: types.ChainTypeEVM}))
	assert.True(t, r.Has(types.ChainTypeEVM))
	assert.False(t, r.Has(types.ChainType("solana")))
}

func TestRegistryConcurrencySafe(t *testing.T) {
	r := NewRegistry()
	err := r.Register(&mockAdapter{chainType: types.ChainTypeEVM})
	require.NoError(t, err)

	got, err := r.Get(types.ChainTypeEVM)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, r.Has(types.ChainTypeEVM))
	assert.True(t, errors.Is(err, nil))
}

func TestNewRegistryEmptySupported(t *testing.T) {
	r := NewRegistry()
	assert.Empty(t, r.SupportedChains())
	assert.False(t, r.Has(types.ChainTypeEVM))
}
