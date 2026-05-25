//go:build integration

package evm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDecimalsQuerierAdapter_Success(t *testing.T) {
	srv := mockRPCServer(t, map[string]string{
		"eth_call": abiEncodeUint256(6),
	})
	defer srv.Close()

	provider, err := NewRPCProvider(srv.URL, "")
	require.NoError(t, err)
	cache, err := NewTokenMetadataCache(nil, provider, 0)
	require.NoError(t, err)

	a, err := NewDecimalsQuerierAdapter(cache)
	require.NoError(t, err)
	assert.NotNil(t, a)
}

func TestDecimalsQuerierAdapter_QueryDecimals(t *testing.T) {
	srv := mockRPCServer(t, map[string]string{
		"eth_call": abiEncodeUint256(18),
	})
	defer srv.Close()

	provider, err := NewRPCProvider(srv.URL, "")
	require.NoError(t, err)
	cache, err := NewTokenMetadataCache(nil, provider, 0)
	require.NoError(t, err)

	a, err := NewDecimalsQuerierAdapter(cache)
	require.NoError(t, err)

	decimals, err := a.QueryDecimals(t.Context(), "1", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	require.NoError(t, err)
	assert.Equal(t, 18, decimals)
}
