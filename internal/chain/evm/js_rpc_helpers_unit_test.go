package evm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateChainID(t *testing.T) {
	tests := []struct {
		chainID string
		valid   bool
	}{
		{"1", true},
		{"137", true},
		{"42161", true},
		{"", false},
		{"0", false},
		{"abc", false},
		{"1/../../secret", false},
		{"1; DROP TABLE", false},
		{"-1", false},
		{"0x1", false},
		{"00001", true},
	}
	for _, tt := range tests {
		err := ValidateChainID(tt.chainID)
		if tt.valid {
			assert.NoError(t, err, "chainID=%q should be valid", tt.chainID)
		} else {
			assert.Error(t, err, "chainID=%q should be invalid", tt.chainID)
		}
	}
}

func TestValidateHexData(t *testing.T) {
	tests := []struct {
		data  string
		valid bool
	}{
		{"0x313ce567", true},
		{"0x", true},
		{"0xabcdef1234567890", true},
		{"313ce567", false},
		{"0xZZZZ", false},
		{"0x123", false},
	}
	for _, tt := range tests {
		err := ValidateHexData(tt.data)
		if tt.valid {
			assert.NoError(t, err, "data=%q should be valid", tt.data)
		} else {
			assert.Error(t, err, "data=%q should be invalid", tt.data)
		}
	}
}

func TestValidateEthAddress(t *testing.T) {
	tests := []struct {
		addr  string
		valid bool
	}{
		{"0x0000000000000000000000000000000000000001", true},
		{"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", true},
		{"", false},
		{"not_an_address", false},
		{"0x123", false},
		{"0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", false},
	}
	for _, tt := range tests {
		err := ValidateEthAddress(tt.addr)
		if tt.valid {
			assert.NoError(t, err, "addr=%q should be valid", tt.addr)
		} else {
			assert.Error(t, err, "addr=%q should be invalid", tt.addr)
		}
	}
}

func TestRPCCallCounter(t *testing.T) {
	c := NewRPCCallCounter(3)
	require.NoError(t, c.Increment())
	require.NoError(t, c.Increment())
	require.NoError(t, c.Increment())
	err := c.Increment()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "limit exceeded")
}

func TestDecodeUint8FromHex(t *testing.T) {
	result, err := decodeUint8FromHex(abiEncodeUint256(6))
	require.NoError(t, err)
	assert.Equal(t, 6, result)

	result, err = decodeUint8FromHex(abiEncodeUint256(18))
	require.NoError(t, err)
	assert.Equal(t, 18, result)

	_, err = decodeUint8FromHex("")
	require.Error(t, err)
}

func TestDecodeUint8FromHex_RejectsOver77(t *testing.T) {
	_, err := decodeUint8FromHex(abiEncodeUint256(78))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of valid range")

	result, err := decodeUint8FromHex(abiEncodeUint256(77))
	require.NoError(t, err)
	assert.Equal(t, 77, result)
}

func TestDecodeStringFromHex(t *testing.T) {
	result, err := decodeStringFromHex(abiEncodeString("USDC"))
	require.NoError(t, err)
	assert.Equal(t, "USDC", result)

	result, err = decodeStringFromHex(abiEncodeString("Wrapped Ether"))
	require.NoError(t, err)
	assert.Equal(t, "Wrapped Ether", result)
}

func TestDecodeBoolFromHex(t *testing.T) {
	assert.True(t, decodeBoolFromHex(abiEncodeBool(true)))
	assert.False(t, decodeBoolFromHex(abiEncodeBool(false)))
	assert.False(t, decodeBoolFromHex(""))
}

func TestRPCProvider_EmptyBaseURL(t *testing.T) {
	_, err := NewRPCProvider("", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base_url is required")
}

func TestRPCProvider_WhitespaceBaseURL(t *testing.T) {
	_, err := NewRPCProvider("   ", "")
	require.Error(t, err)
}

func TestRPCProvider_URLBuilding(t *testing.T) {
	p, err := NewRPCProvider("https://evm-gateway.example.com/chain/evm", "mykey123")
	require.NoError(t, err)
	url := p.rpcURL("137")
	assert.Equal(t, "https://evm-gateway.example.com/chain/evm/137/api_key/mykey123", url)

	p2, err := NewRPCProvider("https://evm-gateway.example.com/chain/evm/", "")
	require.NoError(t, err)
	url2 := p2.rpcURL("1")
	assert.Equal(t, "https://evm-gateway.example.com/chain/evm/1", url2)
}

func TestJSRPC_WriteMethodBlocked(t *testing.T) {
	for _, method := range []string{"eth_sendTransaction", "eth_sendRawTransaction", "eth_sign"} {
		t.Run(method, func(t *testing.T) {
			provider, err := NewRPCProvider("http://localhost:1", "")
			require.NoError(t, err)
			_, err = provider.doRPC(t.Context(), "1", method, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "blocked")
		})
	}
}

func TestJSRPC_OnlyAllowedMethods(t *testing.T) {
	provider, err := NewRPCProvider("http://localhost:1", "")
	require.NoError(t, err)
	_, err = provider.doRPC(t.Context(), "1", "eth_getBalance", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed")
}

func TestRPCCallCounter_CumulativeDuration(t *testing.T) {
	c := NewRPCCallCounter(5)
	assert.Equal(t, int64(0), int64(c.CumulativeDuration()))
	assert.NoError(t, c.AddDuration(100))
	assert.NoError(t, c.AddDuration(200))
	assert.Equal(t, int64(300), int64(c.CumulativeDuration()))
}

func TestNewRPCProvider_EmptyBaseURL(t *testing.T) {
	_, err := NewRPCProvider("", "")
	require.Error(t, err)
}
