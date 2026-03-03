package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// APIKey.TableName()
// ---------------------------------------------------------------------------

func TestAPIKey_TableName(t *testing.T) {
	assert.Equal(t, "api_keys", APIKey{}.TableName())
}

// ---------------------------------------------------------------------------
// APIKey.IsAllowedChain()
// ---------------------------------------------------------------------------

func TestIsAllowedChain_EmptyList_AllowsAll(t *testing.T) {
	k := &APIKey{AllowedChainTypes: []string{}}
	assert.True(t, k.IsAllowedChain(ChainTypeEVM))
	assert.True(t, k.IsAllowedChain(ChainTypeSolana))
}

func TestIsAllowedChain_NilList_AllowsAll(t *testing.T) {
	k := &APIKey{AllowedChainTypes: nil}
	assert.True(t, k.IsAllowedChain(ChainTypeEVM))
}

func TestIsAllowedChain_MatchingChain(t *testing.T) {
	k := &APIKey{AllowedChainTypes: []string{"evm"}}
	assert.True(t, k.IsAllowedChain(ChainTypeEVM))
}

func TestIsAllowedChain_NonMatchingChain(t *testing.T) {
	k := &APIKey{AllowedChainTypes: []string{"solana"}}
	assert.False(t, k.IsAllowedChain(ChainTypeEVM))
}

func TestIsAllowedChain_MultipleChains(t *testing.T) {
	k := &APIKey{AllowedChainTypes: []string{"evm", "solana"}}
	assert.True(t, k.IsAllowedChain(ChainTypeEVM))
	assert.True(t, k.IsAllowedChain(ChainTypeSolana))
	assert.False(t, k.IsAllowedChain(ChainTypeCosmos))
}

// ---------------------------------------------------------------------------
// APIKey.IsAllowedSigner()
// ---------------------------------------------------------------------------

func TestIsAllowedSigner_EmptyList_NoAccess(t *testing.T) {
	k := &APIKey{AllowedSigners: []string{}}
	assert.False(t, k.IsAllowedSigner("0xABC123"))
}

func TestIsAllowedSigner_NilList_NoAccess(t *testing.T) {
	k := &APIKey{AllowedSigners: nil}
	assert.False(t, k.IsAllowedSigner("0xABC123"))
}

func TestIsAllowedSigner_AllowAllSigners_AllowsAny(t *testing.T) {
	k := &APIKey{AllowAllSigners: true, AllowedSigners: []string{}}
	assert.True(t, k.IsAllowedSigner("0xABC123"))
	assert.True(t, k.IsAllowedSigner("0xdef456"))
}

func TestIsAllowedSigner_MatchingAddress(t *testing.T) {
	k := &APIKey{AllowedSigners: []string{"0xabc123"}}
	assert.True(t, k.IsAllowedSigner("0xabc123"))
}

func TestIsAllowedSigner_CaseInsensitiveMatch(t *testing.T) {
	k := &APIKey{AllowedSigners: []string{"0xabc123"}}
	assert.True(t, k.IsAllowedSigner("0xABC123"))
}

func TestIsAllowedSigner_EIP55ChecksumVariations(t *testing.T) {
	// EIP-55 checksum address vs all-lowercase
	checksumAddr := "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
	lowerAddr := "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"

	k := &APIKey{AllowedSigners: []string{checksumAddr}}
	assert.True(t, k.IsAllowedSigner(lowerAddr), "lowercase should match EIP-55 checksum")
	assert.True(t, k.IsAllowedSigner(checksumAddr), "checksum should match itself")
}

func TestIsAllowedSigner_NonMatchingAddress(t *testing.T) {
	k := &APIKey{AllowedSigners: []string{"0xabc123"}}
	assert.False(t, k.IsAllowedSigner("0xdef456"))
}

func TestIsAllowedSigner_MultipleSigners(t *testing.T) {
	k := &APIKey{AllowedSigners: []string{"0xabc123", "0xdef456"}}
	assert.True(t, k.IsAllowedSigner("0xabc123"))
	assert.True(t, k.IsAllowedSigner("0xDEF456"))
	assert.False(t, k.IsAllowedSigner("0x000000"))
}
