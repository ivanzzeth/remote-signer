package evm

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TokenMetadata is an alias for types.TokenMetadata.
// The struct definition lives in core/types to avoid import cycles (storage -> evm -> rule -> storage).
type TokenMetadata = types.TokenMetadata

// TokenMetadataCache provides DB-backed cache for token metadata with RPC fallback.
type TokenMetadataCache struct {
	db       *gorm.DB
	provider *RPCProvider
	cacheTTL time.Duration
}

// NewTokenMetadataCache creates a new cache. db may be nil (cache disabled, always RPC).
func NewTokenMetadataCache(db *gorm.DB, provider *RPCProvider, cacheTTL time.Duration) (*TokenMetadataCache, error) {
	if provider == nil {
		return nil, fmt.Errorf("rpc provider is required for token metadata cache")
	}
	if cacheTTL <= 0 {
		cacheTTL = 24 * time.Hour
	}
	return &TokenMetadataCache{
		db:       db,
		provider: provider,
		cacheTTL: cacheTTL,
	}, nil
}

// ERC20 selectors
var (
	selectorDecimals = crypto.Keccak256([]byte("decimals()"))[:4]
	selectorSymbol   = crypto.Keccak256([]byte("symbol()"))[:4]
	selectorName     = crypto.Keccak256([]byte("name()"))[:4]
	// ERC165 supportsInterface(bytes4)
	selectorSupportsInterface = crypto.Keccak256([]byte("supportsInterface(bytes4)"))[:4]
)

// GetDecimals returns token decimals, using cache first then RPC.
func (c *TokenMetadataCache) GetDecimals(ctx context.Context, chainID, address string, counter *RPCCallCounter) (int, error) {
	address = common.HexToAddress(address).Hex()

	if c.db != nil {
		var meta TokenMetadata
		err := c.db.WithContext(ctx).Where("chain_id = ? AND address = ?", chainID, address).First(&meta).Error
		if err == nil && meta.Decimals != nil && time.Since(meta.QueriedAt) < c.cacheTTL {
			return *meta.Decimals, nil
		}
	}

	if err := counter.Increment(); err != nil {
		return 0, err
	}

	calldata := "0x" + hex.EncodeToString(selectorDecimals)
	result, err := c.provider.Call(ctx, chainID, address, calldata)
	if err != nil {
		return 0, fmt.Errorf("erc20.decimals rpc: %w", err)
	}

	decimals, err := decodeUint8FromHex(result)
	if err != nil {
		return 0, fmt.Errorf("decode decimals: %w", err)
	}

	c.upsertField(ctx, chainID, address, func(m *TokenMetadata) { m.Decimals = &decimals })
	return decimals, nil
}

// GetSymbol returns token symbol, using cache first then RPC.
func (c *TokenMetadataCache) GetSymbol(ctx context.Context, chainID, address string, counter *RPCCallCounter) (string, error) {
	address = common.HexToAddress(address).Hex()

	if c.db != nil {
		var meta TokenMetadata
		err := c.db.WithContext(ctx).Where("chain_id = ? AND address = ?", chainID, address).First(&meta).Error
		if err == nil && meta.Symbol != nil && time.Since(meta.QueriedAt) < c.cacheTTL {
			return *meta.Symbol, nil
		}
	}

	if err := counter.Increment(); err != nil {
		return "", err
	}

	calldata := "0x" + hex.EncodeToString(selectorSymbol)
	result, err := c.provider.Call(ctx, chainID, address, calldata)
	if err != nil {
		return "", fmt.Errorf("erc20.symbol rpc: %w", err)
	}

	symbol, err := decodeStringFromHex(result)
	if err != nil {
		return "", fmt.Errorf("decode symbol: %w", err)
	}

	c.upsertField(ctx, chainID, address, func(m *TokenMetadata) { m.Symbol = &symbol })
	return symbol, nil
}

// GetName returns token name, using cache first then RPC.
func (c *TokenMetadataCache) GetName(ctx context.Context, chainID, address string, counter *RPCCallCounter) (string, error) {
	address = common.HexToAddress(address).Hex()

	if c.db != nil {
		var meta TokenMetadata
		err := c.db.WithContext(ctx).Where("chain_id = ? AND address = ?", chainID, address).First(&meta).Error
		if err == nil && meta.Name != nil && time.Since(meta.QueriedAt) < c.cacheTTL {
			return *meta.Name, nil
		}
	}

	if err := counter.Increment(); err != nil {
		return "", err
	}

	calldata := "0x" + hex.EncodeToString(selectorName)
	result, err := c.provider.Call(ctx, chainID, address, calldata)
	if err != nil {
		return "", fmt.Errorf("erc20.name rpc: %w", err)
	}

	name, err := decodeStringFromHex(result)
	if err != nil {
		return "", fmt.Errorf("decode name: %w", err)
	}

	c.upsertField(ctx, chainID, address, func(m *TokenMetadata) { m.Name = &name })
	return name, nil
}

// SupportsInterface checks ERC165 supportsInterface(bytes4).
func (c *TokenMetadataCache) SupportsInterface(ctx context.Context, chainID, address, interfaceID string, counter *RPCCallCounter) (bool, error) {
	address = common.HexToAddress(address).Hex()

	if err := counter.Increment(); err != nil {
		return false, err
	}

	// Build calldata: supportsInterface(bytes4)
	ifaceBytes, err := hex.DecodeString(strings.TrimPrefix(interfaceID, "0x"))
	if err != nil || len(ifaceBytes) != 4 {
		return false, fmt.Errorf("invalid interface ID: %s", interfaceID)
	}
	// ABI encode: selector + bytes4 padded to 32 bytes
	padded := make([]byte, 32)
	copy(padded[:4], ifaceBytes)
	calldata := "0x" + hex.EncodeToString(selectorSupportsInterface) + hex.EncodeToString(padded)

	result, err := c.provider.Call(ctx, chainID, address, calldata)
	if err != nil {
		return false, nil // ERC165 may not be supported; return false, not error
	}

	return decodeBoolFromHex(result), nil
}

// IsERC721 checks if contract supports ERC721 interface (0x80ac58cd).
// SECURITY (HIGH-4 ERC165 spoofing): A malicious contract may claim ERC721 to make
// transferFrom be tracked as 1 NFT instead of an ERC20 amount. As a conservative
// defense, if the contract also has a valid decimals() response, treat it as ERC20
// (return false). This prevents under-counting budget for spoofed NFTs.
func (c *TokenMetadataCache) IsERC721(ctx context.Context, chainID, address string, counter *RPCCallCounter) (bool, error) {
	address = common.HexToAddress(address).Hex()

	if c.db != nil {
		var meta TokenMetadata
		err := c.db.WithContext(ctx).Where("chain_id = ? AND address = ?", chainID, address).First(&meta).Error
		if err == nil && meta.IsERC721 && time.Since(meta.QueriedAt) < c.cacheTTL {
			return true, nil
		}
	}

	result, err := c.SupportsInterface(ctx, chainID, address, "0x80ac58cd", counter)
	if err != nil {
		return false, err
	}

	if result {
		// Anti-spoofing: if contract also has decimals(), treat as ERC20 (conservative)
		if c.hasDecimals(ctx, chainID, address, counter) {
			return false, nil
		}
		c.upsertField(ctx, chainID, address, func(m *TokenMetadata) { m.IsERC721 = true })
	}
	return result, nil
}

// IsERC1155 checks if contract supports ERC1155 interface (0xd9b67a26).
// SECURITY: Same anti-spoofing check as IsERC721.
func (c *TokenMetadataCache) IsERC1155(ctx context.Context, chainID, address string, counter *RPCCallCounter) (bool, error) {
	address = common.HexToAddress(address).Hex()

	if c.db != nil {
		var meta TokenMetadata
		err := c.db.WithContext(ctx).Where("chain_id = ? AND address = ?", chainID, address).First(&meta).Error
		if err == nil && meta.IsERC1155 && time.Since(meta.QueriedAt) < c.cacheTTL {
			return true, nil
		}
	}

	result, err := c.SupportsInterface(ctx, chainID, address, "0xd9b67a26", counter)
	if err != nil {
		return false, err
	}

	if result {
		// Anti-spoofing: if contract also has decimals(), treat as ERC20 (conservative)
		if c.hasDecimals(ctx, chainID, address, counter) {
			return false, nil
		}
		c.upsertField(ctx, chainID, address, func(m *TokenMetadata) { m.IsERC1155 = true })
	}
	return result, nil
}

// hasDecimals returns true if the contract responds to decimals() with a valid value.
// Used as an anti-spoofing heuristic: genuine ERC721/1155 contracts don't have decimals().
func (c *TokenMetadataCache) hasDecimals(ctx context.Context, chainID, address string, counter *RPCCallCounter) bool {
	// Check cache first — don't consume rate limit counter if already cached
	if c.db != nil {
		var meta TokenMetadata
		err := c.db.WithContext(ctx).Where("chain_id = ? AND address = ?", chainID, address).First(&meta).Error
		if err == nil && meta.Decimals != nil {
			return true
		}
	}

	// Try RPC — ignore counter errors (fail open: assume not ERC20 if we can't check)
	if err := counter.Increment(); err != nil {
		return false
	}

	calldata := "0x" + hex.EncodeToString(selectorDecimals)
	result, err := c.provider.Call(ctx, chainID, address, calldata)
	if err != nil {
		return false // no decimals() = likely genuine NFT
	}

	_, err = decodeUint8FromHex(result)
	return err == nil // valid decimals means it's an ERC20
}

func (c *TokenMetadataCache) upsertField(ctx context.Context, chainID, address string, update func(*TokenMetadata)) {
	if c.db == nil {
		return
	}
	meta := TokenMetadata{
		ChainID:   chainID,
		Address:   address,
		QueriedAt: time.Now().UTC(),
	}
	// Try to load existing
	var existing TokenMetadata
	if err := c.db.WithContext(ctx).Where("chain_id = ? AND address = ?", chainID, address).First(&existing).Error; err == nil {
		meta = existing
		meta.QueriedAt = time.Now().UTC()
	}
	update(&meta)
	c.db.WithContext(ctx).Save(&meta)
}

// maxValidDecimals is the maximum valid token decimals. 10^77 fits in uint256;
// values above this are almost certainly bogus (proxy not initialized, etc.).
const maxValidDecimals = 77

// decodeUint8FromHex decodes a uint256 hex result to an int (for decimals).
// SECURITY: Rejects values outside 0-77 to prevent cache poisoning from uninitialized proxies.
func decodeUint8FromHex(hexStr string) (int, error) {
	raw := strings.TrimPrefix(strings.TrimPrefix(hexStr, "0x"), "0X")
	if raw == "" {
		return 0, fmt.Errorf("empty result")
	}
	b := new(big.Int)
	if _, ok := b.SetString(raw, 16); !ok {
		return 0, fmt.Errorf("invalid hex: %s", hexStr)
	}
	if !b.IsInt64() || b.Int64() < 0 || b.Int64() > maxValidDecimals {
		return 0, fmt.Errorf("decimals out of valid range (0-%d): %s", maxValidDecimals, b.String())
	}
	return int(b.Int64()), nil
}

// decodeStringFromHex decodes an ABI-encoded string from hex RPC result.
func decodeStringFromHex(hexStr string) (string, error) {
	raw := strings.TrimPrefix(strings.TrimPrefix(hexStr, "0x"), "0X")
	if len(raw) < 128 { // minimum: offset(32) + length(32) = 64 bytes = 128 hex chars
		return "", fmt.Errorf("result too short for ABI string: %d hex chars", len(raw))
	}
	data, err := hex.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("decode hex: %w", err)
	}
	// ABI string: offset at [0:32], length at [offset:offset+32], data at [offset+32:offset+32+length]
	offset := new(big.Int).SetBytes(data[:32])
	if !offset.IsInt64() || offset.Int64()+32 > int64(len(data)) {
		return "", fmt.Errorf("invalid ABI string offset")
	}
	off := int(offset.Int64())
	length := new(big.Int).SetBytes(data[off : off+32])
	if !length.IsInt64() || off+32+int(length.Int64()) > len(data) {
		return "", fmt.Errorf("invalid ABI string length")
	}
	return string(data[off+32 : off+32+int(length.Int64())]), nil
}

// decodeBoolFromHex decodes a bool from ABI-encoded hex (32-byte uint256, 1 = true).
func decodeBoolFromHex(hexStr string) bool {
	raw := strings.TrimPrefix(strings.TrimPrefix(hexStr, "0x"), "0X")
	if raw == "" {
		return false
	}
	b := new(big.Int)
	if _, ok := b.SetString(raw, 16); !ok {
		return false
	}
	return b.Cmp(big.NewInt(1)) == 0
}
