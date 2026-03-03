package evm

import (
	"context"

	"github.com/ivanzzeth/ethsig"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// SignerProvider is the abstraction for pluggable signing backends.
// Each backend (private_key, keystore, hd_wallet, future HSM) implements this.
// All providers produce *ethsig.Signer instances registered in the shared registry.
type SignerProvider interface {
	// Type returns the signer type this provider manages.
	Type() types.SignerType
	// Close releases resources (zeroize keys, close HD wallet sessions, etc.)
	Close() error
}

// SignerCreator can dynamically create new signers at runtime (via API).
type SignerCreator interface {
	SignerProvider
	CreateSigner(ctx context.Context, params interface{}) (*types.SignerInfo, error)
}

// SignerDiscoverer can discover locked signers on startup (scan disk, probe HSM, etc.).
type SignerDiscoverer interface {
	SignerProvider
	DiscoverLockedSigners() ([]types.SignerInfo, error)
}

// SignerUnlocker can unlock a locked signer at runtime.
type SignerUnlocker interface {
	SignerProvider
	UnlockSigner(ctx context.Context, address string, password string) (*ethsig.Signer, error)
}

// SignerLocker can lock an unlocked signer at runtime (zeroize key, remove from memory).
type SignerLocker interface {
	SignerProvider
	LockSigner(ctx context.Context, address string) error
}

// HDWalletManager defines HD wallet-specific operations.
// The API handler type-asserts a SignerProvider to this interface.
type HDWalletManager interface {
	CreateHDWallet(ctx context.Context, params types.CreateHDWalletParams) (*HDWalletInfo, error)
	ImportHDWallet(ctx context.Context, params types.ImportHDWalletParams) (*HDWalletInfo, error)
	DeriveAddress(ctx context.Context, primaryAddr string, index uint32) (*types.SignerInfo, error)
	DeriveAddresses(ctx context.Context, primaryAddr string, start, count uint32) ([]types.SignerInfo, error)
	ListHDWallets() []HDWalletInfo
	ListDerivedAddresses(primaryAddr string) ([]types.SignerInfo, error)
}

// HDWalletInfo contains information about an HD wallet.
type HDWalletInfo struct {
	PrimaryAddress string            `json:"primary_address"`
	BasePath       string            `json:"base_path"`
	DerivedCount   int               `json:"derived_count"`
	Derived        []types.SignerInfo `json:"derived,omitempty"`
}
