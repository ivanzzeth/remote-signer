package evm

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ivanzzeth/ethsig"
	"github.com/ivanzzeth/ethsig/keystore"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/logger"
)

// hdWalletState tracks a loaded HD wallet and its derived signers.
type hdWalletState struct {
	wallet         *keystore.HDWallet
	walletPath     string
	derived        []types.SignerInfo // all derived signer infos
	derivedIndices []uint32           // indices that have been derived (for persistence)
}

// HDWalletProvider manages HD wallet signers.
type HDWalletProvider struct {
	registry       *SignerRegistry
	walletDir      string
	derivStore     *DerivationStateStore
	mu             sync.RWMutex
	wallets        map[string]*hdWalletState // primaryAddr (checksummed) -> state
	lockedPaths    map[string]string          // primaryAddr (checksummed) -> filePath
}

// NewHDWalletProvider creates an HDWalletProvider and loads all configured HD wallets.
func NewHDWalletProvider(
	registry *SignerRegistry,
	configs []HDWalletConfig,
	walletDir string,
	pwProvider PasswordProvider,
) (*HDWalletProvider, error) {
	if registry == nil {
		return nil, fmt.Errorf("registry is required")
	}

	derivStore, err := NewDerivationStateStore(walletDir)
	if err != nil {
		return nil, fmt.Errorf("derivation state store: %w", err)
	}

	p := &HDWalletProvider{
		registry:    registry,
		walletDir:   walletDir,
		derivStore:  derivStore,
		wallets:     make(map[string]*hdWalletState),
		lockedPaths: make(map[string]string),
	}

	for _, cfg := range configs {
		if !cfg.Enabled {
			continue
		}

		// Get password via the same provider pattern as keystores
		ksConfig := KeystoreConfig{
			Path:          cfg.Path,
			PasswordEnv:   cfg.PasswordEnv,
			PasswordStdin: cfg.PasswordStdin,
		}
		password, err := pwProvider.GetPassword(cfg.Path, ksConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to get password for HD wallet %s: %w", cfg.Path, err)
		}

		wallet, err := keystore.OpenHDWallet(cfg.Path, password)
		keystore.SecureZeroize(password)
		if err != nil {
			return nil, fmt.Errorf("failed to open HD wallet %s: %w", cfg.Path, err)
		}

		// Derive the primary address (index 0) for identification
		primaryAddr, err := wallet.DeriveAddress(0)
		if err != nil {
			if closeErr := wallet.Close(); closeErr != nil {
				logger.EVM().Warn().Str("path", cfg.Path).Err(closeErr).Msg("failed to close wallet on error")
			}
			return nil, fmt.Errorf("failed to derive primary address from %s: %w", cfg.Path, err)
		}

		addrKey := normalizeAddress(primaryAddr.Hex())
		state := &hdWalletState{
			wallet:         wallet,
			walletPath:     cfg.Path,
			derivedIndices: []uint32{0},
		}

		// Register primary address signer
		if err := p.registerDerivedSigner(primaryAddr, wallet, 0, state); err != nil {
			if closeErr := wallet.Close(); closeErr != nil {
				logger.EVM().Warn().Str("path", cfg.Path).Err(closeErr).Msg("failed to close wallet on error")
			}
			return nil, fmt.Errorf("failed to register primary signer from %s: %w", cfg.Path, err)
		}

		// Derive additional indices from config
		for _, idx := range cfg.DeriveIndices {
			if idx == 0 {
				continue // already derived
			}
			addr, err := wallet.DeriveAddress(idx)
			if err != nil {
				if closeErr := wallet.Close(); closeErr != nil {
					logger.EVM().Warn().Str("path", cfg.Path).Err(closeErr).Msg("failed to close wallet on error")
				}
				return nil, fmt.Errorf("failed to derive index %d from %s: %w", idx, cfg.Path, err)
			}
			if err := p.registerDerivedSigner(addr, wallet, idx, state); err != nil {
				if closeErr := wallet.Close(); closeErr != nil {
					logger.EVM().Warn().Str("path", cfg.Path).Err(closeErr).Msg("failed to close wallet on error")
				}
				return nil, fmt.Errorf("failed to register derived signer index %d from %s: %w", idx, cfg.Path, err)
			}
			state.derivedIndices = appendUniqueUint32(state.derivedIndices, idx)
		}

		// Persist config-derived indices so they survive restart and API derives merge correctly
		if err := p.derivStore.Save(addrKey, state.derivedIndices); err != nil {
			logger.EVM().Warn().Str("primary_address", primaryAddr.Hex()).Err(err).Msg("failed to persist derivation state")
		}

		p.wallets[addrKey] = state

		logger.EVM().Info().Str("primary_address", primaryAddr.Hex()).Str("path", cfg.Path).Int("derived_count", len(state.derived)).Msg("HD wallet loaded")
	}

	return p, nil
}

func (p *HDWalletProvider) Type() types.SignerType {
	return types.SignerTypeHDWallet
}

func (p *HDWalletProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var firstErr error
	for _, state := range p.wallets {
		if err := state.wallet.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// CreateSigner creates a new HD wallet. Implements SignerCreator.
func (p *HDWalletProvider) CreateSigner(ctx context.Context, params interface{}) (*types.SignerInfo, error) {
	hdParams, ok := params.(*types.CreateHDWalletParams)
	if !ok {
		return nil, fmt.Errorf("invalid params type for HD wallet provider: expected *CreateHDWalletParams")
	}
	if hdParams == nil {
		return nil, types.ErrMissingHDWalletParams
	}

	info, err := p.CreateHDWallet(ctx, *hdParams)
	if err != nil {
		return nil, err
	}

	if len(info.Derived) == 0 {
		return nil, fmt.Errorf("HD wallet created but no derived addresses")
	}
	return &info.Derived[0], nil
}

// CreateHDWallet creates a new HD wallet and registers the primary address.
func (p *HDWalletProvider) CreateHDWallet(ctx context.Context, params types.CreateHDWalletParams) (*HDWalletInfo, error) {
	if params.Password == "" {
		return nil, types.ErrEmptyPassword
	}

	entropyBits := params.EntropyBits
	if entropyBits == 0 {
		entropyBits = 256
	}

	password := []byte(params.Password)
	defer keystore.SecureZeroize(password)

	address, walletPath, err := keystore.CreateHDWallet(p.walletDir, password, entropyBits)
	if err != nil {
		return nil, fmt.Errorf("failed to create HD wallet: %w", err)
	}

	// Open the newly created wallet
	wallet, err := keystore.OpenHDWallet(walletPath, password)
	if err != nil {
		return nil, fmt.Errorf("failed to open newly created HD wallet: %w", err)
	}

	addrKey := normalizeAddress(address)
	state := &hdWalletState{
		wallet:         wallet,
		walletPath:     walletPath,
		derivedIndices: []uint32{0},
	}

	primaryAddr := common.HexToAddress(address)
	if err := p.registerDerivedSigner(primaryAddr, wallet, 0, state); err != nil {
		if closeErr := wallet.Close(); closeErr != nil {
			logger.EVM().Warn().Err(closeErr).Msg("failed to close wallet on error")
		}
		return nil, fmt.Errorf("failed to register primary signer: %w", err)
	}

	if err := p.derivStore.Save(addrKey, state.derivedIndices); err != nil {
		logger.EVM().Warn().Str("primary_address", address).Err(err).Msg("failed to persist derivation state")
	}

	p.mu.Lock()
	p.wallets[addrKey] = state
	p.mu.Unlock()

	logger.EVM().Info().Str("primary_address", address).Str("path", walletPath).Msg("HD wallet created")

	// Get base path from wallet info
	walletInfo, _ := keystore.GetHDWalletInfo(walletPath)
	basePath := ""
	if walletInfo != nil {
		basePath = walletInfo.BasePath
	}

	return &HDWalletInfo{
		PrimaryAddress: address,
		BasePath:       basePath,
		DerivedCount:   len(state.derived),
		Derived:        state.derived,
	}, nil
}

// ImportHDWallet imports an HD wallet from a mnemonic and registers the primary address.
func (p *HDWalletProvider) ImportHDWallet(ctx context.Context, params types.ImportHDWalletParams) (*HDWalletInfo, error) {
	if params.Mnemonic == "" {
		return nil, fmt.Errorf("mnemonic is required")
	}
	if params.Password == "" {
		return nil, types.ErrEmptyPassword
	}

	mnemonic := []byte(params.Mnemonic)
	password := []byte(params.Password)
	defer keystore.SecureZeroize(mnemonic)
	defer keystore.SecureZeroize(password)

	address, walletPath, err := keystore.ImportHDWallet(p.walletDir, mnemonic, password)
	if err != nil {
		return nil, fmt.Errorf("failed to import HD wallet: %w", err)
	}

	wallet, err := keystore.OpenHDWallet(walletPath, password)
	if err != nil {
		return nil, fmt.Errorf("failed to open imported HD wallet: %w", err)
	}

	addrKey := normalizeAddress(address)

	p.mu.RLock()
	_, exists := p.wallets[addrKey]
	p.mu.RUnlock()
	if exists {
		if closeErr := wallet.Close(); closeErr != nil {
			logger.EVM().Warn().Err(closeErr).Msg("failed to close wallet on error")
		}
		return nil, types.ErrAlreadyExists
	}

	state := &hdWalletState{
		wallet:         wallet,
		walletPath:     walletPath,
		derivedIndices: []uint32{0},
	}

	primaryAddr := common.HexToAddress(address)
	if err := p.registerDerivedSigner(primaryAddr, wallet, 0, state); err != nil {
		if closeErr := wallet.Close(); closeErr != nil {
			logger.EVM().Warn().Err(closeErr).Msg("failed to close wallet on error")
		}
		return nil, fmt.Errorf("failed to register primary signer: %w", err)
	}

	if err := p.derivStore.Save(addrKey, state.derivedIndices); err != nil {
		logger.EVM().Warn().Str("primary_address", address).Err(err).Msg("failed to persist derivation state")
	}

	p.mu.Lock()
	p.wallets[addrKey] = state
	p.mu.Unlock()

	logger.EVM().Info().Str("primary_address", address).Str("path", walletPath).Msg("HD wallet imported")

	walletInfo, _ := keystore.GetHDWalletInfo(walletPath)
	basePath := ""
	if walletInfo != nil {
		basePath = walletInfo.BasePath
	}

	return &HDWalletInfo{
		PrimaryAddress: address,
		BasePath:       basePath,
		DerivedCount:   len(state.derived),
		Derived:        state.derived,
	}, nil
}

// DeriveAddress derives a single address at the given index from an HD wallet.
func (p *HDWalletProvider) DeriveAddress(ctx context.Context, primaryAddr string, index uint32) (*types.SignerInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	addrKey := normalizeAddress(primaryAddr)
	state, ok := p.wallets[addrKey]
	if !ok {
		if _, locked := p.lockedPaths[addrKey]; locked {
			return nil, fmt.Errorf("HD wallet is locked for primary address %s (unlock first)", primaryAddr)
		}
		return nil, fmt.Errorf("HD wallet not found for primary address %s", primaryAddr)
	}

	addr, err := state.wallet.DeriveAddress(index)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address at index %d: %w", index, err)
	}

	if err := p.registerDerivedSigner(addr, state.wallet, index, state); err != nil {
		return nil, err
	}

	state.derivedIndices = appendUniqueUint32(state.derivedIndices, index)
	if err := p.derivStore.Save(addrKey, state.derivedIndices); err != nil {
		logger.EVM().Warn().Str("primary_address", primaryAddr).Err(err).Msg("failed to persist derivation state")
	}

	info := types.SignerInfo{
		Address: addr.Hex(),
		Type:    string(types.SignerTypeHDWallet),
		Enabled: true,
	}

	logger.EVM().Info().Str("primary_address", primaryAddr).Uint64("index", uint64(index)).Str("derived_address", addr.Hex()).Msg("address derived")

	return &info, nil
}

// DeriveAddresses derives multiple addresses from an HD wallet.
func (p *HDWalletProvider) DeriveAddresses(ctx context.Context, primaryAddr string, start, count uint32) ([]types.SignerInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	addrKey := normalizeAddress(primaryAddr)
	state, ok := p.wallets[addrKey]
	if !ok {
		if _, locked := p.lockedPaths[addrKey]; locked {
			return nil, fmt.Errorf("HD wallet is locked for primary address %s (unlock first)", primaryAddr)
		}
		return nil, fmt.Errorf("HD wallet not found for primary address %s", primaryAddr)
	}

	end := start + count
	addrs, err := state.wallet.DeriveAddresses(start, end)
	if err != nil {
		return nil, fmt.Errorf("failed to derive addresses [%d, %d): %w", start, end, err)
	}

	var result []types.SignerInfo
	for i, addr := range addrs {
		idx := start + uint32(i)
		if err := p.registerDerivedSigner(addr, state.wallet, idx, state); err != nil {
			// Already exists is not an error — it was previously derived
			if err == types.ErrAlreadyExists {
				state.derivedIndices = appendUniqueUint32(state.derivedIndices, idx)
				result = append(result, types.SignerInfo{
					Address: addr.Hex(),
					Type:    string(types.SignerTypeHDWallet),
					Enabled: true,
				})
				continue
			}
			return nil, err
		}
		state.derivedIndices = appendUniqueUint32(state.derivedIndices, idx)
		result = append(result, types.SignerInfo{
			Address: addr.Hex(),
			Type:    string(types.SignerTypeHDWallet),
			Enabled: true,
		})
	}

	if err := p.derivStore.Save(addrKey, state.derivedIndices); err != nil {
		logger.EVM().Warn().Str("primary_address", primaryAddr).Err(err).Msg("failed to persist derivation state")
	}

	logger.EVM().Info().Str("primary_address", primaryAddr).Uint64("start", uint64(start)).Uint64("count", uint64(count)).Int("derived", len(result)).Msg("addresses derived")

	return result, nil
}

// ListHDWallets returns information about all HD wallets: loaded (unlocked) and discovered (locked) on disk.
func (p *HDWalletProvider) ListHDWallets() []HDWalletInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var wallets []HDWalletInfo
	for _, state := range p.wallets {
		info, _ := keystore.GetHDWalletInfo(state.walletPath)
		basePath := ""
		primaryAddress := ""
		if info != nil {
			basePath = info.BasePath
			primaryAddress = info.PrimaryAddress
		}
		wallets = append(wallets, HDWalletInfo{
			PrimaryAddress: primaryAddress,
			BasePath:       basePath,
			DerivedCount:   len(state.derived),
			Derived:        state.derived,
			Locked:         false,
		})
	}
	for addrKey, walletPath := range p.lockedPaths {
		if _, loaded := p.wallets[addrKey]; loaded {
			continue
		}
		info, _ := keystore.GetHDWalletInfo(walletPath)
		basePath := ""
		primaryAddress := addrKey
		if info != nil {
			basePath = info.BasePath
			primaryAddress = info.PrimaryAddress
		}
		wallets = append(wallets, HDWalletInfo{
			PrimaryAddress: primaryAddress,
			BasePath:       basePath,
			DerivedCount:   0,
			Derived:        nil,
			Locked:         true,
		})
	}
	return wallets
}

// ListPrimaryAddresses returns primary addresses of all HD wallets (for permission checks).
func (p *HDWalletProvider) ListPrimaryAddresses() []string {
	wallets := p.ListHDWallets()
	out := make([]string, 0, len(wallets))
	for _, w := range wallets {
		if w.PrimaryAddress != "" {
			out = append(out, w.PrimaryAddress)
		}
	}
	return out
}

// ListDerivedAddresses returns all derived addresses for an HD wallet.
func (p *HDWalletProvider) ListDerivedAddresses(primaryAddr string) ([]types.SignerInfo, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	addrKey := normalizeAddress(primaryAddr)
	state, ok := p.wallets[addrKey]
	if !ok {
		if _, locked := p.lockedPaths[addrKey]; locked {
			return nil, fmt.Errorf("HD wallet is locked for primary address %s (unlock first)", primaryAddr)
		}
		return nil, fmt.Errorf("HD wallet not found for primary address %s", primaryAddr)
	}

	result := make([]types.SignerInfo, len(state.derived))
	copy(result, state.derived)
	return result, nil
}

// registerDerivedSigner creates an ethsig.Signer from a derived key and registers it.
// Must be called with p.mu held (or during construction when no concurrency).
func (p *HDWalletProvider) registerDerivedSigner(addr common.Address, wallet *keystore.HDWallet, index uint32, state *hdWalletState) error {
	// Check if already registered
	addrKey := normalizeAddress(addr.Hex())
	if p.registry.HasSigner(addrKey) {
		// Already registered, just track in state if not already
		for _, d := range state.derived {
			if strings.EqualFold(d.Address, addr.Hex()) {
				return types.ErrAlreadyExists
			}
		}
		state.derived = append(state.derived, types.SignerInfo{
			Address: addr.Hex(),
			Type:    string(types.SignerTypeHDWallet),
			Enabled: true,
		})
		return types.ErrAlreadyExists
	}

	privKey, err := wallet.DeriveKey(index)
	if err != nil {
		return fmt.Errorf("failed to derive key at index %d: %w", index, err)
	}

	keySigner := ethsig.NewEthPrivateKeySigner(privKey)
	signer := ethsig.NewSigner(keySigner)

	info := types.SignerInfo{
		Address: addr.Hex(),
		Type:    string(types.SignerTypeHDWallet),
		Enabled: true,
	}

	if err := p.registry.RegisterSigner(addr.Hex(), signer, info); err != nil {
		return fmt.Errorf("failed to register derived signer %s: %w", addr.Hex(), err)
	}

	state.derived = append(state.derived, info)
	return nil
}

// DiscoverLockedSigners scans walletDir for HD wallet files not already loaded.
func (p *HDWalletProvider) DiscoverLockedSigners() ([]types.SignerInfo, error) {
	if p.walletDir == "" {
		return nil, nil
	}

	wallets, err := keystore.ListHDWallets(p.walletDir)
	if err != nil {
		return nil, fmt.Errorf("failed to list HD wallets in %s: %w", p.walletDir, err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	var discovered []types.SignerInfo
	for _, w := range wallets {
		addrKey := normalizeAddress(w.PrimaryAddress)
		if _, exists := p.wallets[addrKey]; exists {
			continue
		}
		if p.registry.HasSigner(addrKey) {
			continue
		}

		p.lockedPaths[addrKey] = w.Path
		info := types.SignerInfo{
			Address: common.HexToAddress(w.PrimaryAddress).Hex(),
			Type:    string(types.SignerTypeHDWallet),
			Enabled: false,
			Locked:  true,
		}
		discovered = append(discovered, info)

		logger.EVM().Info().Str("primary_address", info.Address).Str("path", w.Path).Msg("discovered locked HD wallet")
	}

	return discovered, nil
}

// UnlockSigner unlocks a locked HD wallet signer with the given password.
// Derives all persisted indices (or [0] if none) so derivation state survives restart.
func (p *HDWalletProvider) UnlockSigner(ctx context.Context, address string, password string) (*ethsig.Signer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	addrKey := normalizeAddress(address)
	filePath, ok := p.lockedPaths[addrKey]
	if !ok {
		return nil, fmt.Errorf("no locked HD wallet found for address %s", address)
	}

	passwordBytes := []byte(password)
	wallet, err := keystore.OpenHDWallet(filePath, passwordBytes)
	keystore.SecureZeroize(passwordBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unlock HD wallet for %s: %w", address, err)
	}

	// Load persisted derivation indices; default to [0] if none
	indices := p.derivStore.Load(addrKey)
	if len(indices) == 0 {
		indices = []uint32{0}
	}

	state := &hdWalletState{
		wallet:         wallet,
		walletPath:     filePath,
		derivedIndices: indices,
	}

	var primarySigner *ethsig.Signer

	// Derive and register all indices
	for _, idx := range indices {
		addr, err := wallet.DeriveAddress(idx)
		if err != nil {
			if closeErr := wallet.Close(); closeErr != nil {
				logger.EVM().Warn().Err(closeErr).Msg("failed to close wallet on error")
			}
			return nil, fmt.Errorf("failed to derive address at index %d: %w", idx, err)
		}
		if idx == 0 {
			// Primary address is already in registry as locked (from DiscoverLockedSigners).
			// Create signer for return; SignerManager will call registry.UnlockSigner to replace it.
			privKey, err := wallet.DeriveKey(0)
			if err != nil {
				if closeErr := wallet.Close(); closeErr != nil {
					logger.EVM().Warn().Err(closeErr).Msg("failed to close wallet on error")
				}
				return nil, fmt.Errorf("failed to derive key at index 0: %w", err)
			}
			keySigner := ethsig.NewEthPrivateKeySigner(privKey)
			primarySigner = ethsig.NewSigner(keySigner)
			state.derived = append(state.derived, types.SignerInfo{
				Address: addr.Hex(),
				Type:    string(types.SignerTypeHDWallet),
				Enabled: true,
			})
			continue
		}
		if err := p.registerDerivedSigner(addr, wallet, idx, state); err != nil {
			if err != types.ErrAlreadyExists {
				if closeErr := wallet.Close(); closeErr != nil {
					logger.EVM().Warn().Err(closeErr).Msg("failed to close wallet on error")
				}
				return nil, err
			}
		}
	}

	if primarySigner == nil {
		if closeErr := wallet.Close(); closeErr != nil {
			logger.EVM().Warn().Err(closeErr).Msg("failed to close wallet on error")
		}
		return nil, fmt.Errorf("primary signer not created (indices missing 0?)")
	}

	p.wallets[addrKey] = state
	delete(p.lockedPaths, addrKey)

	logger.EVM().Info().Str("primary_address", address).Int("derived_count", len(state.derived)).Msg("HD wallet signer unlocked")

	return primarySigner, nil
}

// LockSigner locks an unlocked HD wallet signer (closes wallet, stores path for later unlock).
func (p *HDWalletProvider) LockSigner(ctx context.Context, address string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	addrKey := normalizeAddress(address)
	state, ok := p.wallets[addrKey]
	if !ok {
		return fmt.Errorf("HD wallet not found for address %s", address)
	}

	// Close the wallet to zeroize keys
	if err := state.wallet.Close(); err != nil {
		logger.EVM().Warn().Err(err).Msg("failed to close wallet during lock")
	}

	// Store path for later unlock
	p.lockedPaths[addrKey] = state.walletPath

	// Lock all derived signers in the registry
	for _, d := range state.derived {
		derivedKey := normalizeAddress(d.Address)
		if derivedKey == addrKey {
			continue // primary will be locked by the manager
		}
		// Remove derived signers from registry (they need the wallet to be usable)
		// The registry doesn't have a Remove method, so we lock them too
		if err := p.registry.LockSigner(d.Address); err != nil {
			logger.EVM().Warn().Str("address", d.Address).Err(err).Msg("failed to lock derived signer")
		}
	}

	delete(p.wallets, addrKey)

	logger.EVM().Info().Str("primary_address", address).Msg("HD wallet signer locked")

	return nil
}

// appendUniqueUint32 appends v to s if not already present.
func appendUniqueUint32(s []uint32, v uint32) []uint32 {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// Compile-time interface checks.
var (
	_ SignerDiscoverer = (*HDWalletProvider)(nil)
	_ SignerUnlocker   = (*HDWalletProvider)(nil)
	_ SignerLocker     = (*HDWalletProvider)(nil)
)
