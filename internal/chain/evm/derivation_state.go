package evm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/ivanzzeth/remote-signer/internal/logger"
)

const derivationStateFilename = ".derivation-state.json"

// derivationStateFile is the on-disk format for persisted derivation indices.
type derivationStateFile struct {
	Wallets map[string][]uint32 `json:"wallets"` // primaryAddr (checksummed) -> derive indices
}

// DerivationStateStore persists and loads HD wallet derivation indices.
type DerivationStateStore struct {
	path string
	mu   sync.RWMutex
}

// NewDerivationStateStore creates a store at {walletDir}/.derivation-state.json.
func NewDerivationStateStore(walletDir string) (*DerivationStateStore, error) {
	if walletDir == "" {
		return nil, fmt.Errorf("wallet directory is required")
	}
	return &DerivationStateStore{
		path: filepath.Join(walletDir, derivationStateFilename),
	}, nil
}

// Load returns the persisted derive indices for a primary address.
// Returns nil if not found or on error (caller uses [0] as default).
func (s *DerivationStateStore) Load(primaryAddr string) []uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.EVM().Debug().Str("path", s.path).Err(err).Msg("failed to read derivation state")
		}
		return nil
	}

	var file derivationStateFile
	if err := json.Unmarshal(data, &file); err != nil {
		logger.EVM().Debug().Str("path", s.path).Err(err).Msg("failed to parse derivation state")
		return nil
	}

	if file.Wallets == nil {
		return nil
	}

	indices, ok := file.Wallets[primaryAddr]
	if !ok || len(indices) == 0 {
		return nil
	}

	// Return a copy, sorted and deduplicated
	return dedupeAndSort(indices)
}

// Save persists derive indices for a primary address.
func (s *DerivationStateStore) Save(primaryAddr string, indices []uint32) error {
	if primaryAddr == "" {
		return fmt.Errorf("primary address is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var file derivationStateFile
	data, err := os.ReadFile(s.path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read derivation state: %w", err)
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &file); err != nil {
			return fmt.Errorf("parse derivation state: %w", err)
		}
	}
	if file.Wallets == nil {
		file.Wallets = make(map[string][]uint32)
	}

	file.Wallets[primaryAddr] = dedupeAndSort(indices)

	newData, err := json.MarshalIndent(&file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal derivation state: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create wallet dir: %w", err)
	}

	if err := os.WriteFile(s.path, newData, 0600); err != nil {
		return fmt.Errorf("write derivation state: %w", err)
	}

	return nil
}

// dedupeAndSort returns a sorted, deduplicated copy of indices.
func dedupeAndSort(indices []uint32) []uint32 {
	seen := make(map[uint32]struct{})
	var out []uint32
	for _, i := range indices {
		if _, ok := seen[i]; ok {
			continue
		}
		seen[i] = struct{}{}
		out = append(out, i)
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}
