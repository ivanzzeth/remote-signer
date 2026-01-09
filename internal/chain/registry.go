package chain

import (
	"fmt"
	"sync"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// Registry manages chain adapters
type Registry struct {
	mu       sync.RWMutex
	adapters map[types.ChainType]types.ChainAdapter
}

// NewRegistry creates a new chain adapter registry
func NewRegistry() *Registry {
	return &Registry{
		adapters: make(map[types.ChainType]types.ChainAdapter),
	}
}

// Register registers a chain adapter
func (r *Registry) Register(adapter types.ChainAdapter) error {
	if adapter == nil {
		return fmt.Errorf("adapter cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	chainType := adapter.Type()
	if _, exists := r.adapters[chainType]; exists {
		return fmt.Errorf("adapter for chain type %s already registered", chainType)
	}

	r.adapters[chainType] = adapter
	return nil
}

// Get returns a chain adapter by type
func (r *Registry) Get(chainType types.ChainType) (types.ChainAdapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	adapter, exists := r.adapters[chainType]
	if !exists {
		return nil, fmt.Errorf("no adapter registered for chain type: %s", chainType)
	}

	return adapter, nil
}

// SupportedChains returns all registered chain types
func (r *Registry) SupportedChains() []types.ChainType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	chains := make([]types.ChainType, 0, len(r.adapters))
	for ct := range r.adapters {
		chains = append(chains, ct)
	}
	return chains
}

// Has checks if a chain type is registered
func (r *Registry) Has(chainType types.ChainType) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.adapters[chainType]
	return exists
}
