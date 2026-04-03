package simulation

import "context"

// Simulator runs transaction simulation (eth_simulateV1 via the configured RPC gateway).
type Simulator interface {
	Simulate(ctx context.Context, req *SimulationRequest) (*SimulationResult, error)
	SimulateBatch(ctx context.Context, req *BatchSimulationRequest) (*BatchSimulationResult, error)
	// SyncIfDirty is a no-op for the RPC backend; reserved for future stateful engines.
	SyncIfDirty(ctx context.Context, chainID string) error
	// MarkDirty is a no-op for the RPC backend; reserved for future stateful engines.
	MarkDirty(chainID string)
	Status(ctx context.Context) *ManagerStatus
	Close() error
}
