// Package storage — request_simulation_repo.go persists
// types.RequestSimulation. One row per sign request; re-eval Upserts.
//
// Kept narrow on purpose — the simulation pipeline writes via
// Upsert, the handler reads via GetByRequestID, nothing else
// touches this table. List/filter endpoints can land later if
// operators need a "show me everything the simulator denied today"
// view.

package storage

import (
	"context"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// RequestSimulationRepository defines the persistence surface.
type RequestSimulationRepository interface {
	Upsert(ctx context.Context, sim *types.RequestSimulation) error
	GetByRequestID(ctx context.Context, signRequestID string) (*types.RequestSimulation, error)
}

// GormRequestSimulationRepository implements the interface against Gorm.
type GormRequestSimulationRepository struct {
	db *gorm.DB
}

// NewGormRequestSimulationRepository validates and returns a ready repo.
func NewGormRequestSimulationRepository(db *gorm.DB) (*GormRequestSimulationRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is required")
	}
	return &GormRequestSimulationRepository{db: db}, nil
}

// Upsert writes the simulation row, keyed by sign_request_id. ON
// CONFLICT replaces every column except sign_request_id + chain_id
// (those are stable per request). Each call refreshes UpdatedAt so
// the UI's auto-refresh can show "last simulated 3s ago" without
// the repo tracking a separate revision counter.
func (r *GormRequestSimulationRepository) Upsert(ctx context.Context, sim *types.RequestSimulation) error {
	if sim == nil {
		return fmt.Errorf("simulation row cannot be nil")
	}
	if sim.SignRequestID == "" {
		return fmt.Errorf("sign_request_id is required")
	}
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "sign_request_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"decision", "reason",
			"success", "gas_used", "revert_reason",
			"balance_changes", "events", "contracts",
			"decoded_calldata", "raw_result",
			"simulated_at", "updated_at",
		}),
	}).Create(sim).Error
}

// GetByRequestID returns ErrNotFound when no simulation row exists —
// the UI uses that to render "evaluating, please wait" rather than a
// hard error.
func (r *GormRequestSimulationRepository) GetByRequestID(ctx context.Context, signRequestID string) (*types.RequestSimulation, error) {
	var sim types.RequestSimulation
	err := r.db.WithContext(ctx).Where("sign_request_id = ?", signRequestID).First(&sim).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, types.ErrNotFound
		}
		return nil, fmt.Errorf("get simulation: %w", err)
	}
	return &sim, nil
}
