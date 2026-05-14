package registry

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// PresetRegistry is the preset counterpart to TemplateRegistry. The
// shape is intentionally identical — same Sync semantics, same
// content-hash skip — so operators see consistent boot logs for the
// two catalogues and a future cross-source orchestrator can drive
// both via one loop.
type PresetRegistry struct {
	repo   storage.PresetRepository
	source PresetSource
	log    *slog.Logger
}

func NewPresetRegistry(repo storage.PresetRepository, source PresetSource, log *slog.Logger) *PresetRegistry {
	if log == nil {
		log = slog.Default()
	}
	return &PresetRegistry{repo: repo, source: source, log: log}
}

// Sync mirrors TemplateRegistry.Sync. See that method's doc for the
// invariants — they apply identically here.
func (r *PresetRegistry) Sync(ctx context.Context) (SyncReport, error) {
	items, err := r.source.List(ctx)
	if err != nil {
		return SyncReport{Source: r.source.Kind()}, fmt.Errorf("source list: %w", err)
	}

	report := SyncReport{Source: r.source.Kind()}
	seen := make(map[string]bool, len(items))

	for _, p := range items {
		if p == nil || p.ID == "" {
			report.Errors = append(report.Errors, SyncError{Err: fmt.Errorf("nil or empty ID in source list")})
			continue
		}
		if seen[p.ID] {
			report.Errors = append(report.Errors, SyncError{
				ID:   p.ID,
				Path: p.SourcePath,
				Err:  fmt.Errorf("duplicate ID %q (collides with earlier file)", p.ID),
			})
			continue
		}
		seen[p.ID] = true

		changed, err := r.repo.Upsert(ctx, p)
		if err != nil {
			report.Errors = append(report.Errors, SyncError{ID: p.ID, Path: p.SourcePath, Err: err})
			continue
		}
		if changed {
			report.Changed++
		} else {
			report.Skipped++
		}
	}

	existing, err := r.repo.ListIDsBySource(ctx, r.source.Kind())
	if err != nil {
		return report, fmt.Errorf("list existing: %w", err)
	}
	var toDelete []string
	for _, id := range existing {
		if !seen[id] {
			toDelete = append(toDelete, id)
		}
	}
	if len(toDelete) > 0 {
		if err := r.repo.DeleteMany(ctx, toDelete); err != nil {
			return report, fmt.Errorf("prune: %w", err)
		}
		report.Deleted = len(toDelete)
	}

	r.log.Info("preset sync complete",
		"source", string(r.source.Kind()),
		"changed", report.Changed,
		"skipped", report.Skipped,
		"deleted", report.Deleted,
		"errors", len(report.Errors),
	)
	return report, nil
}
