package registry

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ---------- the sync loop both catalogues run ----------
//
// Templates and presets are two catalogues with one lifecycle: read what the
// source exposes, upsert each item, prune the rows that are no longer there.
// PresetRegistry.Sync and TemplateRegistry.Sync were byte-for-byte identical
// apart from a loop variable name and the noun in the log line — which
// PresetRegistry's own doc comment said out loud: "the shape is intentionally
// identical ... a future cross-source orchestrator can drive both via one
// loop." This is that loop.
//
// ⚠️ Two copies of a prune step is a worse problem than two copies of a
// getter. Sync deletes rows the source no longer lists, so a divergence here
// removes a catalogue entry on one path and keeps it on the other, and the
// operator sees a template that exists until the next restart.

// syncRepo is the slice of a catalogue repository that Sync needs. Both
// ports.TemplateRepository and ports.PresetRepository satisfy it structurally.
type syncRepo[T any] interface {
	Upsert(ctx context.Context, item T) (changed bool, err error)
	ListIDsBySource(ctx context.Context, source types.RuleSource) ([]string, error)
	DeleteMany(ctx context.Context, ids []string) error
}

// syncSource is the slice of a catalogue source that Sync needs.
type syncSource[T any] interface {
	Kind() types.RuleSource
	List(ctx context.Context) ([]T, error)
}

// syncCatalogue mirrors one source into one repository.
//
// ident returns the item's ID and source path. ⚠️ It must return an empty ID
// for a nil item: the caller's nil check and its empty-ID check were one
// branch, and Sync reports both as the same error rather than panicking on a
// source that yields a nil entry.
//
// noun appears in the completion log ("template sync complete"), which
// operators read at boot to see which catalogue moved.
func syncCatalogue[T any](
	ctx context.Context,
	repo syncRepo[T],
	source syncSource[T],
	ident func(T) (id string, path string),
	noun string,
	log *slog.Logger,
) (SyncReport, error) {
	items, err := source.List(ctx)
	if err != nil {
		return SyncReport{Source: source.Kind()}, fmt.Errorf("source list: %w", err)
	}

	report := SyncReport{Source: source.Kind()}
	seen := make(map[string]bool, len(items))

	for _, item := range items {
		id, path := ident(item)
		if id == "" {
			report.Errors = append(report.Errors, SyncError{Err: fmt.Errorf("nil or empty ID in source list")})
			continue
		}
		if seen[id] {
			report.Errors = append(report.Errors, SyncError{
				ID:   id,
				Path: path,
				Err:  fmt.Errorf("duplicate ID %q (collides with earlier file)", id),
			})
			continue
		}
		seen[id] = true

		changed, err := repo.Upsert(ctx, item)
		if err != nil {
			report.Errors = append(report.Errors, SyncError{ID: id, Path: path, Err: err})
			continue
		}
		if changed {
			report.Changed++
		} else {
			report.Skipped++
		}
	}

	// Prune: rows this source used to expose and no longer does. Scoped to
	// source.Kind(), so a file catalogue never deletes rows another source owns.
	existing, err := repo.ListIDsBySource(ctx, source.Kind())
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
		if err := repo.DeleteMany(ctx, toDelete); err != nil {
			return report, fmt.Errorf("prune: %w", err)
		}
		report.Deleted = len(toDelete)
	}

	log.Info(noun+" sync complete",
		"source", string(source.Kind()),
		"changed", report.Changed,
		"skipped", report.Skipped,
		"deleted", report.Deleted,
		"errors", len(report.Errors),
	)
	return report, nil
}
