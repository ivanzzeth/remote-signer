package registry

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// TemplateRegistry coordinates one TemplateSource against the
// TemplateRepository. Its single Sync entry point is called at boot
// (and later via API) to bring the DB in line with the source.
//
// The Registry is stateless across calls: every Sync re-reads the full
// source list. That keeps the protocol simple at the cost of one
// directory walk per refresh, which is fine for the file-count we
// expect (sub-thousand). Remote sources implementing TemplateSource
// are free to cache internally.
type TemplateRegistry struct {
	repo   storage.TemplateRepository
	source TemplateSource
	log    *slog.Logger
}

// NewTemplateRegistry returns a Registry bound to one source. The
// logger is required; pass slog.Default() if the caller has no
// preference. nil repo or source panics at Sync time, not here, so the
// constructor stays trivial.
func NewTemplateRegistry(repo storage.TemplateRepository, source TemplateSource, log *slog.Logger) *TemplateRegistry {
	if log == nil {
		log = slog.Default()
	}
	return &TemplateRegistry{repo: repo, source: source, log: log}
}

// Sync runs one reconcile cycle: enumerate the source, upsert each
// item (content-hash skip on no change), then prune DB rows under the
// same Source kind that the source no longer lists.
//
// The returned error is non-nil only for infrastructure-level failures
// (source.List, repo.ListIDsBySource, repo.DeleteMany). Per-item upsert
// errors are collected in SyncReport.Errors so a single bad row does
// not block a thousand-template catalogue. The caller decides whether
// non-empty Errors should fail boot.
func (r *TemplateRegistry) Sync(ctx context.Context) (SyncReport, error) {
	items, err := r.source.List(ctx)
	if err != nil {
		return SyncReport{Source: r.source.Kind()}, fmt.Errorf("source list: %w", err)
	}

	report := SyncReport{Source: r.source.Kind()}
	seen := make(map[string]bool, len(items))

	for _, t := range items {
		if t == nil || t.ID == "" {
			report.Errors = append(report.Errors, SyncError{Err: fmt.Errorf("nil or empty ID in source list")})
			continue
		}
		if seen[t.ID] {
			report.Errors = append(report.Errors, SyncError{
				ID:   t.ID,
				Path: t.SourcePath,
				Err:  fmt.Errorf("duplicate ID %q (collides with earlier file)", t.ID),
			})
			continue
		}
		seen[t.ID] = true

		changed, err := r.repo.Upsert(ctx, t)
		if err != nil {
			report.Errors = append(report.Errors, SyncError{ID: t.ID, Path: t.SourcePath, Err: err})
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

	r.log.Info("template sync complete",
		"source", string(r.source.Kind()),
		"changed", report.Changed,
		"skipped", report.Skipped,
		"deleted", report.Deleted,
		"errors", len(report.Errors),
	)
	return report, nil
}
